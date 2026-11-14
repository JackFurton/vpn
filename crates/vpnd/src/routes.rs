//! Points the OS routing table at the tunnel for each peer's allowed_ips.
//!
//! Ordinary prefixes get a main-table route on the TUN device. A default
//! route (0.0.0.0/0 or ::/0) can't go in the main table: vpnd's own UDP
//! packets to the server would match it and loop into the tunnel. So, like
//! wg-quick, vpnd marks its socket and adds two policy rules:
//!
//!   from all lookup main suppress_prefixlength 0     main, minus its default
//!   not from all fwmark MARK lookup TABLE            everything else unmarked
//!
//! TABLE holds just "default dev tun". Marked packets (ours) skip both rules
//! and use the normal default route. This keeps working when the server's
//! endpoint changes, which a /32 host route wouldn't.
//!
//! macOS has no fwmark routing, so there a default route becomes the classic
//! split instead: 0.0.0.0/1 and 128.0.0.0/1 on the tunnel (each more specific
//! than the real default route, which stays untouched), plus a host route
//! for every peer endpoint via whatever reached it before. vpnd stays root on
//! macOS and removes those on exit.
//!
//! On Linux every route points at the TUN device, so the kernel deletes them when the
//! device goes away, which matters because vpnd drops the privilege to remove
//! anything itself. The two rules can outlive vpnd, but with TABLE empty
//! they only fall through, and the next start clears them.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::config::Config;

pub const FWMARK: u32 = 0x7670;
pub const TABLE: u32 = 0x7670;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Main-table routes on the TUN device.
    pub routes: Vec<IpNet>,
    pub default_v4: bool,
    pub default_v6: bool,
    /// Where peers live. On macOS these need host routes that bypass the
    /// tunnel once it carries a default route.
    pub endpoints: Vec<IpAddr>,
}

impl Plan {
    pub fn has_default(&self) -> bool {
        self.default_v4 || self.default_v6
    }
}

pub fn plan(config: &Config) -> Plan {
    let own: Vec<IpNet> = config
        .interface
        .addresses
        .iter()
        .map(IpNet::trunc)
        .collect();
    let mut p = Plan::default();
    for net in config.peers.iter().flat_map(|peer| &peer.allowed_ips) {
        match net {
            IpNet::V4(n) if n.prefix_len() == 0 => p.default_v4 = true,
            IpNet::V6(n) if n.prefix_len() == 0 => p.default_v6 = true,
            // The interface address already brought its subnet's route.
            _ if own.iter().any(|o| o.contains(net)) => {}
            _ if p.routes.contains(net) => {}
            _ => p.routes.push(*net),
        }
    }
    p.endpoints = config
        .peers
        .iter()
        .filter_map(|peer| peer.endpoint.map(|e| e.ip()))
        .collect();
    p
}

/// What `apply` changed, to undo on exit where vpnd still can.
#[derive(Default)]
pub struct Installed {
    #[cfg(target_os = "macos")]
    routes: Vec<route_manager::Route>,
}

#[cfg(target_os = "linux")]
pub use linux::apply;
#[cfg(target_os = "macos")]
pub use macos::apply;

impl Installed {
    pub fn remove(self) {
        #[cfg(target_os = "macos")]
        macos::remove(self.routes);
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use anyhow::{Context, Result};
    use route_manager::{Route, RouteManager};

    use super::{Installed, Plan};

    pub async fn apply(plan: &Plan, ifname: &str) -> Result<Installed> {
        let mut rm = RouteManager::new().context("opening routing socket")?;
        let mut added = Vec::new();
        let on_tunnel = |dst: IpAddr, len: u8| Route::new(dst, len).with_if_name(ifname.to_owned());

        let mut wanted: Vec<Route> = Vec::new();
        if plan.has_default() {
            // Pin each endpoint to its current path before the /1s capture it.
            for &ep in &plan.endpoints {
                let current = rm
                    .find_route(&ep)?
                    .with_context(|| format!("no route to endpoint {ep}"))?;
                let len = if ep.is_ipv4() { 32 } else { 128 };
                let mut host = Route::new(ep, len);
                host = match (current.gateway(), current.if_name()) {
                    (Some(gw), _) if !gw.is_unspecified() => host.with_gateway(gw),
                    (_, Some(name)) => host.with_if_name(name.clone()),
                    _ => continue,
                };
                wanted.push(host);
            }
        }
        if plan.default_v4 {
            wanted.push(on_tunnel(Ipv4Addr::new(0, 0, 0, 0).into(), 1));
            wanted.push(on_tunnel(Ipv4Addr::new(128, 0, 0, 0).into(), 1));
        }
        if plan.default_v6 {
            wanted.push(on_tunnel(Ipv6Addr::UNSPECIFIED.into(), 1));
            wanted.push(on_tunnel(
                Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0).into(),
                1,
            ));
        }
        wanted.extend(
            plan.routes
                .iter()
                .map(|n| on_tunnel(n.network(), n.prefix_len())),
        );

        for route in wanted {
            match rm.add(&route) {
                Ok(()) => {
                    tracing::info!(dst = %route.destination(), prefix = route.prefix(), "route added");
                    added.push(route);
                }
                Err(e) => {
                    tracing::warn!(dst = %route.destination(), prefix = route.prefix(), %e, "couldn't add route")
                }
            }
        }
        Ok(Installed { routes: added })
    }

    pub fn remove(routes: Vec<Route>) {
        let Ok(mut rm) = RouteManager::new() else {
            return;
        };
        for route in routes.iter().rev() {
            // Routes on the utun device usually vanish with it already.
            let _ = rm.delete(route);
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use anyhow::{Context, Result};
    use futures_util::TryStreamExt;
    use ipnet::IpNet;
    use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleFlags, RuleMessage};
    use rtnetlink::{Handle, IpVersion, RouteMessageBuilder};

    use super::{FWMARK, Plan, TABLE};

    // Just ahead of the main table's rule at 32766.
    const SUPPRESS_PRIORITY: u32 = 32_760;
    const NOT_MARKED_PRIORITY: u32 = 32_761;

    pub async fn apply(plan: &Plan, ifname: &str) -> Result<super::Installed> {
        let (conn, handle, _) = rtnetlink::new_connection().context("opening netlink")?;
        tokio::spawn(conn);
        let index = handle
            .link()
            .get()
            .match_name(ifname.to_owned())
            .execute()
            .try_next()
            .await?
            .with_context(|| format!("no interface {ifname}"))?
            .header
            .index;

        for v in [IpVersion::V4, IpVersion::V6] {
            remove_our_rules(&handle, v).await?;
        }
        for net in &plan.routes {
            let msg = match net {
                IpNet::V4(n) => RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(n.network(), n.prefix_len())
                    .output_interface(index)
                    .build(),
                IpNet::V6(n) => RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(n.network(), n.prefix_len())
                    .output_interface(index)
                    .build(),
            };
            match handle.route().add(msg).execute().await {
                Ok(()) => tracing::info!(%net, dev = ifname, "route added"),
                // Someone else's route for the same prefix wins; say so.
                Err(e) => tracing::warn!(%net, %e, "couldn't add route"),
            }
        }
        if plan.default_v4 {
            let route = RouteMessageBuilder::<Ipv4Addr>::new()
                .output_interface(index)
                .table_id(TABLE)
                .build();
            handle
                .route()
                .add(route)
                .execute()
                .await
                .context("adding IPv4 tunnel default route")?;
            let r = handle.rule().add().v4();
            add_rules(r.table_id(TABLE).fw_mark(FWMARK), handle.rule().add().v4()).await?;
            tracing::info!(dev = ifname, "all IPv4 traffic now goes through the tunnel");
        }
        if plan.default_v6 {
            let route = RouteMessageBuilder::<Ipv6Addr>::new()
                .output_interface(index)
                .table_id(TABLE)
                .build();
            handle
                .route()
                .add(route)
                .execute()
                .await
                .context("adding IPv6 tunnel default route")?;
            let r = handle.rule().add().v6();
            add_rules(r.table_id(TABLE).fw_mark(FWMARK), handle.rule().add().v6()).await?;
            tracing::info!(dev = ifname, "all IPv6 traffic now goes through the tunnel");
        }
        Ok(super::Installed::default())
    }

    async fn add_rules<T>(
        mut not_marked: rtnetlink::RuleAddRequest<T>,
        suppress: rtnetlink::RuleAddRequest<T>,
    ) -> Result<()> {
        not_marked.message_mut().header.flags |= RuleFlags::Invert;
        // The builder defaults to action "none", which makes the kernel fail
        // every lookup that reaches the rule with EINVAL.
        not_marked
            .action(RuleAction::ToTable)
            .priority(NOT_MARKED_PRIORITY)
            .execute()
            .await
            .context("adding fwmark rule")?;
        let mut suppress = suppress.table_id(u32::from(
            rtnetlink::packet_route::route::RouteHeader::RT_TABLE_MAIN,
        ));
        suppress
            .message_mut()
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(0));
        suppress
            .action(RuleAction::ToTable)
            .priority(SUPPRESS_PRIORITY)
            .execute()
            .await
            .context("adding suppress_prefixlength rule")?;
        Ok(())
    }

    fn is_ours(rule: &RuleMessage) -> bool {
        rule.attributes.iter().any(|a| match a {
            RuleAttribute::FwMark(m) => *m == FWMARK,
            RuleAttribute::Table(t) => *t == TABLE,
            RuleAttribute::Priority(p) => *p == SUPPRESS_PRIORITY,
            _ => false,
        })
    }

    async fn remove_our_rules(handle: &Handle, v: IpVersion) -> Result<()> {
        let rules: Vec<RuleMessage> = handle.rule().get(v).execute().try_collect().await?;
        for rule in rules.into_iter().filter(is_ours) {
            handle
                .rule()
                .del(rule)
                .execute()
                .await
                .context("removing stale rule")?;
            tracing::debug!("removed a policy rule left by an earlier run");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(addresses: &[&str], peers: &[&[&str]]) -> Config {
        let key = vpn_proto::keys::KeyPair::generate().unwrap();
        let mut text = format!(
            "[interface]\nprivate_key = \"{}\"\naddresses = [{}]\n",
            key.private.to_base64(),
            addresses
                .iter()
                .map(|a| format!("\"{a}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for ips in peers {
            let pk = vpn_proto::keys::KeyPair::generate().unwrap().public;
            text += &format!(
                "[[peer]]\npublic_key = \"{}\"\nallowed_ips = [{}]\n",
                pk.to_base64(),
                ips.iter()
                    .map(|a| format!("\"{a}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        Config::parse(&text).unwrap()
    }

    #[test]
    fn skips_what_the_interface_subnet_covers() {
        let c = config(
            &["10.8.0.2/24"],
            &[&["10.8.0.0/24", "10.8.0.1/32", "192.168.50.0/24"]],
        );
        let p = plan(&c);
        assert_eq!(p.routes, vec!["192.168.50.0/24".parse::<IpNet>().unwrap()]);
        assert!(!p.has_default());
    }

    #[test]
    fn default_routes_switch_on_policy_routing() {
        let c = config(
            &["10.8.0.2/24", "fd08::2/64"],
            &[&["0.0.0.0/0", "::/0"], &["172.16.0.0/12"]],
        );
        let p = plan(&c);
        assert!(p.default_v4 && p.default_v6 && p.has_default());
        assert_eq!(p.routes, vec!["172.16.0.0/12".parse::<IpNet>().unwrap()]);
    }
}
