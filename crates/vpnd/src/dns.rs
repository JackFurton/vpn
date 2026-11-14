//! Points the system resolver at the tunnel's DNS servers while it's up.
//!
//! Linux: systemd-resolved, as per-link DNS on the tunnel interface with the
//! routing domain "~.", so every lookup goes there. resolved drops per-link
//! settings when the interface disappears, so there's nothing to undo after
//! vpnd has given up its privileges. Setting them needs CAP_NET_ADMIN, which
//! is why this runs before the drop.
//!
//! macOS: a resolver entry in the dynamic store via scutil, removed on exit.
//!
//! If DNS is configured but can't be applied, vpnd refuses to start rather
//! than come up with lookups silently leaking outside the tunnel.

use std::net::IpAddr;

use anyhow::Result;

#[must_use = "call remove() on shutdown"]
pub struct Applied {
    #[cfg(target_os = "macos")]
    key: Option<String>,
}

pub fn apply(servers: &[IpAddr], ifname: &str) -> Result<Applied> {
    if servers.is_empty() {
        return Ok(Applied {
            #[cfg(target_os = "macos")]
            key: None,
        });
    }
    imp::apply(servers, ifname)
}

impl Applied {
    pub fn remove(self) {
        #[cfg(target_os = "macos")]
        if let Some(key) = self.key {
            let _ = scutil(&format!("remove {key}\n"));
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::process::Command;

    use anyhow::{Context, bail};

    use super::*;

    fn run(cmd: &str, args: &[String]) -> Result<()> {
        let out = Command::new(cmd)
            .args(args)
            .output()
            .with_context(|| format!("running {cmd}"))?;
        if !out.status.success() {
            bail!(
                "{cmd} {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    pub fn apply(servers: &[IpAddr], ifname: &str) -> Result<Applied> {
        let mut dns = vec!["dns".to_owned(), ifname.to_owned()];
        dns.extend(servers.iter().map(IpAddr::to_string));
        run("resolvectl", &dns).context(
            "setting DNS through systemd-resolved; it needs to be running, or remove `dns` from the config and set DNS yourself",
        )?;
        // "~." makes this link the route for every domain, not just a search
        // domain, so nothing falls through to the physical interface's DNS.
        run("resolvectl", &["domain".into(), ifname.into(), "~.".into()])?;
        run(
            "resolvectl",
            &["default-route".into(), ifname.into(), "yes".into()],
        )?;
        tracing::info!(?servers, interface = ifname, "DNS goes through the tunnel");
        Ok(Applied {})
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    pub fn apply(servers: &[IpAddr], ifname: &str) -> Result<Applied> {
        let key = format!("State:/Network/Service/vpnd-{ifname}/DNS");
        let addrs: Vec<String> = servers.iter().map(IpAddr::to_string).collect();
        // An empty supplemental match domain matches every name, so this
        // resolver gets all queries rather than only some domains.
        scutil(&format!(
            "d.init\nd.add ServerAddresses * {}\nd.add SupplementalMatchDomains * \"\"\nset {key}\n",
            addrs.join(" ")
        ))?;
        tracing::info!(?servers, interface = ifname, "DNS goes through the tunnel");
        Ok(Applied { key: Some(key) })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use anyhow::bail;

    use super::*;

    pub fn apply(_: &[IpAddr], _: &str) -> Result<Applied> {
        bail!("`dns` isn't supported on this platform yet");
    }
}

#[cfg(target_os = "macos")]
fn scutil(script: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use anyhow::{Context, bail};

    let mut child = Command::new("/usr/sbin/scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("running scutil")?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("scutil: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}
