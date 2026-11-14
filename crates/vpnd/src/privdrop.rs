//! Giving up privilege once it's no longer needed. vpnd needs CAP_NET_ADMIN
//! (or root) only to create the TUN device and set its addresses; after that
//! the fd is all it needs. So it opens everything, then drops to nothing:
//! a compromised vpnd can't reconfigure the network or touch root's files.

use anyhow::Result;

/// Switches to `user` if given (needs root), then clears every capability
/// set and sets no_new_privs so neither can come back, even through exec.
#[cfg(target_os = "linux")]
pub fn drop_privileges(user: Option<&str>) -> Result<()> {
    use anyhow::{Context, bail};
    use caps::CapSet;
    use nix::unistd::{Gid, Uid, User, getgid, getuid, setgid, setgroups, setuid};

    if let Some(name) = user {
        let u = match name.parse::<u32>() {
            Ok(uid) => User::from_uid(Uid::from_raw(uid))?,
            Err(_) => User::from_name(name)?,
        }
        .with_context(|| format!("no such user {name}"))?;
        if !Uid::effective().is_root() {
            bail!("--user needs vpnd started as root, so it can switch to {name}");
        }
        // Groups first: once the uid is gone we're no longer allowed to.
        setgroups(&[u.gid]).context("setgroups")?;
        setgid(u.gid).context("setgid")?;
        setuid(u.uid).context("setuid")?;
        if setuid(Uid::from_raw(0)).is_ok() || setgid(Gid::from_raw(0)).is_ok() {
            bail!("could switch back to root after dropping privileges");
        }
    }

    for set in [
        CapSet::Ambient,
        CapSet::Inheritable,
        CapSet::Effective,
        CapSet::Permitted,
    ] {
        caps::clear(None, set).with_context(|| format!("clearing {set:?} capabilities"))?;
    }
    nix::sys::prctl::set_no_new_privs().context("setting no_new_privs")?;
    tracing::info!(
        uid = getuid().as_raw(),
        gid = getgid().as_raw(),
        "dropped privileges, no capabilities left"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn drop_privileges(user: Option<&str>) -> Result<()> {
    if user.is_some() {
        anyhow::bail!("--user is only supported on Linux");
    }
    Ok(())
}
