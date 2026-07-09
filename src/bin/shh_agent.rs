//! shh-agent — the SHH key agent.
//!
//! The agent keeps Ed25519 keys in one long-lived process and signs for
//! clients over a Unix socket, so it is inherently Unix (the socket, its
//! peer-credential checks, and the daemon lifecycle have no Windows analogue
//! short of a named-pipe rewrite — see the Windows agent follow-up). On
//! non-Unix this builds as an honest stub rather than a broken binary.

#[cfg(unix)]
#[path = "shh_agent_impl.rs"]
mod imp;

#[cfg(unix)]
fn main() {
    imp::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!(
        "shh-agent runs only on Unix — it serves keys over a Unix socket with \
         peer-credential checks. A Windows named-pipe agent is a separate task."
    );
    std::process::exit(1);
}
