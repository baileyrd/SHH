//! KEXINIT construction, parsing, and algorithm negotiation (RFC 4253 §7.1),
//! plus the strict-KEX and ext-info indicator flags that ride in the KEX
//! name-list (RFC 8308, OpenSSH PROTOCOL "strict KEX").

use rand_core::{OsRng, RngCore};

use crate::crypto::{self, cipher, kex};
use crate::wire::{msg, Reader, Writer};
use crate::{Error, Result};

pub const STRICT_CLIENT: &str = "kex-strict-c-v00@openssh.com";
pub const STRICT_SERVER: &str = "kex-strict-s-v00@openssh.com";
pub const EXT_INFO_CLIENT: &str = "ext-info-c";
pub const EXT_INFO_SERVER: &str = "ext-info-s";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Client,
    Server,
}

#[derive(Clone, Debug)]
pub struct KexInit {
    pub cookie: [u8; 16],
    pub kex: Vec<String>,
    pub host_keys: Vec<String>,
    pub enc_c2s: Vec<String>,
    pub enc_s2c: Vec<String>,
    pub mac_c2s: Vec<String>,
    pub mac_s2c: Vec<String>,
    pub comp_c2s: Vec<String>,
    pub comp_s2c: Vec<String>,
    pub lang_c2s: Vec<String>,
    pub lang_s2c: Vec<String>,
    pub first_packet_follows: bool,
}

impl KexInit {
    /// Our own KEXINIT. The strict-KEX marker is always present: this
    /// implementation does not have a non-strict mode.
    pub fn local(side: Side) -> Self {
        let mut kex: Vec<String> = crypto::KEX_ALGORITHMS.iter().map(|s| s.to_string()).collect();
        match side {
            Side::Client => {
                kex.push(EXT_INFO_CLIENT.into());
                kex.push(STRICT_CLIENT.into());
            }
            Side::Server => {
                kex.push(EXT_INFO_SERVER.into());
                kex.push(STRICT_SERVER.into());
            }
        }
        let strs = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut cookie = [0u8; 16];
        OsRng.fill_bytes(&mut cookie);
        KexInit {
            cookie,
            kex,
            host_keys: strs(crypto::HOST_KEY_ALGORITHMS),
            enc_c2s: strs(crypto::CIPHERS),
            enc_s2c: strs(crypto::CIPHERS),
            mac_c2s: strs(crypto::MACS),
            mac_s2c: strs(crypto::MACS),
            comp_c2s: strs(crypto::COMPRESSION),
            comp_s2c: strs(crypto::COMPRESSION),
            lang_c2s: vec![],
            lang_s2c: vec![],
            first_packet_follows: false,
        }
    }

    /// Full payload including the message byte — this exact byte string is
    /// what enters the exchange hash as I_C / I_S.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.byte(msg::KEXINIT);
        w.raw(&self.cookie);
        for list in [
            &self.kex,
            &self.host_keys,
            &self.enc_c2s,
            &self.enc_s2c,
            &self.mac_c2s,
            &self.mac_s2c,
            &self.comp_c2s,
            &self.comp_s2c,
            &self.lang_c2s,
            &self.lang_s2c,
        ] {
            let refs: Vec<&str> = list.iter().map(String::as_str).collect();
            w.name_list(&refs);
        }
        w.boolean(self.first_packet_follows);
        w.u32(0); // reserved
        w.into_bytes()
    }

    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        if r.byte()? != msg::KEXINIT {
            return Err(Error::proto("expected KEXINIT"));
        }
        let mut cookie = [0u8; 16];
        for b in cookie.iter_mut() {
            *b = r.byte()?;
        }
        let mut lists: Vec<Vec<String>> = Vec::with_capacity(10);
        for _ in 0..10 {
            lists.push(r.name_list()?);
        }
        let first_packet_follows = r.boolean()?;
        let _reserved = r.u32()?;
        r.finish()?;
        let mut it = lists.into_iter();
        Ok(KexInit {
            cookie,
            kex: it.next().unwrap(),
            host_keys: it.next().unwrap(),
            enc_c2s: it.next().unwrap(),
            enc_s2c: it.next().unwrap(),
            mac_c2s: it.next().unwrap(),
            mac_s2c: it.next().unwrap(),
            comp_c2s: it.next().unwrap(),
            comp_s2c: it.next().unwrap(),
            lang_c2s: it.next().unwrap(),
            lang_s2c: it.next().unwrap(),
            first_packet_follows,
        })
    }
}

/// Everything the rest of the handshake needs to know.
#[derive(Debug)]
pub struct Negotiated {
    pub kex: kex::Algorithm,
    pub cipher_c2s: cipher::Algorithm,
    pub cipher_s2c: cipher::Algorithm,
    /// Peer advertised ext-info (RFC 8308).
    pub peer_ext_info: bool,
    /// Peer sent a guessed KEX packet that must be discarded.
    pub discard_guess: bool,
}

/// RFC 4253 §7.1: for each category, pick the first entry of the client's
/// list that also appears in the server's list.
fn choose<'a>(
    kind: &'static str,
    client: &'a [String],
    server: &'a [String],
) -> Result<&'a str> {
    client
        .iter()
        .find(|c| server.contains(c))
        .map(String::as_str)
        .ok_or_else(|| Error::Negotiation {
            kind,
            offered: client.join(","),
        })
}

/// Negotiate. `side` is who *we* are; `ours`/`theirs` are the two KEXINITs.
pub fn negotiate(side: Side, ours: &KexInit, theirs: &KexInit) -> Result<Negotiated> {
    let (client, server) = match side {
        Side::Client => (ours, theirs),
        Side::Server => (theirs, ours),
    };

    // Strict KEX is not optional here. Every maintained implementation has
    // shipped it since the Terrapin disclosure; a peer without it is either
    // ancient or an active middlebox. Refuse both.
    let (peer_flag, peer_ext) = match side {
        Side::Client => (STRICT_SERVER, EXT_INFO_SERVER),
        Side::Server => (STRICT_CLIENT, EXT_INFO_CLIENT),
    };
    if !theirs.kex.iter().any(|a| a == peer_flag) {
        return Err(Error::proto(
            "peer does not support strict key exchange (kex-strict, the \
             Terrapin countermeasure); refusing to continue",
        ));
    }

    let kex_name = choose("key exchange", &client.kex, &server.kex)?;
    let kex = kex::Algorithm::from_name(kex_name)
        .ok_or_else(|| Error::proto(format!("negotiated unusable kex {kex_name:?}")))?;

    let host_key = choose("host key", &client.host_keys, &server.host_keys)?;
    if host_key != "ssh-ed25519" {
        return Err(Error::proto(format!(
            "negotiated unusable host key algorithm {host_key:?}"
        )));
    }

    let c2s = choose("cipher (client→server)", &client.enc_c2s, &server.enc_c2s)?;
    let s2c = choose("cipher (server→client)", &client.enc_s2c, &server.enc_s2c)?;
    let cipher_c2s = cipher::Algorithm::from_name(c2s)
        .ok_or_else(|| Error::proto(format!("negotiated unusable cipher {c2s:?}")))?;
    let cipher_s2c = cipher::Algorithm::from_name(s2c)
        .ok_or_else(|| Error::proto(format!("negotiated unusable cipher {s2c:?}")))?;

    // Compression must land on "none"; we never offer anything else, so
    // this can only fail against a zlib-only peer.
    choose("compression (client→server)", &client.comp_c2s, &server.comp_c2s)?;
    choose("compression (server→client)", &client.comp_s2c, &server.comp_s2c)?;

    // A wrong guess by the peer means their next KEX packet is garbage to
    // discard (RFC 4253 §7). The guess is right only when both parties'
    // first choices already agreed.
    let guess_right = client.kex.first() == server.kex.first()
        && client.host_keys.first() == server.host_keys.first();
    let discard_guess = theirs.first_packet_follows && !guess_right;

    Ok(Negotiated {
        kex,
        cipher_c2s,
        cipher_s2c,
        peer_ext_info: theirs.kex.iter().any(|a| a == peer_ext),
        discard_guess,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_parse_roundtrip() {
        let ki = KexInit::local(Side::Client);
        let bytes = ki.encode();
        let back = KexInit::parse(&bytes).unwrap();
        assert_eq!(back.cookie, ki.cookie);
        assert_eq!(back.kex, ki.kex);
        assert_eq!(back.enc_c2s, ki.enc_c2s);
        assert!(!back.first_packet_follows);
    }

    #[test]
    fn negotiates_preferred_algorithms() {
        let c = KexInit::local(Side::Client);
        let s = KexInit::local(Side::Server);
        let n = negotiate(Side::Client, &c, &s).unwrap();
        assert_eq!(n.kex, kex::Algorithm::MlKem768X25519Sha256);
        assert_eq!(n.cipher_c2s, cipher::Algorithm::ChaChaPoly);
        assert!(n.peer_ext_info);
        assert!(!n.discard_guess);
    }

    #[test]
    fn falls_back_to_curve25519() {
        let c = KexInit::local(Side::Client);
        let mut s = KexInit::local(Side::Server);
        s.kex = vec!["curve25519-sha256".into(), STRICT_SERVER.into()];
        let n = negotiate(Side::Client, &c, &s).unwrap();
        assert_eq!(n.kex, kex::Algorithm::Curve25519Sha256);
    }

    #[test]
    fn refuses_peer_without_strict_kex() {
        let c = KexInit::local(Side::Client);
        let mut s = KexInit::local(Side::Server);
        s.kex.retain(|a| a != STRICT_SERVER);
        assert!(negotiate(Side::Client, &c, &s).is_err());
    }

    #[test]
    fn refuses_legacy_only_peer() {
        let c = KexInit::local(Side::Client);
        let mut s = KexInit::local(Side::Server);
        s.kex = vec!["diffie-hellman-group14-sha256".into(), STRICT_SERVER.into()];
        assert!(matches!(
            negotiate(Side::Client, &c, &s),
            Err(Error::Negotiation { .. })
        ));

        let mut s = KexInit::local(Side::Server);
        s.host_keys = vec!["rsa-sha2-512".into()];
        assert!(negotiate(Side::Client, &c, &s).is_err());

        let mut s = KexInit::local(Side::Server);
        s.enc_c2s = vec!["aes128-cbc".into()];
        assert!(negotiate(Side::Client, &c, &s).is_err());
    }

    #[test]
    fn wrong_guess_flagged_for_discard() {
        let c = KexInit::local(Side::Client);
        let mut s = KexInit::local(Side::Server);
        s.kex = vec![
            "curve25519-sha256".into(),
            "mlkem768x25519-sha256".into(),
            STRICT_SERVER.into(),
        ];
        s.first_packet_follows = true;
        let n = negotiate(Side::Client, &c, &s).unwrap();
        assert!(n.discard_guess);
    }
}
