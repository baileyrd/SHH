/// Builder for outgoing message bodies.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer::default()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn byte(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Fixed-size raw bytes with no length prefix (e.g. the KEXINIT cookie).
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    pub fn boolean(&mut self, v: bool) -> &mut Self {
        self.buf.push(v as u8);
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn string(&mut self, v: &[u8]) -> &mut Self {
        self.u32(v.len() as u32);
        self.buf.extend_from_slice(v);
        self
    }

    pub fn utf8(&mut self, v: &str) -> &mut Self {
        self.string(v.as_bytes())
    }

    pub fn name_list(&mut self, names: &[&str]) -> &mut Self {
        self.utf8(&names.join(","))
    }

    /// `mpint`: big-endian two's complement. Our values are always
    /// non-negative, so: strip leading zeros, then prepend a zero byte if
    /// the high bit is set (RFC 4251 §5).
    pub fn mpint(&mut self, v: &[u8]) -> &mut Self {
        let v = {
            let mut s = v;
            while let Some((0, rest)) = s.split_first() {
                s = rest;
            }
            s
        };
        if v.is_empty() {
            return self.u32(0);
        }
        let sign = (v[0] & 0x80 != 0) as u32;
        self.u32(v.len() as u32 + sign);
        if sign == 1 {
            self.buf.push(0);
        }
        self.buf.extend_from_slice(v);
        self
    }
}
