use super::WireError;

/// Bounds-checked cursor over a received message body.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.remaining() < n {
            return Err(WireError::Truncated {
                needed: n - self.remaining(),
            });
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn byte(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    pub fn boolean(&mut self) -> Result<bool, WireError> {
        // RFC 4251 §5: 0 is false, all non-zero values MUST be interpreted
        // as true (though applications MUST NOT store values other than 0/1).
        Ok(self.byte()? != 0)
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes(b.try_into().expect("len checked")))
    }

    /// `string`: u32 length followed by that many bytes.
    pub fn string(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// A `string` that must be valid UTF-8.
    pub fn utf8(&mut self) -> Result<&'a str, WireError> {
        std::str::from_utf8(self.string()?).map_err(|_| WireError::BadUtf8)
    }

    /// `name-list`: comma-separated names inside a string.
    pub fn name_list(&mut self) -> Result<Vec<String>, WireError> {
        let s = self.utf8()?;
        if s.is_empty() {
            return Ok(Vec::new());
        }
        Ok(s.split(',').map(str::to_owned).collect())
    }

    /// Everything not yet consumed.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.buf[self.pos..];
        self.pos = self.buf.len();
        out
    }

    /// Assert the message was fully consumed. Messages with trailing bytes
    /// are malformed — tolerating them invites smuggling.
    pub fn finish(&self) -> Result<(), WireError> {
        match self.remaining() {
            0 => Ok(()),
            n => Err(WireError::TrailingBytes(n)),
        }
    }
}
