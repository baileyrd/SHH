//! The SFTP v3 server engine.
//!
//! [`run`] drives one client to completion over an async reader/writer pair.
//! It operates on the real filesystem with the process's own credentials —
//! exactly OpenSSH's non-chroot `sftp-server` model — so the daemon runs it
//! in a subprocess that has already dropped to the logged-in user. There is
//! no path sandbox here: ordinary filesystem permissions are the boundary.
//!
//! The loop is strictly request→reply, so blocking `std::fs` calls are fine —
//! the subprocess has nothing else to do while a syscall runs.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use tokio::io::{AsyncRead, AsyncWrite};

use super::{fxp, open, status, Attrs, MAX_PACKET};
use crate::wire::{Reader, Writer};

/// An open handle the server tracks between requests.
enum Handle {
    File(File),
    /// A directory read: the entries snapshotted at OPENDIR, and how many
    /// have been returned so far. `None` name means the "." / ".." synthetics.
    Dir { entries: Vec<PathBuf>, next: usize },
}

struct Session {
    handles: HashMap<String, Handle>,
    next_handle: u64,
}

impl Session {
    fn new() -> Session {
        Session {
            handles: HashMap::new(),
            next_handle: 0,
        }
    }

    fn insert(&mut self, h: Handle) -> String {
        let id = self.next_handle.to_string();
        self.next_handle += 1;
        self.handles.insert(id.clone(), h);
        id
    }
}

/// Serve one SFTP client until it closes the channel (clean EOF) or a
/// transport error occurs.
pub async fn run<R, W>(mut reader: R, mut writer: W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Handshake: the first packet must be INIT; we answer VERSION 3.
    let (typ, payload) = super::read_packet(&mut reader).await?;
    if typ != fxp::INIT {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "expected SSH_FXP_INIT",
        ));
    }
    // Payload is the client's version; we simply advertise ours.
    let _ = payload;
    let mut vw = Writer::new();
    vw.u32(super::VERSION);
    super::write_packet(&mut writer, fxp::VERSION, &vw.into_bytes()).await?;

    let mut sess = Session::new();
    loop {
        let (typ, payload) = match super::read_packet(&mut reader).await {
            Ok(p) => p,
            // A clean EOF from the client ends the session normally.
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let reply = handle_request(&mut sess, typ, &payload);
        super::write_packet(&mut writer, reply.0, &reply.1).await?;
    }
}

/// Dispatch one request to a `(type, payload)` reply. Parse failures become a
/// BAD_MESSAGE status against request-id 0 — malformed input never aborts the
/// session.
fn handle_request(sess: &mut Session, typ: u8, payload: &[u8]) -> (u8, Vec<u8>) {
    let mut r = Reader::new(payload);
    // Every request but INIT leads with a request-id.
    let id = match r.u32() {
        Ok(id) => id,
        Err(_) => return status_reply(0, status::BAD_MESSAGE, "truncated request"),
    };
    match dispatch(sess, typ, id, &mut r) {
        Ok(reply) => reply,
        Err(Fail::Wire) => status_reply(id, status::BAD_MESSAGE, "malformed request"),
        Err(Fail::Io(e)) => status_reply(id, errno_status(&e), &e.to_string()),
        Err(Fail::Unsupported) => {
            status_reply(id, status::OP_UNSUPPORTED, "operation not supported")
        }
    }
}

/// Internal failure kinds, mapped to SFTP statuses at the edge.
enum Fail {
    Wire,
    Io(std::io::Error),
    Unsupported,
}
impl From<crate::wire::WireError> for Fail {
    fn from(_: crate::wire::WireError) -> Fail {
        Fail::Wire
    }
}
impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Fail {
        Fail::Io(e)
    }
}

fn dispatch(sess: &mut Session, typ: u8, id: u32, r: &mut Reader) -> Result<(u8, Vec<u8>), Fail> {
    match typ {
        fxp::REALPATH => {
            let path = r.utf8()?;
            let resolved = realpath(Path::new(path));
            Ok(name_reply(id, &resolved, &Attrs::default()))
        }
        fxp::STAT => {
            let path = r.utf8()?.to_owned();
            let meta = std::fs::metadata(&path)?;
            Ok(attrs_reply(id, &Attrs::from_metadata(&meta)))
        }
        fxp::LSTAT => {
            let path = r.utf8()?.to_owned();
            let meta = std::fs::symlink_metadata(&path)?;
            Ok(attrs_reply(id, &Attrs::from_metadata(&meta)))
        }
        fxp::FSTAT => {
            let handle = r.utf8()?;
            match sess.handles.get(handle) {
                Some(Handle::File(f)) => {
                    let meta = f.metadata()?;
                    Ok(attrs_reply(id, &Attrs::from_metadata(&meta)))
                }
                _ => Ok(status_reply(id, status::FAILURE, "not an open file")),
            }
        }
        fxp::OPEN => {
            let path = r.utf8()?.to_owned();
            let pflags = r.u32()?;
            let attrs = Attrs::read(r)?;
            open_file(sess, id, &path, pflags, &attrs)
        }
        fxp::CLOSE => {
            let handle = r.utf8()?.to_owned();
            let existed = sess.handles.remove(&handle).is_some();
            if existed {
                Ok(status_reply(id, status::OK, "closed"))
            } else {
                Ok(status_reply(id, status::FAILURE, "no such handle"))
            }
        }
        fxp::READ => {
            let handle = r.utf8()?;
            let offset = r.u64()?;
            // Reserve headroom for the DATA frame's header (id + length +
            // type byte) so the reply never exceeds MAX_PACKET, which a
            // conformant peer — including our own read_packet — would reject.
            let len = r.u32()?.min(MAX_PACKET - 1024) as usize;
            match sess.handles.get(handle) {
                Some(Handle::File(f)) => {
                    let mut buf = vec![0u8; len];
                    let n = f.read_at(&mut buf, offset)?;
                    if n == 0 {
                        Ok(status_reply(id, status::EOF, "end of file"))
                    } else {
                        buf.truncate(n);
                        Ok(data_reply(id, &buf))
                    }
                }
                _ => Ok(status_reply(id, status::FAILURE, "not an open file")),
            }
        }
        fxp::WRITE => {
            let handle = r.utf8()?;
            let offset = r.u64()?;
            let data = r.string()?;
            match sess.handles.get(handle) {
                Some(Handle::File(f)) => {
                    f.write_all_at(data, offset)?;
                    Ok(status_reply(id, status::OK, "written"))
                }
                _ => Ok(status_reply(id, status::FAILURE, "not an open file")),
            }
        }
        fxp::OPENDIR => {
            let path = r.utf8()?.to_owned();
            let mut entries = Vec::new();
            for ent in std::fs::read_dir(&path)? {
                entries.push(ent?.path());
            }
            let handle = sess.insert(Handle::Dir { entries, next: 0 });
            Ok(handle_reply(id, &handle))
        }
        fxp::READDIR => {
            let handle = r.utf8()?.to_owned();
            read_dir(sess, id, &handle)
        }
        fxp::REMOVE => {
            let path = r.utf8()?.to_owned();
            std::fs::remove_file(&path)?;
            Ok(status_reply(id, status::OK, "removed"))
        }
        fxp::MKDIR => {
            let path = r.utf8()?.to_owned();
            let attrs = Attrs::read(r)?;
            std::fs::create_dir(&path)?;
            if let Some(mode) = attrs.permissions {
                set_mode(Path::new(&path), mode)?;
            }
            Ok(status_reply(id, status::OK, "created"))
        }
        fxp::RMDIR => {
            let path = r.utf8()?.to_owned();
            std::fs::remove_dir(&path)?;
            Ok(status_reply(id, status::OK, "removed"))
        }
        fxp::RENAME => {
            let from = r.utf8()?.to_owned();
            let to = r.utf8()?.to_owned();
            std::fs::rename(&from, &to)?;
            Ok(status_reply(id, status::OK, "renamed"))
        }
        fxp::SETSTAT => {
            let path = r.utf8()?.to_owned();
            let attrs = Attrs::read(r)?;
            apply_setstat(Path::new(&path), None, &attrs)?;
            Ok(status_reply(id, status::OK, "updated"))
        }
        fxp::FSETSTAT => {
            let handle = r.utf8()?.to_owned();
            let attrs = Attrs::read(r)?;
            match sess.handles.get(&handle) {
                Some(Handle::File(f)) => {
                    apply_setstat(Path::new(""), Some(f), &attrs)?;
                    Ok(status_reply(id, status::OK, "updated"))
                }
                _ => Ok(status_reply(id, status::FAILURE, "not an open file")),
            }
        }
        fxp::READLINK => {
            let path = r.utf8()?.to_owned();
            let target = std::fs::read_link(&path)?;
            Ok(name_reply(id, &target.to_string_lossy(), &Attrs::default()))
        }
        fxp::SYMLINK => {
            // v3 order: linkpath (the new symlink), then targetpath.
            let linkpath = r.utf8()?.to_owned();
            let targetpath = r.utf8()?.to_owned();
            std::os::unix::fs::symlink(&targetpath, &linkpath)?;
            Ok(status_reply(id, status::OK, "linked"))
        }
        _ => Err(Fail::Unsupported),
    }
}

fn open_file(
    sess: &mut Session,
    id: u32,
    path: &str,
    pflags: u32,
    attrs: &Attrs,
) -> Result<(u8, Vec<u8>), Fail> {
    let mut opts = OpenOptions::new();
    opts.read(pflags & open::READ != 0);
    if pflags & open::WRITE != 0 {
        opts.write(true);
    }
    if pflags & open::APPEND != 0 {
        opts.append(true);
    }
    if pflags & open::CREAT != 0 {
        opts.create(true);
    }
    if pflags & open::TRUNC != 0 {
        opts.truncate(true);
    }
    if pflags & open::EXCL != 0 {
        opts.create_new(true);
    }
    // A file created here honors the requested mode; default 0644 otherwise.
    let mode = attrs.permissions.unwrap_or(0o644) & 0o7777;
    opts.mode(mode);
    let file = opts.open(path)?;
    let handle = sess.insert(Handle::File(file));
    Ok(handle_reply(id, &handle))
}

fn read_dir(sess: &mut Session, id: u32, handle: &str) -> Result<(u8, Vec<u8>), Fail> {
    let (batch, done) = match sess.handles.get_mut(handle) {
        Some(Handle::Dir { entries, next }) => {
            if *next >= entries.len() {
                (Vec::new(), true)
            } else {
                // Serve up to 64 entries per READDIR, as OpenSSH does.
                let end = (*next + 64).min(entries.len());
                let batch: Vec<PathBuf> = entries[*next..end].to_vec();
                *next = end;
                (batch, false)
            }
        }
        _ => return Ok(status_reply(id, status::FAILURE, "not an open directory")),
    };
    if done {
        return Ok(status_reply(id, status::EOF, "end of directory"));
    }

    let mut w = Writer::new();
    w.u32(id);
    w.u32(batch.len() as u32);
    for path in &batch {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // lstat so a symlink is reported as a link, not its target.
        let attrs = std::fs::symlink_metadata(path)
            .map(|m| Attrs::from_metadata(&m))
            .unwrap_or_default();
        w.utf8(&name);
        w.utf8(&long_name(&name, &attrs));
        attrs.write(&mut w);
    }
    Ok((fxp::NAME, w.into_bytes()))
}

/// Apply a SETSTAT/FSETSTAT: size (truncate), permissions, and mtime. `file`
/// is present for FSETSTAT (operate on the handle), else operate on `path`.
fn apply_setstat(path: &Path, file: Option<&File>, attrs: &Attrs) -> std::io::Result<()> {
    if let Some(size) = attrs.size {
        match file {
            Some(f) => f.set_len(size)?,
            None => OpenOptions::new().write(true).open(path)?.set_len(size)?,
        }
    }
    if let Some(mode) = attrs.permissions {
        match file {
            Some(f) => {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(mode))?;
            }
            None => set_mode(path, mode)?,
        }
    }
    if let Some((atime, mtime)) = attrs.times {
        set_times(path, file, atime, mtime)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(unix)]
fn set_times(path: &Path, file: Option<&File>, atime: u32, mtime: u32) -> std::io::Result<()> {
    use nix::sys::stat::{utimensat, UtimensatFlags};
    use nix::sys::time::TimeSpec;
    let atime = TimeSpec::new(atime as i64, 0);
    let mtime = TimeSpec::new(mtime as i64, 0);
    match file {
        Some(f) => {
            use std::os::unix::io::AsRawFd;
            nix::sys::stat::futimens(f.as_raw_fd(), &atime, &mtime).map_err(std::io::Error::from)
        }
        None => utimensat(None, path, &atime, &mtime, UtimensatFlags::FollowSymlink)
            .map_err(std::io::Error::from),
    }
}

// ---------------------------------------------------------- reply builders --

fn status_reply(id: u32, code: u32, message: &str) -> (u8, Vec<u8>) {
    let mut w = Writer::new();
    w.u32(id);
    w.u32(code);
    w.utf8(message);
    w.utf8(""); // language tag
    (fxp::STATUS, w.into_bytes())
}

fn handle_reply(id: u32, handle: &str) -> (u8, Vec<u8>) {
    let mut w = Writer::new();
    w.u32(id);
    w.utf8(handle);
    (fxp::HANDLE, w.into_bytes())
}

fn data_reply(id: u32, data: &[u8]) -> (u8, Vec<u8>) {
    let mut w = Writer::new();
    w.u32(id);
    w.string(data);
    (fxp::DATA, w.into_bytes())
}

fn attrs_reply(id: u32, attrs: &Attrs) -> (u8, Vec<u8>) {
    let mut w = Writer::new();
    w.u32(id);
    attrs.write(&mut w);
    (fxp::ATTRS, w.into_bytes())
}

fn name_reply(id: u32, name: &str, attrs: &Attrs) -> (u8, Vec<u8>) {
    let mut w = Writer::new();
    w.u32(id);
    w.u32(1); // one name
    w.utf8(name);
    w.utf8(&long_name(name, attrs));
    attrs.write(&mut w);
    (fxp::NAME, w.into_bytes())
}

/// Map an I/O error to the closest SFTP status code.
fn errno_status(e: &std::io::Error) -> u32 {
    match e.kind() {
        ErrorKind::NotFound => status::NO_SUCH_FILE,
        ErrorKind::PermissionDenied => status::PERMISSION_DENIED,
        _ => status::FAILURE,
    }
}

/// Resolve a path the way REALPATH should: canonicalize when it exists,
/// otherwise return a lexically-absolute best effort (OpenSSH does the same,
/// so `put` into a not-yet-existing name still gets a usable absolute path).
fn realpath(path: &Path) -> String {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return canon.to_string_lossy().into_owned();
    }
    let base = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
    };
    let mut out = base;
    for comp in path.components() {
        use std::path::Component::*;
        match comp {
            RootDir => out = PathBuf::from("/"),
            CurDir => {}
            ParentDir => {
                out.pop();
            }
            Normal(c) => out.push(c),
            Prefix(_) => {}
        }
    }
    if out.as_os_str().is_empty() {
        out = PathBuf::from("/");
    }
    out.to_string_lossy().into_owned()
}

/// An `ls -l`-style long name, as SFTP v3 expects in NAME replies.
fn long_name(name: &str, attrs: &Attrs) -> String {
    let mode = attrs.permissions.unwrap_or(0);
    let size = attrs.size.unwrap_or(0);
    let mtime = attrs.times.map(|(_, m)| m).unwrap_or(0);
    let (owner, group) = attrs
        .uid_gid
        .map(|(u, g)| (owner_name(u), group_name(g)))
        .unwrap_or_else(|| ("0".into(), "0".into()));
    format!(
        "{} 1 {:<8} {:<8} {:>8} {} {}",
        perm_string(mode),
        owner,
        group,
        size,
        ls_date(mtime),
        name
    )
}

/// The 10-character permission string, e.g. `-rwxr-xr-x`.
fn perm_string(mode: u32) -> String {
    let file_type = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o060000 => 'b',
        0o020000 => 'c',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '-',
    };
    let rwx = |shift: u32| {
        let bits = (mode >> shift) & 0o7;
        [
            if bits & 0o4 != 0 { 'r' } else { '-' },
            if bits & 0o2 != 0 { 'w' } else { '-' },
            if bits & 0o1 != 0 { 'x' } else { '-' },
        ]
    };
    let mut s = String::with_capacity(10);
    s.push(file_type);
    for shift in [6, 3, 0] {
        s.extend(rwx(shift));
    }
    s
}

#[cfg(unix)]
fn owner_name(uid: u32) -> String {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string())
}

#[cfg(unix)]
fn group_name(gid: u32) -> String {
    nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))
        .ok()
        .flatten()
        .map(|g| g.name)
        .unwrap_or_else(|| gid.to_string())
}

/// Format an epoch time as `Mon DD HH:MM`, the `ls` short form. Uses a plain
/// civil-date computation so we need no calendar crate.
fn ls_date(secs: u32) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (_, month, day) = civil_from_days(days);
    format!(
        "{} {:>2} {:02}:{:02}",
        MONTHS[(month - 1) as usize],
        day,
        rem / 3600,
        (rem % 3600) / 60
    )
}

/// Convert days-since-epoch to a (year, month, day) civil date. Howard
/// Hinnant's algorithm; epoch day 0 is 1970-01-01.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perm_string_formats_common_modes() {
        assert_eq!(perm_string(0o100_644), "-rw-r--r--");
        assert_eq!(perm_string(0o040_755), "drwxr-xr-x");
        assert_eq!(perm_string(0o120_777), "lrwxrwxrwx");
    }

    #[test]
    fn civil_date_epoch_and_a_known_day() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2021-01-01 is 18628 days after the epoch.
        assert_eq!(civil_from_days(18628), (2021, 1, 1));
    }
}
