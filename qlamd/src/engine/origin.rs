//! Where a downloaded file came from, checked against URLhaus.
//!
//! Chromium-based browsers (and `wget --xattr`, `curl --xattr`) record the
//! download URL in the `user.xdg.origin.url` extended attribute. A file
//! fetched from a URL that URLhaus lists as distributing malware is reported
//! whatever its content looks like: the URL is the evidence, and it also
//! covers payloads no signature knows yet.
//!
//! URLs are compared after `normalize`, and stored only as SHA-256 of the
//! normalized form (in the hash-list format, see hashdb.rs), so the feed is
//! small and exact matching is a binary search.

use std::os::fd::{AsRawFd, BorrowedFd};

use sha2::{Digest, Sha256};

const XATTR: &[u8] = b"user.xdg.origin.url\0";

/// The download URL recorded on the file, if any.
pub fn origin_url(fd: BorrowedFd<'_>) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = unsafe { libc::fgetxattr(fd.as_raw_fd(), XATTR.as_ptr().cast(), buf.as_mut_ptr().cast(), buf.len()) };
    if n <= 0 {
        return None;
    }
    let s = std::str::from_utf8(&buf[..n as usize]).ok()?;
    Some(s.trim_end_matches('\0').to_string())
}

/// Canonical form of a URL for matching: scheme and host lowercased, user
/// info, fragment and default ports dropped, an empty path made "/". Path
/// and query are kept byte for byte (no percent-decoding: a different
/// encoding is a different URL to the server too). None for anything but
/// http, https and ftp.
pub fn normalize(url: &str) -> Option<String> {
    let url = url.trim();
    let url = url.split('#').next()?;
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => "80",
        "https" => "443",
        "ftp" => "21",
        _ => return None,
    };
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(split);
    let host_port = authority.rsplit('@').next()?;
    // IPv6 literals keep their brackets; the port is after the last ']'.
    let (host, port) = match host_port.rfind(':') {
        Some(i) if !host_port[i..].contains(']') => (&host_port[..i], Some(&host_port[i + 1..])),
        _ => (host_port, None),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let port = port.filter(|p| !p.is_empty() && *p != default_port).map(|p| format!(":{p}")).unwrap_or_default();
    let path = if path.is_empty() { "/".to_string() } else if path.starts_with('?') { format!("/{path}") } else { path.to_string() };
    Some(format!("{scheme}://{host}{port}{path}"))
}

/// Hash-list key of a URL: hex SHA-256 of its normalized form.
pub fn url_key(url: &str) -> Option<String> {
    normalize(url).map(|n| hex::encode(Sha256::digest(n.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        assert_eq!(normalize("HTTP://Example.COM:80/a/B?x=1#frag").as_deref(), Some("http://example.com/a/B?x=1"));
        assert_eq!(normalize("https://user:pw@host.example.:443").as_deref(), Some("https://host.example/"));
        assert_eq!(normalize("http://1.2.3.4:8080/bins/x.mips").as_deref(), Some("http://1.2.3.4:8080/bins/x.mips"));
        assert_eq!(normalize("http://h?q").as_deref(), Some("http://h/?q"));
        assert_eq!(normalize("http://[::1]:81/x").as_deref(), Some("http://[::1]:81/x"));
        assert_eq!(normalize("http://[::1]/x").as_deref(), Some("http://[::1]/x"));
        assert_eq!(normalize("file:///etc/passwd"), None);
        assert_eq!(normalize("javascript:alert(1)"), None);
        assert_eq!(url_key("http://A.example/x"), url_key("http://a.example:80/x#y"));
    }

    #[test]
    fn reads_the_origin_attribute() {
        let dir = std::env::temp_dir().join(format!("qlam-origin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("dl.bin");
        std::fs::write(&p, b"x").unwrap();
        let f = std::fs::File::open(&p).unwrap();
        use std::os::fd::AsFd;
        assert_eq!(origin_url(f.as_fd()), None);
        let path = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        let url = b"http://bad.example/x";
        let set = unsafe { libc::setxattr(path.as_ptr(), XATTR.as_ptr().cast(), url.as_ptr().cast(), url.len(), 0) };
        // tmpfs without user xattrs, or an old kernel: nothing to test.
        if set == 0 {
            assert_eq!(origin_url(f.as_fd()).as_deref(), Some("http://bad.example/x"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
