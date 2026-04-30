// ── String Literal Classification ──────────────────────────────────
//
// Classifies a raw string extracted from a binary into one of a small
// set of intent-bearing types. Lets users filter binary strings by
// what they mean: meta-path "pe->string->endpoint" filtered to
// string_type=url, etc.
//
// Pure heuristic — no false-positive cost since the classification
// is informational. Generic-fallback for anything we don't recognize.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringType {
    Url,
    Sql,
    FilePath,
    RegistryKey,
    Guid,
    Base64,
    Hex,
    FormatString,
    ErrorMessage,
    EmailAddress,
    EnvVar,
    UserAgent,
    /// Default — none of the above matched.
    Generic,
}

impl StringType {
    pub fn as_str(&self) -> &'static str {
        match self {
            StringType::Url           => "url",
            StringType::Sql           => "sql",
            StringType::FilePath      => "path",
            StringType::RegistryKey   => "registry",
            StringType::Guid          => "guid",
            StringType::Base64        => "base64",
            StringType::Hex           => "hex",
            StringType::FormatString  => "format_str",
            StringType::ErrorMessage  => "error_msg",
            StringType::EmailAddress  => "email",
            StringType::EnvVar        => "envvar",
            StringType::UserAgent     => "user_agent",
            StringType::Generic       => "generic",
        }
    }
}

/// Classify a string by intent. Order matters — more specific patterns
/// are checked first (URLs / GUIDs / Base64 etc.) before generic
/// substring fallbacks.
pub fn classify(s: &str) -> StringType {
    let len = s.len();
    if len < 4 { return StringType::Generic; }
    let lower = s.to_ascii_lowercase();

    // ── URL ───────────────────────────────────────────────────────
    if lower.starts_with("http://") || lower.starts_with("https://")
        || lower.starts_with("ftp://") || lower.starts_with("ws://")
        || lower.starts_with("wss://") || lower.starts_with("file://")
        || lower.starts_with("ldap://") || lower.starts_with("ssh://") {
        return StringType::Url;
    }

    // ── User-Agent (must come before generic UA fragments slip into Url) ──
    if lower.starts_with("mozilla/") || lower.starts_with("curl/")
        || lower.starts_with("python-requests/") || lower.starts_with("wget/") {
        return StringType::UserAgent;
    }

    // ── Email ─────────────────────────────────────────────────────
    if let Some(at) = s.find('@') {
        if at > 0 && at < s.len() - 3 {
            let after = &s[at + 1..];
            if after.contains('.') && !after.contains(' ') && !after.contains('/') {
                let local = &s[..at];
                if local.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '+') {
                    return StringType::EmailAddress;
                }
            }
        }
    }

    // ── GUID/UUID ─────────────────────────────────────────────────
    if is_guid(s) { return StringType::Guid; }

    // ── Registry key (Windows) ────────────────────────────────────
    if lower.starts_with("hkey_") || lower.starts_with("hklm")
        || lower.starts_with("hkcu") || lower.starts_with("software\\")
        || lower.starts_with("system\\") {
        return StringType::RegistryKey;
    }

    // ── File path (Windows or POSIX) ──────────────────────────────
    if is_file_path(s) { return StringType::FilePath; }

    // ── Env var reference (case-insensitive prefix) ───────────────
    if (s.starts_with('%') && s.ends_with('%') && s.len() > 2 && !s[1..s.len()-1].contains('%'))
        || lower.starts_with("path=") || lower.starts_with("home=") {
        return StringType::EnvVar;
    }

    // ── SQL ───────────────────────────────────────────────────────
    if is_sql(&lower) { return StringType::Sql; }

    // ── Format string (printf / .NET) ─────────────────────────────
    if is_format_string(s) { return StringType::FormatString; }

    // ── Error message ─────────────────────────────────────────────
    if is_error_message(&lower) { return StringType::ErrorMessage; }

    // ── Hex blob (often a hash or address) ────────────────────────
    if is_hex_blob(s) { return StringType::Hex; }

    // ── Base64 (last because URLs etc. can look base64-ish) ───────
    if is_base64(s) { return StringType::Base64; }

    StringType::Generic
}

fn is_guid(s: &str) -> bool {
    // 8-4-4-4-12 hex, optionally wrapped in {} or as bare 32-hex
    let core = s.trim_start_matches('{').trim_end_matches('}');
    if core.len() == 36 {
        let parts: Vec<&str> = core.split('-').collect();
        if parts.len() == 5 && parts[0].len() == 8 && parts[1].len() == 4
            && parts[2].len() == 4 && parts[3].len() == 4 && parts[4].len() == 12 {
            return parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
    false
}

fn is_file_path(s: &str) -> bool {
    // Windows: drive letter + : + \ or /, OR \\server\share, OR starts with %APPDATA%
    let bytes = s.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/') {
        return true;
    }
    if s.starts_with("\\\\") && s[2..].contains('\\') { return true; }
    // POSIX path: starts with /, has at least one more / segment, contains common path chars
    if s.starts_with('/') && s.len() > 4 && s[1..].contains('/')
        && !s.contains(' ') && !s.contains('\t') {
        // Avoid classifying URLs as paths; those have already been caught above.
        return true;
    }
    // Relative path with extension (./foo/bar.txt or ../etc)
    if (s.starts_with("./") || s.starts_with("../")) && s.len() > 4 { return true; }
    false
}

fn is_sql(lower: &str) -> bool {
    // Must contain a SQL verb followed by structure-like tokens.
    let kw = ["select ", "insert into ", "update ", "delete from ",
              "create table", "drop table", "alter table", "create index",
              "merge into", "with recursive"];
    kw.iter().any(|k| lower.contains(k))
        // Common from-clause / where-clause anchors to avoid matching
        // English prose starting with "select" etc.
        && (lower.contains(" from ") || lower.contains(" set ") || lower.contains(" where ")
            || lower.contains(" values ") || lower.contains(" into ") || lower.contains("("))
}

fn is_format_string(s: &str) -> bool {
    // C printf: %s %d %x %f etc., must have at least 2 distinct OR be
    // long enough that the conversion specs aren't accidental.
    let mut count = 0;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'%' {
            // Skip flags / width / precision: -+# 0 digits . *
            let mut j = i + 1;
            while j < bytes.len() && b"-+#0 .*0123456789".contains(&bytes[j]) { j += 1; }
            // Length modifier: h l ll L z j t
            while j < bytes.len() && b"hlLjzt".contains(&bytes[j]) { j += 1; }
            if j < bytes.len() && b"diouxXeEfgGaAscpn%".contains(&bytes[j]) {
                if bytes[j] != b'%' { count += 1; }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    if count >= 2 { return true; }
    // .NET format string: at least one {N} or {N:fmt}
    let mut net_count = 0;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '{' {
            let mut digits = 0;
            while let Some(&nc) = chars.peek() {
                if nc.is_ascii_digit() { digits += 1; chars.next(); }
                else { break; }
            }
            if digits > 0 && (chars.peek() == Some(&'}') || chars.peek() == Some(&':')) {
                net_count += 1;
            }
        }
    }
    net_count >= 1
}

fn is_error_message(lower: &str) -> bool {
    if lower.len() < 12 { return false; }
    // Has natural-language stop words AND error-y keywords
    let error_keywords = ["error", "failed", "cannot", "unable to", "invalid",
                          "exception", "panic", "assertion", "fatal", "warning:",
                          "expected", "unexpected", "missing", "denied", "refused",
                          "timeout", "permission", "access denied"];
    error_keywords.iter().any(|k| lower.contains(k))
        // Guard against single-word literals that happen to contain "error"
        // (e.g. "ERROR_NONE"). Real messages have spaces.
        && lower.contains(' ')
}

fn is_hex_blob(s: &str) -> bool {
    // 32+ hex chars (MD5+) and nothing else
    if s.len() < 32 { return false; }
    s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_base64(s: &str) -> bool {
    // 24+ chars, all base64-alphabet, with optional = padding
    if s.len() < 24 { return false; }
    let trimmed = s.trim_end_matches('=');
    if trimmed.is_empty() || trimmed.len() < 16 { return false; }
    let trail = s.len() - trimmed.len();
    if trail > 2 { return false; }
    if (trimmed.len() + trail) % 4 != 0 { return false; }
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '-' || c == '_') {
        return false;
    }
    // Require character diversity to avoid classifying hyphenated
    // lowercase prose (e.g. "not-a-guid-at-all-string") as base64.
    // Real base64 has uppercase + digits or explicit `=` padding.
    if trail > 0 { return true; }
    let has_upper = trimmed.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = trimmed.chars().any(|c| c.is_ascii_digit());
    let has_b64_special = trimmed.chars().any(|c| c == '+' || c == '/');
    has_upper || has_digit || has_b64_special
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_url() {
        assert_eq!(classify("https://example.com/api"), StringType::Url);
        assert_eq!(classify("ws://localhost:8080"), StringType::Url);
        assert_eq!(classify("ftp://user@host/file"), StringType::Url);
    }

    #[test]
    fn classify_guid() {
        assert_eq!(classify("550e8400-e29b-41d4-a716-446655440000"), StringType::Guid);
        assert_eq!(classify("{550e8400-e29b-41d4-a716-446655440000}"), StringType::Guid);
        assert_eq!(classify("not-a-guid-at-all-string"), StringType::Generic);
    }

    #[test]
    fn classify_path() {
        assert_eq!(classify("C:\\Users\\foo\\bar.exe"), StringType::FilePath);
        assert_eq!(classify("/usr/local/bin/codemap"), StringType::FilePath);
        assert_eq!(classify("./src/main.rs"), StringType::FilePath);
        assert_eq!(classify("\\\\fileserver\\share\\file"), StringType::FilePath);
    }

    #[test]
    fn classify_registry() {
        assert_eq!(classify("HKEY_LOCAL_MACHINE\\Software\\Microsoft"), StringType::RegistryKey);
        assert_eq!(classify("HKLM\\Software\\Foo"), StringType::RegistryKey);
    }

    #[test]
    fn classify_sql() {
        assert_eq!(classify("SELECT * FROM users WHERE id = ?"), StringType::Sql);
        assert_eq!(classify("INSERT INTO logs (msg) VALUES (?)"), StringType::Sql);
        assert_eq!(classify("UPDATE accounts SET balance = balance - ? WHERE id = ?"), StringType::Sql);
    }

    #[test]
    fn classify_format_string() {
        assert_eq!(classify("Error %d: %s\n"), StringType::FormatString);
        assert_eq!(classify("Hello {0}, you owe {1:C}"), StringType::FormatString);
    }

    #[test]
    fn classify_error_message() {
        assert_eq!(classify("Error: failed to open file"), StringType::ErrorMessage);
        assert_eq!(classify("Permission denied"), StringType::ErrorMessage);
    }

    #[test]
    fn classify_hex_and_base64() {
        // 32-char hex (MD5)
        assert_eq!(classify("d41d8cd98f00b204e9800998ecf8427e"), StringType::Hex);
        // base64 (24 chars, divisible by 4 with trailing =)
        assert_eq!(classify("U29tZSBleGFtcGxlIHRleHQ="), StringType::Base64);
    }

    #[test]
    fn classify_email() {
        assert_eq!(classify("admin@example.com"), StringType::EmailAddress);
        assert_eq!(classify("not.an.email"), StringType::Generic);
    }

    #[test]
    fn classify_envvar() {
        assert_eq!(classify("%APPDATA%"), StringType::EnvVar);
        assert_eq!(classify("PATH=/usr/local/bin"), StringType::EnvVar);
    }

    #[test]
    fn classify_user_agent() {
        assert_eq!(classify("Mozilla/5.0 (Windows NT 10.0)"), StringType::UserAgent);
        assert_eq!(classify("curl/7.81.0"), StringType::UserAgent);
    }

    #[test]
    fn classify_generic_fallback() {
        assert_eq!(classify("just some text"), StringType::Generic);
        assert_eq!(classify("Foo"), StringType::Generic);
    }
}
