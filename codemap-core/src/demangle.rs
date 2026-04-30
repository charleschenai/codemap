// ── Symbol Demangling ──────────────────────────────────────────────
//
// Three ABIs cover ~99% of real-world mangled names:
//
//   Itanium C++  — _Z<length><name>... (Linux/macOS C++, also used by
//                  GCC on Windows for some cases)
//   MSVC C++     — ?<name>@@<flags>... (Visual Studio C++ on Windows)
//   Rust         — _ZN... or _R... (legacy + v0)
//
// This is a pragmatic demangler: it covers the common shapes (functions,
// methods, simple template instantiations, C++ namespaces) and falls
// back to the raw name for anything exotic. Goal is to make
// pe-exports / elf-info / macho-info readable, not to be a complete
// rustc demangler.
//
// Pure pattern matching — no external deps.

/// Try every known mangling scheme. Returns Some(demangled) on success,
/// None if the name doesn't appear to be mangled or doesn't match any
/// scheme we handle.
pub fn demangle(name: &str) -> Option<String> {
    let n = name.trim();
    if n.is_empty() { return None; }

    // Rust v0 mangling: _R...
    if let Some(out) = try_rust_v0(n) { return Some(out); }

    // Rust legacy + Itanium C++: _Z... or __Z... (macOS prefixes _ to all
    // symbols, so a mangled `_Z3foo` becomes `__Z3foo`). Try the stripped
    // form first; fall back to the original.
    let candidates: [&str; 2] = [n.strip_prefix('_').unwrap_or(n), n];
    for c in &candidates {
        if c.starts_with("_Z") {
            if let Some(out) = try_rust_legacy(c) { return Some(out); }
            if let Some(out) = try_itanium(c) { return Some(out); }
        }
    }

    // MSVC C++: ?name@class@@flags...
    if n.starts_with('?') {
        if let Some(out) = try_msvc(n) { return Some(out); }
    }

    None
}

/// Hierarchical components of a demangled C++/Rust name. For
/// `tokio::time::sleep` returns `["tokio", "time", "sleep"]`.
/// Used to register parent→child edges in the graph.
pub fn split_namespace(demangled: &str) -> Vec<String> {
    // Drop any function-arg signature: "foo::bar(int, char*)" → "foo::bar"
    let head = demangled.split_once('(').map(|(h, _)| h).unwrap_or(demangled);
    head.split("::")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ── Itanium C++ ABI ────────────────────────────────────────────────
//
// _Z<encoding>
//   <encoding> = <function name> | <data name> | <special-name>
//   <name>     = <nested-name> | <unscoped-name> | ...
//   <nested-name> = N <prefix> E
//   <prefix>   = <unqualified-name>+
//   <unqualified-name> = <source-name> | ...
//   <source-name> = <length><identifier>
//
// We handle: simple functions, nested-name (namespaces/classes), and
// fall back to the raw <length><identifier> chain. Templates after `I`
// are detected and elided as `<...>`.

fn try_itanium(name: &str) -> Option<String> {
    let rest = name.strip_prefix("_Z")?;
    let mut p = Parser::new(rest);

    // Optional 'N' prefix means nested
    let nested = p.eat('N');
    let mut parts: Vec<String> = Vec::new();

    while let Some(c) = p.peek() {
        if c == 'E' && nested { p.bump(); break; }
        if c.is_ascii_digit() {
            let len: usize = p.read_number()?;
            let name = p.read_n(len)?;
            parts.push(name.to_string());
        } else if c == 'I' {
            // Template arguments — elide.
            // Skip until matching 'E' (allow nested).
            p.bump();
            let mut depth = 1;
            while let Some(ch) = p.peek() {
                p.bump();
                if ch == 'I' { depth += 1; }
                else if ch == 'E' { depth -= 1; if depth == 0 { break; } }
            }
            if let Some(last) = parts.last_mut() { last.push_str("<...>"); }
        } else if c == 'S' || c == 'C' || c == 'D' {
            // Substitutions / ctor-dtor markers — best-effort: stop here.
            break;
        } else {
            break;
        }
        if !nested && !parts.is_empty() { break; }
    }

    if parts.is_empty() { return None; }
    Some(parts.join("::"))
}

// ── Rust legacy mangling (_ZN...17h<hash>E) ────────────────────────
//
// Rust legacy mangling reuses Itanium-style nesting but adds a 17-char
// hash like `17h7e8a3b4c5d6e7f8g` as the final component. Strip it.

fn try_rust_legacy(name: &str) -> Option<String> {
    let demangled = try_itanium(name)?;
    // Drop trailing hash component if shaped like 17h<16 hex>
    if let Some(last) = demangled.rsplit("::").next() {
        if last.len() == 19 && last.starts_with("17h") {
            let parts: Vec<&str> = demangled.rsplitn(2, "::").collect();
            if parts.len() == 2 {
                return Some(parts[1].to_string());
            }
        }
    }
    Some(demangled)
}

// ── Rust v0 mangling (_R...) ────────────────────────────────────────
//
// Rust v0 (RFC 2603) uses a different scheme:
//   _R<path><instantiating args>?<vendor specific>
//   <path> = N<namespace><identifier> | C<identifier> (crate root) | ...
//
// We handle: crate root C<id>, single-namespace N<ns>C<id><id>, and
// the common nested-Cn pattern. Generics are elided.

fn try_rust_v0(name: &str) -> Option<String> {
    let rest = name.strip_prefix("_R")?;
    if rest.is_empty() { return None; }
    let mut p = Parser::new(rest);
    let mut parts: Vec<String> = Vec::new();

    // Optional disambiguator/instantiation prefix N<namespace>
    while let Some(c) = p.peek() {
        match c {
            'C' => { p.bump(); if let Some(s) = read_v0_ident(&mut p) { parts.push(s); } else { break; } }
            'N' => { p.bump(); p.bump(); /* skip namespace tag char */ if let Some(s) = read_v0_ident(&mut p) { parts.push(s); } else { break; } }
            'M' | 'X' => { p.bump(); /* impl block / trait impl — skip type encoding */ break; }
            _ => break,
        }
    }
    if parts.is_empty() { return None; }
    Some(parts.join("::"))
}

fn read_v0_ident(p: &mut Parser) -> Option<String> {
    // v0 idents can have a disambiguator (s<base62 number>_) before the length.
    if p.peek() == Some('s') {
        p.bump();
        // skip base62 digits
        while let Some(c) = p.peek() {
            if c.is_ascii_alphanumeric() { p.bump(); } else { break; }
        }
        if p.peek() == Some('_') { p.bump(); }
    }
    // Optional 'u' for punycode-encoded ident — skip prefix
    if p.peek() == Some('u') { p.bump(); }
    let len: usize = p.read_number()?;
    let raw = p.read_n(len)?;
    Some(raw.to_string())
}

// ── MSVC C++ mangling ──────────────────────────────────────────────
//
// Format: ?<name>@<scope>@@<flags><return><args>Z
// Examples:
//   ?MyFunc@Foo@@QAEHXZ        — Foo::MyFunc()
//   ?baz@bar@foo@@YAHXZ        — foo::bar::baz()
//   ??0Foo@@QAE@XZ             — Foo::Foo() (constructor)
//   ??1Foo@@UAE@XZ             — Foo::~Foo() (destructor)
//
// We extract the name + scopes; elide everything after @@.

fn try_msvc(name: &str) -> Option<String> {
    let rest = name.strip_prefix('?')?;
    // Constructor / destructor markers
    let (prefix_marker, rest) = if let Some(r) = rest.strip_prefix("?0") {
        (Some("ctor"), r)
    } else if let Some(r) = rest.strip_prefix("?1") {
        (Some("dtor"), r)
    } else if rest.starts_with('?') {
        // Other special operators (?2 = new, ?3 = delete, etc.) — skip
        return None;
    } else {
        (None, rest)
    };

    // Split at @@ (the scope→signature delimiter)
    let scope_part = rest.split("@@").next()?;
    let parts: Vec<&str> = scope_part.split('@').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() { return None; }
    // MSVC reverses scope: ?baz@bar@foo@@... is foo::bar::baz
    let mut reversed: Vec<&str> = parts.iter().rev().copied().collect();
    if let Some(marker) = prefix_marker {
        // For ctor/dtor, MSVC encodes as ??0Class@@... (no method name);
        // synthesize Class::Class or Class::~Class
        let class = reversed.last().copied().unwrap_or("");
        let synthetic = match marker {
            "ctor" => class.to_string(),
            "dtor" => format!("~{class}"),
            _ => return None,
        };
        reversed.push(Box::leak(synthetic.into_boxed_str()));
    }
    Some(reversed.join("::"))
}

// ── Mini parser ────────────────────────────────────────────────────

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self { Parser { src: s.as_bytes(), pos: 0 } }
    fn peek(&self) -> Option<char> { self.src.get(self.pos).map(|&b| b as char) }
    fn bump(&mut self) { self.pos += 1; }
    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) { self.bump(); true } else { false }
    }
    fn read_number(&mut self) -> Option<usize> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() { self.bump(); } else { break; }
        }
        if self.pos == start { return None; }
        std::str::from_utf8(&self.src[start..self.pos]).ok()?.parse().ok()
    }
    fn read_n(&mut self, n: usize) -> Option<&'a str> {
        if self.pos + n > self.src.len() { return None; }
        let s = std::str::from_utf8(&self.src[self.pos..self.pos + n]).ok()?;
        self.pos += n;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn itanium_simple_function() {
        // _Z3foov = foo()
        assert_eq!(demangle("_Z3foov").as_deref(), Some("foo"));
    }

    #[test]
    fn itanium_nested_namespace() {
        // _ZN3std3ios7failureE = std::ios::failure
        assert_eq!(demangle("_ZN3std3ios7failureE").as_deref(), Some("std::ios::failure"));
    }

    #[test]
    fn itanium_macos_double_underscore() {
        // macOS prefixes with double underscore
        assert_eq!(demangle("__ZN5tokio4time5sleepE").as_deref(), Some("tokio::time::sleep"));
    }

    #[test]
    fn rust_legacy_strips_hash() {
        // Rust legacy: _ZN5tokio4time5sleep17h7e8a3b4c5d6e7f8gE
        let mangled = "_ZN5tokio4time5sleep17h7e8a3b4c5d6e7f8gE";
        let result = demangle(mangled).unwrap();
        // Hash should be stripped
        assert!(!result.contains("17h"));
        assert!(result.starts_with("tokio::time::sleep"), "got: {result}");
    }

    #[test]
    fn rust_v0_crate_root() {
        // _RC4core = core (crate root)
        assert_eq!(demangle("_RC4core").as_deref(), Some("core"));
    }

    #[test]
    fn msvc_simple_method() {
        // ?MyFunc@Foo@@QAEHXZ = Foo::MyFunc
        assert_eq!(demangle("?MyFunc@Foo@@QAEHXZ").as_deref(), Some("Foo::MyFunc"));
    }

    #[test]
    fn msvc_deeply_nested() {
        // ?baz@bar@foo@@YAHXZ = foo::bar::baz
        assert_eq!(demangle("?baz@bar@foo@@YAHXZ").as_deref(), Some("foo::bar::baz"));
    }

    #[test]
    fn unmangled_passthrough_returns_none() {
        assert_eq!(demangle("regular_c_function"), None);
        assert_eq!(demangle("malloc"), None);
        assert_eq!(demangle("_GLOBAL_OFFSET_TABLE_"), None);
    }

    #[test]
    fn split_namespace_hierarchy() {
        assert_eq!(split_namespace("tokio::time::sleep"), vec!["tokio", "time", "sleep"]);
        assert_eq!(split_namespace("foo::bar::baz(int, char*)"), vec!["foo", "bar", "baz"]);
        assert_eq!(split_namespace("simple"), vec!["simple"]);
    }
}
