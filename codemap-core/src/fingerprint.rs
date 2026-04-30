// ── Language / Compiler Fingerprinting ─────────────────────────────
//
// Identify which compiler / language / runtime produced a binary by
// looking at telltale section names + signature strings. First-pass
// triage: knowing "this is a Rust binary" or "this is PyInstaller"
// shapes every subsequent question.
//
// Pure heuristics, no external dep. False-positive rate is acceptable
// because the result is informational, not load-bearing on graph
// algorithms. Output is two strings: language (rust/go/.net/cpp/etc.)
// and toolchain (rustc/golang/msvc/gcc/mingw/etc.).

#[derive(Debug, Clone, Default)]
pub struct Fingerprint {
    pub language: Option<String>,
    pub compiler: Option<String>,
    pub runtime: Option<String>,
    /// Confidence 0–100. Multiple matching signatures bump it up.
    pub confidence: u8,
}

impl Fingerprint {
    pub fn is_known(&self) -> bool { self.language.is_some() || self.compiler.is_some() || self.runtime.is_some() }

    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(l) = &self.language { parts.push(format!("lang={l}")); }
        if let Some(c) = &self.compiler { parts.push(format!("compiler={c}")); }
        if let Some(r) = &self.runtime { parts.push(format!("runtime={r}")); }
        if parts.is_empty() { return "unknown".to_string(); }
        format!("{} (conf={})", parts.join(" "), self.confidence)
    }
}

/// Run all detectors against (sections, raw bytes). Returns the
/// highest-confidence match. Sections is a list of section names found
/// in the binary; raw bytes is a bounded slice to scan for signature
/// strings (caller decides how much to feed in — typically the first
/// 512 KB is enough).
pub fn fingerprint(sections: &[&str], raw: &[u8]) -> Fingerprint {
    let mut fp = Fingerprint::default();

    // ── Go ────────────────────────────────────────────────────────
    // Go binaries always have .gopclntab + .go.buildinfo sections (at
    // least one of them) and embed runtime.morestack / Go strings.
    if sections.iter().any(|s| s.contains("gopclntab") || s.contains("go.buildinfo") || s.contains("noptrdata") || s.contains("typelink")) {
        fp.language = Some("go".to_string());
        fp.compiler = Some("golang".to_string());
        fp.runtime = Some("go".to_string());
        fp.confidence = 95;
        return fp;
    }
    if find_bytes(raw, b"runtime.morestack").is_some() && find_bytes(raw, b"goroutine ").is_some() {
        fp.language = Some("go".to_string());
        fp.compiler = Some("golang".to_string());
        fp.runtime = Some("go".to_string());
        fp.confidence = 90;
        return fp;
    }

    // ── Rust ──────────────────────────────────────────────────────
    // Rust binaries embed __rust_alloc / __rdl_oom + RUST_BACKTRACE
    // string + frequent panic-handler symbols.
    let rust_sigs = [
        b"__rust_alloc" as &[u8],
        b"__rdl_oom",
        b"RUST_BACKTRACE",
        b"rust_eh_personality",
        b"core::panicking::panic",
    ];
    let rust_hits = rust_sigs.iter().filter(|sig| find_bytes(raw, sig).is_some()).count();
    if rust_hits >= 2 {
        fp.language = Some("rust".to_string());
        fp.compiler = Some("rustc".to_string());
        fp.confidence = (60 + rust_hits as u8 * 10).min(95);
        return fp;
    }

    // ── .NET (CLR) ────────────────────────────────────────────────
    // PE binaries with a CLR header have a section called .text with
    // an embedded CLR header pointer; simpler tell: the string "BSJB"
    // (the metadata signature) appears in the binary.
    if find_bytes(raw, b"BSJB").is_some() && find_bytes(raw, b"mscorlib").is_some() {
        fp.language = Some(".net".to_string());
        fp.compiler = Some("csc".to_string());
        fp.runtime = Some("clr".to_string());
        fp.confidence = 90;
        return fp;
    }
    if find_bytes(raw, b"mscoree.dll").is_some() {
        fp.language = Some(".net".to_string());
        fp.compiler = Some("csc".to_string());
        fp.runtime = Some("clr".to_string());
        fp.confidence = 75;
        return fp;
    }

    // ── PyInstaller / Nuitka / Cython packed Python ───────────────
    if find_bytes(raw, b"_MEIPASS").is_some() || find_bytes(raw, b"PyInstaller").is_some() {
        fp.language = Some("python".to_string());
        fp.compiler = Some("pyinstaller".to_string());
        fp.runtime = Some("cpython".to_string());
        fp.confidence = 90;
        return fp;
    }
    if find_bytes(raw, b"Nuitka").is_some() || find_bytes(raw, b"nuitka_").is_some() {
        fp.language = Some("python".to_string());
        fp.compiler = Some("nuitka".to_string());
        fp.runtime = Some("cpython".to_string());
        fp.confidence = 85;
        return fp;
    }
    if find_bytes(raw, b"Py_InitModule").is_some() && find_bytes(raw, b"PyArg_Parse").is_some() {
        fp.language = Some("c-extension".to_string());
        fp.compiler = Some("cpython-ext".to_string());
        fp.runtime = Some("cpython".to_string());
        fp.confidence = 70;
        return fp;
    }

    // ── Electron / Node native ────────────────────────────────────
    if find_bytes(raw, b"electron").is_some() && find_bytes(raw, b"node_modules").is_some() {
        fp.language = Some("javascript".to_string());
        fp.compiler = Some("electron".to_string());
        fp.runtime = Some("v8".to_string());
        fp.confidence = 85;
        return fp;
    }
    if find_bytes(raw, b"napi_register_module").is_some() || find_bytes(raw, b"v8::Isolate").is_some() {
        fp.runtime = Some("v8".to_string());
        fp.confidence = 60;
        // continue — could still be C/C++ underneath
    }

    // ── Delphi / Borland ──────────────────────────────────────────
    if find_bytes(raw, b"Borland").is_some() || find_bytes(raw, b"Embarcadero").is_some() ||
       find_bytes(raw, b"FastMM").is_some() || sections.iter().any(|s| s.contains(".bss") && raw.iter().take(4096).any(|&b| b == 0xE8)) {
        if find_bytes(raw, b"Software\\Embarcadero").is_some() || find_bytes(raw, b"@System@").is_some() {
            fp.language = Some("delphi".to_string());
            fp.compiler = Some("delphi".to_string());
            fp.confidence = 85;
            return fp;
        }
    }

    // ── MinGW vs MSVC vs GCC ──────────────────────────────────────
    // CRT signatures.
    if find_bytes(raw, b"libstdc++").is_some() && find_bytes(raw, b"libgcc").is_some() {
        if find_bytes(raw, b"mingw").is_some() {
            fp.compiler = Some("mingw".to_string());
        } else {
            fp.compiler = Some("gcc".to_string());
        }
        fp.language = Some("c++".to_string());
        fp.confidence = 70;
        return fp;
    }
    if find_bytes(raw, b"_main_CRTStartup").is_some() || find_bytes(raw, b"VCRUNTIME").is_some() ||
       find_bytes(raw, b"vcruntime").is_some() || find_bytes(raw, b"MSVCR").is_some() {
        fp.compiler = Some("msvc".to_string());
        fp.language = Some("c++".to_string());
        fp.confidence = 75;
        return fp;
    }
    if find_bytes(raw, b"__libc_start_main").is_some() {
        fp.compiler = Some("gcc".to_string());
        fp.language = Some("c".to_string());
        fp.confidence = 50;
        return fp;
    }

    // ── Swift ─────────────────────────────────────────────────────
    if find_bytes(raw, b"libswiftCore").is_some() || find_bytes(raw, b"$ss").is_some() {
        fp.language = Some("swift".to_string());
        fp.compiler = Some("swiftc".to_string());
        fp.confidence = 75;
        return fp;
    }

    // ── Java (already handled by java-class action, but native libs may carry signatures)
    if find_bytes(raw, b"JNI_OnLoad").is_some() {
        fp.runtime = Some("jvm".to_string());
        fp.confidence = 55;
    }

    fp
}

/// Substring search optimized for short needles in long haystacks.
/// Avoids std's Pattern overhead for our common case.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() { return None; }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if haystack[i] == first && &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_go_via_section_name() {
        let fp = fingerprint(&[".gopclntab", ".text"], b"");
        assert_eq!(fp.language.as_deref(), Some("go"));
        assert_eq!(fp.compiler.as_deref(), Some("golang"));
        assert!(fp.confidence >= 90);
    }

    #[test]
    fn detects_go_via_runtime_string() {
        let raw = b"some bytes runtime.morestack more bytes goroutine 1 stack";
        let fp = fingerprint(&[], raw);
        assert_eq!(fp.language.as_deref(), Some("go"));
    }

    #[test]
    fn detects_rust_via_signatures() {
        let raw = b"...some...__rust_alloc...stuff...rust_eh_personality...end";
        let fp = fingerprint(&[], raw);
        assert_eq!(fp.language.as_deref(), Some("rust"));
        assert_eq!(fp.compiler.as_deref(), Some("rustc"));
    }

    #[test]
    fn detects_dotnet_via_clr_header() {
        let raw = b"some PE bytes BSJB metadata mscorlib refs more";
        let fp = fingerprint(&[], raw);
        assert_eq!(fp.language.as_deref(), Some(".net"));
        assert_eq!(fp.runtime.as_deref(), Some("clr"));
    }

    #[test]
    fn detects_pyinstaller() {
        let raw = b"...header...PyInstaller_MEIPASS bootloader...";
        let fp = fingerprint(&[], raw);
        assert_eq!(fp.compiler.as_deref(), Some("pyinstaller"));
    }

    #[test]
    fn detects_msvc() {
        let raw = b"binary ... VCRUNTIME140.dll ... MSVCR ...";
        let fp = fingerprint(&[], raw);
        assert_eq!(fp.compiler.as_deref(), Some("msvc"));
        assert_eq!(fp.language.as_deref(), Some("c++"));
    }

    #[test]
    fn unknown_returns_empty() {
        let fp = fingerprint(&[".text", ".data"], b"plain c binary");
        assert!(!fp.is_known());
    }
}
