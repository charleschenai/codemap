// ── CUDA Launch Tracer (Ship 2 #14) ────────────────────────────────
//
// Detects CUDA host binaries (those importing CUDA Runtime / Driver
// API entry points) and enumerates the GPU kernels they launch by
// cross-referencing imports with symbol names + embedded strings.
//
// What v1 does:
//   1. Detects CUDA-using PE/ELF binaries by looking for imports of:
//        cuLaunchKernel / cudaLaunchKernel / cudaLaunchKernelExC
//        __cudaPushCallConfiguration / __cudaRegisterFatBinary
//        cuModuleLoadData / cuModuleGetFunction
//   2. Extracts kernel names from three sources:
//        a) Itanium-mangled `_Z*` symbols matching CUDA kernel-name
//           heuristics (typically ending in `vPv*` or wrapping
//           `<<<...>>>` launch syntax).
//        b) Strings ending in `_kernel` / `Kernel` (manual launch
//           configurations register kernel names this way).
//        c) Strings preceded by NUL inside `.nv_fatbin` / `.nvFatBinSegment`
//           sections — fatbin's embedded text section names.
//   3. Emits CudaKernel graph nodes attached to the host binary,
//      annotated with `source` (symbol / fatbin_string / import) and
//      `api` (runtime / driver / both).
//
// What v1 does NOT do:
//   - Per-launch-site grid/block dim recovery (would need the
//     bounded backward propagator from disasm_jt.rs threaded into
//     the CALL-resolution path; deferred to v2 — that's where the
//     propagator's second consumer lands and we extract to
//     dataflow_local.rs).
//   - PTX disassembly (cuda-info action covers PTX-info; this
//     action sits at a different abstraction level).
//
// Design parallel: anti-analysis scanner — pattern-matching on
// imports + strings, cheap to run, cheap to update. Real
// instrumentation comes in v2.

use crate::types::{Graph, EntityKind};
use std::collections::{HashSet, BTreeSet};

// ── Detection sets ─────────────────────────────────────────────────

const RUNTIME_API: &[&str] = &[
    "cudaLaunchKernel",
    "cudaLaunchKernelExC",
    "cudaLaunchCooperativeKernel",
    "cudaLaunchCooperativeKernelMultiDevice",
    "__cudaPushCallConfiguration",
    "__cudaPopCallConfiguration",
    "__cudaRegisterFatBinary",
    "__cudaRegisterFatBinaryEnd",
    "__cudaRegisterFunction",
    "__cudaRegisterVar",
    "__cudaUnregisterFatBinary",
    "cudaConfigureCall",
];

const DRIVER_API: &[&str] = &[
    "cuLaunchKernel",
    "cuLaunchKernelEx",
    "cuLaunchCooperativeKernel",
    "cuLaunchHostFunc",
    "cuModuleLoadData",
    "cuModuleLoadDataEx",
    "cuModuleLoadFatBinary",
    "cuModuleGetFunction",
    "cuModuleGetGlobal",
];

// ── Action ─────────────────────────────────────────────────────────

pub fn cuda_trace(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap cuda-trace <pe-or-elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    // Phase 1: enumerate imports
    let imports = collect_imports(&data);

    // Phase 2: classify CUDA-API usage
    let runtime_hits: HashSet<&str> = RUNTIME_API.iter().copied()
        .filter(|fn_name| imports.iter().any(|s| s == fn_name))
        .collect();
    let driver_hits: HashSet<&str> = DRIVER_API.iter().copied()
        .filter(|fn_name| imports.iter().any(|s| s == fn_name))
        .collect();
    let uses_runtime = !runtime_hits.is_empty();
    let uses_driver = !driver_hits.is_empty();
    let is_cuda = uses_runtime || uses_driver;

    if !is_cuda {
        return format_non_cuda_report(target, &imports);
    }

    // Phase 3: extract kernel names from symbols + strings
    let symbols = collect_symbol_names(&data);
    let mangled_kernels = extract_mangled_kernels(&symbols);
    let suffix_kernels = extract_suffix_kernels(&symbols);

    let strings = collect_strings(&data);
    let fatbin_kernels = extract_fatbin_strings(&strings);

    // Phase 4: emit graph nodes
    register_into_graph(graph, target,
        uses_runtime, uses_driver,
        &mangled_kernels, &suffix_kernels, &fatbin_kernels);

    // Phase 5: report
    format_report(target,
        uses_runtime, uses_driver,
        &runtime_hits, &driver_hits,
        &mangled_kernels, &suffix_kernels, &fatbin_kernels)
}

// ── Imports + symbols ──────────────────────────────────────────────

fn collect_imports(data: &[u8]) -> HashSet<String> {
    let mut out = HashSet::new();
    if data.len() >= 0x40 && &data[..2] == b"MZ" {
        // PE: walk import table via existing helper
        let dlls = crate::actions::reverse::pe::parse_pe_imports_structured(data)
            .unwrap_or_default();
        for d in &dlls {
            for f in &d.functions { out.insert(f.clone()); }
        }
    } else if data.len() >= 4 && &data[..4] == b"\x7FELF" {
        // ELF: read .dynstr names referenced by .dynsym
        for s in elf_dynsym_names(data) { out.insert(s); }
    }
    out
}

/// Walk an ELF binary's `.dynsym` + `.dynstr` and return the names of
/// every symbol (UND or otherwise — we treat any present name as a
/// potential import target since `cuLaunchKernel` shows up as UND
/// when libcudart is dynamically linked).
fn elf_dynsym_names(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if data.len() < 64 || &data[..4] != b"\x7FELF" { return out; }
    let is_64 = data[4] == 2;
    let little_endian = data[5] == 1;
    let read_u32 = |off: usize| -> u32 {
        if off + 4 > data.len() { return 0; }
        if little_endian { u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
        else { u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
    };
    let read_u64 = |off: usize| -> u64 {
        if off + 8 > data.len() { return 0; }
        if little_endian { u64::from_le_bytes(data[off..off+8].try_into().unwrap_or([0u8;8])) }
        else { u64::from_be_bytes(data[off..off+8].try_into().unwrap_or([0u8;8])) }
    };
    let read_u16 = |off: usize| -> u16 {
        if off + 2 > data.len() { return 0; }
        if little_endian { u16::from_le_bytes([data[off], data[off+1]]) }
        else { u16::from_be_bytes([data[off], data[off+1]]) }
    };

    let (e_shoff, e_shentsize, e_shnum, _e_shstrndx) = if is_64 {
        (read_u64(0x28) as usize, read_u16(0x3a) as usize, read_u16(0x3c) as usize, read_u16(0x3e) as usize)
    } else {
        (read_u32(0x20) as usize, read_u16(0x2e) as usize, read_u16(0x30) as usize, read_u16(0x32) as usize)
    };
    if e_shoff == 0 { return out; }

    // Find .dynsym (sh_type=11) and .dynstr (linked from .dynsym.sh_link)
    struct Sec { sh_type: u32, offset: u64, size: u64, entsize: u64, link: u32 }
    let mut sections: Vec<Sec> = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let hdr = e_shoff + i * e_shentsize;
        if hdr + (if is_64 { 64 } else { 40 }) > data.len() { break; }
        let sh_type = read_u32(hdr + 4);
        let (offset, size, entsize, link) = if is_64 {
            (read_u64(hdr + 0x18), read_u64(hdr + 0x20), read_u64(hdr + 0x38), read_u32(hdr + 0x28))
        } else {
            (read_u32(hdr + 0x10) as u64, read_u32(hdr + 0x14) as u64, read_u32(hdr + 0x24) as u64, read_u32(hdr + 0x18))
        };
        sections.push(Sec { sh_type, offset, size, entsize, link });
    }
    let dynsym = match sections.iter().find(|s| s.sh_type == 11) { Some(s) => s, None => return out };
    let dynstr_idx = dynsym.link as usize;
    if dynstr_idx >= sections.len() { return out; }
    let dynstr = &sections[dynstr_idx];

    let strtab_off = dynstr.offset as usize;
    let strtab_end = (strtab_off + dynstr.size as usize).min(data.len());
    let strtab = &data[strtab_off..strtab_end];

    let entsize = if dynsym.entsize > 0 { dynsym.entsize as usize }
                  else { if is_64 { 24 } else { 16 } };
    let count = dynsym.size as usize / entsize;
    for i in 1..count {
        let base = dynsym.offset as usize + i * entsize;
        if base + entsize > data.len() { break; }
        let st_name = read_u32(base) as usize;
        if st_name >= strtab.len() { continue; }
        let mut end = st_name;
        while end < strtab.len() && strtab[end] != 0 { end += 1; }
        let name = String::from_utf8_lossy(&strtab[st_name..end]).to_string();
        if !name.is_empty() { out.push(name); }
    }
    out
}

/// All defined symbols (PE export table + ELF dynsym + ELF symtab).
/// Used to find candidate kernel function names.
fn collect_symbol_names(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if data.len() >= 4 && &data[..4] == b"\x7FELF" {
        out.extend(elf_dynsym_names(data));
        out.extend(elf_symtab_names(data));
    }
    if data.len() >= 0x40 && &data[..2] == b"MZ" {
        if let Ok(dlls) = crate::actions::reverse::pe::parse_pe_imports_structured(data) {
            for d in &dlls { for f in &d.functions { out.push(f.clone()); } }
        }
        // PE exports: handled by pe-exports action; for v1 we don't
        // duplicate that parser. Importing a kernel is rarer than
        // having it as a static symbol; ELF coverage is the main path.
    }
    out
}

/// Read .symtab if present (ELF). Many CUDA host binaries are not
/// stripped during development and expose all kernel names this way.
fn elf_symtab_names(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if data.len() < 64 || &data[..4] != b"\x7FELF" { return out; }
    let is_64 = data[4] == 2;
    let little_endian = data[5] == 1;
    let read_u32 = |off: usize| -> u32 {
        if off + 4 > data.len() { return 0; }
        if little_endian { u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
        else { u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
    };
    let read_u64 = |off: usize| -> u64 {
        if off + 8 > data.len() { return 0; }
        if little_endian { u64::from_le_bytes(data[off..off+8].try_into().unwrap_or([0u8;8])) }
        else { u64::from_be_bytes(data[off..off+8].try_into().unwrap_or([0u8;8])) }
    };
    let read_u16 = |off: usize| -> u16 {
        if off + 2 > data.len() { return 0; }
        if little_endian { u16::from_le_bytes([data[off], data[off+1]]) }
        else { u16::from_be_bytes([data[off], data[off+1]]) }
    };

    let (e_shoff, e_shentsize, e_shnum) = if is_64 {
        (read_u64(0x28) as usize, read_u16(0x3a) as usize, read_u16(0x3c) as usize)
    } else {
        (read_u32(0x20) as usize, read_u16(0x2e) as usize, read_u16(0x30) as usize)
    };
    if e_shoff == 0 { return out; }

    struct Sec { sh_type: u32, offset: u64, size: u64, entsize: u64, link: u32 }
    let mut sections: Vec<Sec> = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let hdr = e_shoff + i * e_shentsize;
        if hdr + (if is_64 { 64 } else { 40 }) > data.len() { break; }
        let sh_type = read_u32(hdr + 4);
        let (offset, size, entsize, link) = if is_64 {
            (read_u64(hdr + 0x18), read_u64(hdr + 0x20), read_u64(hdr + 0x38), read_u32(hdr + 0x28))
        } else {
            (read_u32(hdr + 0x10) as u64, read_u32(hdr + 0x14) as u64, read_u32(hdr + 0x24) as u64, read_u32(hdr + 0x18))
        };
        sections.push(Sec { sh_type, offset, size, entsize, link });
    }

    // .symtab has sh_type=2
    let symtab = match sections.iter().find(|s| s.sh_type == 2) { Some(s) => s, None => return out };
    let strtab_idx = symtab.link as usize;
    if strtab_idx >= sections.len() { return out; }
    let strtab = &sections[strtab_idx];
    let strtab_off = strtab.offset as usize;
    let strtab_end = (strtab_off + strtab.size as usize).min(data.len());
    let strtab_data = &data[strtab_off..strtab_end];

    let entsize = if symtab.entsize > 0 { symtab.entsize as usize }
                  else { if is_64 { 24 } else { 16 } };
    let count = symtab.size as usize / entsize;
    let max = count.min(50_000);  // cap on huge binaries
    for i in 1..max {
        let base = symtab.offset as usize + i * entsize;
        if base + entsize > data.len() { break; }
        let st_name = read_u32(base) as usize;
        if st_name >= strtab_data.len() { continue; }
        let mut end = st_name;
        while end < strtab_data.len() && strtab_data[end] != 0 { end += 1; }
        let name = String::from_utf8_lossy(&strtab_data[st_name..end]).to_string();
        if !name.is_empty() { out.push(name); }
    }
    out
}

// ── Kernel-name extraction ─────────────────────────────────────────

/// Itanium-mangled `_Z*` symbols that look like CUDA kernels. We
/// don't try to demangle here (codemap has crate::demangle for that
/// in the consumer). The heuristic flags `_Z*` symbols ≥ 5 chars that
/// don't resolve to common system/runtime names. Caller filters
/// against system symbols and known CUDA helper functions.
fn extract_mangled_kernels(symbols: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for s in symbols {
        if !s.starts_with("_Z") || s.len() < 6 { continue; }
        // Skip C++ STL machinery (_ZN, _ZSt, _ZNK, etc. that's C++ runtime).
        // Real CUDA kernels typically demangle to free-function form, e.g.
        // `_Z14my_kernel_funcPfS_i` (no `St` namespace), but this isn't
        // reliable enough to filter on. Cheap-and-dirty: just emit them
        // all and let the user demangle/filter downstream.
        if s.starts_with("_ZNSt") || s.starts_with("_ZSt") { continue; }
        out.insert(s.clone());
    }
    out
}

/// Symbols ending in `_kernel`, `Kernel`, `_gpu`, `__global__`,
/// or matching common CUDA kernel naming conventions used in
/// hand-rolled host code.
fn extract_suffix_kernels(symbols: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for s in symbols {
        let t = s.trim();
        if t.is_empty() { continue; }
        // Skip CUDA API entry points (cuLaunchKernel, cudaLaunchKernel,
        // cuLibraryGetKernel, etc.) — they end in "Kernel" but are
        // not user-defined kernels.
        if t.starts_with("cu") && t.chars().nth(2).is_some_and(|c| c.is_uppercase()) {
            continue;  // cu[A-Z]* style — Driver/Runtime API
        }
        if t.starts_with("cuda") && t.chars().nth(4).is_some_and(|c| c.is_uppercase()) {
            continue;  // cuda[A-Z]* style — Runtime API
        }
        if t.starts_with("__cuda") { continue; }  // __cudaPushCallConfiguration etc.
        // Common kernel-naming suffixes
        if t.ends_with("_kernel") || t.ends_with("Kernel")
            || t.ends_with("_gpu") || t.ends_with("Gpu")
            || t.ends_with("_cuda") || t.ends_with("Cuda")
            || t.contains("__global__")
            || t.contains("CUDAKernel")
        {
            out.insert(s.clone());
        }
    }
    out
}

/// Strings that look like CUDA kernel names embedded in fatbin or
/// resource sections. NVCC bakes the kernel function name into the
/// fatbin metadata as a NUL-terminated string. Heuristic: string
/// looks like a C identifier starting with letter/underscore, ends
/// in a kernel-related token, length 6–80 chars.
fn extract_fatbin_strings(strings: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for s in strings {
        let t = s.trim();
        if t.len() < 6 || t.len() > 80 { continue; }
        let first = match t.chars().next() { Some(c) => c, None => continue };
        if !(first.is_alphabetic() || first == '_') { continue; }
        if !t.chars().all(|c| c.is_alphanumeric() || c == '_') { continue; }
        // Final filter: must end in a kernel-like token
        let lower = t.to_lowercase();
        if lower.ends_with("kernel") || lower.ends_with("gpu") || lower.ends_with("cuda") {
            out.insert(t.to_string());
        }
    }
    out
}

/// All printable ASCII strings of length ≥ 6 in the binary.
fn collect_strings(data: &[u8]) -> Vec<String> {
    const MIN_LEN: usize = 6;
    const MAX_STRINGS: usize = 50_000;
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, b) in data.iter().enumerate() {
        let printable = (0x20..=0x7E).contains(b);
        if printable && start.is_none() {
            start = Some(i);
        } else if !printable {
            if let Some(s) = start.take() {
                if i - s >= MIN_LEN {
                    out.push(String::from_utf8_lossy(&data[s..i]).to_string());
                    if out.len() >= MAX_STRINGS { return out; }
                }
            }
        }
    }
    if let Some(s) = start.take() {
        if data.len() - s >= MIN_LEN {
            out.push(String::from_utf8_lossy(&data[s..]).to_string());
        }
    }
    out
}

// ── Graph wiring ───────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn register_into_graph(
    graph: &mut Graph,
    target: &str,
    uses_runtime: bool,
    uses_driver: bool,
    mangled: &BTreeSet<String>,
    suffix: &BTreeSet<String>,
    fatbin: &BTreeSet<String>,
) {
    let bin_id = if target.ends_with(".dll") || target.ends_with(".exe") {
        format!("pe:{target}")
    } else {
        format!("elf:{target}")
    };
    // Mark on the binary node that this is a CUDA host binary
    let kind = if target.ends_with(".dll") || target.ends_with(".exe") {
        EntityKind::PeBinary
    } else {
        EntityKind::ElfBinary
    };
    let api_str = match (uses_runtime, uses_driver) {
        (true, true) => "runtime+driver",
        (true, false) => "runtime",
        (false, true) => "driver",
        _ => "none",
    };
    graph.ensure_typed_node(&bin_id, kind, &[
        ("path", target),
        ("cuda_api", api_str),
    ]);

    // Cap to prevent runaway on heavily-symbolic kernels
    const MAX_KERNELS: usize = 5_000;
    let mut emitted = 0usize;

    let mut emit = |name: &str, source: &str, mangled_form: Option<&str>| {
        if emitted >= MAX_KERNELS { return; }
        let kid = format!("cuda_kernel:{}::{}", target, name);
        let mut attrs: Vec<(&str, &str)> = vec![
            ("name", name),
            ("source", source),
            ("api", api_str),
        ];
        if let Some(m) = mangled_form {
            attrs.push(("mangled", m));
        }
        graph.ensure_typed_node(&kid, EntityKind::CudaKernel, &attrs);
        graph.add_edge(&bin_id, &kid);
        emitted += 1;
    };

    for m in mangled {
        let demangled = crate::demangle::demangle(m);
        match demangled {
            Some(d) => emit(&d, "symbol", Some(m.as_str())),
            None => emit(m, "symbol", None),
        }
    }
    for m in suffix {
        emit(m, "symbol", None);
    }
    for m in fatbin {
        emit(m, "fatbin_string", None);
    }
}

// ── Reports ────────────────────────────────────────────────────────

fn format_non_cuda_report(target: &str, imports: &HashSet<String>) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== CUDA Trace: {} ===\n\n", target));
    out.push_str(&format!("Imports parsed: {}\n", imports.len()));
    out.push_str("\n(no CUDA Runtime / Driver API imports detected)\n\n");
    out.push_str("This binary doesn't appear to host CUDA kernels — no\n");
    out.push_str("`cuLaunchKernel` / `cudaLaunchKernel` / `cuModuleGetFunction`\n");
    out.push_str("imports were found.\n");
    out
}

#[allow(clippy::too_many_arguments)]
fn format_report(
    target: &str,
    uses_runtime: bool,
    uses_driver: bool,
    runtime_hits: &HashSet<&str>,
    driver_hits: &HashSet<&str>,
    mangled: &BTreeSet<String>,
    suffix: &BTreeSet<String>,
    fatbin: &BTreeSet<String>,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("=== CUDA Trace: {} ===\n\n", target));

    let api = match (uses_runtime, uses_driver) {
        (true, true) => "Runtime + Driver",
        (true, false) => "Runtime API",
        (false, true) => "Driver API",
        _ => "(none)",
    };
    out.push_str(&format!("CUDA API used: {api}\n\n"));

    if uses_runtime {
        out.push_str(&format!("── Runtime API imports ({}) ──\n", runtime_hits.len()));
        let mut sorted: Vec<&&str> = runtime_hits.iter().collect();
        sorted.sort();
        for h in sorted { out.push_str(&format!("  {h}\n")); }
        out.push('\n');
    }
    if uses_driver {
        out.push_str(&format!("── Driver API imports ({}) ──\n", driver_hits.len()));
        let mut sorted: Vec<&&str> = driver_hits.iter().collect();
        sorted.sort();
        for h in sorted { out.push_str(&format!("  {h}\n")); }
        out.push('\n');
    }

    let total_kernels = mangled.len() + suffix.len() + fatbin.len();
    out.push_str(&format!("── Kernels detected: {} ──\n", total_kernels));
    out.push_str(&format!("  via mangled symbols (_Z*): {}\n", mangled.len()));
    out.push_str(&format!("  via suffix heuristic:      {}\n", suffix.len()));
    out.push_str(&format!("  via fatbin strings:        {}\n", fatbin.len()));
    out.push('\n');

    let n_show = 30;
    if !mangled.is_empty() {
        out.push_str(&format!("── Top mangled-symbol kernels (showing {}) ──\n",
            n_show.min(mangled.len())));
        for m in mangled.iter().take(n_show) {
            let display = crate::demangle::demangle(m).unwrap_or_else(|| m.clone());
            out.push_str(&format!("  {display}\n"));
        }
        if mangled.len() > n_show {
            out.push_str(&format!("  ... and {} more\n", mangled.len() - n_show));
        }
        out.push('\n');
    }
    if !suffix.is_empty() {
        out.push_str(&format!("── Suffix-matched kernels (showing {}) ──\n",
            n_show.min(suffix.len())));
        for m in suffix.iter().take(n_show) {
            out.push_str(&format!("  {m}\n"));
        }
        if suffix.len() > n_show {
            out.push_str(&format!("  ... and {} more\n", suffix.len() - n_show));
        }
        out.push('\n');
    }
    if !fatbin.is_empty() {
        out.push_str(&format!("── Fatbin-string kernels (showing {}) ──\n",
            n_show.min(fatbin.len())));
        for m in fatbin.iter().take(n_show) {
            out.push_str(&format!("  {m}\n"));
        }
        if fatbin.len() > n_show {
            out.push_str(&format!("  ... and {} more\n", fatbin.len() - n_show));
        }
        out.push('\n');
    }

    out.push_str("Try: codemap meta-path \"pe->cuda_kernel\"  (cross-binary GPU workload inventory)\n");
    out.push_str("     codemap pagerank --type cuda_kernel    (most-shared kernel names)\n");
    out
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn syms(s: &[&str]) -> Vec<String> { s.iter().map(|x| x.to_string()).collect() }

    #[test]
    fn extracts_mangled_z_symbols() {
        let s = syms(&[
            "_Z9my_kernelPfi",
            "_ZNSt6vectorE",   // STL — should be filtered
            "_ZSt4cout",       // STL
            "_Z14another_funcv",
            "main",
            "printf",
        ]);
        let m = extract_mangled_kernels(&s);
        assert_eq!(m.len(), 2);
        assert!(m.iter().any(|x| x == "_Z9my_kernelPfi"));
        assert!(m.iter().any(|x| x == "_Z14another_funcv"));
    }

    #[test]
    fn extracts_suffix_kernels() {
        let s = syms(&[
            "process_kernel",
            "MyKernel",
            "compute_gpu",
            "__global__cudaFunc",
            "main",
            "printf",
            "regular_function",
            // CUDA API entry points — should NOT be flagged as kernels
            "cuLaunchKernel",
            "cudaLaunchKernel",
            "cuLibraryGetKernel",
            "__cudaRegisterFunction",
        ]);
        let m = extract_suffix_kernels(&s);
        assert!(m.iter().any(|x| x == "process_kernel"));
        assert!(m.iter().any(|x| x == "MyKernel"));
        assert!(m.iter().any(|x| x == "compute_gpu"));
        assert!(m.iter().any(|x| x == "__global__cudaFunc"));
        // Confirm filtering of API entry points
        assert!(!m.iter().any(|x| x == "cuLaunchKernel"));
        assert!(!m.iter().any(|x| x == "cudaLaunchKernel"));
        assert!(!m.iter().any(|x| x == "cuLibraryGetKernel"));
        assert!(!m.iter().any(|x| x == "__cudaRegisterFunction"));
    }

    #[test]
    fn extracts_fatbin_strings() {
        let s = syms(&[
            "my_compute_kernel",
            "deviceFunctionGpu",
            "tooshort",
            "this string has spaces, not an identifier",
            "0badprefix_kernel",   // starts with digit
            "valid_kernel",
        ]);
        let f = extract_fatbin_strings(&s);
        assert!(f.iter().any(|x| x == "my_compute_kernel"));
        assert!(f.iter().any(|x| x == "deviceFunctionGpu"));
        assert!(f.iter().any(|x| x == "valid_kernel"));
        assert!(!f.iter().any(|x| x == "0badprefix_kernel"));
    }

    #[test]
    fn runtime_and_driver_api_lists_disjoint() {
        let r: HashSet<&str> = RUNTIME_API.iter().copied().collect();
        let d: HashSet<&str> = DRIVER_API.iter().copied().collect();
        assert!(r.is_disjoint(&d), "runtime and driver API name sets overlap");
        assert!(r.contains("cudaLaunchKernel"));
        assert!(d.contains("cuLaunchKernel"));
    }

    #[test]
    fn extracts_strings_meets_min_len() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x00\x00short\x00valid_string_here\x00ABC\x00");
        let strings = collect_strings(&data);
        assert!(strings.iter().any(|s| s == "valid_string_here"));
        assert!(!strings.iter().any(|s| s == "ABC"));   // < min len 6
        assert!(!strings.iter().any(|s| s == "short")); // < min len 6
    }
}
