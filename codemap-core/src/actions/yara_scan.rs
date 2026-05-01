// ── YARA Scanner — generic rule corpus runner (5.38.0) ────────────
//
// Wraps yara-x (the official VirusTotal pure-Rust port) so users can
// run any YARA corpus over codemap's binaries / source files without
// shelling out to libyara. Drop a directory of .yar files at the action
// (`--rules-dir`) or a single `--rules-file`, and every loaded rule
// becomes a YaraRule node, every fire becomes a YaraMatch node, and
// edges reach back to the binary that lit them up. Section-aware: PE
// `IMAGE_SECTION_HEADER` / ELF `Elf64_Shdr` / Mach-O `section_64`
// entries get walked and scanned independently, with file offsets
// translated to virtual addresses using each section's VA mapping.
//
// Companion of the per-corpus loaders (anti_analysis, crypto_const,
// vtable_detect): those have hand-coded heuristics; yara-scan is the
// runtime engine for arbitrary user-supplied rule sets (capa-rules-yara,
// Florian Roth's signature-base, findcrypt3, signsrch-derived, custom).
//
// `import "cuckoo"` rules are filtered via Compiler::ignore_module —
// they describe dynamic-analysis predicates that always evaluate false
// in static-only operation, so loading them just adds noise.

use crate::types::{Graph, EntityKind};
use std::path::{Path, PathBuf};

/// Sections that almost never carry detection-worthy bytes — typically
/// resource blobs, relocation deltas, or zero-fill. Skipping these on
/// the per-section pass avoids gigabytes of false-negative-prone scans
/// on large installers without hurting recall.
const NOISE_SECTIONS: &[&str] = &[".rsrc", ".reloc", ".bss", ".idata"];

/// Cap how many YaraMatch nodes we emit per (rule, target) pair. Some
/// rules (e.g. detect-debug-string-by-substring) match thousands of
/// times in a single binary; we keep the first N for the graph and
/// summarize the rest in the report.
const MAX_MATCHES_PER_RULE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryFormat { Pe, Elf, Macho, Unknown }

#[derive(Debug, Clone)]
struct Section {
    name: String,
    raw_offset: usize,
    raw_size: usize,
    /// PE: VirtualAddress (RVA, image-base relative).
    /// ELF: sh_addr (absolute virtual address when loaded).
    /// Mach-O: section_64.addr (vmaddr).
    /// 0 when no VA mapping exists (zero-fill, debug, etc.).
    virtual_address: u64,
}

struct Args {
    rules_files: Vec<PathBuf>,
    rules_dirs: Vec<PathBuf>,
    inline_rules: Option<String>,
    target_paths: Vec<String>,
}

pub fn yara_scan(graph: &mut Graph, target: &str) -> String {
    let args = match parse_args(target) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if args.target_paths.is_empty() {
        return USAGE.to_string();
    }
    if args.rules_files.is_empty() && args.rules_dirs.is_empty() && args.inline_rules.is_none() {
        return format!("yara-scan: no rules provided. {USAGE}");
    }

    let rule_paths = collect_rule_paths(&args);
    let (rules, mut load_report) =
        match compile_rules(&rule_paths, args.inline_rules.as_deref()) {
            Ok(x) => x,
            Err(e) => return format!("yara-scan: failed to compile rules: {e}"),
        };

    let mut total_hits = 0usize;
    let mut total_files_scanned = 0usize;
    for tgt in &args.target_paths {
        let data = match std::fs::read(tgt) {
            Ok(d) => d,
            Err(e) => {
                load_report.push_str(&format!("[error] {tgt}: {e}\n"));
                continue;
            }
        };
        total_files_scanned += 1;
        let format = detect_format(&data);
        let bin_id = ensure_target_node(graph, tgt, &data, format);
        let sections = collect_sections(&data, format);

        load_report.push_str(&format!(
            "── {tgt} ({}, {} bytes, {} sections) ──\n",
            format_label(format), data.len(), sections.len()
        ));

        // Whole-buffer pass: catches rules that reference file-format
        // meta (`pe.entry_point`, `elf.entry_point`) or use offsets
        // anchored to the start of the file.
        let mut scanner = yara_x::Scanner::new(&rules);
        let hits = scan_buffer(
            graph, &mut scanner, &data, &bin_id, tgt, "<whole>", 0, &mut load_report,
        );
        total_hits += hits;

        // Per-section pass — VA-correct match offsets per yara4ida pick #4.
        for sec in &sections {
            if is_noise_section(&sec.name) { continue; }
            let end = sec.raw_offset.saturating_add(sec.raw_size).min(data.len());
            if sec.raw_offset >= data.len() || end <= sec.raw_offset { continue; }
            let view = &data[sec.raw_offset..end];
            // Each per-section scan needs its own scanner (Scanner is
            // single-buffer-at-a-time); cheap because Rules is shared.
            let mut sec_scanner = yara_x::Scanner::new(&rules);
            let h = scan_buffer(
                graph, &mut sec_scanner, view, &bin_id, tgt,
                &sec.name, sec.virtual_address, &mut load_report,
            );
            total_hits += h;
        }
    }
    load_report.push_str(&format!(
        "\n=== yara-scan summary ===\nFiles scanned: {total_files_scanned}\nTotal matches: {total_hits}\n"
    ));
    load_report
}

const USAGE: &str = "Usage: codemap yara-scan [--rules-dir <dir>]... [--rules-file <file>]... <target> [<target>...]";

// ── Argument parsing ───────────────────────────────────────────────

fn parse_args(target: &str) -> Result<Args, String> {
    let mut args = Args {
        rules_files: Vec::new(),
        rules_dirs: Vec::new(),
        inline_rules: None,
        target_paths: Vec::new(),
    };
    let toks: Vec<&str> = target.split_whitespace().collect();
    let mut i = 0;
    while i < toks.len() {
        match toks[i] {
            "--rules-file" | "--rule-file" | "-f" => {
                i += 1;
                if i >= toks.len() {
                    return Err("yara-scan: --rules-file requires a path".into());
                }
                args.rules_files.push(PathBuf::from(toks[i]));
                i += 1;
            }
            "--rules-dir" | "--rule-dir" | "-d" => {
                i += 1;
                if i >= toks.len() {
                    return Err("yara-scan: --rules-dir requires a path".into());
                }
                args.rules_dirs.push(PathBuf::from(toks[i]));
                i += 1;
            }
            "--rules-text" => {
                // Inline rule string; useful for one-liners and tests.
                // Everything until the next `--` flag or token that looks
                // like a flag is treated as part of the rule text.
                i += 1;
                if i >= toks.len() {
                    return Err("yara-scan: --rules-text requires a rule string".into());
                }
                let mut buf = String::new();
                while i < toks.len() && !toks[i].starts_with("--") {
                    if !buf.is_empty() { buf.push(' '); }
                    buf.push_str(toks[i]);
                    i += 1;
                }
                args.inline_rules = Some(buf);
            }
            other if other.starts_with("--") => {
                return Err(format!("yara-scan: unknown flag '{other}'"));
            }
            other => {
                args.target_paths.push(other.to_string());
                i += 1;
            }
        }
    }
    Ok(args)
}

fn collect_rule_paths(args: &Args) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = args.rules_files.clone();
    for d in &args.rules_dirs {
        for entry in walk_yar_files(d) {
            out.push(entry);
        }
    }
    out.sort();
    out.dedup();
    out
}

fn walk_yar_files(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let meta = match std::fs::metadata(&p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                for ent in rd.flatten() {
                    stack.push(ent.path());
                }
            }
        } else if meta.is_file() {
            if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                let e = ext.to_ascii_lowercase();
                if e == "yar" || e == "yara" {
                    out.push(p);
                }
            }
        }
    }
    out
}

// ── Rule compilation ───────────────────────────────────────────────

fn compile_rules(
    rule_paths: &[PathBuf],
    inline: Option<&str>,
) -> Result<(yara_x::Rules, String), String> {
    let mut compiler = yara_x::Compiler::new();
    // Cuckoo rules describe dynamic-analysis predicates (process tree,
    // network artifacts, registry writes mid-run) that always evaluate
    // false against a static buffer. Filter the import — yara-x will
    // skip the rule entirely with just a warning.
    compiler.ignore_module("cuckoo");

    let mut report = String::new();
    let mut loaded_files = 0usize;
    let mut skipped_files = 0usize;

    for rule_path in rule_paths {
        let src = match std::fs::read_to_string(rule_path) {
            Ok(s) => s,
            Err(e) => {
                report.push_str(&format!(
                    "[skip] {} — read error: {e}\n", rule_path.display()
                ));
                skipped_files += 1;
                continue;
            }
        };
        let origin = rule_path.display().to_string();
        let src_in = yara_x::SourceCode::from(src.as_str()).with_origin(origin.as_str());
        match compiler.add_source(src_in) {
            Ok(_) => loaded_files += 1,
            Err(e) => {
                report.push_str(&format!(
                    "[skip] {} — compile error: {}\n",
                    rule_path.display(),
                    first_line(&e.to_string()),
                ));
                skipped_files += 1;
            }
        }
    }

    if let Some(text) = inline {
        match compiler.add_source(text) {
            Ok(_) => loaded_files += 1,
            Err(e) => {
                return Err(format!("inline rule failed to compile: {}", first_line(&e.to_string())));
            }
        }
    }

    let warnings = compiler.warnings().len();
    let rules = compiler.build();

    report.push_str(&format!(
        "Loaded {loaded_files} rule file(s); skipped {skipped_files}; {warnings} compiler warning(s).\n"
    ));
    Ok((rules, report))
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or(s).to_string()
}

// ── Scanning ───────────────────────────────────────────────────────

fn scan_buffer(
    graph: &mut Graph,
    scanner: &mut yara_x::Scanner,
    data: &[u8],
    bin_id: &str,
    target: &str,
    section: &str,
    section_va: u64,
    report: &mut String,
) -> usize {
    let results = match scanner.scan(data) {
        Ok(r) => r,
        Err(e) => {
            report.push_str(&format!("  [scan-error in section {section}] {e}\n"));
            return 0;
        }
    };
    let mut emitted = 0usize;
    for r in results.matching_rules() {
        let rule_name = r.identifier();
        let namespace = r.namespace();
        let tags: Vec<String> = r.tags().map(|t| t.identifier().to_string()).collect();
        let tags_joined = tags.join(",");

        // Register the YaraRule node on first sight (idempotent).
        let rule_id = format!("yara_rule:{namespace}::{rule_name}");
        let metas: Vec<(String, String)> = r.metadata()
            .map(|(k, v)| (k.to_string(), meta_to_string(&v)))
            .collect();
        register_rule_node(graph, &rule_id, rule_name, namespace, &tags_joined, &metas);

        // Walk patterns & matches.
        let mut rule_match_count = 0usize;
        for pat in r.patterns() {
            for m in pat.matches() {
                if rule_match_count >= MAX_MATCHES_PER_RULE { break; }
                let range = m.range();
                let preview = preview_bytes(m.data());
                let file_offset = if section == "<whole>" {
                    range.start
                } else {
                    // Section-relative offset only meaningful inside the
                    // section view; record both.
                    range.start
                };
                let va_str = if section_va > 0 {
                    format!("{:#x}", section_va.wrapping_add(range.start as u64))
                } else {
                    String::new()
                };

                // YaraMatch node id: includes (target, section, offset,
                // rule, pattern) so duplicates within a single (rule,
                // target) pair don't collide between sections.
                let match_id = format!(
                    "yara_match:{}:{}:{}:{:#x}:{}",
                    target, section, rule_name, file_offset, pat.identifier()
                );
                let len_str = m.data().len().to_string();
                let off_str = format!("{:#x}", file_offset);
                let attrs: Vec<(&str, &str)> = vec![
                    ("rule_name", rule_name),
                    ("namespace", namespace),
                    ("target", target),
                    ("section", section),
                    ("offset", &off_str),
                    ("virtual_address", &va_str),
                    ("pattern_id", pat.identifier()),
                    ("match_len", &len_str),
                    ("preview", &preview),
                ];
                graph.ensure_typed_node(&match_id, EntityKind::YaraMatch, &attrs);
                graph.add_edge(bin_id, &match_id);
                graph.add_edge(&rule_id, &match_id);
                emitted += 1;
                rule_match_count += 1;
            }
            if rule_match_count >= MAX_MATCHES_PER_RULE { break; }
        }
        let summary = if rule_match_count == 0 {
            // Rule fired on its condition (e.g. all of them with no
            // patterns of interest in this slice) — record a single
            // "no-pattern" match anchored at offset 0 so the graph
            // still sees the hit.
            let match_id = format!(
                "yara_match:{}:{}:{}:cond:0",
                target, section, rule_name
            );
            let zero = "0x0";
            graph.ensure_typed_node(&match_id, EntityKind::YaraMatch, &[
                ("rule_name", rule_name),
                ("namespace", namespace),
                ("target", target),
                ("section", section),
                ("offset", zero),
                ("virtual_address", ""),
                ("pattern_id", "<condition>"),
                ("match_len", "0"),
                ("preview", ""),
            ]);
            graph.add_edge(bin_id, &match_id);
            graph.add_edge(&rule_id, &match_id);
            emitted += 1;
            "(condition-only hit)".to_string()
        } else {
            format!("{rule_match_count} match(es)")
        };
        report.push_str(&format!(
            "  [hit] {}::{} in section={section} — {summary}\n",
            namespace, rule_name
        ));
    }
    emitted
}

fn register_rule_node(
    graph: &mut Graph,
    rule_id: &str,
    rule_name: &str,
    namespace: &str,
    tags: &str,
    metas: &[(String, String)],
) {
    let mut attrs: Vec<(String, String)> = vec![
        ("name".to_string(), rule_name.to_string()),
        ("namespace".to_string(), namespace.to_string()),
        ("tags".to_string(), tags.to_string()),
    ];
    for (k, v) in metas {
        // Prefix metas to avoid collision with our own attrs (`name`,
        // `namespace`, `tags`).
        let key = format!("meta_{}", sanitize_attr_key(k));
        let val = if v.len() > 256 { v[..256].to_string() } else { v.clone() };
        attrs.push((key, val));
    }
    let attrs_ref: Vec<(&str, &str)> = attrs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    graph.ensure_typed_node(rule_id, EntityKind::YaraRule, &attrs_ref);
}

fn sanitize_attr_key(k: &str) -> String {
    k.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

fn meta_to_string(v: &yara_x::MetaValue) -> String {
    match v {
        yara_x::MetaValue::Integer(i) => i.to_string(),
        yara_x::MetaValue::Float(f)   => f.to_string(),
        yara_x::MetaValue::Bool(b)    => b.to_string(),
        yara_x::MetaValue::String(s)  => s.to_string(),
        yara_x::MetaValue::Bytes(b)   => format!("{:?}", b),
    }
}

fn preview_bytes(data: &[u8]) -> String {
    let cap = data.len().min(32);
    let mut out = String::new();
    for &b in &data[..cap] {
        if (0x20..=0x7E).contains(&b) {
            out.push(b as char);
        } else {
            out.push('.');
        }
    }
    if data.len() > cap { out.push_str("…"); }
    out
}

// ── Format detection + node bootstrap ──────────────────────────────

fn detect_format(data: &[u8]) -> BinaryFormat {
    if data.len() >= 0x40 && &data[..2] == b"MZ" { return BinaryFormat::Pe; }
    if data.len() >= 4 && &data[..4] == b"\x7FELF" { return BinaryFormat::Elf; }
    if data.len() >= 4 {
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        // 0xFEEDFACE / 0xFEEDFACF / 0xCAFEBABE (fat) / 0xBEBAFECA
        if matches!(magic, 0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE | 0xCAFEBABE | 0xBEBAFECA) {
            return BinaryFormat::Macho;
        }
    }
    BinaryFormat::Unknown
}

fn format_label(f: BinaryFormat) -> &'static str {
    match f {
        BinaryFormat::Pe      => "PE",
        BinaryFormat::Elf     => "ELF",
        BinaryFormat::Macho   => "Mach-O",
        BinaryFormat::Unknown => "buffer",
    }
}

fn ensure_target_node(graph: &mut Graph, path: &str, _data: &[u8], fmt: BinaryFormat) -> String {
    let (id, kind) = match fmt {
        BinaryFormat::Pe       => (format!("pe:{path}"),    EntityKind::PeBinary),
        BinaryFormat::Elf      => (format!("elf:{path}"),   EntityKind::ElfBinary),
        BinaryFormat::Macho    => (format!("macho:{path}"), EntityKind::MachoBinary),
        BinaryFormat::Unknown  => (format!("file:{path}"),  EntityKind::SourceFile),
    };
    graph.ensure_typed_node(&id, kind, &[("path", path)]);
    id
}

fn is_noise_section(name: &str) -> bool {
    let trimmed = name.trim_end_matches('\0').trim();
    NOISE_SECTIONS.iter().any(|n| trimmed.eq_ignore_ascii_case(n))
}

// ── Per-format section walkers ─────────────────────────────────────

fn collect_sections(data: &[u8], fmt: BinaryFormat) -> Vec<Section> {
    match fmt {
        BinaryFormat::Pe       => collect_pe_sections(data).unwrap_or_default(),
        BinaryFormat::Elf      => collect_elf_sections(data).unwrap_or_default(),
        BinaryFormat::Macho    => collect_macho_sections(data).unwrap_or_default(),
        BinaryFormat::Unknown  => Vec::new(),
    }
}

fn collect_pe_sections(data: &[u8]) -> Option<Vec<Section>> {
    if data.len() < 0x40 || &data[..2] != b"MZ" { return None; }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return None; }
    let coff = e_lfanew + 4;
    let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let sec_table = coff + 20 + opt_size;

    let mut out = Vec::with_capacity(n_sections.min(96));
    for i in 0..n_sections.min(96) {
        let off = sec_table + i * 40;
        if off + 40 > data.len() { break; }
        let name_bytes = &data[off..off + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name: String = name_bytes[..name_end].iter()
            .map(|&b| if (0x20..=0x7E).contains(&b) { b as char } else { '.' })
            .collect();
        let virt_addr = u32::from_le_bytes([data[off + 12], data[off + 13], data[off + 14], data[off + 15]]) as u64;
        let raw_size = u32::from_le_bytes([data[off + 16], data[off + 17], data[off + 18], data[off + 19]]) as usize;
        let raw_off  = u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]) as usize;
        out.push(Section { name, raw_offset: raw_off, raw_size, virtual_address: virt_addr });
    }
    Some(out)
}

fn collect_elf_sections(data: &[u8]) -> Option<Vec<Section>> {
    if data.len() < 64 || &data[..4] != b"\x7FELF" { return None; }
    let class = data[4];   // 1 = ELF32, 2 = ELF64
    let endian = data[5];  // 1 = little, 2 = big
    let read16 = |off: usize| -> u16 {
        if off + 2 > data.len() { return 0; }
        if endian == 2 { u16::from_be_bytes([data[off], data[off+1]]) }
        else            { u16::from_le_bytes([data[off], data[off+1]]) }
    };
    let read32 = |off: usize| -> u32 {
        if off + 4 > data.len() { return 0; }
        let b = [data[off], data[off+1], data[off+2], data[off+3]];
        if endian == 2 { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
    };
    let read64 = |off: usize| -> u64 {
        if off + 8 > data.len() { return 0; }
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[off..off+8]);
        if endian == 2 { u64::from_be_bytes(b) } else { u64::from_le_bytes(b) }
    };

    let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if class == 1 {
        // ELF32: e_shoff @ 0x20 (4), e_shentsize @ 0x2E (2), e_shnum @ 0x30 (2), e_shstrndx @ 0x32
        (read32(0x20) as u64, read16(0x2E) as usize, read16(0x30) as usize, read16(0x32) as usize)
    } else {
        // ELF64: e_shoff @ 0x28 (8), e_shentsize @ 0x3A (2), e_shnum @ 0x3C (2), e_shstrndx @ 0x3E
        (read64(0x28), read16(0x3A) as usize, read16(0x3C) as usize, read16(0x3E) as usize)
    };
    if e_shoff == 0 || e_shentsize == 0 || e_shnum == 0 { return None; }
    let table_start = e_shoff as usize;
    if table_start.saturating_add(e_shentsize.saturating_mul(e_shnum)) > data.len() {
        return None;
    }

    // Locate .shstrtab to resolve names.
    let shstr = if e_shstrndx < e_shnum {
        let entry = table_start + e_shstrndx * e_shentsize;
        if class == 1 {
            let off = read32(entry + 16) as usize;
            let sz  = read32(entry + 20) as usize;
            (off, sz)
        } else {
            let off = read64(entry + 24) as usize;
            let sz  = read64(entry + 32) as usize;
            (off, sz as usize)
        }
    } else { (0, 0) };

    let read_name = |name_off: u32| -> String {
        let start = shstr.0 + name_off as usize;
        let end_cap = shstr.0 + shstr.1;
        if start >= data.len() || start >= end_cap { return String::new(); }
        let mut s = String::new();
        for i in start..data.len().min(end_cap) {
            if data[i] == 0 { break; }
            if (0x20..=0x7E).contains(&data[i]) {
                s.push(data[i] as char);
            } else { break; }
        }
        s
    };

    let mut out = Vec::with_capacity(e_shnum.min(256));
    for i in 0..e_shnum.min(256) {
        let entry = table_start + i * e_shentsize;
        let (name_off, sh_addr, sh_offset, sh_size) = if class == 1 {
            (read32(entry), read32(entry + 12) as u64, read32(entry + 16) as usize, read32(entry + 20) as usize)
        } else {
            (read32(entry), read64(entry + 16), read64(entry + 24) as usize, read64(entry + 32) as usize)
        };
        let name = read_name(name_off);
        out.push(Section {
            name,
            raw_offset: sh_offset,
            raw_size: sh_size,
            virtual_address: sh_addr,
        });
    }
    Some(out)
}

fn collect_macho_sections(data: &[u8]) -> Option<Vec<Section>> {
    if data.len() < 32 { return None; }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (is64, swap) = match magic {
        0xFEEDFACE => (false, false),
        0xCEFAEDFE => (false, true),
        0xFEEDFACF => (true,  false),
        0xCFFAEDFE => (true,  true),
        _ => return None, // fat binaries not handled here
    };
    let read32 = |off: usize| -> u32 {
        if off + 4 > data.len() { return 0; }
        let b = [data[off], data[off+1], data[off+2], data[off+3]];
        if swap { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
    };
    let read64 = |off: usize| -> u64 {
        if off + 8 > data.len() { return 0; }
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[off..off+8]);
        if swap { u64::from_be_bytes(b) } else { u64::from_le_bytes(b) }
    };
    let header_size = if is64 { 32 } else { 28 };
    let n_cmds = read32(16) as usize;
    let mut cur = header_size;
    let mut out: Vec<Section> = Vec::new();
    for _ in 0..n_cmds.min(512) {
        if cur + 8 > data.len() { break; }
        let cmd = read32(cur);
        let cmd_size = read32(cur + 4) as usize;
        if cmd_size == 0 || cur + cmd_size > data.len() { break; }
        // LC_SEGMENT = 0x1, LC_SEGMENT_64 = 0x19
        if cmd == 0x1 || cmd == 0x19 {
            let seg64 = cmd == 0x19;
            let nsects = if seg64 {
                read32(cur + 8 + 16 + 8 + 8 + 8 + 8 + 4 + 4 + 4) as usize
            } else {
                read32(cur + 8 + 16 + 4 + 4 + 4 + 4 + 4 + 4 + 4) as usize
            };
            let sects_start = cur + if seg64 { 72 } else { 56 };
            let sect_size = if seg64 { 80 } else { 68 };
            for i in 0..nsects.min(64) {
                let s = sects_start + i * sect_size;
                if s + sect_size > data.len() { break; }
                let mut name_buf = [0u8; 16];
                name_buf.copy_from_slice(&data[s..s + 16]);
                let name_end = name_buf.iter().position(|&b| b == 0).unwrap_or(16);
                let name: String = name_buf[..name_end].iter()
                    .map(|&b| if (0x20..=0x7E).contains(&b) { b as char } else { '.' })
                    .collect();
                let (addr, size, raw_off) = if seg64 {
                    (read64(s + 32), read64(s + 40) as usize, read32(s + 48) as usize)
                } else {
                    (read32(s + 32) as u64, read32(s + 36) as usize, read32(s + 40) as usize)
                };
                out.push(Section { name, raw_offset: raw_off, raw_size: size, virtual_address: addr });
            }
        }
        cur += cmd_size;
    }
    Some(out)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Graph;
    use std::collections::HashMap;

    fn empty_graph() -> Graph {
        Graph { nodes: HashMap::new(), scan_dir: String::new(), cpg: None }
    }

    fn write_tmp(name: &str, content: &[u8]) -> String {
        let dir = std::env::temp_dir().join(format!("codemap_yara_test_{}_{}", std::process::id(), name));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(name);
        std::fs::write(&path, content).expect("write tmp");
        path.to_string_lossy().to_string()
    }

    /// Construct a deliberately minimal but well-formed PE32+ image
    /// with one .text section that contains the bytes from `text`.
    /// Section file offset = 0x200, virtual address = 0x1000.
    fn build_minimal_pe(text: &[u8]) -> Vec<u8> {
        let raw_off: usize = 0x200;
        let virt_addr: u32 = 0x1000;
        let raw_size: usize = 0x200; // one file-alignment slot
        let total = raw_off + raw_size;
        let mut data = vec![0u8; total];
        // DOS header
        data[0] = b'M'; data[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        data[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        // PE signature
        let pe = e_lfanew as usize;
        data[pe..pe+4].copy_from_slice(b"PE\0\0");
        // COFF header (20 bytes): machine x64=0x8664, n_sections=1,
        // ts=0, sym_off=0, sym_count=0, opt_hdr_size=240, chars=0x22
        let coff = pe + 4;
        data[coff..coff+2].copy_from_slice(&0x8664u16.to_le_bytes());
        data[coff+2..coff+4].copy_from_slice(&1u16.to_le_bytes());
        // skip ts/symbol table fields (zero already)
        let opt_hdr_size: u16 = 240;
        data[coff+16..coff+18].copy_from_slice(&opt_hdr_size.to_le_bytes());
        data[coff+18..coff+20].copy_from_slice(&0x22u16.to_le_bytes());
        // Optional header magic = 0x20B (PE32+); leave the rest zeroed
        // — section table parser only needs the size to skip ahead.
        let opt = coff + 20;
        data[opt..opt+2].copy_from_slice(&0x20Bu16.to_le_bytes());
        // Section header at opt + opt_hdr_size
        let sec = opt + opt_hdr_size as usize;
        let name = b".text\0\0\0";
        data[sec..sec+8].copy_from_slice(name);
        // virtual_size
        data[sec+8..sec+12].copy_from_slice(&(text.len() as u32).to_le_bytes());
        // virtual_address
        data[sec+12..sec+16].copy_from_slice(&virt_addr.to_le_bytes());
        // raw_size
        data[sec+16..sec+20].copy_from_slice(&(raw_size as u32).to_le_bytes());
        // raw_offset
        data[sec+20..sec+24].copy_from_slice(&(raw_off as u32).to_le_bytes());
        // characteristics: code|exec|read = 0x60000020
        data[sec+36..sec+40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        // Insert the text payload at raw_off.
        data[raw_off..raw_off + text.len()].copy_from_slice(text);
        data
    }

    #[test]
    fn parse_args_basic() {
        let a = parse_args("--rules-file foo.yar bar.bin").unwrap();
        assert_eq!(a.rules_files.len(), 1);
        assert_eq!(a.target_paths, vec!["bar.bin"]);

        let b = parse_args("--rules-dir /etc/yara some.bin other.bin").unwrap();
        assert_eq!(b.rules_dirs.len(), 1);
        assert_eq!(b.target_paths, vec!["some.bin", "other.bin"]);

        let c = parse_args("").unwrap();
        assert!(c.target_paths.is_empty());
    }

    #[test]
    fn parse_args_unknown_flag_errors() {
        let r = parse_args("--bogus thing.bin");
        assert!(r.is_err());
    }

    #[test]
    fn detect_format_smoke() {
        assert_eq!(detect_format(b"MZ\0\0"), BinaryFormat::Unknown); // too short
        let mut pe = vec![0u8; 0x80];
        pe[0] = b'M'; pe[1] = b'Z';
        assert_eq!(detect_format(&pe), BinaryFormat::Pe);
        let mut elf = vec![0u8; 0x40];
        elf[..4].copy_from_slice(b"\x7FELF");
        assert_eq!(detect_format(&elf), BinaryFormat::Elf);
        let mut macho = vec![0u8; 0x40];
        macho[..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
        assert_eq!(detect_format(&macho), BinaryFormat::Macho);
    }

    #[test]
    fn synthetic_rule_finds_hello() {
        // 100-byte buffer with "hello" inside.
        let mut buf = vec![0xAAu8; 100];
        buf[40..45].copy_from_slice(b"hello");
        let target_path = write_tmp("hello.bin", &buf);
        let rule = "rule yarax_hello { strings: $a = \"hello\" condition: $a }";
        let rule_path = write_tmp("hello.yar", rule.as_bytes());
        let arg = format!("--rules-file {} {}", rule_path, target_path);

        let mut graph = empty_graph();
        let report = yara_scan(&mut graph, &arg);
        assert!(report.contains("Total matches: 1"), "report:\n{report}");
        // Verify graph state.
        let yara_rules: Vec<_> = graph.nodes.values().filter(|n| n.kind == EntityKind::YaraRule).collect();
        assert_eq!(yara_rules.len(), 1, "exactly one rule node");
        assert_eq!(yara_rules[0].attrs.get("name").map(|s| s.as_str()), Some("yarax_hello"));

        let matches: Vec<_> = graph.nodes.values().filter(|n| n.kind == EntityKind::YaraMatch).collect();
        assert_eq!(matches.len(), 1, "exactly one match node");
        let m = matches[0];
        assert_eq!(m.attrs.get("rule_name").map(|s| s.as_str()), Some("yarax_hello"));
        assert_eq!(m.attrs.get("offset").map(|s| s.as_str()), Some("0x28"));
        assert_eq!(m.attrs.get("section").map(|s| s.as_str()), Some("<whole>"));
    }

    #[test]
    fn per_section_scan_translates_to_va() {
        // Tiny PE with .text at file offset 0x200, VA 0x1000. Put
        // "hello" 5 bytes into .text → file offset 0x205, VA 0x1005.
        let mut payload = vec![0u8; 0x80];
        payload[5..10].copy_from_slice(b"hello");
        let pe = build_minimal_pe(&payload);
        let target_path = write_tmp("mini.pe", &pe);

        let rule = "rule yarax_pe_hello { strings: $a = \"hello\" condition: $a }";
        let rule_path = write_tmp("pe_hello.yar", rule.as_bytes());
        let arg = format!("--rules-file {} {}", rule_path, target_path);

        let mut graph = empty_graph();
        let report = yara_scan(&mut graph, &arg);
        // Expect 2 matches: one whole-buffer, one per-section.
        let hits = graph.nodes.values()
            .filter(|n| n.kind == EntityKind::YaraMatch)
            .collect::<Vec<_>>();
        assert!(hits.len() >= 2, "expected ≥2 matches (whole + section), got {}\n{report}", hits.len());

        let sec_match = hits.iter().find(|n| n.attrs.get("section").map(|s| s.as_str()) == Some(".text"));
        assert!(sec_match.is_some(), "missing .text section match\n{report}");
        let sm = sec_match.unwrap();
        // Section VA = 0x1000, payload pushed "hello" 5 bytes in →
        // VA should be 0x1005.
        assert_eq!(sm.attrs.get("virtual_address").map(|s| s.as_str()), Some("0x1005"),
            "VA translation wrong:\n{report}");
        assert_eq!(sm.attrs.get("offset").map(|s| s.as_str()), Some("0x5"),
            "section-local file offset wrong");
    }

    #[test]
    fn cuckoo_imported_rule_is_filtered() {
        // The compiler should silently drop this rule (cuckoo ignored).
        let rule = r#"
            import "cuckoo"
            rule cuckoo_only_rule {
              condition:
                cuckoo.network.host(/example/)
            }
        "#;
        let buf = vec![0u8; 100];
        let target_path = write_tmp("buf.bin", &buf);
        let rule_path = write_tmp("cuckoo_only.yar", rule.as_bytes());
        let arg = format!("--rules-file {} {}", rule_path, target_path);
        let mut graph = empty_graph();
        let report = yara_scan(&mut graph, &arg);
        // No YaraRule node should exist (cuckoo rule was dropped) and
        // no matches were emitted. The scan still completed cleanly.
        let hits = graph.nodes.values().filter(|n| n.kind == EntityKind::YaraMatch).count();
        assert_eq!(hits, 0, "no matches should fire when cuckoo rule is filtered\n{report}");
        assert!(report.contains("Total matches: 0"), "report:\n{report}");
    }

    #[test]
    fn missing_rules_reports_usage() {
        let target_path = write_tmp("blank.bin", b"\0\0\0\0");
        let r = yara_scan(&mut empty_graph(), &target_path);
        assert!(r.contains("no rules provided"), "{r}");
    }

    #[test]
    fn noise_section_skipped() {
        assert!(is_noise_section(".rsrc"));
        assert!(is_noise_section(".RELOC"));
        assert!(!is_noise_section(".text"));
    }
}
