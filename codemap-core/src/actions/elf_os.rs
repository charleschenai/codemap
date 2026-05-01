// ── ELF OS Detection Cascade (5.38.0 — Ship 5 #2) ─────────────────
//
// Tags every ELF binary with `os: linux/freebsd/openbsd/android/...`
// (24-variant enum) + `language: go|c|cpp|...`. Today codemap labels
// ELFs as just "ELF". After this, `audit` clusters by OS — Android
// code separates from server-targeting from kernel modules.
//
// Algorithm port from capa's `detect_elf_os(f)` cascade
// (~/reference/codemap-research-targets/01-capa/capa/features/
// extractors/elf.py). 9 chained heuristics, ranked by confidence:
//
//   1. ABI tag (PT_NOTE with NT_GNU_ABI_TAG)        — most reliable
//   2. PT_NOTE / SHT_NOTE owner-name scan           — kernel modules
//   3. PT_INTERP linker path                        — high confidence
//   4. GLIBC versions in DT_VERNEED                 — Linux/Hurd
//   5. NEEDED dependency names                      — Android, Hurd
//   6. .ident / .comment GCC string                 — Debian/Ubuntu/...
//   7. Symtab keyword scan                          — best-effort
//   8. Go buildinfo (`.go.buildinfo` magic + GOOS=) — language=go
//   9. OS/ABI byte (e_ident[7])                     — fallback
//
// Capa's algorithm logic is Apache-2.0; algorithm reformulation in
// Rust is fine. No source pasted; structure rebuilt from the
// algorithm description in `analysis.md`.

use crate::types::{Graph, EntityKind};

// ── OS Enum (24 variants from capa) ────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    Hurd,
    Solaris,
    Freebsd,
    Netbsd,
    Openbsd,
    Dragonflybsd,
    Illumos,
    Aix,
    Irix,
    Android,
    Tru64,
    Openvms,
    Nsk,
    Aros,
    Fenixos,
    Cloud,
    Syllable,
    Nacl,
    Zos,
    Hpux,
    _86open,
    Modesto,
    Unix,
}

impl Os {
    pub fn as_str(self) -> &'static str {
        match self {
            Os::Linux        => "linux",
            Os::Hurd         => "hurd",
            Os::Solaris      => "solaris",
            Os::Freebsd      => "freebsd",
            Os::Netbsd       => "netbsd",
            Os::Openbsd      => "openbsd",
            Os::Dragonflybsd => "dragonfly",
            Os::Illumos      => "illumos",
            Os::Aix          => "aix",
            Os::Irix         => "irix",
            Os::Android      => "android",
            Os::Tru64        => "tru64",
            Os::Openvms      => "openvms",
            Os::Nsk          => "nsk",
            Os::Aros         => "aros",
            Os::Fenixos      => "fenixos",
            Os::Cloud        => "cloud",
            Os::Syllable     => "syllable",
            Os::Nacl         => "nacl",
            Os::Zos          => "z/os",
            Os::Hpux         => "hpux",
            Os::_86open      => "86open",
            Os::Modesto      => "modesto",
            Os::Unix         => "unix",
        }
    }
}

// ── Heuristic IDs ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsHeuristic {
    OsabiByte,
    PhNote,
    ShNote,
    Linker,
    GlibcVerneed,
    NeededDep,
    IdentComment,
    Symtab,
    GoBuildinfo,
}

impl OsHeuristic {
    fn as_str(self) -> &'static str {
        match self {
            OsHeuristic::OsabiByte    => "osabi-byte",
            OsHeuristic::PhNote       => "ph-note",
            OsHeuristic::ShNote       => "sh-note",
            OsHeuristic::Linker       => "linker",
            OsHeuristic::GlibcVerneed => "glibc-verneed",
            OsHeuristic::NeededDep    => "needed-dep",
            OsHeuristic::IdentComment => "ident-comment",
            OsHeuristic::Symtab       => "symtab",
            OsHeuristic::GoBuildinfo  => "go-buildinfo",
        }
    }

    /// Rank confidence 0..=10 used to pick a winner when multiple
    /// heuristics fire. Mirrors capa's tier ordering in detect_elf_os.
    fn confidence(self) -> u8 {
        match self {
            OsHeuristic::PhNote       => 10, // ABI tag (capa's #1)
            OsHeuristic::ShNote       => 9,  // kernel modules — high
            OsHeuristic::Linker       => 8,  // PT_INTERP — strong
            OsHeuristic::GlibcVerneed => 7,
            OsHeuristic::NeededDep    => 7,
            OsHeuristic::Symtab       => 5,
            OsHeuristic::GoBuildinfo  => 6,
            OsHeuristic::IdentComment => 4,  // last (cross-compile bias)
            OsHeuristic::OsabiByte    => 3,  // almost-always 0 = SysV
        }
    }
}

#[derive(Debug, Clone)]
pub struct OsGuess {
    pub os: Os,
    pub source: OsHeuristic,
}

// ── ELF parser (just enough for the cascade) ───────────────────────

#[derive(Debug)]
struct ElfView<'a> {
    data: &'a [u8],
    is_64: bool,
    is_le: bool,
    e_machine: u16,
    osabi: u8,
    program_headers: Vec<Phdr>,
    section_headers: Vec<Shdr>,
    shstrtab: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Phdr {
    p_type: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_flags: u32,
}

#[derive(Debug, Clone)]
struct Shdr {
    sh_name: u32,
    sh_type: u32,
    _sh_flags: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    _sh_entsize: u64,
}

impl Shdr {
    fn name<'a>(&self, shstrtab: &'a [u8]) -> &'a [u8] {
        let off = self.sh_name as usize;
        if off >= shstrtab.len() { return &[]; }
        let end = shstrtab[off..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| off + p)
            .unwrap_or(shstrtab.len());
        &shstrtab[off..end]
    }

    fn buf<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        let start = self.sh_offset as usize;
        let end = start.saturating_add(self.sh_size as usize);
        if end > data.len() { return &[]; }
        &data[start..end]
    }
}

fn r16(data: &[u8], off: usize, le: bool) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(if le {
        u16::from_le_bytes([b[0], b[1]])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    })
}
fn r32(data: &[u8], off: usize, le: bool) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(if le {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    })
}
fn r64(data: &[u8], off: usize, le: bool) -> Option<u64> {
    let b = data.get(off..off + 8)?;
    Some(if le {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    } else {
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

fn parse_elf(data: &[u8]) -> Option<ElfView<'_>> {
    if data.len() < 64 { return None; }
    if &data[..4] != b"\x7FELF" { return None; }

    let class = data[4];
    let endian = data[5];
    let osabi = data[7];
    let is_64 = class == 2;
    let is_le = endian == 1;

    let e_machine = r16(data, 18, is_le)?;

    let (ph_off, ph_entsize, ph_num, sh_off, sh_entsize, sh_num, sh_strndx) = if is_64 {
        let ph_off = r64(data, 32, is_le)? as usize;
        let sh_off = r64(data, 40, is_le)? as usize;
        let ph_entsize = r16(data, 54, is_le)? as usize;
        let ph_num = r16(data, 56, is_le)? as usize;
        let sh_entsize = r16(data, 58, is_le)? as usize;
        let sh_num = r16(data, 60, is_le)? as usize;
        let sh_strndx = r16(data, 62, is_le)? as usize;
        (ph_off, ph_entsize, ph_num, sh_off, sh_entsize, sh_num, sh_strndx)
    } else {
        let ph_off = r32(data, 28, is_le)? as usize;
        let sh_off = r32(data, 32, is_le)? as usize;
        let ph_entsize = r16(data, 42, is_le)? as usize;
        let ph_num = r16(data, 44, is_le)? as usize;
        let sh_entsize = r16(data, 46, is_le)? as usize;
        let sh_num = r16(data, 48, is_le)? as usize;
        let sh_strndx = r16(data, 50, is_le)? as usize;
        (ph_off, ph_entsize, ph_num, sh_off, sh_entsize, sh_num, sh_strndx)
    };

    let mut program_headers = Vec::with_capacity(ph_num);
    for i in 0..ph_num {
        let base = ph_off + i * ph_entsize;
        if base + ph_entsize > data.len() { break; }
        let phdr = if is_64 {
            Phdr {
                p_type:    r32(data, base, is_le).unwrap_or(0),
                p_flags:   r32(data, base + 4, is_le).unwrap_or(0),
                p_offset:  r64(data, base + 8, is_le).unwrap_or(0),
                p_vaddr:   r64(data, base + 16, is_le).unwrap_or(0),
                p_filesz:  r64(data, base + 32, is_le).unwrap_or(0),
                p_memsz:   r64(data, base + 40, is_le).unwrap_or(0),
            }
        } else {
            Phdr {
                p_type:    r32(data, base, is_le).unwrap_or(0),
                p_offset:  r32(data, base + 4, is_le).unwrap_or(0) as u64,
                p_vaddr:   r32(data, base + 8, is_le).unwrap_or(0) as u64,
                p_filesz:  r32(data, base + 16, is_le).unwrap_or(0) as u64,
                p_memsz:   r32(data, base + 20, is_le).unwrap_or(0) as u64,
                p_flags:   r32(data, base + 24, is_le).unwrap_or(0),
            }
        };
        program_headers.push(phdr);
    }

    let mut section_headers = Vec::with_capacity(sh_num);
    for i in 0..sh_num {
        let base = sh_off + i * sh_entsize;
        if base + sh_entsize > data.len() { break; }
        let shdr = if is_64 {
            Shdr {
                sh_name:    r32(data, base, is_le).unwrap_or(0),
                sh_type:    r32(data, base + 4, is_le).unwrap_or(0),
                _sh_flags:  r64(data, base + 8, is_le).unwrap_or(0),
                sh_offset:  r64(data, base + 24, is_le).unwrap_or(0),
                sh_size:    r64(data, base + 32, is_le).unwrap_or(0),
                sh_link:    r32(data, base + 40, is_le).unwrap_or(0),
                _sh_entsize:r64(data, base + 56, is_le).unwrap_or(0),
            }
        } else {
            Shdr {
                sh_name:    r32(data, base, is_le).unwrap_or(0),
                sh_type:    r32(data, base + 4, is_le).unwrap_or(0),
                _sh_flags:  r32(data, base + 8, is_le).unwrap_or(0) as u64,
                sh_offset:  r32(data, base + 16, is_le).unwrap_or(0) as u64,
                sh_size:    r32(data, base + 20, is_le).unwrap_or(0) as u64,
                sh_link:    r32(data, base + 24, is_le).unwrap_or(0),
                _sh_entsize:r32(data, base + 36, is_le).unwrap_or(0) as u64,
            }
        };
        section_headers.push(shdr);
    }

    let shstrtab = section_headers.get(sh_strndx)
        .map(|s| s.buf(data).to_vec())
        .unwrap_or_default();

    Some(ElfView {
        data,
        is_64,
        is_le,
        e_machine,
        osabi,
        program_headers,
        section_headers,
        shstrtab,
    })
}

// ── Heuristic 9 (last in cascade): OS/ABI byte ─────────────────────
// Almost always 0 (SysV, == "no info"); useful only for OpenBSD,
// FreeBSD, etc. that bother to set it.
fn guess_os_from_osabi(view: &ElfView) -> Option<Os> {
    match view.osabi {
        1  => Some(Os::Hpux),
        2  => Some(Os::Netbsd),
        3  => Some(Os::Linux),
        4  => Some(Os::Hurd),
        5  => Some(Os::_86open),
        6  => Some(Os::Solaris),
        7  => Some(Os::Aix),
        8  => Some(Os::Irix),
        9  => Some(Os::Freebsd),
        10 => Some(Os::Tru64),
        11 => Some(Os::Modesto),
        12 => Some(Os::Openbsd),
        13 => Some(Os::Openvms),
        14 => Some(Os::Nsk),
        15 => Some(Os::Aros),
        16 => Some(Os::Fenixos),
        17 => Some(Os::Cloud),
        _  => None, // 0 = "UNIX System V" / unspecified — useless
    }
}

// ── Note parsing (PT_NOTE + SHT_NOTE share format) ─────────────────

fn read_cstr(buf: &[u8], off: usize) -> &[u8] {
    if off >= buf.len() { return &[]; }
    let end = buf[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(buf.len());
    &buf[off..end]
}

fn align4(v: usize) -> usize {
    (v + 3) & !3
}

/// Walk a buffer of consecutive ELF notes (used for both PT_NOTE
/// segments and SHT_NOTE sections). Yields (n_type, name, desc).
fn iter_notes(buf: &[u8], is_le: bool) -> Vec<(u32, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 12 <= buf.len() {
        let namesz = r32(buf, off, is_le).unwrap_or(0) as usize;
        let descsz = r32(buf, off + 4, is_le).unwrap_or(0) as usize;
        let n_type = r32(buf, off + 8, is_le).unwrap_or(0);
        let name_off = off + 12;
        let name_end = name_off.checked_add(namesz).unwrap_or(usize::MAX);
        if name_end > buf.len() { break; }
        let desc_off = align4(name_end);
        let desc_end = desc_off.checked_add(descsz).unwrap_or(usize::MAX);
        if desc_end > buf.len() { break; }
        let name = read_cstr(buf, name_off).to_vec();
        let desc = buf[desc_off..desc_end].to_vec();
        out.push((n_type, name, desc));
        let advance = align4(name_end - off) + align4(descsz);
        if advance == 0 { break; }
        off += advance;
    }
    out
}

// ── Heuristic 1: PT_NOTE (program-header notes) ────────────────────
// NT_GNU_ABI_TAG (n_type=1, name="GNU") encodes target OS in desc[0..4].
// Mappings: 0=Linux 1=Hurd 2=Solaris 3=Freebsd 4=Netbsd 5=Syllable 6=Nacl.
// Other note owners (Linux/OpenBSD/NetBSD/FreeBSD/Android) name the OS.
fn guess_os_from_ph_notes(view: &ElfView) -> Option<Os> {
    const PT_NOTE: u32 = 4;
    for ph in &view.program_headers {
        if ph.p_type != PT_NOTE { continue; }
        let start = ph.p_offset as usize;
        let end = start.saturating_add(ph.p_filesz as usize);
        if end > view.data.len() { continue; }
        let buf = &view.data[start..end];
        for (n_type, name, desc) in iter_notes(buf, view.is_le) {
            if let Some(os) = note_to_os(n_type, &name, &desc, view.is_le) {
                return Some(os);
            }
        }
    }
    None
}

// ── Heuristic 2: SHT_NOTE (section-header notes; kernel modules) ──
fn guess_os_from_sh_notes(view: &ElfView) -> Option<Os> {
    const SHT_NOTE: u32 = 7;
    for sh in &view.section_headers {
        if sh.sh_type != SHT_NOTE { continue; }
        let buf = sh.buf(view.data);
        for (n_type, name, desc) in iter_notes(buf, view.is_le) {
            if let Some(os) = note_to_os(n_type, &name, &desc, view.is_le) {
                return Some(os);
            }
        }
    }
    None
}

fn note_to_os(n_type: u32, name: &[u8], desc: &[u8], is_le: bool) -> Option<Os> {
    // Owner-name notes (SHT_NOTE typically; PT_NOTE only when n_type=1
    // per LSB 1.2). We accept both — modern toolchains generate either.
    match name {
        b"Linux"   => return Some(Os::Linux),
        b"OpenBSD" => return Some(Os::Openbsd),
        b"NetBSD"  => return Some(Os::Netbsd),
        b"FreeBSD" => return Some(Os::Freebsd),
        b"Android" => return Some(Os::Android),
        _ => {}
    }
    // GNU ABI tag (n_type=1 NT_GNU_ABI_TAG, name="GNU", desc[0..4] = os).
    if name == b"GNU" && n_type == 1 && desc.len() >= 4 {
        let abi = r32(desc, 0, is_le).unwrap_or(99);
        return match abi {
            0 => Some(Os::Linux),
            1 => Some(Os::Hurd),
            2 => Some(Os::Solaris),
            3 => Some(Os::Freebsd),
            4 => Some(Os::Netbsd),
            5 => Some(Os::Syllable),
            6 => Some(Os::Nacl),
            _ => None,
        };
    }
    None
}

// ── Helpers for sections ───────────────────────────────────────────

fn find_section_by_name<'a>(view: &'a ElfView, name: &[u8]) -> Option<&'a Shdr> {
    view.section_headers.iter().find(|s| s.name(&view.shstrtab) == name)
}

// ── Heuristic 3: PT_INTERP linker path ─────────────────────────────
fn read_interp(view: &ElfView) -> Option<String> {
    const PT_INTERP: u32 = 3;
    for ph in &view.program_headers {
        if ph.p_type != PT_INTERP { continue; }
        let start = ph.p_offset as usize;
        let end = start.saturating_add(ph.p_filesz as usize);
        if end > view.data.len() { continue; }
        let buf = &view.data[start..end];
        let s = read_cstr(buf, 0);
        if !s.is_empty() {
            return Some(String::from_utf8_lossy(s).into_owned());
        }
    }
    None
}

fn guess_os_from_linker(view: &ElfView) -> Option<Os> {
    let linker = read_interp(view)?;
    if linker.contains("ld-linux") || linker.contains("ld-musl") {
        // Android has its own linker path, but ld-musl appears on Alpine
        // (Linux). Distinguish Android by `/system/bin/linker` first.
        if linker.contains("linker") && (linker.starts_with("/system/") || linker.contains("/system/bin/")) {
            return Some(Os::Android);
        }
        return Some(Os::Linux);
    }
    if linker.starts_with("/system/bin/linker") || linker.contains("/system/bin/linker") {
        return Some(Os::Android);
    }
    if linker.contains("/lib/ld.so") || linker.ends_with("/ld.so") {
        // Hurd is the only real GNU userland that names its loader plain
        // `/lib/ld.so` without `ld-linux`. See capa's notes.
        return Some(Os::Hurd);
    }
    if linker.contains("ld-elf.so") {
        // FreeBSD: /libexec/ld-elf.so.1
        return Some(Os::Freebsd);
    }
    if linker.contains("ld.so.1") && linker.contains("openbsd") {
        return Some(Os::Openbsd);
    }
    None
}

// ── Heuristic 4 + 5: walk DT_NEEDED + scan .gnu.version_r ──────────

fn read_dynamic(view: &ElfView) -> (Vec<String>, Vec<String>) {
    // Returns (needed, glibc_versions). glibc_versions is the set of
    // version names referenced from DT_VERNEED entries (e.g. "GLIBC_2.2.5").
    let mut needed: Vec<String> = Vec::new();
    let mut versions: Vec<String> = Vec::new();

    let dyn_sec = view.section_headers.iter().find(|s| s.sh_type == 6);
    if let Some(dyn_sec) = dyn_sec {
        let dynstr = find_section_by_name(view, b".dynstr");
        if let Some(dynstr) = dynstr {
            let dynstr_buf = dynstr.buf(view.data);
            let dyn_buf = dyn_sec.buf(view.data);
            let entry_size: usize = if view.is_64 { 16 } else { 8 };
            let count = dyn_buf.len() / entry_size;
            for i in 0..count {
                let base = i * entry_size;
                let (tag, val) = if view.is_64 {
                    let t = r64(dyn_buf, base, view.is_le).unwrap_or(0);
                    let v = r64(dyn_buf, base + 8, view.is_le).unwrap_or(0);
                    (t, v)
                } else {
                    let t = r32(dyn_buf, base, view.is_le).unwrap_or(0) as u64;
                    let v = r32(dyn_buf, base + 4, view.is_le).unwrap_or(0) as u64;
                    (t, v)
                };
                if tag == 0 { break; } // DT_NULL
                if tag == 1 { // DT_NEEDED
                    let s = read_cstr(dynstr_buf, val as usize);
                    if !s.is_empty() {
                        needed.push(String::from_utf8_lossy(s).into_owned());
                    }
                }
            }
        }
    }

    // .gnu.version_r — DT_VERNEED, format Vernaux: u16 vna_hash @0x4
    // doesn't matter, we want vna_name @ 0x8 (u32 string offset into
    // verneed's strtab). The associated strtab is .dynstr (Verneed's
    // file string is at vn_file, but version names go through the
    // same .dynstr pool).
    let verneed_sec = find_section_by_name(view, b".gnu.version_r");
    let dynstr = find_section_by_name(view, b".dynstr");
    if let (Some(vn_sec), Some(dynstr)) = (verneed_sec, dynstr) {
        let dynstr_buf = dynstr.buf(view.data);
        let vn_buf = vn_sec.buf(view.data);
        let mut off = 0usize;
        // walk Verneed records (16 bytes each: u16 version, u16 cnt,
        // u32 file, u32 aux, u32 next).
        while off + 16 <= vn_buf.len() {
            let cnt = r16(vn_buf, off + 2, view.is_le).unwrap_or(0) as usize;
            let aux_off = r32(vn_buf, off + 8, view.is_le).unwrap_or(0) as usize;
            let next = r32(vn_buf, off + 12, view.is_le).unwrap_or(0) as usize;
            // walk Vernaux records (16 bytes each: u32 hash, u16 flags,
            // u16 other, u32 name, u32 next).
            let mut a_off = off + aux_off;
            for _ in 0..cnt {
                if a_off + 16 > vn_buf.len() { break; }
                let name_off = r32(vn_buf, a_off + 8, view.is_le).unwrap_or(0) as usize;
                let a_next = r32(vn_buf, a_off + 12, view.is_le).unwrap_or(0) as usize;
                let s = read_cstr(dynstr_buf, name_off);
                if !s.is_empty() {
                    versions.push(String::from_utf8_lossy(s).into_owned());
                }
                if a_next == 0 { break; }
                a_off += a_next;
            }
            if next == 0 { break; }
            off += next;
        }
    }

    (needed, versions)
}

fn guess_os_from_glibc_verneed(view: &ElfView, versions: &[String]) -> Option<Os> {
    let has_glibc = versions.iter().any(|v| v.starts_with("GLIBC"));
    if !has_glibc { return None; }
    // GLIBC runs on Linux + Hurd. Hurd is i386-only; everything else => Linux.
    // e_machine 0x03 = i386. In practice Hurd is rare enough we follow capa
    // and default to Linux even on i386 unless the linker path says otherwise.
    if view.e_machine != 0x03 {
        return Some(Os::Linux);
    }
    let linker = read_interp(view).unwrap_or_default();
    if linker.contains("ld-linux") {
        Some(Os::Linux)
    } else if linker.ends_with("/ld.so") || linker.contains("/lib/ld.so") {
        Some(Os::Hurd)
    } else {
        Some(Os::Linux)
    }
}

fn guess_os_from_needed(needed: &[String]) -> Option<Os> {
    for n in needed {
        if n.starts_with("libmachuser.so") || n.starts_with("libhurduser.so") {
            return Some(Os::Hurd);
        }
        if n.starts_with("libandroid.so") || n.starts_with("liblog.so") {
            return Some(Os::Android);
        }
    }
    None
}

// ── Heuristic 6: .comment .ident GCC string ────────────────────────
fn guess_os_from_ident(view: &ElfView) -> Option<Os> {
    let sec = find_section_by_name(view, b".comment")?;
    let buf = sec.buf(view.data);
    let s = String::from_utf8_lossy(buf);
    if !s.contains("GCC:") { return None; }
    if s.contains("Android") { return Some(Os::Android); }
    if s.contains("Debian") || s.contains("Ubuntu")
        || s.contains("Red Hat") || s.contains("Alpine") {
        return Some(Os::Linux);
    }
    None
}

// ── Heuristic 7: symtab keyword scan ───────────────────────────────
fn guess_os_from_symtab(view: &ElfView) -> Option<Os> {
    // Walk .symtab + .strtab for symbol names containing "linux" /
    // "/linux/". This is a low-confidence check (capa's #symtab).
    let symtab = view.section_headers.iter().find(|s| s.sh_type == 2)?; // SHT_SYMTAB
    let strtab_idx = symtab.sh_link as usize;
    if strtab_idx >= view.section_headers.len() { return None; }
    let strtab = &view.section_headers[strtab_idx];
    let str_buf = strtab.buf(view.data);
    let sym_buf = symtab.buf(view.data);
    let entsize: usize = if view.is_64 { 24 } else { 16 };
    let count = sym_buf.len() / entsize;
    for i in 1..count {
        let base = i * entsize;
        if base + entsize > sym_buf.len() { break; }
        let name_off = r32(sym_buf, base, view.is_le).unwrap_or(0) as usize;
        let name = read_cstr(str_buf, name_off);
        if name.is_empty() { continue; }
        // Avoid matching things like "linux_kernel_extension" — restrict
        // to whole-word "linux" or path "/linux/" segments.
        if matches_linux_keyword(name) {
            return Some(Os::Linux);
        }
    }
    None
}

fn matches_linux_keyword(name: &[u8]) -> bool {
    // Look for "/linux/" anywhere or for "linux" as a whole word.
    if find_subseq(name, b"/linux/").is_some() { return true; }
    if let Some(idx) = find_subseq(name, b"linux") {
        let before_ok = idx == 0 || !is_ident_byte(name[idx - 1]);
        let after = idx + 5;
        let after_ok = after >= name.len() || !is_ident_byte(name[after]);
        if before_ok && after_ok { return true; }
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() { return None; }
    let n = needle.len();
    for i in 0..=haystack.len() - n {
        if &haystack[i..i + n] == needle { return Some(i); }
    }
    None
}

// ── Heuristic 8: Go buildinfo ──────────────────────────────────────
//
// `.go.buildinfo` section starts with a 16-byte header:
//   - 14 bytes magic: "\xff Go buildinf:"
//   - 1 byte ptrsize (4 or 8)
//   - 1 byte flags (bit 0 = big-endian, bit 1 = inline strings)
//
// If has_inline_strings, the rest of the section contains
// varint-prefixed strings — including a "GOOS=<os>" k=v pair — which
// we brute-force-grep for.
//
// If !has_inline_strings (older Go), the next two pointers point to
// runtime.buildVersion and runtime.modinfo strings; we'd need to
// follow them through PT_LOAD segments. For v1 we cover the common
// inline case; the address-following path returns None.

const GO_BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";

fn extract_go_buildinfo<'a>(view: &'a ElfView<'a>) -> Option<&'a [u8]> {
    // Prefer .go.buildinfo section.
    if let Some(sec) = find_section_by_name(view, b".go.buildinfo") {
        let buf = sec.buf(view.data);
        if !buf.is_empty() { return Some(buf); }
    }
    // Fallback: scan PT_LOAD writable-but-not-exec segment (Go data segment).
    const PT_LOAD: u32 = 1;
    const PF_X: u32 = 1;
    const PF_W: u32 = 2;
    for ph in &view.program_headers {
        if ph.p_type != PT_LOAD { continue; }
        if (ph.p_flags & (PF_X | PF_W)) != PF_W { continue; }
        let start = ph.p_offset as usize;
        let end = start.saturating_add(ph.p_filesz as usize);
        if end > view.data.len() { continue; }
        let buf = &view.data[start..end];
        if find_subseq(buf, GO_BUILDINFO_MAGIC).is_some() {
            return Some(buf);
        }
    }
    None
}

fn is_go_binary(view: &ElfView) -> bool {
    if find_section_by_name(view, b".note.go.buildid").is_some() { return true; }
    if find_section_by_name(view, b".go.buildinfo").is_some() { return true; }
    // Also true when the buildinfo magic sits inside a data segment.
    extract_go_buildinfo(view).is_some()
}

fn guess_os_from_go_buildinfo(view: &ElfView) -> Option<Os> {
    let buf = extract_go_buildinfo(view)?;
    let magic_idx = find_subseq(buf, GO_BUILDINFO_MAGIC)?;

    // Brute-force scan for `GOOS=<name>` k=v pair (capa's path).
    // This is the common inline-strings case in Go ≥ 1.18 and works
    // for the older path too (modinfo blob lives in the same segment).
    let goos_map: &[(&[u8], Os)] = &[
        (b"GOOS=aix",       Os::Aix),
        (b"GOOS=android",   Os::Android),
        (b"GOOS=dragonfly", Os::Dragonflybsd),
        (b"GOOS=freebsd",   Os::Freebsd),
        (b"GOOS=hurd",      Os::Hurd),
        (b"GOOS=illumos",   Os::Illumos),
        (b"GOOS=linux",     Os::Linux),
        (b"GOOS=netbsd",    Os::Netbsd),
        (b"GOOS=openbsd",   Os::Openbsd),
        (b"GOOS=solaris",   Os::Solaris),
        (b"GOOS=zos",       Os::Zos),
    ];
    let _ = magic_idx; // (kept around for future psize/flags parsing)
    for (key, os) in goos_map {
        if find_subseq(buf, key).is_some() { return Some(*os); }
    }
    None
}

// ── Cascade ────────────────────────────────────────────────────────

/// Run all heuristics. Returns *every* guess — caller picks winner.
pub fn detect_elf_os_all(data: &[u8]) -> Vec<OsGuess> {
    let mut out: Vec<OsGuess> = Vec::new();
    let view = match parse_elf(data) {
        Some(v) => v,
        None => return out,
    };

    if let Some(os) = guess_os_from_ph_notes(&view) {
        out.push(OsGuess { os, source: OsHeuristic::PhNote });
    }
    if let Some(os) = guess_os_from_sh_notes(&view) {
        out.push(OsGuess { os, source: OsHeuristic::ShNote });
    }
    if let Some(os) = guess_os_from_linker(&view) {
        out.push(OsGuess { os, source: OsHeuristic::Linker });
    }

    let (needed, versions) = read_dynamic(&view);
    if let Some(os) = guess_os_from_glibc_verneed(&view, &versions) {
        out.push(OsGuess { os, source: OsHeuristic::GlibcVerneed });
    }
    if let Some(os) = guess_os_from_needed(&needed) {
        out.push(OsGuess { os, source: OsHeuristic::NeededDep });
    }
    if let Some(os) = guess_os_from_ident(&view) {
        out.push(OsGuess { os, source: OsHeuristic::IdentComment });
    }
    if let Some(os) = guess_os_from_symtab(&view) {
        out.push(OsGuess { os, source: OsHeuristic::Symtab });
    }
    if let Some(os) = guess_os_from_go_buildinfo(&view) {
        out.push(OsGuess { os, source: OsHeuristic::GoBuildinfo });
    }
    if let Some(os) = guess_os_from_osabi(&view) {
        out.push(OsGuess { os, source: OsHeuristic::OsabiByte });
    }

    out
}

/// Pick the highest-confidence guess. Returns None if nothing fired.
pub fn detect_elf_os(data: &[u8]) -> Option<OsGuess> {
    let mut all = detect_elf_os_all(data);
    if all.is_empty() { return None; }
    all.sort_by_key(|g| std::cmp::Reverse(g.source.confidence()));
    Some(all.into_iter().next().unwrap())
}

/// Best-effort language detection (Go for now; C is the trivial default
/// on ELF, so we don't tag it). Future: Rust (`__rust_alloc`), .NET, etc.
pub fn detect_elf_language(data: &[u8]) -> Option<&'static str> {
    let view = parse_elf(data)?;
    if is_go_binary(&view) { return Some("go"); }
    None
}

// ── Action entry point ─────────────────────────────────────────────

pub fn elf_os(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap elf-os <elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    if data.len() < 64 || &data[..4] != b"\x7FELF" {
        return format!("Not an ELF file: {target}");
    }

    let guesses = detect_elf_os_all(&data);
    let lang = detect_elf_language(&data);

    // Register the ELF binary node and stamp os/language attrs.
    let bin_id = format!("elf:{target}");
    let mut attrs: Vec<(&str, &str)> = vec![("path", target)];
    let winner_os: Option<&'static str> = guesses.iter()
        .max_by_key(|g| g.source.confidence())
        .map(|g| g.os.as_str());
    let winner_src: Option<&'static str> = guesses.iter()
        .max_by_key(|g| g.source.confidence())
        .map(|g| g.source.as_str());
    if let Some(os) = winner_os { attrs.push(("os", os)); }
    if let Some(src) = winner_src { attrs.push(("os_source", src)); }
    if let Some(l) = lang { attrs.push(("language", l)); }
    graph.ensure_typed_node(&bin_id, EntityKind::ElfBinary, &attrs);

    // Format report.
    let mut out = String::new();
    out.push_str(&format!("=== ELF OS Detection: {target} ===\n"));
    out.push_str(&format!("Heuristics fired: {}\n", guesses.len()));
    if let Some(os) = winner_os {
        out.push_str(&format!("Winner:           os={os}  (via {})\n",
            winner_src.unwrap_or("?")));
    } else {
        out.push_str("Winner:           (unknown)\n");
    }
    if let Some(l) = lang {
        out.push_str(&format!("Language:         {l}\n"));
    }
    out.push('\n');
    if guesses.is_empty() {
        out.push_str("(no heuristics fired)\n");
    } else {
        out.push_str("── All heuristics ──\n");
        let mut sorted = guesses.clone();
        sorted.sort_by_key(|g| std::cmp::Reverse(g.source.confidence()));
        for g in &sorted {
            out.push_str(&format!(
                "  [c={:>2}] {:<14} → {}\n",
                g.source.confidence(), g.source.as_str(), g.os.as_str()
            ));
        }
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal little-endian 64-bit ELF with the requested
    /// program headers and section headers laid out at the end of the file.
    /// Returns the constructed buffer.
    struct ElfBuilder {
        e_machine: u16,
        osabi: u8,
        program_headers: Vec<(u32, u32, Vec<u8>)>, // (p_type, p_flags, payload)
        sections: Vec<(String, u32, Vec<u8>)>,     // (name, sh_type, payload)
    }

    impl ElfBuilder {
        fn new() -> Self {
            Self {
                e_machine: 0x3E, // x86_64
                osabi: 0,
                program_headers: Vec::new(),
                sections: Vec::new(),
            }
        }
        fn ph(mut self, p_type: u32, p_flags: u32, payload: Vec<u8>) -> Self {
            self.program_headers.push((p_type, p_flags, payload));
            self
        }
        fn sec(mut self, name: &str, sh_type: u32, payload: Vec<u8>) -> Self {
            self.sections.push((name.to_string(), sh_type, payload));
            self
        }
        fn build(self) -> Vec<u8> {
            let ehdr_size = 64usize;
            let ph_entsize = 56usize;
            let sh_entsize = 64usize;

            let ph_num = self.program_headers.len();

            // Build .shstrtab content (always last section, plus we
            // need a leading empty string + an empty/null section first).
            let mut shstrtab: Vec<u8> = vec![0]; // index 0 = empty
            // null section first
            let mut all_sections: Vec<(String, u32, Vec<u8>)> = Vec::new();
            all_sections.push((String::new(), 0, Vec::new())); // SHT_NULL
            for s in &self.sections {
                all_sections.push(s.clone());
            }
            all_sections.push((".shstrtab".to_string(), 3 /* SHT_STRTAB */, Vec::new()));

            // Reserve name offsets.
            let mut name_offsets: Vec<u32> = Vec::with_capacity(all_sections.len());
            for (name, _, _) in &all_sections {
                if name.is_empty() {
                    name_offsets.push(0);
                } else {
                    let off = shstrtab.len() as u32;
                    name_offsets.push(off);
                    shstrtab.extend_from_slice(name.as_bytes());
                    shstrtab.push(0);
                }
            }
            // Set the actual shstrtab payload on the last section.
            let last_idx = all_sections.len() - 1;
            all_sections[last_idx].2 = shstrtab.clone();

            // Layout:
            //   [0 .. ehdr_size)               ELF header
            //   [ehdr_size .. ph_off + ph*phentsize) program headers
            //   then the program-header payloads
            //   then section payloads
            //   then section header table

            let ph_off = ehdr_size as u64;
            let mut cursor = ph_off as usize + ph_num * ph_entsize;

            // Place each ph's payload right after the ph table.
            let mut ph_payload_offsets: Vec<u64> = Vec::with_capacity(ph_num);
            for (_, _, payload) in &self.program_headers {
                ph_payload_offsets.push(cursor as u64);
                cursor += payload.len();
            }

            // Place section payloads.
            let mut sh_payload_offsets: Vec<u64> = Vec::with_capacity(all_sections.len());
            for (_, _, payload) in &all_sections {
                sh_payload_offsets.push(cursor as u64);
                cursor += payload.len();
            }

            let sh_off = cursor as u64;
            let total = cursor + all_sections.len() * sh_entsize;
            let mut buf = vec![0u8; total];

            // ELF header.
            buf[0..4].copy_from_slice(b"\x7FELF");
            buf[4] = 2; // EI_CLASS = 64-bit
            buf[5] = 1; // EI_DATA = little-endian
            buf[6] = 1; // EI_VERSION
            buf[7] = self.osabi;
            // e_type = 2 (Executable) at 0x10 (u16)
            buf[16..18].copy_from_slice(&2u16.to_le_bytes());
            buf[18..20].copy_from_slice(&self.e_machine.to_le_bytes());
            buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
            // e_entry @ 0x18 (8 bytes) = 0
            // e_phoff @ 0x20
            buf[32..40].copy_from_slice(&ph_off.to_le_bytes());
            // e_shoff @ 0x28
            buf[40..48].copy_from_slice(&sh_off.to_le_bytes());
            // e_flags @ 0x30
            // e_ehsize @ 0x34
            buf[52..54].copy_from_slice(&(ehdr_size as u16).to_le_bytes());
            // e_phentsize @ 0x36
            buf[54..56].copy_from_slice(&(ph_entsize as u16).to_le_bytes());
            // e_phnum @ 0x38
            buf[56..58].copy_from_slice(&(ph_num as u16).to_le_bytes());
            // e_shentsize @ 0x3a
            buf[58..60].copy_from_slice(&(sh_entsize as u16).to_le_bytes());
            // e_shnum @ 0x3c
            buf[60..62].copy_from_slice(&(all_sections.len() as u16).to_le_bytes());
            // e_shstrndx @ 0x3e — last section is .shstrtab
            buf[62..64].copy_from_slice(&((all_sections.len() - 1) as u16).to_le_bytes());

            // Program headers.
            for (i, (p_type, p_flags, payload)) in self.program_headers.iter().enumerate() {
                let base = ph_off as usize + i * ph_entsize;
                buf[base..base + 4].copy_from_slice(&p_type.to_le_bytes());
                buf[base + 4..base + 8].copy_from_slice(&p_flags.to_le_bytes());
                buf[base + 8..base + 16].copy_from_slice(&ph_payload_offsets[i].to_le_bytes());
                // p_vaddr, p_paddr left zero
                buf[base + 32..base + 40].copy_from_slice(&(payload.len() as u64).to_le_bytes()); // p_filesz
                buf[base + 40..base + 48].copy_from_slice(&(payload.len() as u64).to_le_bytes()); // p_memsz
                // payload at offset
                let off = ph_payload_offsets[i] as usize;
                buf[off..off + payload.len()].copy_from_slice(payload);
            }

            // Section payloads.
            for (i, (_, _, payload)) in all_sections.iter().enumerate() {
                if payload.is_empty() { continue; }
                let off = sh_payload_offsets[i] as usize;
                buf[off..off + payload.len()].copy_from_slice(payload);
            }

            // Section header table.
            for (i, (_, sh_type, payload)) in all_sections.iter().enumerate() {
                let base = sh_off as usize + i * sh_entsize;
                buf[base..base + 4].copy_from_slice(&name_offsets[i].to_le_bytes());
                buf[base + 4..base + 8].copy_from_slice(&sh_type.to_le_bytes());
                // sh_flags @ +8 u64 = 0
                // sh_addr @ +16 u64 = 0
                buf[base + 24..base + 32].copy_from_slice(&sh_payload_offsets[i].to_le_bytes());
                buf[base + 32..base + 40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
                // sh_link @ +40 u32 = 0
            }

            buf
        }
    }

    /// Build a PT_NOTE payload with one note (n_type=1, name="GNU",
    /// desc=u32 abi_tag + 12 padding bytes for kernel version).
    fn build_gnu_abi_note(abi: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        let name = b"GNU\0";
        let namesz: u32 = name.len() as u32;
        let descsz: u32 = 16;
        buf.extend_from_slice(&namesz.to_le_bytes());
        buf.extend_from_slice(&descsz.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes()); // n_type=1
        buf.extend_from_slice(name);
        // descsz = 16 bytes: abi_tag + kmajor + kminor + kpatch
        buf.extend_from_slice(&abi.to_le_bytes());
        buf.extend_from_slice(&[0u8; 12]);
        buf
    }

    #[test]
    fn pt_interp_linux_linker() {
        let interp = b"/lib64/ld-linux-x86-64.so.2\0".to_vec();
        let elf = ElfBuilder::new()
            .ph(3 /* PT_INTERP */, 0, interp)
            .build();
        let g = detect_elf_os(&elf).expect("should detect");
        assert_eq!(g.os, Os::Linux);
        assert_eq!(g.source, OsHeuristic::Linker);
    }

    #[test]
    fn pt_interp_android_linker() {
        let interp = b"/system/bin/linker64\0".to_vec();
        let elf = ElfBuilder::new()
            .ph(3 /* PT_INTERP */, 0, interp)
            .build();
        let g = detect_elf_os(&elf).expect("should detect");
        assert_eq!(g.os, Os::Android);
        assert_eq!(g.source, OsHeuristic::Linker);
    }

    #[test]
    fn pt_note_gnu_abi_tag_linux() {
        let elf = ElfBuilder::new()
            .ph(4 /* PT_NOTE */, 0, build_gnu_abi_note(0))
            .build();
        let g = detect_elf_os(&elf).expect("should detect");
        assert_eq!(g.os, Os::Linux);
        assert_eq!(g.source, OsHeuristic::PhNote);
    }

    #[test]
    fn needed_libandroid_so() {
        // Build a binary with .dynamic + .dynstr where DT_NEEDED points
        // to "libandroid.so". Tricky: we need the section's payload to
        // contain raw dynamic entries.
        //
        // Layout:
        //   .dynstr   = "\0libandroid.so\0"
        //   .dynamic  = [ (DT_NEEDED=1, val=1), (DT_NULL=0, 0) ]
        let dynstr: Vec<u8> = {
            let mut v = vec![0u8];
            v.extend_from_slice(b"libandroid.so");
            v.push(0);
            v
        };
        let mut dynamic: Vec<u8> = Vec::new();
        // 64-bit Elf64_Dyn = 16 bytes (i64 d_tag, u64 d_un).
        dynamic.extend_from_slice(&1u64.to_le_bytes()); // DT_NEEDED
        dynamic.extend_from_slice(&1u64.to_le_bytes()); // offset of "libandroid.so"
        dynamic.extend_from_slice(&0u64.to_le_bytes()); // DT_NULL
        dynamic.extend_from_slice(&0u64.to_le_bytes());
        let elf = ElfBuilder::new()
            .sec(".dynstr", 3, dynstr)
            .sec(".dynamic", 6, dynamic)
            .build();
        let g = detect_elf_os(&elf).expect("should detect");
        assert_eq!(g.os, Os::Android);
        assert_eq!(g.source, OsHeuristic::NeededDep);
    }

    #[test]
    fn go_buildinfo_linux() {
        // Build an ELF whose `.go.buildinfo` section contains the magic
        // followed by an inline "GOOS=linux" string.
        let mut payload: Vec<u8> = GO_BUILDINFO_MAGIC.to_vec();
        payload.push(8);    // psize = 8
        payload.push(0b10); // flags: inline strings, little-endian
        payload.extend_from_slice(&[0u8; 16]); // remainder of header
        payload.extend_from_slice(b"\x09GOOS=linux"); // varint-prefix
        let elf = ElfBuilder::new()
            .sec(".go.buildinfo", 1, payload)
            .build();
        let lang = detect_elf_language(&elf);
        assert_eq!(lang, Some("go"));
        let g = detect_elf_os(&elf).expect("should detect");
        assert_eq!(g.os, Os::Linux);
        assert_eq!(g.source, OsHeuristic::GoBuildinfo);
    }

    #[test]
    fn ident_comment_debian() {
        let comment = b"GCC: (Debian 12.2.0-14) 12.2.0\0".to_vec();
        let elf = ElfBuilder::new()
            .sec(".comment", 1 /* SHT_PROGBITS */, comment)
            .build();
        let g = detect_elf_os(&elf).expect("should detect");
        assert_eq!(g.os, Os::Linux);
        assert_eq!(g.source, OsHeuristic::IdentComment);
    }

    #[test]
    fn osabi_freebsd_byte() {
        let mut b = ElfBuilder::new();
        b.osabi = 9; // FreeBSD
        let elf = b.build();
        let g = detect_elf_os(&elf).expect("should detect");
        assert_eq!(g.os, Os::Freebsd);
        assert_eq!(g.source, OsHeuristic::OsabiByte);
    }

    #[test]
    fn no_heuristics_fire() {
        // Empty ELF — no PHs, no useful sections, osabi=0.
        let elf = ElfBuilder::new().build();
        assert!(detect_elf_os(&elf).is_none());
    }

    #[test]
    fn note_iteration_alignment() {
        // Two consecutive notes; ensures align4 cursor advance is right.
        let mut buf = Vec::new();
        buf.extend_from_slice(&build_gnu_abi_note(0));
        // Add a second junk note that we don't decode but mustn't crash.
        let trailing = build_gnu_abi_note(99);
        buf.extend_from_slice(&trailing);
        let elf = ElfBuilder::new().ph(4, 0, buf).build();
        let g = detect_elf_os(&elf).expect("should detect");
        assert_eq!(g.os, Os::Linux);
    }
}
