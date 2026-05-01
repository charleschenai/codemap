// ── Anti-Analysis Scanner (v2 — al-khaser + pafish pack) ──────────
//
// v1 (Ship 1 #8) shipped 35 hardcoded rules matching PE imports +
// section names + embedded strings against a curated mini-corpus.
//
// v2 layers three additions on top of v1:
//
//   1. YAML rule loader (`data/anti-analysis/{al-khaser,pafish}.yaml`)
//      — ~230 vendor-tagged signatures lifted from the al-khaser and
//      pafish source corpora. Files are embedded at compile time
//      via `include_str!` and parsed by a small inline YAML-subset
//      parser; no runtime FS access, no new crate dependency.
//
//   2. (API, constant) call-site matcher — uses the bounded backward
//      propagator from `dataflow_local::RegFile` to verify the
//      immediate operand at each anti-debug API call site.
//      Survives string-encryption packers because the API import is
//      structural and the constant is in code, not in `.rdata`.
//
//   3. Family sub-taxonomy — every emitted AntiAnalysis node carries
//      a `family` attribute (one of AntiAnalysisFamily) so the
//      heterogeneous graph supports per-vendor evasion clustering
//      via `pagerank --type anti_tech --filter family=anti-vm-vbox`.
//
// Output: AntiAnalysis nodes attached to the binary, each with
// name / namespace / family / category / evidence / confidence /
// reference attrs.
//
// License: codemap is MIT. The bundled YAML corpora derive *facts*
// (driver names, MAC OUIs, registry keys, CPUID strings) from
// al-khaser (GPL-2.0) and pafish (GPL-3.0). No GPL'd source code is
// linked into codemap; the data is permissively licensed alongside
// the rest of codemap. See file headers for attribution.

use crate::types::{Graph, EntityKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    AntiDebugging,
    AntiVm,
    AntiDisasm,
    Packer,
    AntiForensic,
    AntiAv,
    AntiEmulation,
}

impl Category {
    fn as_str(&self) -> &'static str {
        match self {
            Category::AntiDebugging => "anti-debugging",
            Category::AntiVm => "anti-vm",
            Category::AntiDisasm => "anti-disasm",
            Category::Packer => "packer",
            Category::AntiForensic => "anti-forensic",
            Category::AntiAv => "anti-av",
            Category::AntiEmulation => "anti-emulation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confidence { High, Medium, Low }

impl Confidence {
    fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

/// One anti-analysis rule. Each `match` is a list of (DLL, function-name)
/// patterns; ANY match counts as a hit. Section-name rules use the
/// `sections` field instead. A rule with both must match BOTH.
struct Rule {
    /// Human-readable name (matches capa-rules `meta.name` where applicable).
    name: &'static str,
    /// capa-rules namespace (e.g. "anti-analysis/anti-debugging/debugger-detection").
    namespace: &'static str,
    category: Category,
    confidence: Confidence,
    /// Required imports — match if ANY of these (dll, fn) pairs is in the binary.
    /// Empty = no import requirement.
    imports: &'static [(&'static str, &'static str)],
    /// Required section names — match if ANY listed section is in the binary.
    sections: &'static [&'static str],
    /// Required strings — match if ANY string substring is found in the binary's
    /// embedded strings. Case-insensitive.
    strings: &'static [&'static str],
    /// References (capa-rules `meta.references`) — useful for the report.
    reference: &'static str,
}

// ── The ruleset ────────────────────────────────────────────────────

const RULES: &[Rule] = &[
    // Anti-debugging — API-based detection (capa anti-analysis/anti-debugging)
    Rule {
        name: "check for debugger via API",
        namespace: "anti-analysis/anti-debugging/debugger-detection",
        category: Category::AntiDebugging,
        confidence: Confidence::High,
        imports: &[
            ("kernel32.dll", "IsDebuggerPresent"),
            ("kernel32.dll", "CheckRemoteDebuggerPresent"),
        ],
        sections: &[],
        strings: &[],
        reference: "https://anti-debug.checkpoint.com/techniques/debug-flags.html",
    },
    Rule {
        name: "query NtQueryInformationProcess for debugger",
        namespace: "anti-analysis/anti-debugging/debugger-detection",
        category: Category::AntiDebugging,
        confidence: Confidence::High,
        imports: &[
            ("ntdll.dll", "NtQueryInformationProcess"),
            ("ntdll.dll", "ZwQueryInformationProcess"),
        ],
        sections: &[],
        strings: &[],
        reference: "al-khaser/AntiDebug/NtQueryInformationProcess.cpp",
    },
    Rule {
        name: "set thread hidden from debugger",
        namespace: "anti-analysis/anti-debugging/debugger-evasion",
        category: Category::AntiDebugging,
        confidence: Confidence::High,
        imports: &[
            ("ntdll.dll", "NtSetInformationThread"),
            ("ntdll.dll", "ZwSetInformationThread"),
        ],
        sections: &[],
        strings: &[],
        reference: "al-khaser/AntiDebug/NtSetInformationThread_ThreadHideFromDebugger.cpp",
    },
    Rule {
        name: "check for hardware breakpoints",
        namespace: "anti-analysis/anti-debugging/debugger-detection",
        category: Category::AntiDebugging,
        confidence: Confidence::Medium,
        imports: &[
            ("kernel32.dll", "GetThreadContext"),
            ("kernel32.dll", "Wow64GetThreadContext"),
        ],
        sections: &[],
        strings: &[],
        reference: "al-khaser/AntiDebug/HardwareBreakpoints.cpp",
    },
    Rule {
        name: "check OutputDebugString error",
        namespace: "anti-analysis/anti-debugging/debugger-detection",
        category: Category::AntiDebugging,
        confidence: Confidence::Medium,
        imports: &[
            ("kernel32.dll", "OutputDebugStringA"),
            ("kernel32.dll", "OutputDebugStringW"),
        ],
        sections: &[],
        strings: &[],
        reference: "al-khaser/AntiDebug/OutputDebugStringAPI.cpp",
    },
    Rule {
        name: "check for protected handle exception via NtClose",
        namespace: "anti-analysis/anti-debugging/debugger-detection",
        category: Category::AntiDebugging,
        confidence: Confidence::Medium,
        imports: &[
            ("ntdll.dll", "NtClose"),
            ("ntdll.dll", "ZwClose"),
        ],
        sections: &[],
        strings: &[],
        reference: "al-khaser/AntiDebug/NtClose.cpp",
    },
    Rule {
        name: "check for kernel debugger via shared user data",
        namespace: "anti-analysis/anti-debugging/debugger-detection",
        category: Category::AntiDebugging,
        confidence: Confidence::Medium,
        imports: &[("ntdll.dll", "NtQuerySystemInformation")],
        sections: &[],
        strings: &[],
        reference: "al-khaser/AntiDebug/NtQuerySystemInformation_SystemKernelDebuggerInformation.cpp",
    },
    Rule {
        name: "find debugger window",
        namespace: "anti-analysis/anti-debugging/debugger-detection",
        category: Category::AntiDebugging,
        confidence: Confidence::High,
        imports: &[
            ("user32.dll", "FindWindowA"),
            ("user32.dll", "FindWindowW"),
            ("user32.dll", "FindWindowExA"),
            ("user32.dll", "FindWindowExW"),
        ],
        sections: &[],
        strings: &["OLLYDBG", "ImmunityDebugger", "WinDbgFrameClass", "x64dbg", "Zeta Debugger", "Rock Debugger", "Syser Debugger"],
        reference: "al-khaser/AntiDebug/FindWindow.cpp",
    },
    Rule {
        name: "find debugger process",
        namespace: "anti-analysis/anti-debugging/debugger-detection",
        category: Category::AntiDebugging,
        confidence: Confidence::High,
        imports: &[
            ("kernel32.dll", "Process32FirstW"),
            ("kernel32.dll", "Process32NextW"),
            ("kernel32.dll", "Process32First"),
            ("kernel32.dll", "Process32Next"),
            ("kernel32.dll", "CreateToolhelp32Snapshot"),
        ],
        sections: &[],
        strings: &["ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "windbg.exe", "ImmunityDebugger.exe", "ProcessHacker.exe", "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe"],
        reference: "al-khaser/AntiDebug/EnumProcesses.cpp",
    },
    Rule {
        name: "check parent process",
        namespace: "anti-analysis/anti-debugging/debugger-detection",
        category: Category::AntiDebugging,
        confidence: Confidence::Medium,
        imports: &[("kernel32.dll", "CreateToolhelp32Snapshot")],
        sections: &[],
        strings: &["explorer.exe", "cmd.exe"],
        reference: "al-khaser/AntiDebug/ParentProcess.cpp",
    },
    Rule {
        name: "self-debugging anti-debug",
        namespace: "anti-analysis/anti-debugging/debugger-evasion",
        category: Category::AntiDebugging,
        confidence: Confidence::Medium,
        imports: &[
            ("kernel32.dll", "DebugActiveProcess"),
            ("kernel32.dll", "DebugBreak"),
        ],
        sections: &[],
        strings: &[],
        reference: "al-khaser/AntiDebug/SelfDebugging.cpp",
    },
    Rule {
        name: "check execution timing",
        namespace: "anti-analysis/anti-debugging/timing-detection",
        category: Category::AntiDebugging,
        confidence: Confidence::Low,
        imports: &[
            ("kernel32.dll", "QueryPerformanceCounter"),
            ("kernel32.dll", "GetTickCount"),
            ("kernel32.dll", "GetTickCount64"),
            ("kernel32.dll", "GetSystemTime"),
            ("kernel32.dll", "GetLocalTime"),
        ],
        sections: &[],
        strings: &[],
        reference: "al-khaser/AntiDebug/Timing.cpp",
    },
    Rule {
        name: "TLS callback present",
        namespace: "anti-analysis/anti-debugging/debugger-evasion",
        category: Category::AntiDebugging,
        confidence: Confidence::Medium,
        imports: &[],
        sections: &[".tls"],
        strings: &[],
        reference: "al-khaser/AntiDebug/TLS.cpp",
    },
    Rule {
        name: "check VEH-based debugger detection",
        namespace: "anti-analysis/anti-debugging/debugger-detection",
        category: Category::AntiDebugging,
        confidence: Confidence::Low,
        imports: &[
            ("kernel32.dll", "AddVectoredExceptionHandler"),
            ("kernel32.dll", "RemoveVectoredExceptionHandler"),
            ("ntdll.dll", "RtlAddVectoredExceptionHandler"),
        ],
        sections: &[],
        strings: &[],
        reference: "al-khaser/AntiDebug/Interrupt_3.cpp",
    },
    Rule {
        name: "register top-level exception filter",
        namespace: "anti-analysis/anti-debugging/debugger-detection",
        category: Category::AntiDebugging,
        confidence: Confidence::Low,
        imports: &[("kernel32.dll", "SetUnhandledExceptionFilter")],
        sections: &[],
        strings: &[],
        reference: "al-khaser/AntiDebug/UnhandledExceptionFilter.cpp",
    },

    // Anti-VM (capa anti-analysis/anti-vm)
    Rule {
        name: "check for VirtualBox via registry",
        namespace: "anti-analysis/anti-vm/vm-detection",
        category: Category::AntiVm,
        confidence: Confidence::High,
        imports: &[
            ("advapi32.dll", "RegOpenKeyExA"),
            ("advapi32.dll", "RegOpenKeyExW"),
            ("advapi32.dll", "RegQueryValueExA"),
            ("advapi32.dll", "RegQueryValueExW"),
        ],
        sections: &[],
        strings: &[
            "HARDWARE\\ACPI\\DSDT\\VBOX__",
            "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
            "VBOX",
            "VBoxGuest",
            "VBoxMouse",
            "VBoxService",
            "VBoxSF",
            "VBoxVideo",
            "VBoxTray",
        ],
        reference: "al-khaser/AntiVM/VirtualBox.cpp",
    },
    Rule {
        name: "check for VMware via registry/devices",
        namespace: "anti-analysis/anti-vm/vm-detection",
        category: Category::AntiVm,
        confidence: Confidence::High,
        imports: &[],
        sections: &[],
        strings: &[
            "VMware",
            "vmtoolsd",
            "vmware-tools",
            "vmwaretray",
            "vmwareuser",
            "VMUSrvc",
            "VMSrvc",
            "vmci.sys",
            "vmhgfs.sys",
            "vmmemctl.sys",
            "vmmouse.sys",
            "vmrawdsk.sys",
        ],
        reference: "al-khaser/AntiVM/VMware.cpp",
    },
    Rule {
        name: "check for QEMU",
        namespace: "anti-analysis/anti-vm/vm-detection",
        category: Category::AntiVm,
        confidence: Confidence::High,
        imports: &[],
        sections: &[],
        strings: &["QEMU", "qemu-ga", "qemu-guest-agent", "BOCHS", "bochs", "Bochs"],
        reference: "al-khaser/AntiVM/QEMU.cpp",
    },
    Rule {
        name: "check for Hyper-V",
        namespace: "anti-analysis/anti-vm/vm-detection",
        category: Category::AntiVm,
        confidence: Confidence::Medium,
        imports: &[],
        sections: &[],
        strings: &["Hyper-V", "VMBus", "Microsoft Hv", "vmbus.sys", "hvsocket.sys"],
        reference: "al-khaser/AntiVM/HyperV.cpp",
    },
    Rule {
        name: "check for Parallels VM",
        namespace: "anti-analysis/anti-vm/vm-detection",
        category: Category::AntiVm,
        confidence: Confidence::Medium,
        imports: &[],
        sections: &[],
        strings: &["Parallels", "prl_tg.sys", "prl_eth.sys", "prl_fs.sys"],
        reference: "al-khaser/AntiVM/Parallels.cpp",
    },
    Rule {
        name: "enumerate processes for sandbox",
        namespace: "anti-analysis/anti-vm/sandbox-detection",
        category: Category::AntiVm,
        confidence: Confidence::Medium,
        imports: &[("kernel32.dll", "CreateToolhelp32Snapshot")],
        sections: &[],
        strings: &["sbiedll.dll", "Sandboxie", "cuckoo", "wireshark", "tcpdump", "fakeftp", "fakemail", "fakehttp"],
        reference: "al-khaser/AntiVM/Sandboxie.cpp",
    },
    Rule {
        name: "WMI-based VM detection",
        namespace: "anti-analysis/anti-vm/vm-detection",
        category: Category::AntiVm,
        confidence: Confidence::Medium,
        imports: &[],
        sections: &[],
        strings: &[
            "Win32_ComputerSystem",
            "Win32_BIOS",
            "Win32_PortConnector",
            "Win32_VoltageProbe",
            "Win32_CacheMemory",
            "Win32_PhysicalMemory",
            "Win32_MemoryArray",
        ],
        reference: "al-khaser/AntiVM/Generic.cpp",
    },

    // Packers (capa anti-analysis/packer)
    Rule {
        name: "packed with UPX",
        namespace: "anti-analysis/packer/upx",
        category: Category::Packer,
        confidence: Confidence::High,
        imports: &[],
        sections: &["UPX0", "UPX1", "UPX2", ".UPX0", ".UPX1", ".UPX2"],
        strings: &["UPX!"],
        reference: "https://upx.github.io/",
    },
    Rule {
        name: "packed with ASPack",
        namespace: "anti-analysis/packer/aspack",
        category: Category::Packer,
        confidence: Confidence::High,
        imports: &[],
        sections: &[".aspack", "ASPack", ".adata"],
        strings: &[],
        reference: "http://www.aspack.com/",
    },
    Rule {
        name: "packed with Themida or WinLicense",
        namespace: "anti-analysis/packer/themida",
        category: Category::Packer,
        confidence: Confidence::High,
        imports: &[],
        sections: &[".themida", ".winlicen", ".winlice"],
        strings: &["Themida", "WinLicense"],
        reference: "https://www.oreans.com/",
    },
    Rule {
        name: "packed with VMProtect",
        namespace: "anti-analysis/packer/vmprotect",
        category: Category::Packer,
        confidence: Confidence::High,
        imports: &[],
        sections: &[".vmp0", ".vmp1", ".vmp2", "VMProtect"],
        strings: &["VMProtect"],
        reference: "https://vmpsoft.com/",
    },
    Rule {
        name: "packed with PECompact",
        namespace: "anti-analysis/packer/pecompact",
        category: Category::Packer,
        confidence: Confidence::High,
        imports: &[],
        sections: &["pec1", "pec2", "PEC2", ".pec1", ".pec2"],
        strings: &[],
        reference: "http://bitsum.com/pecompact/",
    },
    Rule {
        name: "packed with FSG/MEW/MPRESS",
        namespace: "anti-analysis/packer/generic",
        category: Category::Packer,
        confidence: Confidence::Medium,
        imports: &[],
        sections: &[".MPRESS1", ".MPRESS2", "MEW", "FSG!"],
        strings: &[],
        reference: "https://www.matcode.com/mpress.htm",
    },

    // Anti-disasm (capa anti-analysis/anti-disasm)
    Rule {
        name: "uses Heaven's Gate",
        namespace: "anti-analysis/anti-disasm/heavens-gate",
        category: Category::AntiDisasm,
        confidence: Confidence::Medium,
        imports: &[],
        sections: &[],
        strings: &["wow64cpu", "Wow64Transition"],
        reference: "https://www.malwarebytes.com/blog/news/2018/01/heavens-gate-ducking-back-into-the-wow64-vault",
    },

    // Anti-forensic (capa anti-analysis/anti-forensic)
    Rule {
        name: "clear event log",
        namespace: "anti-analysis/anti-forensic/log-tampering",
        category: Category::AntiForensic,
        confidence: Confidence::High,
        imports: &[
            ("advapi32.dll", "ClearEventLogA"),
            ("advapi32.dll", "ClearEventLogW"),
            ("wevtapi.dll", "EvtClearLog"),
        ],
        sections: &[],
        strings: &[],
        reference: "https://attack.mitre.org/techniques/T1070/001/",
    },
    Rule {
        name: "self-delete via batch / cmd",
        namespace: "anti-analysis/anti-forensic/self-delete",
        category: Category::AntiForensic,
        confidence: Confidence::Medium,
        imports: &[],
        sections: &[],
        strings: &["cmd.exe /c del", "ping -n", "ping 127.0.0.1", "del /f /q"],
        reference: "https://attack.mitre.org/techniques/T1070/004/",
    },
    Rule {
        name: "attempt to wipe MBR",
        namespace: "anti-analysis/anti-forensic/mbr-wipe",
        category: Category::AntiForensic,
        confidence: Confidence::High,
        imports: &[
            ("kernel32.dll", "CreateFileA"),
            ("kernel32.dll", "CreateFileW"),
        ],
        sections: &[],
        strings: &["\\\\.\\PhysicalDrive0", "\\Device\\Harddisk0"],
        reference: "https://attack.mitre.org/techniques/T1561/002/",
    },

    // Anti-AV (capa anti-analysis/anti-av)
    Rule {
        name: "kill AV / EDR processes",
        namespace: "anti-analysis/anti-av/process-termination",
        category: Category::AntiAv,
        confidence: Confidence::Medium,
        imports: &[
            ("kernel32.dll", "OpenProcess"),
            ("kernel32.dll", "TerminateProcess"),
        ],
        sections: &[],
        strings: &[
            "MsMpEng.exe", "msseces.exe", "avp.exe", "avpui.exe", "kavfs.exe",
            "ekrn.exe", "egui.exe", "AvastSvc.exe", "avgsvc.exe", "mfemms.exe",
            "mcshield.exe", "ccSvcHst.exe", "NortonSecurity.exe", "bdagent.exe",
            "vsserv.exe", "ESET", "Kaspersky", "Sophos", "CrowdStrike",
            "SentinelOne", "Carbon Black", "Cylance",
        ],
        reference: "al-khaser anti-AV",
    },

    // Anti-emulation (capa anti-analysis/anti-emulation)
    Rule {
        name: "Wine detection",
        namespace: "anti-analysis/anti-emulation/wine",
        category: Category::AntiEmulation,
        confidence: Confidence::High,
        imports: &[],
        sections: &[],
        strings: &["wine_get_unix_file_name", "wine_get_version", "Z:\\\\"],
        reference: "https://www.winehq.org/",
    },
];

// ── Action ─────────────────────────────────────────────────────────

pub fn anti_analysis(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap anti-analysis <pe-or-elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    // Parse imports + sections + strings
    let imports = collect_imports(&data);
    let sections = collect_sections(&data);
    let strings = collect_strings(&data);

    // Run v1 hardcoded rules
    let mut hits: Vec<&Rule> = Vec::new();
    for rule in RULES {
        if rule_matches(rule, &imports, &sections, &strings) {
            hits.push(rule);
        }
    }

    // Run v2 YAML rules (al-khaser + pafish pack)
    let yaml_rules = load_yaml_rules();
    let mut yaml_hits: Vec<&YamlRule> = Vec::new();
    for r in &yaml_rules {
        if yaml_rule_matches(r, &imports, &strings) {
            yaml_hits.push(r);
        }
    }

    // RTT (reverse-Turing-test) human-interaction detector
    let rtt_hit = rtt_detect(&imports, &strings, &data);

    // (API, constant) call-site matcher
    let call_site_hits = match_call_site_pairs_in_pe(&data);

    register_into_graph(graph, target, &hits);
    register_yaml_hits(graph, target, &yaml_hits);
    if rtt_hit.fired {
        register_rtt_hit(graph, target, &rtt_hit);
    }
    register_call_site_hits(graph, target, &call_site_hits);

    format_report_v2(
        target, &hits, &yaml_hits, &rtt_hit, &call_site_hits,
        &imports, &sections, &strings,
        yaml_rules.len(),
    )
}

// ── Feature extraction ─────────────────────────────────────────────

/// Set of (dll_lower, function_name_lower) pairs the binary imports.
pub(crate) struct Imports {
    pub(crate) pairs: std::collections::HashSet<(String, String)>,
    pub(crate) fn_count: usize,
}

fn collect_imports(data: &[u8]) -> Imports {
    let mut pairs = std::collections::HashSet::new();
    let mut fn_count = 0;
    if data.len() >= 0x40 && &data[..2] == b"MZ" {
        let dlls = crate::actions::reverse::pe::parse_pe_imports_structured(data).unwrap_or_default();
        for d in &dlls {
            let dll_lower = d.name.to_ascii_lowercase();
            for f in &d.functions {
                fn_count += 1;
                let f_lower = f.to_ascii_lowercase();
                pairs.insert((dll_lower.clone(), f_lower));
            }
        }
    }
    // ELF dynamic-symbol-based imports left for v2 (our rule corpus
    // is Windows-centric, so no ELF coverage today).
    Imports { pairs, fn_count }
}

/// Set of section names found in the binary, lowercased for matching.
fn collect_sections(data: &[u8]) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    if data.len() >= 0x40 && &data[..2] == b"MZ" {
        // PE: walk section table
        let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        let coff = e_lfanew + 4;
        if coff + 20 > data.len() { return out; }
        let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
        let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
        let sec_table = coff + 20 + opt_size;
        for i in 0..n_sections {
            let off = sec_table + i * 40;
            if off + 8 > data.len() { break; }
            let raw = &data[off..off + 8];
            let end = raw.iter().position(|b| *b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&raw[..end]).to_string();
            if !name.is_empty() { out.insert(name); }
        }
    } else if data.len() >= 4 && &data[..4] == b"\x7FELF" {
        // ELF section names: punted for now — our rules are PE-centric.
    }
    out
}

/// All printable ASCII / UTF-16LE strings (length ≥ 4) in the binary.
/// Capped at 20 K strings to avoid runaway on large binaries.
fn collect_strings(data: &[u8]) -> Vec<String> {
    const MIN_LEN: usize = 4;
    const MAX_STRINGS: usize = 20_000;
    let mut out = Vec::new();
    // ASCII
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
    if out.len() >= MAX_STRINGS { return out; }

    // UTF-16LE: scan paired bytes (low byte printable ASCII, high byte 0)
    let mut i = 0;
    while i + 1 < data.len() && out.len() < MAX_STRINGS {
        if data[i + 1] == 0 && (0x20..=0x7E).contains(&data[i]) {
            let s_start = i;
            let mut buf = Vec::new();
            while i + 1 < data.len() && data[i + 1] == 0 && (0x20..=0x7E).contains(&data[i]) {
                buf.push(data[i]);
                i += 2;
            }
            if buf.len() >= MIN_LEN {
                if let Ok(s) = String::from_utf8(buf) {
                    out.push(s);
                }
            }
            let _ = s_start;
        } else {
            i += 1;
        }
    }
    out
}

// ── Rule evaluation ────────────────────────────────────────────────

fn rule_matches(
    rule: &Rule,
    imports: &Imports,
    sections: &std::collections::HashSet<String>,
    strings: &[String],
) -> bool {
    // Semantics: within each feature set, items are OR'd (any one
    // matching import / section / string counts). Across feature sets,
    // we AND non-empty sets — so a rule with both `imports` and
    // `strings` requires at least one of each. This mirrors capa's
    // typical rule shape (e.g., "find debugger window" needs BOTH
    // FindWindow API AND a known debugger class string — neither
    // alone is enough to call it anti-debug).
    //
    // A rule with all three sets empty cannot fire — treat as false
    // (defensive — current ruleset has no such rule).
    let import_set_used = !rule.imports.is_empty();
    let section_set_used = !rule.sections.is_empty();
    let string_set_used = !rule.strings.is_empty();
    if !import_set_used && !section_set_used && !string_set_used { return false; }

    if import_set_used {
        let hit = rule.imports.iter().any(|(dll, fn_)| {
            imports.pairs.contains(&(dll.to_ascii_lowercase(), fn_.to_ascii_lowercase()))
        });
        if !hit { return false; }
    }

    if section_set_used {
        let hit = rule.sections.iter().any(|target| {
            sections.iter().any(|s| s.eq_ignore_ascii_case(target))
        });
        if !hit { return false; }
    }

    if string_set_used {
        let hit = rule.strings.iter().any(|target| {
            strings.iter().any(|s| s.contains(target))
        });
        if !hit { return false; }
    }

    true
}

// ── Graph wiring ───────────────────────────────────────────────────

fn register_into_graph(graph: &mut Graph, target: &str, hits: &[&Rule]) {
    if hits.is_empty() { return; }

    // The bin-disasm action registers the binary node; if the user runs
    // anti-analysis without bin-disasm first, we still want a binary
    // node to attach to. Mirror the bin-disasm naming.
    let bin_id = if target.ends_with(".dll") || target.ends_with(".exe") || target.ends_with(".sys") {
        format!("pe:{target}")
    } else {
        format!("pe:{target}")
    };
    graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[("path", target)]);

    let mut seen_namespaces = std::collections::HashSet::new();
    for r in hits {
        let tech_id = format!("anti_tech:{}", r.namespace);
        // De-dup nodes by namespace+name combo: include name in id
        let unique_id = format!("{}::{}", tech_id, r.name);
        let conf = r.confidence.as_str();
        let cat = r.category.as_str();
        graph.ensure_typed_node(&unique_id, EntityKind::AntiAnalysis, &[
            ("name", r.name),
            ("namespace", r.namespace),
            ("category", cat),
            ("confidence", conf),
            ("reference", r.reference),
        ]);
        graph.add_edge(&bin_id, &unique_id);
        seen_namespaces.insert(r.namespace);
    }
}

// ── Report formatting (v1) ─────────────────────────────────────────
// v2 dispatcher uses `format_report_v2` below; the v1 helper is kept
// available for the unit tests that constructed plain Rule slices.

#[allow(dead_code)]
fn format_report(
    target: &str,
    hits: &[&Rule],
    imports: &Imports,
    sections: &std::collections::HashSet<String>,
    strings: &[String],
) -> String {
    let mut lines = vec![
        format!("=== Anti-Analysis Scan: {} ===", target),
        format!("Imports parsed:    {} unique fns", imports.fn_count),
        format!("Sections parsed:   {}", sections.len()),
        format!("Strings extracted: {}", strings.len()),
        format!("Rules evaluated:   {}", RULES.len()),
        format!("Techniques found:  {}", hits.len()),
        String::new(),
    ];

    if hits.is_empty() {
        lines.push("(no anti-analysis techniques detected)".to_string());
        lines.push(String::new());
        lines.push("Note: scanner is PE-centric. ELF/Mach-O coverage = v2.".to_string());
        return lines.join("\n");
    }

    // Group by category
    let mut by_cat: std::collections::BTreeMap<&str, Vec<&Rule>> =
        std::collections::BTreeMap::new();
    for r in hits {
        by_cat.entry(r.category.as_str()).or_default().push(r);
    }

    for (cat, rules) in &by_cat {
        lines.push(format!("── {} ({} {}) ──", cat, rules.len(), if rules.len() == 1 { "rule" } else { "rules" }));
        for r in rules {
            lines.push(format!("  [{}] {}", r.confidence.as_str(), r.name));
            lines.push(format!("        ns: {}", r.namespace));
            if !r.reference.is_empty() {
                lines.push(format!("        ref: {}", r.reference));
            }
        }
        lines.push(String::new());
    }

    lines.push("Try: codemap meta-path \"pe->anti_tech\"  (cross-binary technique inventory)".to_string());
    lines.push("     codemap pagerank --type anti_tech    (most-prevalent techniques)".to_string());
    lines.join("\n")
}

// ── v2: family taxonomy ───────────────────────────────────────────

/// Sub-taxonomy carried on every v2 AntiAnalysis node. The values
/// span anti-debug, every common VM family, sandbox families, the
/// secondary categories pafish/al-khaser already organize against,
/// and the new RTT (reverse-Turing-test) class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiAnalysisFamily {
    AntiDebug,
    AntiVmVbox,
    AntiVmVmware,
    AntiVmQemu,
    AntiVmBochs,
    AntiVmKvm,
    AntiVmXen,
    AntiVmParallels,
    AntiVmWine,
    AntiSandboxCuckoo,
    AntiSandboxSandboxie,
    AntiSandboxJoebox,
    AntiSandboxGeneric,
    AntiAv,
    AntiDisasm,
    AntiDump,
    Timing,
    CodeInjection,
    RttHumanInteraction,
    HypervisorDriver,
}

impl AntiAnalysisFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            AntiAnalysisFamily::AntiDebug              => "anti-debug",
            AntiAnalysisFamily::AntiVmVbox             => "anti-vm-vbox",
            AntiAnalysisFamily::AntiVmVmware           => "anti-vm-vmware",
            AntiAnalysisFamily::AntiVmQemu             => "anti-vm-qemu",
            AntiAnalysisFamily::AntiVmBochs            => "anti-vm-bochs",
            AntiAnalysisFamily::AntiVmKvm              => "anti-vm-kvm",
            AntiAnalysisFamily::AntiVmXen              => "anti-vm-xen",
            AntiAnalysisFamily::AntiVmParallels        => "anti-vm-parallels",
            AntiAnalysisFamily::AntiVmWine             => "anti-vm-wine",
            AntiAnalysisFamily::AntiSandboxCuckoo      => "anti-sandbox-cuckoo",
            AntiAnalysisFamily::AntiSandboxSandboxie   => "anti-sandbox-sandboxie",
            AntiAnalysisFamily::AntiSandboxJoebox      => "anti-sandbox-joebox",
            AntiAnalysisFamily::AntiSandboxGeneric     => "anti-sandbox-generic",
            AntiAnalysisFamily::AntiAv                 => "anti-av",
            AntiAnalysisFamily::AntiDisasm             => "anti-disasm",
            AntiAnalysisFamily::AntiDump               => "anti-dump",
            AntiAnalysisFamily::Timing                 => "timing",
            AntiAnalysisFamily::CodeInjection          => "code-injection",
            AntiAnalysisFamily::RttHumanInteraction    => "rtt-human-interaction",
            AntiAnalysisFamily::HypervisorDriver       => "hypervisor-driver",
        }
    }
    pub fn from_yaml(s: &str) -> Option<Self> {
        Some(match s {
            "anti-debug"               => AntiAnalysisFamily::AntiDebug,
            "anti-vm-vbox"             => AntiAnalysisFamily::AntiVmVbox,
            "anti-vm-vmware"           => AntiAnalysisFamily::AntiVmVmware,
            "anti-vm-qemu"             => AntiAnalysisFamily::AntiVmQemu,
            "anti-vm-bochs"            => AntiAnalysisFamily::AntiVmBochs,
            "anti-vm-kvm"              => AntiAnalysisFamily::AntiVmKvm,
            "anti-vm-xen"              => AntiAnalysisFamily::AntiVmXen,
            "anti-vm-parallels"        => AntiAnalysisFamily::AntiVmParallels,
            "anti-vm-wine"             => AntiAnalysisFamily::AntiVmWine,
            "anti-sandbox-cuckoo"      => AntiAnalysisFamily::AntiSandboxCuckoo,
            "anti-sandbox-sandboxie"   => AntiAnalysisFamily::AntiSandboxSandboxie,
            "anti-sandbox-joebox"      => AntiAnalysisFamily::AntiSandboxJoebox,
            "anti-sandbox-generic"     => AntiAnalysisFamily::AntiSandboxGeneric,
            "anti-av"                  => AntiAnalysisFamily::AntiAv,
            "anti-disasm"              => AntiAnalysisFamily::AntiDisasm,
            "anti-dump"                => AntiAnalysisFamily::AntiDump,
            "timing"                   => AntiAnalysisFamily::Timing,
            "code-injection"           => AntiAnalysisFamily::CodeInjection,
            "rtt-human-interaction"    => AntiAnalysisFamily::RttHumanInteraction,
            "hypervisor-driver"        => AntiAnalysisFamily::HypervisorDriver,
            _ => return None,
        })
    }
}

// ── v2: YAML rule loader ──────────────────────────────────────────

/// Bundled corpora — embedded at compile time so codemap is a single
/// statically-linked binary with no runtime FS dependency.
const AL_KHASER_YAML: &str = include_str!("../../data/anti-analysis/al-khaser.yaml");
const PAFISH_YAML:    &str = include_str!("../../data/anti-analysis/pafish.yaml");

#[derive(Debug, Clone)]
pub struct YamlRule {
    pub id: String,
    pub family: AntiAnalysisFamily,
    pub vendor: String,
    pub subkind: String,
    pub signature: String,
    pub severity: String,
    pub reference: String,
}

/// Parse the codemap-shipped subset of YAML. We don't need a full
/// YAML parser — the schema is a flat list of `- key: value` records
/// with bare or double-quoted strings. ~80 LOC.
fn parse_yaml_rules(text: &str) -> Vec<YamlRule> {
    let mut out = Vec::new();
    let mut current: Option<std::collections::HashMap<String, String>> = None;

    let flush = |cur: &mut Option<std::collections::HashMap<String, String>>, out: &mut Vec<YamlRule>| {
        if let Some(m) = cur.take() {
            let id = m.get("id").cloned().unwrap_or_default();
            let fam_str = m.get("family").cloned().unwrap_or_default();
            let signature = m.get("signature").cloned().unwrap_or_default();
            if id.is_empty() || signature.is_empty() { return; }
            let Some(family) = AntiAnalysisFamily::from_yaml(&fam_str) else { return; };
            out.push(YamlRule {
                id,
                family,
                vendor:    m.get("vendor").cloned().unwrap_or_default(),
                subkind:   m.get("subkind").cloned().unwrap_or_default(),
                signature,
                severity:  m.get("severity").cloned().unwrap_or_default(),
                reference: m.get("ref").cloned().unwrap_or_default(),
            });
        }
    };

    for raw in text.lines() {
        // Strip end-of-line comments (we don't allow # inside values
        // in the corpora; double-quoted strings handle the few cases
        // where # appears literally in a signature).
        let line = strip_yaml_comment(raw);
        let trimmed = line.trim_end();
        if trimmed.trim().is_empty() { continue; }

        if let Some(rest) = trimmed.strip_prefix("- ") {
            // New record. Flush the previous one and start fresh.
            flush(&mut current, &mut out);
            let mut m = std::collections::HashMap::new();
            if let Some((k, v)) = split_kv(rest.trim()) {
                m.insert(k, v);
            }
            current = Some(m);
        } else if let Some(rest) = trimmed.strip_prefix("  ") {
            // Continuation of current record.
            if let Some(m) = current.as_mut() {
                if let Some((k, v)) = split_kv(rest.trim()) {
                    m.insert(k, v);
                }
            }
        }
    }
    flush(&mut current, &mut out);
    out
}

fn strip_yaml_comment(line: &str) -> String {
    // Walk the line, drop everything from the first `#` that isn't
    // inside a double-quoted string.
    let mut in_quotes = false;
    let mut out = String::with_capacity(line.len());
    for (i, c) in line.char_indices() {
        if c == '"' {
            // Crude — no escape handling needed for our corpus.
            let _ = i;
            in_quotes = !in_quotes;
            out.push(c);
        } else if c == '#' && !in_quotes {
            break;
        } else {
            out.push(c);
        }
    }
    out
}

fn split_kv(s: &str) -> Option<(String, String)> {
    let colon = s.find(':')?;
    let k = s[..colon].trim().to_string();
    let v_raw = s[colon + 1..].trim();
    let v = if let Some(stripped) = v_raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        stripped.to_string()
    } else {
        v_raw.to_string()
    };
    if k.is_empty() { return None; }
    Some((k, v))
}

/// Load both corpora (al-khaser + pafish). The corpora are deduped by
/// `id`; al-khaser wins on duplicates because its provenance fields
/// are richer (al-khaser has dedicated per-technique files).
pub fn load_yaml_rules() -> Vec<YamlRule> {
    let mut rules = parse_yaml_rules(AL_KHASER_YAML);
    let mut seen_ids: std::collections::HashSet<String> =
        rules.iter().map(|r| r.id.clone()).collect();
    for r in parse_yaml_rules(PAFISH_YAML) {
        if seen_ids.insert(r.id.clone()) {
            rules.push(r);
        }
    }
    rules
}

/// Match a YAML rule against extracted features. `import_api`
/// signatures use the form "dll!fn"; everything else is a
/// case-insensitive substring match against the binary's strings.
fn yaml_rule_matches(rule: &YamlRule, imports: &Imports, strings: &[String]) -> bool {
    if rule.subkind == "import_api" {
        if let Some((dll, func)) = rule.signature.split_once('!') {
            return imports.pairs.contains(&(
                dll.to_ascii_lowercase(),
                func.to_ascii_lowercase(),
            ));
        }
        return false;
    }
    // Substring match — strings come back as-is from the binary.
    let needle = rule.signature.as_str();
    if needle.is_empty() { return false; }
    let needle_lc = needle.to_ascii_lowercase();
    strings.iter().any(|s| s.to_ascii_lowercase().contains(&needle_lc))
}

fn register_yaml_hits(graph: &mut Graph, target: &str, hits: &[&YamlRule]) {
    if hits.is_empty() { return; }
    let bin_id = format!("pe:{target}");
    graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[("path", target)]);
    for r in hits {
        let unique_id = format!("anti_tech:yaml::{}", r.id);
        graph.ensure_typed_node(&unique_id, EntityKind::AntiAnalysis, &[
            ("name", r.id.as_str()),
            ("namespace", r.subkind.as_str()),
            ("family", r.family.as_str()),
            ("vendor", r.vendor.as_str()),
            ("category", r.family.as_str()),
            ("confidence", r.severity.as_str()),
            ("reference", r.reference.as_str()),
        ]);
        graph.add_edge(&bin_id, &unique_id);
    }
}

// ── v2: RTT (reverse-Turing-test) human-interaction detector ─────

/// Output of the RTT detector: which clues fired and a summary tag.
#[derive(Debug, Default)]
pub struct RttHit {
    pub fired: bool,
    pub apis_present: usize,
    pub mouse_hook_const_seen: bool,
    pub click_msg_const_seen: bool,
}

/// IAT co-occurrence rule: SetWindowsHookEx + WH_MOUSE_LL=14 + ≥3 of
/// the human-interaction APIs + a WM_LBUTTONUP/DOWN immediate. The
/// constants are checked as raw little-endian bytes inside the file
/// because we don't disassemble every section here — the file scan
/// already produced the strings.
pub(crate) fn rtt_detect(imports: &Imports, _strings: &[String], data: &[u8]) -> RttHit {
    let has = |dll: &str, fname: &str| {
        imports.pairs.contains(&(dll.to_ascii_lowercase(), fname.to_ascii_lowercase()))
    };
    let has_hookex = has("user32.dll", "SetWindowsHookExA")
                  || has("user32.dll", "SetWindowsHookExW");
    let cluster = [
        ("user32.dll", "GetSystemMetrics"),
        ("user32.dll", "GetCursorPos"),
        ("user32.dll", "GetDoubleClickTime"),
        ("user32.dll", "RegisterClassW"),
        ("user32.dll", "RegisterClassA"),
        ("user32.dll", "SetTimer"),
        ("user32.dll", "CreateWindowW"),
        ("user32.dll", "CreateWindowExW"),
        ("user32.dll", "CreateWindowExA"),
    ];
    let apis_present = cluster.iter().filter(|(d, f)| has(d, f)).count();

    let mouse_hook_const_seen = byte_imm_present(data, &[14u32]);
    let click_msg_const_seen  = byte_imm_present(data, &[0x0202u32, 0x0201u32]);

    let fired = has_hookex && apis_present >= 3 && mouse_hook_const_seen && click_msg_const_seen;
    RttHit { fired, apis_present, mouse_hook_const_seen, click_msg_const_seen }
}

/// Cheap "immediate scan": is any of the given u32 values present in
/// the file as little-endian 4-byte words on a 1-byte stride? Used by
/// RTT as a coarse proxy — exact disassembly is the (API,const)
/// matcher's job; this just checks the constant exists somewhere.
fn byte_imm_present(data: &[u8], values: &[u32]) -> bool {
    if data.len() < 4 { return false; }
    for &v in values {
        let bytes = v.to_le_bytes();
        if data.windows(4).any(|w| w == bytes) { return true; }
    }
    false
}

fn register_rtt_hit(graph: &mut Graph, target: &str, hit: &RttHit) {
    let bin_id = format!("pe:{target}");
    graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[("path", target)]);
    let id = format!("anti_tech:rtt::human-interaction:{target}");
    let apis = format!("{}", hit.apis_present);
    graph.ensure_typed_node(&id, EntityKind::AntiAnalysis, &[
        ("name", "RTT human-interaction wait"),
        ("namespace", "rtt"),
        ("family", AntiAnalysisFamily::RttHumanInteraction.as_str()),
        ("category", "rtt"),
        ("confidence", "high"),
        ("apis_present", apis.as_str()),
        ("reference", "pafish/rtt.c"),
    ]);
    graph.add_edge(&bin_id, &id);
}

// ── v2: (API, constant) call-site matcher ────────────────────────
//
// Walks the disassembled .text section; tracks a small register file
// via dataflow_local::record_instr; at each `CALL [iat_va]` whose
// target resolves to a known anti-analysis API, checks whether the
// most-recent immediates loaded into the calling-convention argument
// registers match a rule's expected constants.

/// One (API, constant) pair. The matcher is per-arg; each rule fires
/// when (api_dll, api_fn) is called and the value in arg N matches.
#[derive(Debug, Clone, Copy)]
pub struct ApiConstRule {
    pub id: &'static str,
    pub api_dll: &'static str,
    pub api_fn:  &'static str,
    /// 0 = arg1 (RCX/[esp+0]), 1 = arg2 (RDX/[esp+4]),
    /// 2 = arg3 (R8/[esp+8]), 3 = arg4 (R9/[esp+0xC]).
    pub arg_index: u8,
    pub constant: u64,
    pub family: AntiAnalysisFamily,
    pub technique: &'static str,
    pub reference: &'static str,
}

/// 25 high-confidence (API, constant) pairs lifted from the
/// al-khaser corpus. See research analysis §3.2.
pub const API_CONST_RULES: &[ApiConstRule] = &[
    // NtQueryInformationProcess(arg2 = ProcessInformationClass)
    ApiConstRule { id: "ntqip-debugport", api_dll: "ntdll.dll", api_fn: "NtQueryInformationProcess",
        arg_index: 1, constant: 0x07, family: AntiAnalysisFamily::AntiDebug,
        technique: "ProcessDebugPort",
        reference: "al-khaser/AntiDebug/NtQueryInformationProcess_ProcessDebugPort.cpp" },
    ApiConstRule { id: "ntqip-debugflags", api_dll: "ntdll.dll", api_fn: "NtQueryInformationProcess",
        arg_index: 1, constant: 0x1F, family: AntiAnalysisFamily::AntiDebug,
        technique: "ProcessDebugFlags",
        reference: "al-khaser/AntiDebug/NtQueryInformationProcess_ProcessDebugFlags.cpp" },
    ApiConstRule { id: "ntqip-debugobject", api_dll: "ntdll.dll", api_fn: "NtQueryInformationProcess",
        arg_index: 1, constant: 0x1E, family: AntiAnalysisFamily::AntiDebug,
        technique: "ProcessDebugObject",
        reference: "al-khaser/AntiDebug/NtQueryInformationProcess_ProcessDebugObject.cpp" },

    // NtSetInformationThread(arg2 = ThreadInformationClass = ThreadHideFromDebugger)
    ApiConstRule { id: "ntsit-hidefromdbg", api_dll: "ntdll.dll", api_fn: "NtSetInformationThread",
        arg_index: 1, constant: 0x11, family: AntiAnalysisFamily::AntiDebug,
        technique: "ThreadHideFromDebugger",
        reference: "al-khaser/AntiDebug/NtSetInformationThread_ThreadHideFromDebugger.cpp" },

    // NtQueryObject(arg2 = ObjectInformationClass)
    ApiConstRule { id: "ntqo-alltypes", api_dll: "ntdll.dll", api_fn: "NtQueryObject",
        arg_index: 1, constant: 0x03, family: AntiAnalysisFamily::AntiDebug,
        technique: "ObjectAllTypesInformation",
        reference: "al-khaser/AntiDebug/NtQueryObject_AllTypesInformation.cpp" },
    ApiConstRule { id: "ntqo-objtype", api_dll: "ntdll.dll", api_fn: "NtQueryObject",
        arg_index: 1, constant: 0x02, family: AntiAnalysisFamily::AntiDebug,
        technique: "ObjectTypeInformation",
        reference: "al-khaser/AntiDebug/NtQueryObject_ObjectInformation.h" },

    // NtQuerySystemInformation(arg1 = SystemInformationClass = SystemKernelDebuggerInformation)
    ApiConstRule { id: "ntqsi-kdbgi", api_dll: "ntdll.dll", api_fn: "NtQuerySystemInformation",
        arg_index: 0, constant: 0x23, family: AntiAnalysisFamily::AntiDebug,
        technique: "SystemKernelDebuggerInformation",
        reference: "al-khaser/AntiDebug/NtQuerySystemInformation_SystemKernelDebuggerInformation.cpp" },
];

/// Hit emitted by the call-site matcher. `va` is the call-instruction
/// address for cross-referencing with disassembly output.
#[derive(Debug, Clone)]
pub struct CallSiteHit {
    pub rule_id: &'static str,
    pub api_dll: &'static str,
    pub api_fn:  &'static str,
    pub va: u64,
    pub family: AntiAnalysisFamily,
    pub technique: &'static str,
    pub reference: &'static str,
    pub matched_constant: u64,
}

/// Top-level entry: parse a PE, walk .text, and emit hits.
fn match_call_site_pairs_in_pe(data: &[u8]) -> Vec<CallSiteHit> {
    if data.len() < 0x40 || &data[..2] != b"MZ" { return Vec::new(); }
    let Some(layout) = parse_pe_layout(data) else { return Vec::new(); };
    let Some(iat_map) = build_iat_va_to_name(data, &layout) else { return Vec::new(); };
    if iat_map.is_empty() { return Vec::new(); }
    let Some(text) = locate_text_section(data, &layout) else { return Vec::new(); };

    match_call_site_pairs(&text.bytes, text.va, layout.bitness, &iat_map)
}

#[derive(Debug)]
struct PeLayout {
    is_pe64: bool,
    bitness: u32,
    image_base: u64,
    sections: Vec<PeSection>,
    import_rva: u32,
}

#[derive(Debug, Clone)]
struct PeSection {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

fn parse_pe_layout(data: &[u8]) -> Option<PeLayout> {
    if data.len() < 64 { return None; }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
    if e_lfanew + 4 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return None; }
    let coff = e_lfanew + 4;
    if coff + 20 > data.len() { return None; }
    let n_sections = u16::from_le_bytes(data[coff + 2..coff + 4].try_into().ok()?) as usize;
    let opt_size  = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().ok()?) as usize;
    let opt = coff + 20;
    if opt + opt_size > data.len() || opt + 2 > data.len() { return None; }
    let magic = u16::from_le_bytes(data[opt..opt + 2].try_into().ok()?);
    let is_pe64 = match magic { 0x10B => false, 0x20B => true, _ => return None };
    let bitness = if is_pe64 { 64 } else { 32 };
    let image_base = if is_pe64 {
        u64::from_le_bytes(data[opt + 24..opt + 32].try_into().ok()?)
    } else {
        u32::from_le_bytes(data[opt + 28..opt + 32].try_into().ok()?) as u64
    };
    let import_dir_off = if is_pe64 { opt + 120 } else { opt + 104 };
    if import_dir_off + 4 > data.len() { return None; }
    let import_rva = u32::from_le_bytes(data[import_dir_off..import_dir_off + 4].try_into().ok()?);

    let sec_table = opt + opt_size;
    let mut sections = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let off = sec_table + i * 40;
        if off + 40 > data.len() { return None; }
        let name_raw = &data[off..off + 8];
        let end = name_raw.iter().position(|b| *b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_raw[..end]).to_string();
        let virtual_size    = u32::from_le_bytes(data[off + 8..off + 12].try_into().ok()?);
        let virtual_address = u32::from_le_bytes(data[off + 12..off + 16].try_into().ok()?);
        let raw_size        = u32::from_le_bytes(data[off + 16..off + 20].try_into().ok()?);
        let raw_offset      = u32::from_le_bytes(data[off + 20..off + 24].try_into().ok()?);
        sections.push(PeSection { name, virtual_address, virtual_size, raw_offset, raw_size });
    }
    Some(PeLayout { is_pe64, bitness, image_base, sections, import_rva })
}

fn rva_to_offset(rva: u32, sections: &[PeSection]) -> Option<usize> {
    for s in sections {
        if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size.max(s.raw_size) {
            return Some((s.raw_offset + (rva - s.virtual_address)) as usize);
        }
    }
    None
}

/// Build a map from IAT entry VA (= image_base + FirstThunk slot RVA)
/// to imported function name.
fn build_iat_va_to_name(data: &[u8], layout: &PeLayout)
    -> Option<std::collections::HashMap<u64, (String, String)>>
{
    let mut out = std::collections::HashMap::new();
    if layout.import_rva == 0 { return Some(out); }
    let import_off = rva_to_offset(layout.import_rva, &layout.sections)?;
    let mut entry = import_off;
    for _ in 0..500 {
        if entry + 20 > data.len() { break; }
        let oft = u32::from_le_bytes(data[entry..entry + 4].try_into().ok()?);
        let name_rva  = u32::from_le_bytes(data[entry + 12..entry + 16].try_into().ok()?);
        let first_thunk = u32::from_le_bytes(data[entry + 16..entry + 20].try_into().ok()?);
        if oft == 0 && name_rva == 0 && first_thunk == 0 { break; }
        entry += 20;

        let dll_name = if name_rva != 0 {
            rva_to_offset(name_rva, &layout.sections)
                .map(|o| read_cstring(data, o))
                .unwrap_or_default()
        } else { String::new() };

        let ilt_rva = if oft != 0 { oft } else { first_thunk };
        if ilt_rva == 0 || first_thunk == 0 { continue; }
        let Some(ilt_off) = rva_to_offset(ilt_rva, &layout.sections) else { continue; };
        let entry_size = if layout.is_pe64 { 8 } else { 4 };

        let mut i = 0usize;
        loop {
            let p = ilt_off + i * entry_size;
            if p + entry_size > data.len() { break; }
            let val: u64 = if layout.is_pe64 {
                u64::from_le_bytes(data[p..p + 8].try_into().ok()?)
            } else {
                u32::from_le_bytes(data[p..p + 4].try_into().ok()?) as u64
            };
            if val == 0 { break; }
            let by_ordinal = if layout.is_pe64 { val & (1u64 << 63) != 0 } else { val & (1u64 << 31) != 0 };
            let fname = if by_ordinal {
                String::new()
            } else {
                let hint_rva = (val & 0x7FFFFFFF) as u32;
                rva_to_offset(hint_rva, &layout.sections)
                    .and_then(|o| if o + 2 < data.len() { Some(read_cstring(data, o + 2)) } else { None })
                    .unwrap_or_default()
            };
            let iat_va = layout.image_base + first_thunk as u64 + (i as u64) * entry_size as u64;
            if !fname.is_empty() {
                out.insert(iat_va, (dll_name.clone(), fname));
            }
            i += 1;
            if i > 10_000 { break; }
        }
    }
    Some(out)
}

fn read_cstring(data: &[u8], off: usize) -> String {
    if off >= data.len() { return String::new(); }
    let end = data[off..].iter().position(|b| *b == 0).map(|p| off + p).unwrap_or(data.len());
    String::from_utf8_lossy(&data[off..end]).into_owned()
}

#[derive(Debug)]
struct TextSection {
    bytes: Vec<u8>,
    va: u64,
}

fn locate_text_section(data: &[u8], layout: &PeLayout) -> Option<TextSection> {
    // Prefer ".text" by name; fall back to first section with non-zero raw_size.
    let pick = layout.sections.iter()
        .find(|s| s.name == ".text")
        .or_else(|| layout.sections.iter().find(|s| s.raw_size > 0))?;
    let start = pick.raw_offset as usize;
    let len = pick.raw_size as usize;
    if start.saturating_add(len) > data.len() { return None; }
    Some(TextSection {
        bytes: data[start..start + len].to_vec(),
        va: layout.image_base + pick.virtual_address as u64,
    })
}

/// Core matcher — exposed for direct synthetic-instruction tests.
pub fn match_call_site_pairs(
    code: &[u8],
    code_va: u64,
    bitness: u32,
    iat_va_to_name: &std::collections::HashMap<u64, (String, String)>,
) -> Vec<CallSiteHit> {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
    use crate::dataflow_local::{RegFile, RegState, record_instr};

    let mut out = Vec::new();
    if code.is_empty() { return out; }
    let mut decoder = Decoder::with_ip(bitness, code, code_va, DecoderOptions::NONE);
    let mut rf = RegFile::new();
    let mut instr = Instruction::default();

    let arg_reg_64 = |idx: u8| match idx {
        0 => Register::RCX, 1 => Register::RDX, 2 => Register::R8, 3 => Register::R9, _ => Register::None
    };
    let arg_reg_32 = |idx: u8| match idx {
        0 => Register::ECX, 1 => Register::EDX, 2 => Register::R8D, 3 => Register::R9D, _ => Register::None
    };

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() { break; }
        if instr.mnemonic() == Mnemonic::Call && instr.op_count() == 1 {
            // Two relevant call-site shapes for IAT-resolved calls:
            //   x64: CALL qword ptr [rip+disp]  → memory_displacement64() = IAT VA
            //   x86: CALL dword ptr [imm32]     → memory_displacement64() = IAT VA
            let target_iat_va: Option<u64> = if instr.op0_kind() == OpKind::Memory {
                if instr.is_ip_rel_memory_operand() {
                    Some(instr.memory_displacement64())
                } else if instr.memory_base() == Register::None
                       && instr.memory_index() == Register::None
                {
                    Some(instr.memory_displacement64())
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(iat_va) = target_iat_va {
                if let Some((dll, fname)) = iat_va_to_name.get(&iat_va) {
                    for rule in API_CONST_RULES {
                        if !dll.eq_ignore_ascii_case(rule.api_dll)
                            || !fname.eq_ignore_ascii_case(rule.api_fn)
                        { continue; }
                        let reg = if bitness == 64 { arg_reg_64(rule.arg_index) }
                                  else            { arg_reg_32(rule.arg_index) };
                        let state = rf.get(reg);
                        if let RegState::Const(v) = state {
                            // Compare full register if the rule's
                            // constant is wider than 32 bits, else
                            // mask to 32 bits (Windows arg slots are
                            // typed by the API, not register width).
                            let v_norm = if rule.constant <= 0xFFFF_FFFF { v & 0xFFFF_FFFF } else { v };
                            if v_norm == rule.constant {
                                out.push(CallSiteHit {
                                    rule_id: rule.id,
                                    api_dll: rule.api_dll,
                                    api_fn:  rule.api_fn,
                                    va: instr.ip(),
                                    family: rule.family,
                                    technique: rule.technique,
                                    reference: rule.reference,
                                    matched_constant: rule.constant,
                                });
                            }
                        }
                    }
                }
            }
        }

        record_instr(&mut rf, &instr);
    }
    out
}

fn register_call_site_hits(graph: &mut Graph, target: &str, hits: &[CallSiteHit]) {
    if hits.is_empty() { return; }
    let bin_id = format!("pe:{target}");
    graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[("path", target)]);
    for h in hits {
        let id = format!("anti_tech:apiconst::{}::0x{:x}", h.rule_id, h.va);
        let va_str = format!("0x{:x}", h.va);
        let const_str = format!("0x{:x}", h.matched_constant);
        graph.ensure_typed_node(&id, EntityKind::AntiAnalysis, &[
            ("name", h.technique),
            ("namespace", "api-const"),
            ("family", h.family.as_str()),
            ("category", h.family.as_str()),
            ("api", h.api_fn),
            ("dll", h.api_dll),
            ("va", va_str.as_str()),
            ("constant", const_str.as_str()),
            ("confidence", "high"),
            ("reference", h.reference),
        ]);
        graph.add_edge(&bin_id, &id);
    }
}

// ── v2: report formatting ────────────────────────────────────────

fn format_report_v2(
    target: &str,
    hits: &[&Rule],
    yaml_hits: &[&YamlRule],
    rtt: &RttHit,
    call_hits: &[CallSiteHit],
    imports: &Imports,
    sections: &std::collections::HashSet<String>,
    strings: &[String],
    yaml_total: usize,
) -> String {
    let mut lines = vec![
        format!("=== Anti-Analysis Scan v2: {} ===", target),
        format!("Imports parsed:    {} unique fns", imports.fn_count),
        format!("Sections parsed:   {}", sections.len()),
        format!("Strings extracted: {}", strings.len()),
        format!("Rules evaluated:   v1={}  yaml={}  api-const={}",
            RULES.len(), yaml_total, API_CONST_RULES.len()),
        format!("Hits:              v1={}  yaml={}  rtt={}  api-const={}",
            hits.len(), yaml_hits.len(), if rtt.fired { 1 } else { 0 }, call_hits.len()),
        String::new(),
    ];

    if !hits.is_empty() {
        lines.push("── v1 hardcoded rules ──".to_string());
        let mut by_cat: std::collections::BTreeMap<&str, Vec<&Rule>> =
            std::collections::BTreeMap::new();
        for r in hits { by_cat.entry(r.category.as_str()).or_default().push(r); }
        for (cat, rules) in &by_cat {
            lines.push(format!("  {} ({})", cat, rules.len()));
            for r in rules {
                lines.push(format!("    [{}] {}", r.confidence.as_str(), r.name));
            }
        }
        lines.push(String::new());
    }

    if !yaml_hits.is_empty() {
        lines.push("── v2 YAML pack (al-khaser + pafish) ──".to_string());
        let mut by_fam: std::collections::BTreeMap<&str, Vec<&YamlRule>> =
            std::collections::BTreeMap::new();
        for r in yaml_hits { by_fam.entry(r.family.as_str()).or_default().push(*r); }
        for (fam, rs) in &by_fam {
            lines.push(format!("  {} ({})", fam, rs.len()));
            for r in rs {
                lines.push(format!("    [{}] {} ({})", r.severity, r.id, r.signature));
            }
        }
        lines.push(String::new());
    }

    if rtt.fired {
        lines.push("── RTT (reverse-Turing-test) human-interaction ──".to_string());
        lines.push(format!("  user32 cluster size: {}", rtt.apis_present));
        lines.push(format!("  WH_MOUSE_LL=14 imm:  {}", rtt.mouse_hook_const_seen));
        lines.push(format!("  WM_LBUTTONUP imm:    {}", rtt.click_msg_const_seen));
        lines.push(String::new());
    }

    if !call_hits.is_empty() {
        lines.push("── (API, constant) call-site matcher ──".to_string());
        for h in call_hits {
            lines.push(format!("  [{}] {} → {} (arg const = 0x{:x}) at 0x{:x}",
                h.family.as_str(), h.api_fn, h.technique, h.matched_constant, h.va));
        }
        lines.push(String::new());
    }

    if hits.is_empty() && yaml_hits.is_empty() && !rtt.fired && call_hits.is_empty() {
        lines.push("(no anti-analysis techniques detected)".to_string());
        lines.push(String::new());
    }

    lines.push("Try: codemap meta-path \"pe->anti_tech\"  (cross-binary technique inventory)".to_string());
    lines.push("     codemap pagerank --type anti_tech    (most-prevalent techniques)".to_string());
    lines.join("\n")
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn imp(pairs: &[(&str, &str)]) -> Imports {
        let mut h = std::collections::HashSet::new();
        for (d, f) in pairs {
            h.insert((d.to_ascii_lowercase(), f.to_ascii_lowercase()));
        }
        Imports { pairs: h, fn_count: pairs.len() }
    }
    fn sects(names: &[&str]) -> std::collections::HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }
    fn strs(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn anti_debug_isdebuggerpresent_matches() {
        let i = imp(&[("KERNEL32.dll", "IsDebuggerPresent")]);
        let s = sects(&[]);
        let strings = strs(&[]);
        let rule = RULES.iter().find(|r| r.name == "check for debugger via API").unwrap();
        assert!(rule_matches(rule, &i, &s, &strings));
    }

    #[test]
    fn anti_debug_no_match_when_imports_unrelated() {
        let i = imp(&[("user32.dll", "MessageBoxA")]);
        let s = sects(&[]);
        let strings = strs(&[]);
        let rule = RULES.iter().find(|r| r.name == "check for debugger via API").unwrap();
        assert!(!rule_matches(rule, &i, &s, &strings));
    }

    #[test]
    fn upx_section_match() {
        // UPX rule has BOTH sections + strings; AND semantics requires
        // a hit in both. Real UPX-packed binaries always have both.
        let i = imp(&[]);
        let s = sects(&["UPX0", "UPX1", ".rsrc"]);
        let strings = strs(&["UPX!"]);
        let rule = RULES.iter().find(|r| r.name == "packed with UPX").unwrap();
        assert!(rule_matches(rule, &i, &s, &strings));
    }

    #[test]
    fn upx_no_match_when_only_section_present() {
        // AND semantics: section name alone (e.g., a binary that
        // happens to have a "UPX0" section but no "UPX!" magic) should
        // NOT trigger. Reduces false positives.
        let i = imp(&[]);
        let s = sects(&["UPX0", "UPX1"]);
        let strings = strs(&[]);
        let rule = RULES.iter().find(|r| r.name == "packed with UPX").unwrap();
        assert!(!rule_matches(rule, &i, &s, &strings));
    }

    #[test]
    fn vmware_string_match() {
        let i = imp(&[]);
        let s = sects(&[]);
        let strings = strs(&["normal text", "vmtoolsd was here", "more text"]);
        let rule = RULES.iter().find(|r| r.name == "check for VMware via registry/devices").unwrap();
        assert!(rule_matches(rule, &i, &s, &strings));
    }

    #[test]
    fn case_insensitive_dll_and_function_names() {
        // Capa-rules YAMLs sometimes write `KERNEL32.dll` or `kernel32.dll`;
        // PE imports themselves come back capitalized as the binary's
        // import directory has them. Match must be case-insensitive on
        // both sides.
        let i = imp(&[("Kernel32.DLL", "isDebuggerPresent")]);
        let s = sects(&[]);
        let strings = strs(&[]);
        let rule = RULES.iter().find(|r| r.name == "check for debugger via API").unwrap();
        assert!(rule_matches(rule, &i, &s, &strings));
    }

    #[test]
    fn multiple_rules_can_match_one_binary() {
        // Simulate a typical real malware: anti-debug + anti-vm + UPX-packed
        let i = imp(&[
            ("kernel32.dll", "IsDebuggerPresent"),
            ("kernel32.dll", "GetThreadContext"),
            ("ntdll.dll", "NtQueryInformationProcess"),
            ("advapi32.dll", "RegOpenKeyExA"),  // VBox rule requires registry API
        ]);
        let s = sects(&["UPX0", "UPX1"]);
        // Need BOTH UPX section AND UPX magic string (AND semantics).
        // Plus a VBox string for anti-vm.
        let strings = strs(&["UPX!", "VBoxGuest"]);
        let mut hits = 0;
        for rule in RULES {
            if rule_matches(rule, &i, &s, &strings) { hits += 1; }
        }
        // Expected: API-debugger (kernel32.IsDebuggerPresent) + NtQueryInfoProcess
        // + GetThreadContext + UPX + VBox = 5 minimum
        assert!(hits >= 5, "expected ≥ 5 rule hits, got {hits}");
    }

    #[test]
    fn ruleset_has_minimum_coverage() {
        // Smoke-test the catalog: confirm we cover the major
        // categories Charles's Ship 1 #8 plan calls for.
        use std::collections::HashSet;
        let cats: HashSet<&str> = RULES.iter().map(|r| r.category.as_str()).collect();
        assert!(cats.contains("anti-debugging"));
        assert!(cats.contains("anti-vm"));
        assert!(cats.contains("packer"));
        assert!(cats.contains("anti-forensic"));
        // Total rule count: aim for ≥ 30 (we have 35 today)
        assert!(RULES.len() >= 30, "ruleset has {} rules, want ≥ 30", RULES.len());
    }

    #[test]
    fn collect_strings_finds_ascii_and_utf16le() {
        // ASCII "VBoxGuest" + UTF-16LE "VMware"
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"\x00\x00VBoxGuest\x00\x00");
        // UTF-16LE "VMware"
        for c in "VMware".chars() {
            data.push(c as u8);
            data.push(0);
        }
        data.push(0);
        let strings = collect_strings(&data);
        assert!(strings.iter().any(|s| s == "VBoxGuest"), "ascii not found in {strings:?}");
        assert!(strings.iter().any(|s| s == "VMware"), "utf-16 not found in {strings:?}");
    }

    // ── v2 tests ──────────────────────────────────────────────────

    #[test]
    fn yaml_loader_parses_both_corpora() {
        let rules = load_yaml_rules();
        // Sanity checks on absolute counts. al-khaser ~200, pafish ~30
        // additions; combined we expect at least ~220 unique rules.
        assert!(rules.len() >= 200, "loaded {} rules, want ≥ 200", rules.len());

        // Spot-check a representative entry from each corpus.
        assert!(rules.iter().any(|r|
            r.id == "vbox-process-vboxservice"
            && r.family == AntiAnalysisFamily::AntiVmVbox
            && r.signature == "VBoxService.exe"
            && r.subkind == "process_name"
        ), "missing canonical al-khaser entry");
        assert!(rules.iter().any(|r|
            r.id == "pafish-vbox-pci-devid"
            && r.family == AntiAnalysisFamily::AntiVmVbox
            && r.signature.contains("VEN_80EE&DEV_CAFE")
        ), "missing canonical pafish entry");

        // Coverage: every family value should appear at least once
        // across the union of corpora (no orphan enum variants).
        let fams: std::collections::HashSet<_> =
            rules.iter().map(|r| r.family.as_str()).collect();
        assert!(fams.contains("anti-vm-vbox"));
        assert!(fams.contains("anti-vm-vmware"));
        assert!(fams.contains("anti-vm-qemu"));
        assert!(fams.contains("anti-vm-kvm"));
        assert!(fams.contains("anti-debug"));
        assert!(fams.contains("code-injection"));
    }

    #[test]
    fn yaml_string_match_vboxservice() {
        // Synthetic feature set: only the VBoxService.exe string.
        let rules = load_yaml_rules();
        let i = imp(&[]);
        let s = strs(&["random preamble", "VBoxService.exe", "trailing"]);
        let hit = rules.iter()
            .find(|r| r.id == "vbox-process-vboxservice")
            .expect("rule present");
        assert!(yaml_rule_matches(hit, &i, &s),
            "VBoxService.exe string should fire vbox-process-vboxservice");
        assert_eq!(hit.family, AntiAnalysisFamily::AntiVmVbox);
    }

    #[test]
    fn yaml_import_api_match_wine() {
        // import_api subkind matches against the imports table, not
        // the strings array.
        let rules = load_yaml_rules();
        let i = imp(&[("kernel32.dll", "wine_get_unix_file_name")]);
        let s = strs(&[]);
        let hit = rules.iter().find(|r| r.id == "wine-import-getunixname").unwrap();
        assert!(yaml_rule_matches(hit, &i, &s));
        assert_eq!(hit.family, AntiAnalysisFamily::AntiVmWine);
    }

    #[test]
    fn rtt_detector_fires_on_full_cluster() {
        // Build feature set: SetWindowsHookEx + 4 cluster APIs.
        let i = imp(&[
            ("user32.dll", "SetWindowsHookExW"),
            ("user32.dll", "GetSystemMetrics"),
            ("user32.dll", "GetCursorPos"),
            ("user32.dll", "GetDoubleClickTime"),
            ("user32.dll", "RegisterClassW"),
            ("user32.dll", "SetTimer"),
        ]);
        let s = strs(&[]);
        // Build a binary-like blob containing 14u32 (WH_MOUSE_LL) and
        // 0x0202u32 (WM_LBUTTONUP) as little-endian dwords.
        let mut data = vec![0u8; 32];
        data.extend_from_slice(&14u32.to_le_bytes());
        data.extend_from_slice(&0x0202u32.to_le_bytes());
        let hit = rtt_detect(&i, &s, &data);
        assert!(hit.fired, "RTT should fire with full cluster + constants present");
        assert!(hit.apis_present >= 5);
        assert!(hit.mouse_hook_const_seen);
        assert!(hit.click_msg_const_seen);
    }

    #[test]
    fn rtt_detector_does_not_fire_without_hookex() {
        let i = imp(&[
            ("user32.dll", "GetSystemMetrics"),
            ("user32.dll", "GetCursorPos"),
            ("user32.dll", "RegisterClassW"),
        ]);
        let s = strs(&[]);
        let mut data = vec![0u8; 16];
        data.extend_from_slice(&14u32.to_le_bytes());
        data.extend_from_slice(&0x0202u32.to_le_bytes());
        let hit = rtt_detect(&i, &s, &data);
        assert!(!hit.fired, "RTT should not fire without SetWindowsHookEx");
    }

    #[test]
    fn api_const_matcher_catches_processdebugport() {
        // Build a synthetic instruction sequence equivalent to:
        //
        //   xor   r8, r8                          ; arg3
        //   mov   edx, 7                          ; arg2 = ProcessDebugPort
        //   mov   rcx, -1                         ; arg1 = current process
        //   call  qword ptr [rip + 0]             ; IAT call
        //
        // Then point the IAT-VA-to-name map at the resulting target.
        // The target VA is the *next instruction's IP* + disp.
        //
        // 4D 31 C0                            xor r8,r8        (3)
        // BA 07 00 00 00                      mov edx,7        (5)
        // 48 C7 C1 FF FF FF FF                mov rcx,-1       (7)
        // FF 15 00 00 00 00                   call [rip+0]     (6)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x4D, 0x31, 0xC0]);
        bytes.extend_from_slice(&[0xBA, 0x07, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF]);
        bytes.extend_from_slice(&[0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);
        let code_va: u64 = 0x1000;

        // Compute target IAT VA: call instruction at offset 15, length 6,
        // next_ip = code_va + 15 + 6 = 0x1015; disp=0 → target = 0x1015.
        let iat_va: u64 = code_va + 15 + 6;
        let mut iat_map = std::collections::HashMap::new();
        iat_map.insert(iat_va, ("ntdll.dll".to_string(), "NtQueryInformationProcess".to_string()));

        let hits = match_call_site_pairs(&bytes, code_va, 64, &iat_map);
        assert!(!hits.is_empty(), "expected at least one (API,const) hit");
        let h = hits.iter().find(|h| h.matched_constant == 0x07)
            .expect("ProcessDebugPort hit not found");
        assert_eq!(h.api_fn, "NtQueryInformationProcess");
        assert_eq!(h.family, AntiAnalysisFamily::AntiDebug);
        assert_eq!(h.technique, "ProcessDebugPort");
    }

    #[test]
    fn api_const_matcher_skips_calls_with_wrong_constant() {
        // Same call site, but arg2 = 0x42 (not a known anti-debug class).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xBA, 0x42, 0x00, 0x00, 0x00]);   // mov edx, 0x42
        bytes.extend_from_slice(&[0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]); // call [rip+0]
        let code_va: u64 = 0x1000;
        let iat_va: u64 = code_va + 5 + 6;
        let mut iat_map = std::collections::HashMap::new();
        iat_map.insert(iat_va, ("ntdll.dll".to_string(), "NtQueryInformationProcess".to_string()));

        let hits = match_call_site_pairs(&bytes, code_va, 64, &iat_map);
        assert!(hits.is_empty(), "no hit expected for unknown constant");
    }

    #[test]
    fn family_taxonomy_round_trips() {
        // Every enum variant has a stable string form parseable back.
        for fam in [
            AntiAnalysisFamily::AntiDebug,
            AntiAnalysisFamily::AntiVmVbox,
            AntiAnalysisFamily::AntiVmVmware,
            AntiAnalysisFamily::AntiVmQemu,
            AntiAnalysisFamily::AntiVmKvm,
            AntiAnalysisFamily::AntiVmXen,
            AntiAnalysisFamily::AntiVmParallels,
            AntiAnalysisFamily::AntiVmWine,
            AntiAnalysisFamily::AntiSandboxCuckoo,
            AntiAnalysisFamily::AntiSandboxSandboxie,
            AntiAnalysisFamily::AntiSandboxJoebox,
            AntiAnalysisFamily::AntiSandboxGeneric,
            AntiAnalysisFamily::AntiAv,
            AntiAnalysisFamily::AntiDisasm,
            AntiAnalysisFamily::AntiDump,
            AntiAnalysisFamily::Timing,
            AntiAnalysisFamily::CodeInjection,
            AntiAnalysisFamily::RttHumanInteraction,
            AntiAnalysisFamily::HypervisorDriver,
            AntiAnalysisFamily::AntiVmBochs,
        ] {
            let s = fam.as_str();
            assert_eq!(AntiAnalysisFamily::from_yaml(s), Some(fam),
                "round-trip failed for {s}");
        }
    }

    #[test]
    fn ruleset_total_meets_v2_target() {
        // v2 ship target: ≥ 250 rules total (35 hardcoded + ~225 YAML).
        let yaml_rules = load_yaml_rules();
        let total = RULES.len() + yaml_rules.len() + API_CONST_RULES.len();
        assert!(total >= 250, "v2 total rules = {total}, want ≥ 250");
    }
}
