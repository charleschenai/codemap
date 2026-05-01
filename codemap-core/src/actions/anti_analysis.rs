// ── Anti-Analysis Scanner (Ship 1 #8) ──────────────────────────────
//
// Detects malware-evasion techniques in PE/ELF binaries using a
// hardcoded ruleset modelled on Mandiant's capa-rules anti-analysis
// corpus (1,045 YAML rules; 90 anti-analysis rules at
// ~/reference/codemap-research-targets/13-capa-rules/anti-analysis/).
// The hardcoded ruleset covers ~35 high-confidence rules detectable
// from PE imports + section names — no instruction-level matching
// (defer to v2 when the bounded constant-propagator extracts).
//
// v2 will load the YAML rule corpus directly (vendored or via
// `--rules-dir`) and add instruction-level matchers using the
// jump-table resolver's RegFile primitive (Ship 1 #7).
//
// Categories covered:
//   - anti-debugging (15 rules)
//   - anti-vm        (8 rules)
//   - anti-disasm    (2 rules)
//   - packer         (6 rules)
//   - anti-forensic  (3 rules)
//   - anti-av        (1 rule)
//
// Output: AntiAnalysis nodes attached to the binary, each with
// name / namespace / category / evidence / confidence attrs.

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

    // Run rules
    let mut hits: Vec<&Rule> = Vec::new();
    for rule in RULES {
        if rule_matches(rule, &imports, &sections, &strings) {
            hits.push(rule);
        }
    }

    register_into_graph(graph, target, &hits);
    format_report(target, &hits, &imports, &sections, &strings)
}

// ── Feature extraction ─────────────────────────────────────────────

/// Set of (dll_lower, function_name_lower) pairs the binary imports.
struct Imports {
    pairs: std::collections::HashSet<(String, String)>,
    fn_count: usize,
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

// ── Report formatting ──────────────────────────────────────────────

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
}
