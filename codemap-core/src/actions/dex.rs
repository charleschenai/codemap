// ── DEX bytecode walker (5.23.0) ─────────────────────────────────────
//
// Parses Android Dalvik EXecutable (.dex) files extracted from APKs.
// v1 scope:
//   1. Header validation (dex magic + version)
//   2. String / type / method ID tables (lookup foundation)
//   3. class_def + class_data walk → emit one `DexMethod` per class method
//   4. Per-method bytecode scan for invoke-* opcodes targeting protected
//      Android APIs → emit (caller_method, permission) pairs for the
//      heuristic permission→method linking
//
// Spec reference: Android Open Source Project, Dalvik Executable format
//   <https://source.android.com/docs/core/runtime/dex-format>
//
// Out of scope for v1: full Dalvik opcode catalog (we only decode invoke-*),
// parameter type signatures, annotations, native method signatures.

use std::collections::HashMap;

/// One method discovered inside a DEX file.
pub struct DexMethod {
    /// Java-style class FQN (e.g. `com.example.MyActivity`).
    pub class_name: String,
    /// Method name (e.g. `onCreate`).
    pub method_name: String,
    /// Dalvik access_flags (public=0x01, private=0x02, static=0x08, etc.).
    pub access_flags: u32,
    /// Byte-offset of the method's `code_item` in the DEX, or 0 if abstract/native.
    pub code_off: u32,
}

impl DexMethod {
    pub fn fqn(&self) -> String {
        format!("{}.{}", self.class_name, self.method_name)
    }
}

/// Permission heuristically inferred from a DEX method's invoke-* opcodes.
/// `caller` is the (class_name, method_name) of the callsite; `permission`
/// is the canonical Android permission constant name.
pub struct DexPermissionEdge {
    pub caller_class: String,
    pub caller_method: String,
    pub permission: &'static str,
    /// API that triggered the inference, for the attribute audit trail.
    pub triggered_by: String,
}

/// Top-level entry: parse a DEX byte slice and return everything we extracted.
pub struct DexInfo {
    pub version: String,
    pub method_count: usize,
    pub class_count: usize,
    pub methods: Vec<DexMethod>,
    pub permission_edges: Vec<DexPermissionEdge>,
}

pub fn parse_dex(data: &[u8]) -> Result<DexInfo, String> {
    if data.len() < 0x70 {
        return Err("DEX file too small (need ≥ 0x70 bytes for header)".into());
    }
    // Magic: `dex\n035\0`, `dex\n037\0`, `dex\n038\0`, `dex\n039\0`, etc.
    if &data[0..4] != b"dex\n" || data[7] != 0 {
        return Err("Not a DEX file (missing `dex\\n` magic)".into());
    }
    let version = String::from_utf8_lossy(&data[4..7]).into_owned();

    // Endian check — DEX is almost always little-endian (0x12345678 tag).
    let endian = read_u32(data, 40)?;
    if endian != 0x12345678 {
        return Err(format!("Unsupported DEX endianness: {endian:#010x}"));
    }

    let string_ids_size = read_u32(data, 56)? as usize;
    let string_ids_off  = read_u32(data, 60)? as usize;
    let type_ids_size   = read_u32(data, 64)? as usize;
    let type_ids_off    = read_u32(data, 68)? as usize;
    let method_ids_size = read_u32(data, 88)? as usize;
    let method_ids_off  = read_u32(data, 92)? as usize;
    let class_defs_size = read_u32(data, 96)? as usize;
    let class_defs_off  = read_u32(data, 100)? as usize;

    // Bounds: the string/type/method tables can each be huge (50K+ entries
    // on a real app). Cap at 200K each to defend against malicious or
    // corrupt DEX files.
    if string_ids_size > 200_000 || type_ids_size  > 200_000
        || method_ids_size > 200_000 || class_defs_size > 200_000 {
        return Err("DEX table too large (>200K entries)".into());
    }

    let strings = build_string_table(data, string_ids_off, string_ids_size)?;
    let type_descriptors = build_type_table(data, type_ids_off, type_ids_size, &strings)?;
    let methods_table = build_method_table(data, method_ids_off, method_ids_size, &type_descriptors, &strings)?;

    // Walk class_defs.
    let mut methods: Vec<DexMethod> = Vec::new();
    let mut permission_edges: Vec<DexPermissionEdge> = Vec::new();
    const MAX_METHODS: usize = 5000;

    for class_idx in 0..class_defs_size {
        if methods.len() >= MAX_METHODS { break; }
        let class_def_off = class_defs_off + class_idx * 32;  // class_def_item is 32 bytes
        if class_def_off + 32 > data.len() { break; }

        let class_type_idx = read_u32(data, class_def_off)? as usize;
        let class_data_off = read_u32(data, class_def_off + 24)? as usize;
        if class_type_idx >= type_descriptors.len() { continue; }

        let class_name = jvm_descriptor_to_java(&type_descriptors[class_type_idx]);
        if class_data_off == 0 { continue; }  // empty class (e.g. interface marker)

        // Parse class_data_item: 4 ULEB128 sizes, then the encoded lists.
        let mut p = class_data_off;
        let static_fields_size = match read_uleb128(data, &mut p) {
            Some(v) => v as usize, None => continue
        };
        let instance_fields_size = match read_uleb128(data, &mut p) {
            Some(v) => v as usize, None => continue
        };
        let direct_methods_size = match read_uleb128(data, &mut p) {
            Some(v) => v as usize, None => continue
        };
        let virtual_methods_size = match read_uleb128(data, &mut p) {
            Some(v) => v as usize, None => continue
        };

        // Skip past field lists (we don't need them for v1).
        for _ in 0..(static_fields_size + instance_fields_size) {
            if read_uleb128(data, &mut p).is_none() { break; }  // field_idx_diff
            if read_uleb128(data, &mut p).is_none() { break; }  // access_flags
        }

        // Direct methods + virtual methods are encoded the same way.
        // method_idx is delta-encoded, so we accumulate.
        let mut last_method_idx: u64 = 0;

        for method_section in [direct_methods_size, virtual_methods_size] {
            last_method_idx = 0;
            for _ in 0..method_section {
                if methods.len() >= MAX_METHODS { break; }
                let diff = match read_uleb128(data, &mut p) {
                    Some(v) => v, None => break,
                };
                let access_flags = match read_uleb128(data, &mut p) {
                    Some(v) => v as u32, None => break,
                };
                let code_off = match read_uleb128(data, &mut p) {
                    Some(v) => v as u32, None => break,
                };
                let mid = (last_method_idx.wrapping_add(diff)) as usize;
                last_method_idx = mid as u64;
                if mid >= methods_table.len() { continue; }

                let (m_class_idx, method_name) = &methods_table[mid];
                // Sanity: method's class_idx should match the enclosing class.
                let _ = m_class_idx;

                let dm = DexMethod {
                    class_name: class_name.clone(),
                    method_name: method_name.clone(),
                    access_flags,
                    code_off,
                };

                // Heuristic permission scan via invoke-* opcodes.
                if code_off != 0 && (code_off as usize) < data.len() {
                    scan_method_for_permissions(
                        data, code_off as usize,
                        &methods_table, &type_descriptors,
                        &class_name, &method_name,
                        &mut permission_edges,
                    );
                }
                methods.push(dm);
            }
        }
    }

    Ok(DexInfo {
        version,
        method_count: methods.len(),
        class_count: class_defs_size,
        methods,
        permission_edges,
    })
}

// ── Helpers: byte reading + ULEB128 ──────────────────────────────────

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    if off + 2 > data.len() { return None; }
    Some(u16::from_le_bytes([data[off], data[off + 1]]))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32, String> {
    if off + 4 > data.len() {
        return Err(format!("read_u32 OOB at {off:#x}"));
    }
    Ok(u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]))
}

/// Decode an Unsigned LEB128 in place. Advances `p` past the value.
fn read_uleb128(data: &[u8], p: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for _ in 0..10 {
        if *p >= data.len() { return None; }
        let byte = data[*p];
        *p += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 { return Some(result); }
        shift += 7;
        if shift > 63 { return None; }
    }
    None
}

// ── String / type / method table builders ────────────────────────────

fn build_string_table(data: &[u8], off: usize, size: usize) -> Result<Vec<String>, String> {
    let mut out = Vec::with_capacity(size);
    for i in 0..size {
        let entry_off = off + i * 4;
        if entry_off + 4 > data.len() { break; }
        let str_data_off = read_u32(data, entry_off)? as usize;
        if str_data_off >= data.len() {
            out.push(String::new());
            continue;
        }
        // ULEB128 size, then MUTF-8 bytes terminated by 0x00.
        let mut p = str_data_off;
        let _utf16_units = read_uleb128(data, &mut p).unwrap_or(0);
        let s_start = p;
        let mut s_end = s_start;
        while s_end < data.len() && data[s_end] != 0 { s_end += 1; }
        out.push(String::from_utf8_lossy(&data[s_start..s_end]).into_owned());
    }
    Ok(out)
}

fn build_type_table(data: &[u8], off: usize, size: usize, strings: &[String])
    -> Result<Vec<String>, String>
{
    let mut out = Vec::with_capacity(size);
    for i in 0..size {
        let entry_off = off + i * 4;
        if entry_off + 4 > data.len() { break; }
        let descriptor_idx = read_u32(data, entry_off)? as usize;
        if descriptor_idx < strings.len() {
            out.push(strings[descriptor_idx].clone());
        } else {
            out.push(String::new());
        }
    }
    Ok(out)
}

fn build_method_table(data: &[u8], off: usize, size: usize,
                      types: &[String], strings: &[String])
    -> Result<Vec<(u16, String)>, String>
{
    let mut out = Vec::with_capacity(size);
    for i in 0..size {
        let entry_off = off + i * 8;  // method_id_item is 8 bytes
        if entry_off + 8 > data.len() { break; }
        let class_idx = read_u16(data, entry_off).unwrap_or(0);
        let _proto_idx = read_u16(data, entry_off + 2).unwrap_or(0);
        let name_idx = read_u32(data, entry_off + 4)? as usize;
        let name = strings.get(name_idx).cloned().unwrap_or_default();
        let _ = types;  // we resolve class via class_idx in the caller
        out.push((class_idx, name));
    }
    Ok(out)
}

// ── Permission heuristic ─────────────────────────────────────────────

/// Scan one method's bytecode looking for `invoke-*` opcodes that target
/// known protected Android APIs. Each hit appends a `DexPermissionEdge`.
///
/// Dalvik invoke opcodes (35c form, 6 bytes total):
///   0x6E invoke-virtual
///   0x6F invoke-super
///   0x70 invoke-direct
///   0x71 invoke-static
///   0x72 invoke-interface
/// Layout: opcode(1) + ABCG(1) + method_idx(2) + FEDC(2)
/// 3rc form (range, also 6 bytes) opcodes are 0x74-0x78 — same method_idx
/// position at offset 2.
fn scan_method_for_permissions(
    data: &[u8],
    code_off: usize,
    methods_table: &[(u16, String)],
    types: &[String],
    caller_class: &str,
    caller_method: &str,
    out: &mut Vec<DexPermissionEdge>,
) {
    // code_item header (16 bytes): u16 registers_size + u16 ins_size +
    // u16 outs_size + u16 tries_size + u32 debug_info_off + u32 insns_size.
    if code_off + 16 > data.len() { return; }
    let insns_size = u32::from_le_bytes([
        data[code_off + 12], data[code_off + 13],
        data[code_off + 14], data[code_off + 15],
    ]) as usize;
    let insns_start = code_off + 16;
    let insns_end = insns_start + insns_size * 2;  // insns_size is in 16-bit code units
    if insns_end > data.len() { return; }

    let insns = &data[insns_start..insns_end];
    let mut i = 0;
    while i + 2 <= insns.len() {
        let opcode = insns[i];
        // We only care about invoke-* opcodes.
        let is_invoke_35c = (0x6E..=0x72).contains(&opcode);
        let is_invoke_3rc = (0x74..=0x78).contains(&opcode);
        if (is_invoke_35c || is_invoke_3rc) && i + 6 <= insns.len() {
            let method_idx = u16::from_le_bytes([insns[i + 2], insns[i + 3]]) as usize;
            if method_idx < methods_table.len() {
                let (callee_class_idx, callee_name) = &methods_table[method_idx];
                let callee_class_idx = *callee_class_idx as usize;
                if callee_class_idx < types.len() {
                    let callee_class_desc = &types[callee_class_idx];
                    if let Some(perm) = api_to_permission(callee_class_desc, callee_name) {
                        let triggered = format!(
                            "{}.{}",
                            jvm_descriptor_to_java(callee_class_desc),
                            callee_name,
                        );
                        // Dedup: only push if we haven't already linked
                        // this caller↔permission pair from another callsite
                        // in the same method.
                        let already = out.iter().any(|e|
                            e.caller_class == caller_class
                            && e.caller_method == caller_method
                            && e.permission == perm);
                        if !already {
                            out.push(DexPermissionEdge {
                                caller_class: caller_class.to_string(),
                                caller_method: caller_method.to_string(),
                                permission: perm,
                                triggered_by: triggered,
                            });
                        }
                    }
                }
            }
        }
        // Advance by the opcode's instruction width. For DEX, this is
        // always 2 bytes for the opcode word, but the *full* instruction
        // can be 1, 2, 3, 4, or 5 code units depending on opcode. v1
        // uses a per-opcode width table covering the common formats; on
        // unknown opcodes, advance by 2 (one code unit) and resync.
        i += dex_instruction_width(opcode);
    }
}

/// Map a callee (class descriptor + method name) to the canonical Android
/// permission it requires, if known. Heuristic lookup against ~30 well-known
/// protected-API sites. Returns None if no match.
fn api_to_permission(class_desc: &str, method_name: &str) -> Option<&'static str> {
    // class_desc is JVM-style like "Landroid/hardware/Camera;".
    // We match on class for most APIs, with a few method-name refinements.
    match class_desc {
        "Landroid/hardware/Camera;" => Some("CAMERA"),
        "Landroid/hardware/camera2/CameraManager;" => Some("CAMERA"),
        "Landroid/hardware/camera2/CameraDevice;" => Some("CAMERA"),
        "Landroid/location/LocationManager;" => Some("ACCESS_FINE_LOCATION"),
        "Landroid/location/Location;" => Some("ACCESS_FINE_LOCATION"),
        "Landroid/media/AudioRecord;" => Some("RECORD_AUDIO"),
        "Landroid/media/MediaRecorder;" => match method_name {
            "setAudioSource" => Some("RECORD_AUDIO"),
            "setVideoSource" => Some("CAMERA"),
            _ => None,
        },
        "Landroid/bluetooth/BluetoothAdapter;" => Some("BLUETOOTH_CONNECT"),
        "Landroid/bluetooth/BluetoothDevice;" => Some("BLUETOOTH_CONNECT"),
        "Landroid/bluetooth/le/BluetoothLeScanner;" => Some("BLUETOOTH_SCAN"),
        "Landroid/net/wifi/WifiManager;" => Some("ACCESS_WIFI_STATE"),
        "Landroid/net/wifi/WifiInfo;" => Some("ACCESS_WIFI_STATE"),
        "Landroid/telephony/TelephonyManager;" => match method_name {
            "getDeviceId" | "getImei" | "getMeid" | "getSubscriberId"
            | "getSimSerialNumber" | "getLine1Number" => Some("READ_PHONE_STATE"),
            "getCellLocation" | "getAllCellInfo" => Some("ACCESS_FINE_LOCATION"),
            _ => None,
        },
        "Landroid/telephony/SmsManager;" => Some("SEND_SMS"),
        "Landroid/provider/ContactsContract$Contacts;" => Some("READ_CONTACTS"),
        "Landroid/provider/CallLog$Calls;" => Some("READ_CALL_LOG"),
        "Landroid/provider/Telephony$Sms;" => Some("READ_SMS"),
        "Landroid/accounts/AccountManager;" => Some("GET_ACCOUNTS"),
        "Landroid/hardware/fingerprint/FingerprintManager;" => Some("USE_FINGERPRINT"),
        "Landroid/hardware/biometrics/BiometricManager;" => Some("USE_BIOMETRIC"),
        "Landroid/Manifest$permission;" => None,  // permission constants — informational, no edge
        "Landroid/content/Context;" => match method_name {
            "getExternalFilesDir" | "getExternalCacheDir" => Some("WRITE_EXTERNAL_STORAGE"),
            _ => None,
        },
        "Landroid/os/Vibrator;" => Some("VIBRATE"),
        "Landroid/nfc/NfcAdapter;" => Some("NFC"),
        "Landroid/app/NotificationManager;" => match method_name {
            "notify" => Some("POST_NOTIFICATIONS"),
            _ => None,
        },
        _ => None,
    }
}

/// Convert a JVM type descriptor like `Landroid/hardware/Camera;` into a
/// dotted Java class FQN like `android.hardware.Camera`. Array and
/// primitive descriptors fall back to the raw form.
fn jvm_descriptor_to_java(desc: &str) -> String {
    if desc.starts_with('L') && desc.ends_with(';') && desc.len() > 2 {
        desc[1..desc.len() - 1].replace('/', ".")
    } else {
        desc.to_string()
    }
}

/// Approximate Dalvik instruction width (in bytes) for opcode dispatch.
/// Covers the common formats; unknown opcodes default to 2 bytes (one code
/// unit) so we resync on the next valid opcode rather than panic. For v1
/// permission scanning, we only need invoke-* widths to be exact (6 bytes).
fn dex_instruction_width(opcode: u8) -> usize {
    match opcode {
        0x00 => 2,  // nop (or padding for packed-switch / sparse-switch / fill-array-data)
        // 1-code-unit (2-byte) formats
        0x01..=0x0D | 0x0E..=0x12 | 0x1D | 0x1E | 0x21 | 0x27
        | 0x73 | 0x79 | 0x7A | 0x7B..=0x8F | 0xB0..=0xCF | 0xE3..=0xFF => 2,
        // 2-code-unit (4-byte) formats — most arithmetic, comparisons, branches
        0x13..=0x1C | 0x1F | 0x20 | 0x22..=0x26 | 0x28..=0x3D
        | 0x44..=0x6D | 0x90..=0xAF | 0xD0..=0xE2 => 4,
        // 3-code-unit (6-byte) formats — invoke-*, instance/static field ops, const-string/jumbo, fill-array-data prelude
        0x6E..=0x72 | 0x74..=0x78 => 6,
        // const-wide (0x18) is 5 code units (10 bytes)
        // const-string/jumbo (0x1B) is 3 code units (6 bytes)
        // packed-switch / sparse-switch / fill-array-data tables: variable, but
        // the leading opcode is 3 code units (6 bytes); the table follows out-of-line.
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jvm_descriptor_round_trip() {
        assert_eq!(jvm_descriptor_to_java("Landroid/hardware/Camera;"),
            "android.hardware.Camera");
        assert_eq!(jvm_descriptor_to_java("Lcom/example/MyActivity;"),
            "com.example.MyActivity");
        // Primitives + arrays fall through to raw form
        assert_eq!(jvm_descriptor_to_java("[Ljava/lang/String;"),
            "[Ljava/lang/String;");
        assert_eq!(jvm_descriptor_to_java("I"), "I");
    }

    #[test]
    fn uleb128_decodes_canonical_values() {
        let data = [0x00, 0x7F, 0x80, 0x01, 0xE5, 0x8E, 0x26];
        let mut p = 0;
        assert_eq!(read_uleb128(&data, &mut p), Some(0));
        assert_eq!(p, 1);
        assert_eq!(read_uleb128(&data, &mut p), Some(127));
        assert_eq!(p, 2);
        assert_eq!(read_uleb128(&data, &mut p), Some(128));
        assert_eq!(p, 4);
        // 624485 from the LEB128 wikipedia example
        assert_eq!(read_uleb128(&data, &mut p), Some(624485));
        assert_eq!(p, 7);
    }

    #[test]
    fn api_to_permission_covers_obvious_cases() {
        assert_eq!(api_to_permission("Landroid/hardware/Camera;", "open"), Some("CAMERA"));
        assert_eq!(api_to_permission("Landroid/location/LocationManager;",
            "getLastKnownLocation"), Some("ACCESS_FINE_LOCATION"));
        assert_eq!(api_to_permission("Landroid/telephony/TelephonyManager;",
            "getDeviceId"), Some("READ_PHONE_STATE"));
        assert_eq!(api_to_permission("Landroid/telephony/TelephonyManager;",
            "someUnrelatedMethod"), None);
        assert_eq!(api_to_permission("Lcom/example/MyClass;", "doStuff"), None);
    }

    #[test]
    fn parse_dex_rejects_non_dex() {
        assert!(parse_dex(b"not a dex file at all").is_err());
        let mut tiny = vec![0u8; 0x70];
        tiny[0..4].copy_from_slice(b"dex\n");
        tiny[4..7].copy_from_slice(b"035");
        // endian tag missing → should error
        assert!(parse_dex(&tiny).is_err());
    }
}
