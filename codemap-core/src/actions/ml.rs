use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use crate::types::{Graph, EntityKind};

/// Heterogeneous-graph helper: register an ML model file as an MlModel node.
/// Format-specific attrs (architecture, parameter count, quantization) flow
/// through `attrs`. Lets `codemap pagerank --type model` rank model files
/// by their importance in a project's data layer.
fn register_ml_model(graph: &mut Graph, target: &str, format: &str) {
    let id = format!("model:{target}");
    graph.ensure_typed_node(&id, EntityKind::MlModel, &[
        ("path", target), ("format", format),
    ]);
}

const MAX_BINARY_SIZE: u64 = 256 * 1024 * 1024; // 256 MB

// ── Helpers ────────────────────────────────────────────────────────

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16, String> {
    if offset + 2 > data.len() {
        return Err(format!("Read u16 out of bounds at offset 0x{offset:X}"));
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > data.len() {
        return Err(format!("Read u32 out of bounds at offset 0x{offset:X}"));
    }
    Ok(u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]))
}

fn read_u64_le(data: &[u8], offset: usize) -> Result<u64, String> {
    if offset + 8 > data.len() {
        return Err(format!("Read u64 out of bounds at offset 0x{offset:X}"));
    }
    Ok(u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]))
}

#[allow(dead_code)]
fn read_u16_be(data: &[u8], offset: usize) -> Result<u16, String> {
    if offset + 2 > data.len() {
        return Err(format!("Read u16 out of bounds at offset 0x{offset:X}"));
    }
    Ok(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

#[allow(dead_code)]
fn read_u32_be(data: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > data.len() {
        return Err(format!("Read u32 out of bounds at offset 0x{offset:X}"));
    }
    Ok(u32::from_be_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]))
}

fn read_f32_le(data: &[u8], offset: usize) -> Result<f32, String> {
    if offset + 4 > data.len() {
        return Err(format!("Read f32 out of bounds at offset 0x{offset:X}"));
    }
    Ok(f32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]))
}

fn read_f64_le(data: &[u8], offset: usize) -> Result<f64, String> {
    if offset + 8 > data.len() {
        return Err(format!("Read f64 out of bounds at offset 0x{offset:X}"));
    }
    Ok(f64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]))
}

fn read_cstring(data: &[u8], offset: usize) -> String {
    let mut s = String::new();
    let mut i = offset;
    while i < data.len() && data[i] != 0 {
        if data[i] >= 0x20 && data[i] <= 0x7E {
            s.push(data[i] as char);
        } else {
            break;
        }
        i += 1;
    }
    s
}

fn load_binary(target: &str) -> Result<Vec<u8>, String> {
    let path = Path::new(target);
    if !path.exists() {
        return Err(format!("File not found: {target}"));
    }
    let meta = fs::metadata(path).map_err(|e| format!("Error: {e}"))?;
    if meta.len() > MAX_BINARY_SIZE {
        return Err(format!("File too large ({} bytes, max 256 MB)", meta.len()));
    }
    fs::read(path).map_err(|e| format!("Error reading file: {e}"))
}

fn format_size(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn format_size_human(n: u64) -> String {
    if n >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", n as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if n >= 1024 * 1024 {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

/// Read a GGUF-style string: u64 length followed by UTF-8 bytes (NOT null-terminated).
/// Returns (string, bytes_consumed).
fn read_gguf_string(data: &[u8], offset: usize) -> Result<(String, usize), String> {
    let len = read_u64_le(data, offset)? as usize;
    let str_start = offset + 8;
    if str_start + len > data.len() {
        return Err(format!("GGUF string truncated at offset 0x{offset:X} (len={len})"));
    }
    let s = String::from_utf8_lossy(&data[str_start..str_start + len]).to_string();
    Ok((s, 8 + len))
}

// ── 1. gguf_info ──────────────────────────────────────────────────

pub fn gguf_info(graph: &mut Graph, target: &str) -> String {
    register_ml_model(graph, target, "gguf");
    let data = match load_binary(target) {
        Ok(d) => d,
        Err(e) => return e,
    };
    match parse_gguf(&data, target) {
        Ok((info, tensors)) => {
            // 5.20.0: each GGUF tensor promotes to an MlTensor graph
            // node with edge from the parent MlModel. Capped at 5000
            // per model to keep huge LLM tensor lists tractable
            // (Llama-3-70B has ~700 tensors, well under cap).
            promote_ml_tensors(graph, target, "gguf", &tensors);
            info
        }
        Err(e) => format!("GGUF parse error: {e}"),
    }
}

/// Module-level tensor descriptor — used by both gguf_info and the public
/// promotion helper. Hoisted out of `parse_gguf` (where it was a local
/// struct) so the promotion path can consume the same shape.
pub(crate) struct GgufTensorInfo {
    pub name: String,
    pub dims: Vec<u64>,
    pub dtype: u32,
}

/// Cap on MlTensor / MlOperator nodes promoted per single ML-action call.
/// Mirrors StringLiteral / LSP-symbol caps.
const MAX_ML_NODES_PER_CALL: usize = 5000;

fn promote_ml_tensors(graph: &mut Graph, target: &str, format: &str,
                      tensors: &[GgufTensorInfo]) {
    use crate::types::EntityKind;
    let model_id = format!("model:{target}");
    for (i, t) in tensors.iter().enumerate().take(MAX_ML_NODES_PER_CALL) {
        let tensor_id = format!("tensor:{format}:{target}::{i}");
        let dtype = ggml_type_name(t.dtype);
        let shape: Vec<String> = t.dims.iter().map(|d| d.to_string()).collect();
        let shape_str = shape.join(",");
        let params: u64 = if t.dims.is_empty() { 0 } else { t.dims.iter().product() };
        let params_str = params.to_string();
        graph.ensure_typed_node(&tensor_id, EntityKind::MlTensor, &[
            ("name", t.name.as_str()),
            ("dtype", dtype),
            ("shape", &shape_str),
            ("model_format", format),
            ("params", &params_str),
        ]);
        graph.add_edge(&model_id, &tensor_id);
    }
}

fn ggml_type_name(t: u32) -> &'static str {
    match t {
        0 => "F32",
        1 => "F16",
        2 => "Q4_0",
        3 => "Q4_1",
        6 => "Q5_0",
        7 => "Q5_1",
        8 => "Q8_0",
        9 => "Q8_1",
        10 => "Q2_K",
        11 => "Q3_K",
        12 => "Q4_K",
        13 => "Q5_K",
        14 => "Q6_K",
        15 => "Q8_K",
        16 => "IQ2_XXS",
        17 => "IQ2_XS",
        18 => "IQ3_XXS",
        19 => "IQ1_S",
        20 => "IQ4_NL",
        21 => "IQ3_S",
        22 => "IQ2_S",
        23 => "IQ4_XS",
        24 => "I8",
        25 => "I16",
        26 => "I32",
        27 => "I64",
        28 => "F64",
        29 => "IQ1_M",
        30 => "BF16",
        _ => "Unknown",
    }
}

fn gguf_file_type_name(ft: u64) -> &'static str {
    match ft {
        0 => "F32",
        1 => "F16",
        2 => "Q4_0",
        3 => "Q4_1",
        7 => "Q8_0",
        8 => "Q5_0",
        9 => "Q5_1",
        10 => "Q2_K",
        11 => "Q3_K_S",
        12 => "Q3_K_M",
        13 => "Q3_K_L",
        14 => "Q4_K_S",
        15 => "Q4_K_M",
        16 => "Q5_K_S",
        17 => "Q5_K_M",
        18 => "Q6_K",
        19 => "IQ2_XXS",
        20 => "IQ2_XS",
        21 => "IQ3_XXS",
        22 => "IQ1_S",
        23 => "IQ4_NL",
        24 => "IQ3_S",
        25 => "IQ2_S",
        26 => "IQ4_XS",
        27 => "IQ1_M",
        28 => "BF16",
        _ => "Unknown",
    }
}

/// Skip a GGUF metadata value, returning bytes consumed.
fn skip_gguf_value(data: &[u8], offset: usize, vtype: u32) -> Result<usize, String> {
    match vtype {
        0 => Ok(1),                // UINT8
        1 => Ok(1),                // INT8
        2 => Ok(2),                // UINT16
        3 => Ok(2),                // INT16
        4 => Ok(4),                // UINT32
        5 => Ok(4),                // INT32
        6 => Ok(4),                // FLOAT32
        7 => Ok(1),                // BOOL
        8 => {                     // STRING
            let (_, consumed) = read_gguf_string(data, offset)?;
            Ok(consumed)
        }
        9 => {                     // ARRAY
            let elem_type = read_u32_le(data, offset)?;
            let count = read_u64_le(data, offset + 4)? as usize;
            let mut pos = 12; // 4 (elem_type) + 8 (count)
            for _ in 0..count {
                let consumed = skip_gguf_value(data, offset + pos, elem_type)?;
                pos += consumed;
            }
            Ok(pos)
        }
        10 => Ok(8),               // UINT64
        11 => Ok(8),               // INT64
        12 => Ok(8),               // FLOAT64
        _ => Err(format!("Unknown GGUF value type {vtype}")),
    }
}

/// Read a GGUF metadata value as a display string, returning (value_string, bytes_consumed).
fn read_gguf_value(data: &[u8], offset: usize, vtype: u32) -> Result<(String, usize), String> {
    match vtype {
        0 => { // UINT8
            if offset >= data.len() { return Err("Truncated".into()); }
            Ok((format!("{}", data[offset]), 1))
        }
        1 => { // INT8
            if offset >= data.len() { return Err("Truncated".into()); }
            Ok((format!("{}", data[offset] as i8), 1))
        }
        2 => { // UINT16
            let v = read_u16_le(data, offset)?;
            Ok((format!("{v}"), 2))
        }
        3 => { // INT16
            let v = read_u16_le(data, offset)? as i16;
            Ok((format!("{v}"), 2))
        }
        4 => { // UINT32
            let v = read_u32_le(data, offset)?;
            Ok((format!("{v}"), 4))
        }
        5 => { // INT32
            let v = read_u32_le(data, offset)? as i32;
            Ok((format!("{v}"), 4))
        }
        6 => { // FLOAT32
            let v = read_f32_le(data, offset)?;
            Ok((format!("{v}"), 4))
        }
        7 => { // BOOL
            if offset >= data.len() { return Err("Truncated".into()); }
            Ok((if data[offset] != 0 { "true" } else { "false" }.to_string(), 1))
        }
        8 => { // STRING
            let (s, consumed) = read_gguf_string(data, offset)?;
            Ok((s, consumed))
        }
        9 => { // ARRAY
            let elem_type = read_u32_le(data, offset)?;
            let count = read_u64_le(data, offset + 4)? as usize;
            let mut pos = 12usize;
            let mut items = Vec::new();
            let max_show = 8;
            for i in 0..count {
                if i < max_show {
                    let (val, consumed) = read_gguf_value(data, offset + pos, elem_type)?;
                    items.push(val);
                    pos += consumed;
                } else {
                    let consumed = skip_gguf_value(data, offset + pos, elem_type)?;
                    pos += consumed;
                }
            }
            let display = if count > max_show {
                format!("[{}, ... ({} total)]", items.join(", "), count)
            } else {
                format!("[{}]", items.join(", "))
            };
            Ok((display, pos))
        }
        10 => { // UINT64
            let v = read_u64_le(data, offset)?;
            Ok((format!("{v}"), 8))
        }
        11 => { // INT64
            let v = read_u64_le(data, offset)? as i64;
            Ok((format!("{v}"), 8))
        }
        12 => { // FLOAT64
            let v = read_f64_le(data, offset)?;
            Ok((format!("{v}"), 8))
        }
        _ => Err(format!("Unknown GGUF value type {vtype}")),
    }
}

fn parse_gguf(data: &[u8], target: &str) -> Result<(String, Vec<GgufTensorInfo>), String> {
    if data.len() < 24 {
        return Err("File too small for GGUF".to_string());
    }

    // Magic: "GGUF" (0x47, 0x47, 0x55, 0x46)
    if data[0] != 0x47 || data[1] != 0x47 || data[2] != 0x55 || data[3] != 0x46 {
        return Err("Not a GGUF file (missing GGUF magic)".to_string());
    }

    let version = read_u32_le(data, 4)?;
    let tensor_count = read_u64_le(data, 8)?;
    let metadata_kv_count = read_u64_le(data, 16)?;

    let file_size = fs::metadata(target).map(|m| m.len()).unwrap_or(0);

    let mut out = String::new();
    out.push_str("=== GGUF Model Info ===\n\n");

    let filename = Path::new(target).file_name()
        .and_then(|n| n.to_str()).unwrap_or(target);
    out.push_str(&format!("File: {} ({})\n", filename, format_size_human(file_size)));
    out.push_str(&format!("Format: GGUF v{version}\n"));

    // Parse metadata key-value pairs
    let mut pos = 24usize;
    let mut metadata: Vec<(String, String)> = Vec::new();
    let mut architecture = String::new();
    let mut model_name = String::new();
    let mut file_type_val: Option<u64> = None;
    let mut context_length: Option<u64> = None;
    let mut embedding_length: Option<u64> = None;
    let mut block_count: Option<u64> = None;
    let mut head_count: Option<u64> = None;
    let mut head_count_kv: Option<u64> = None;
    let mut vocab_size: Option<u64> = None;
    let mut tokenizer_model = String::new();
    let mut quant_version: Option<u64> = None;

    for _ in 0..metadata_kv_count {
        if pos >= data.len() {
            break;
        }
        // Read key
        let (key, key_consumed) = read_gguf_string(data, pos)?;
        pos += key_consumed;

        // Read value type
        let vtype = read_u32_le(data, pos)?;
        pos += 4;

        // Read value
        let (value_str, value_consumed) = read_gguf_value(data, pos, vtype)?;
        pos += value_consumed;

        // Extract important metadata
        if key == "general.architecture" {
            architecture = value_str.clone();
        } else if key == "general.name" {
            model_name = value_str.clone();
        } else if key == "general.file_type" {
            file_type_val = value_str.parse::<u64>().ok();
        } else if key == "general.quantization_version" {
            quant_version = value_str.parse::<u64>().ok();
        } else if key == "tokenizer.ggml.model" {
            tokenizer_model = value_str.clone();
        } else if key.ends_with(".context_length") {
            context_length = value_str.parse::<u64>().ok();
        } else if key.ends_with(".embedding_length") {
            embedding_length = value_str.parse::<u64>().ok();
        } else if key.ends_with(".block_count") {
            block_count = value_str.parse::<u64>().ok();
        } else if key.ends_with(".attention.head_count") && !key.ends_with(".attention.head_count_kv") {
            head_count = value_str.parse::<u64>().ok();
        } else if key.ends_with(".attention.head_count_kv") {
            head_count_kv = value_str.parse::<u64>().ok();
        } else if key.ends_with(".vocab_size") {
            vocab_size = value_str.parse::<u64>().ok();
        }

        metadata.push((key, value_str));
    }

    // Display header info
    if !architecture.is_empty() {
        out.push_str(&format!("Architecture: {architecture}\n"));
    }
    if !model_name.is_empty() {
        out.push_str(&format!("Name: {model_name}\n"));
    }
    if let Some(ft) = file_type_val {
        out.push_str(&format!("Quantization: {} (file_type: {ft})\n", gguf_file_type_name(ft)));
    }
    if let Some(qv) = quant_version {
        out.push_str(&format!("Quant version: {qv}\n"));
    }
    if !tokenizer_model.is_empty() {
        out.push_str(&format!("Tokenizer: {tokenizer_model}\n"));
    }

    // Parameters section
    if context_length.is_some() || embedding_length.is_some() || block_count.is_some() {
        out.push_str("\n\u{2500}\u{2500} Parameters \u{2500}\u{2500}\n");
        if let Some(v) = context_length {
            out.push_str(&format!("  Context length: {}\n", format_size(v)));
        }
        if let Some(v) = embedding_length {
            out.push_str(&format!("  Embedding size: {}\n", format_size(v)));
        }
        if let Some(v) = block_count {
            out.push_str(&format!("  Layers: {v}\n"));
        }
        if let Some(v) = head_count {
            out.push_str(&format!("  Attention heads: {v}\n"));
        }
        if let Some(v) = head_count_kv {
            out.push_str(&format!("  KV heads: {v}\n"));
        }
        if let Some(v) = vocab_size {
            out.push_str(&format!("  Vocab size: {}\n", format_size(v)));
        }
    }

    // Parse tensor info entries
    let mut tensors: Vec<GgufTensorInfo> = Vec::new();
    for _ in 0..tensor_count {
        if pos >= data.len() {
            break;
        }
        // Tensor name (GGUF string: u64 len + bytes)
        let (name, name_consumed) = read_gguf_string(data, pos)?;
        pos += name_consumed;

        // Number of dimensions
        let n_dims = read_u32_le(data, pos)? as usize;
        pos += 4;

        // Dimensions
        let mut dims = Vec::with_capacity(n_dims);
        for _ in 0..n_dims {
            let d = read_u64_le(data, pos)?;
            dims.push(d);
            pos += 8;
        }

        // Type
        let dtype = read_u32_le(data, pos)?;
        pos += 4;

        // Offset
        let _tensor_offset = read_u64_le(data, pos)?;
        pos += 8;

        tensors.push(GgufTensorInfo { name, dims, dtype });
    }

    // Display tensors
    if !tensors.is_empty() {
        out.push_str(&format!("\n\u{2500}\u{2500} Tensors ({}) \u{2500}\u{2500}\n", tensors.len()));
        let max_display = 50;
        for (i, t) in tensors.iter().enumerate() {
            if i >= max_display {
                out.push_str(&format!("  ... and {} more\n", tensors.len() - max_display));
                break;
            }
            let dims_str: Vec<String> = t.dims.iter().map(|d| format_size(*d)).collect();
            out.push_str(&format!(
                "  {}: [{}] {}\n",
                t.name,
                dims_str.join(", "),
                ggml_type_name(t.dtype)
            ));
        }

        // Quantization distribution
        let mut type_counts: BTreeMap<&str, usize> = BTreeMap::new();
        for t in &tensors {
            *type_counts.entry(ggml_type_name(t.dtype)).or_insert(0) += 1;
        }
        out.push_str("\n\u{2500}\u{2500} Quantization Distribution \u{2500}\u{2500}\n");
        let mut sorted_types: Vec<_> = type_counts.iter().collect();
        sorted_types.sort_by(|a, b| b.1.cmp(a.1));
        for (tname, count) in &sorted_types {
            out.push_str(&format!("  {}: {} tensors\n", tname, count));
        }
    }

    // Show other metadata (non-parameter keys)
    let shown_keys = [
        "general.architecture", "general.name", "general.file_type",
        "general.quantization_version", "tokenizer.ggml.model",
    ];
    let param_suffixes = [
        ".context_length", ".embedding_length", ".block_count",
        ".attention.head_count", ".attention.head_count_kv", ".vocab_size",
    ];
    let other_meta: Vec<&(String, String)> = metadata.iter()
        .filter(|(k, _)| {
            !shown_keys.contains(&k.as_str())
                && !param_suffixes.iter().any(|s| k.ends_with(s))
        })
        .collect();

    if !other_meta.is_empty() {
        out.push_str(&format!("\n\u{2500}\u{2500} Other Metadata ({}) \u{2500}\u{2500}\n", other_meta.len()));
        for (k, v) in other_meta.iter().take(40) {
            let display_v = if v.len() > 80 {
                format!("{}...", &v[..80])
            } else {
                v.clone()
            };
            out.push_str(&format!("  {k}: {display_v}\n"));
        }
        if other_meta.len() > 40 {
            out.push_str(&format!("  ... and {} more\n", other_meta.len() - 40));
        }
    }

    Ok((out, tensors))
}

// ── 2. safetensors_info ───────────────────────────────────────────

pub fn safetensors_info(graph: &mut Graph, target: &str) -> String {
    register_ml_model(graph, target, "safetensors");
    let data = match load_binary(target) {
        Ok(d) => d,
        Err(e) => return e,
    };
    match parse_safetensors(&data, target) {
        Ok((info, tensors)) => {
            // 5.20.0: each safetensors entry → MlTensor node.
            promote_safetensors_tensors(graph, target, &tensors);
            info
        }
        Err(e) => format!("SafeTensors parse error: {e}"),
    }
}

/// Public-shape safetensors descriptor matching the local TensorEntry
/// inside parse_safetensors. Hoisted to module scope so the promotion
/// helper sees the same struct.
pub(crate) struct SafetensorsTensorInfo {
    pub name: String,
    pub dtype: String,
    pub shape: Vec<u64>,
    pub size_bytes: u64,
}

fn promote_safetensors_tensors(graph: &mut Graph, target: &str,
                               tensors: &[SafetensorsTensorInfo]) {
    use crate::types::EntityKind;
    let model_id = format!("model:{target}");
    for (i, t) in tensors.iter().enumerate().take(MAX_ML_NODES_PER_CALL) {
        let tensor_id = format!("tensor:safetensors:{target}::{i}");
        let shape: Vec<String> = t.shape.iter().map(|d| d.to_string()).collect();
        let shape_str = shape.join(",");
        let size_str = t.size_bytes.to_string();
        let params: u64 = if t.shape.is_empty() { 0 } else { t.shape.iter().product() };
        let params_str = params.to_string();
        graph.ensure_typed_node(&tensor_id, EntityKind::MlTensor, &[
            ("name", t.name.as_str()),
            ("dtype", t.dtype.as_str()),
            ("shape", &shape_str),
            ("model_format", "safetensors"),
            ("size_bytes", &size_str),
            ("params", &params_str),
        ]);
        graph.add_edge(&model_id, &tensor_id);
    }
}

fn dtype_element_size(dtype: &str) -> usize {
    match dtype {
        "F64" => 8,
        "F32" | "I32" | "U32" => 4,
        "F16" | "BF16" | "I16" | "U16" => 2,
        "I8" | "U8" | "BOOL" => 1,
        _ => 0,
    }
}

fn parse_safetensors(data: &[u8], target: &str) -> Result<(String, Vec<SafetensorsTensorInfo>), String> {
    if data.len() < 8 {
        return Err("File too small for SafeTensors".to_string());
    }

    let header_size = read_u64_le(data, 0)? as usize;
    if header_size == 0 || 8 + header_size > data.len() {
        return Err(format!("Invalid header size: {header_size}"));
    }

    // Limit header parsing to reasonable size (100 MB)
    if header_size > 100 * 1024 * 1024 {
        return Err(format!("Header too large: {} bytes", header_size));
    }

    let header_bytes = &data[8..8 + header_size];
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|e| format!("Header is not valid UTF-8: {e}"))?;

    let header: serde_json::Value = serde_json::from_str(header_str)
        .map_err(|e| format!("Header is not valid JSON: {e}"))?;

    let header_obj = header.as_object()
        .ok_or("Header is not a JSON object")?;

    let file_size = fs::metadata(target).map(|m| m.len()).unwrap_or(0);
    let filename = Path::new(target).file_name()
        .and_then(|n| n.to_str()).unwrap_or(target);

    let mut out = String::new();
    out.push_str("=== SafeTensors Info ===\n\n");
    out.push_str(&format!("File: {} ({})\n", filename, format_size_human(file_size)));
    out.push_str(&format!("Header size: {} bytes\n", format_size(header_size as u64)));

    let mut tensors: Vec<SafetensorsTensorInfo> = Vec::new();
    let mut total_params: u64 = 0;
    let mut dtype_counts: BTreeMap<String, usize> = BTreeMap::new();

    for (name, info) in header_obj {
        // Skip __metadata__ key
        if name == "__metadata__" {
            continue;
        }

        let dtype = info.get("dtype")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let shape: Vec<u64> = info.get("shape")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect())
            .unwrap_or_default();

        let offsets = info.get("data_offsets")
            .and_then(|v| v.as_array())
            .map(|arr| {
                let start = arr.first().and_then(|v| v.as_u64()).unwrap_or(0);
                let end = arr.get(1).and_then(|v| v.as_u64()).unwrap_or(0);
                end - start
            })
            .unwrap_or(0);

        let params: u64 = if shape.is_empty() { 0 } else { shape.iter().product() };
        total_params += params;

        let size_bytes = if offsets > 0 {
            offsets
        } else {
            params * dtype_element_size(&dtype) as u64
        };

        *dtype_counts.entry(dtype.clone()).or_insert(0) += 1;

        tensors.push(SafetensorsTensorInfo { name: name.clone(), dtype, shape, size_bytes });
    }

    // Sort tensors by name for consistent display
    tensors.sort_by(|a, b| a.name.cmp(&b.name));

    out.push_str(&format!("Tensors: {}\n", tensors.len()));

    // Display tensors
    if !tensors.is_empty() {
        out.push_str(&"\n\u{2500}\u{2500} Tensors \u{2500}\u{2500}\n".to_string());
        let max_display = 50;
        for (i, t) in tensors.iter().enumerate() {
            if i >= max_display {
                out.push_str(&format!("  ... and {} more\n", tensors.len() - max_display));
                break;
            }
            let shape_str: Vec<String> = t.shape.iter().map(|d| format_size(*d)).collect();
            out.push_str(&format!(
                "  {}: {} [{}] ({})\n",
                t.name,
                t.dtype,
                shape_str.join(", "),
                format_size_human(t.size_bytes)
            ));
        }
    }

    // Summary
    out.push_str("\n\u{2500}\u{2500} Summary \u{2500}\u{2500}\n");
    out.push_str(&format!("  Total parameters: {}\n", format_size(total_params)));

    // Dtype distribution
    let mut sorted_dtypes: Vec<_> = dtype_counts.iter().collect();
    sorted_dtypes.sort_by(|a, b| b.1.cmp(a.1));
    let dtype_strs: Vec<String> = sorted_dtypes.iter()
        .map(|(dt, count)| format!("{} ({})", dt, count))
        .collect();
    out.push_str(&format!("  Dtype distribution: {}\n", dtype_strs.join(", ")));

    // Infer layer count from tensor names
    let mut max_layer: Option<u64> = None;
    for t in &tensors {
        // Match patterns like "model.layers.31." or "blk.31." or "h.31."
        for part in t.name.split('.') {
            if let Ok(n) = part.parse::<u64>() {
                match max_layer {
                    Some(m) if n > m => max_layer = Some(n),
                    None => max_layer = Some(n),
                    _ => {}
                }
            }
        }
    }
    if let Some(max) = max_layer {
        out.push_str(&format!("  Layer count: {} (inferred from tensor names)\n", max + 1));
    }

    // Show metadata if present
    if let Some(meta) = header_obj.get("__metadata__").and_then(|v| v.as_object()) {
        if !meta.is_empty() {
            out.push_str(&"\n\u{2500}\u{2500} Metadata \u{2500}\u{2500}\n".to_string());
            for (k, v) in meta.iter().take(20) {
                let val = v.as_str().unwrap_or(&v.to_string()).to_string();
                let display_v = if val.len() > 80 {
                    format!("{}...", &val[..80])
                } else {
                    val
                };
                out.push_str(&format!("  {k}: {display_v}\n"));
            }
        }
    }

    Ok((out, tensors))
}

// ── 3. onnx_info ──────────────────────────────────────────────────

pub fn onnx_info(graph: &mut Graph, target: &str) -> String {
    register_ml_model(graph, target, "onnx");
    let data = match load_binary(target) {
        Ok(d) => d,
        Err(e) => return e,
    };
    match parse_onnx(&data, target) {
        Ok((info, op_counts, initializer_count)) => {
            // 5.20.0: aggregate ONNX operators by op_type (Conv, MatMul,
            // Add, etc.) so a 1000-node ResNet doesn't generate 1000
            // graph nodes — instead one MlOperator per type with `count`
            // attr. Initializer count attached to the parent MlModel
            // node for cross-model architecture inventory.
            use crate::types::EntityKind;
            let model_id = format!("model:{target}");
            let mut promoted = 0usize;
            for (op_type, count) in &op_counts {
                if promoted >= MAX_ML_NODES_PER_CALL { break; }
                let op_id = format!("ml_op:onnx:{target}::{op_type}");
                let count_str = count.to_string();
                graph.ensure_typed_node(&op_id, EntityKind::MlOperator, &[
                    ("name", op_type.as_str()),
                    ("op_type", op_type.as_str()),
                    ("model_format", "onnx"),
                    ("count_in_model", &count_str),
                ]);
                graph.add_edge(&model_id, &op_id);
                promoted += 1;
            }
            if let Some(node) = graph.nodes.get_mut(&model_id) {
                node.attrs.insert("onnx_initializer_count".into(),
                    initializer_count.to_string());
                node.attrs.insert("onnx_op_type_count".into(),
                    op_counts.len().to_string());
            }
            info
        }
        Err(e) => format!("ONNX parse error: {e}"),
    }
}

/// Decode a protobuf varint, returning (value, bytes_consumed).
fn decode_varint(data: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut i = pos;
    loop {
        if i >= data.len() {
            return Err(format!("Varint truncated at offset 0x{i:X}"));
        }
        let byte = data[i];
        result |= ((byte & 0x7F) as u64) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err("Varint overflow".to_string());
        }
    }
    Ok((result, i - pos))
}

/// Raw protobuf field: (field_number, wire_type, value/offset, consumed_bytes)
struct ProtoField {
    field_number: u64,
    wire_type: u8,
    data_offset: usize,
    data_len: usize,
    varint_value: u64,
}

/// Parse the next protobuf field from data at pos.
/// Returns the field and total bytes consumed (tag + data).
fn parse_proto_field(data: &[u8], pos: usize) -> Result<(ProtoField, usize), String> {
    let (tag, tag_consumed) = decode_varint(data, pos)?;
    let field_number = tag >> 3;
    let wire_type = (tag & 0x7) as u8;
    let after_tag = pos + tag_consumed;

    match wire_type {
        0 => {
            // Varint
            let (value, val_consumed) = decode_varint(data, after_tag)?;
            Ok((ProtoField {
                field_number,
                wire_type,
                data_offset: after_tag,
                data_len: val_consumed,
                varint_value: value,
            }, tag_consumed + val_consumed))
        }
        1 => {
            // 64-bit
            if after_tag + 8 > data.len() {
                return Err("64-bit field truncated".into());
            }
            Ok((ProtoField {
                field_number,
                wire_type,
                data_offset: after_tag,
                data_len: 8,
                varint_value: 0,
            }, tag_consumed + 8))
        }
        2 => {
            // Length-delimited
            let (length, len_consumed) = decode_varint(data, after_tag)?;
            let content_start = after_tag + len_consumed;
            let length = length as usize;
            if content_start + length > data.len() {
                return Err(format!("Length-delimited field truncated at 0x{:X}", content_start));
            }
            Ok((ProtoField {
                field_number,
                wire_type,
                data_offset: content_start,
                data_len: length,
                varint_value: 0,
            }, tag_consumed + len_consumed + length))
        }
        5 => {
            // 32-bit
            if after_tag + 4 > data.len() {
                return Err("32-bit field truncated".into());
            }
            Ok((ProtoField {
                field_number,
                wire_type,
                data_offset: after_tag,
                data_len: 4,
                varint_value: 0,
            }, tag_consumed + 4))
        }
        _ => Err(format!("Unsupported wire type {wire_type} for field {field_number}")),
    }
}

/// Collect all top-level protobuf fields from a message.
fn collect_proto_fields(data: &[u8]) -> Vec<ProtoField> {
    let mut fields = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        match parse_proto_field(data, pos) {
            Ok((field, consumed)) => {
                fields.push(field);
                pos += consumed;
            }
            Err(_) => break,
        }
    }
    fields
}

/// Extract a UTF-8 string from a length-delimited protobuf field.
fn proto_string(data: &[u8], field: &ProtoField) -> Option<String> {
    if field.wire_type != 2 {
        return None;
    }
    let bytes = &data[field.data_offset..field.data_offset + field.data_len];
    String::from_utf8(bytes.to_vec()).ok()
}

fn parse_onnx(data: &[u8], target: &str) -> Result<(String, BTreeMap<String, usize>, u64), String> {
    if data.len() < 4 {
        return Err("File too small for ONNX".to_string());
    }

    let file_size = fs::metadata(target).map(|m| m.len()).unwrap_or(0);
    let filename = Path::new(target).file_name()
        .and_then(|n| n.to_str()).unwrap_or(target);

    let mut out = String::new();
    out.push_str("=== ONNX Model Info ===\n\n");
    out.push_str(&format!("File: {} ({})\n", filename, format_size_human(file_size)));

    // Try to parse as protobuf (ModelProto)
    let fields = collect_proto_fields(data);

    if fields.is_empty() {
        return Err("Could not parse as protobuf".to_string());
    }

    let mut ir_version: Option<u64> = None;
    let mut producer_name: Option<String> = None;
    let mut producer_version: Option<String> = None;
    let mut model_version: Option<u64> = None;
    let mut doc_string: Option<String> = None;
    let mut domain: Option<String> = None;
    let mut opset_versions: Vec<(String, u64)> = Vec::new();
    let mut graph_data: Option<&[u8]> = None;

    for field in &fields {
        match field.field_number {
            1 if field.wire_type == 0 => ir_version = Some(field.varint_value),
            2 if field.wire_type == 2 => producer_name = proto_string(data, field),
            3 if field.wire_type == 2 => producer_version = proto_string(data, field),
            4 if field.wire_type == 2 => domain = proto_string(data, field),
            5 if field.wire_type == 0 => model_version = Some(field.varint_value),
            6 if field.wire_type == 2 => doc_string = proto_string(data, field),
            7 if field.wire_type == 2 => {
                // GraphProto
                graph_data = Some(&data[field.data_offset..field.data_offset + field.data_len]);
            }
            8 if field.wire_type == 2 => {
                // OpsetImport
                let opset_data = &data[field.data_offset..field.data_offset + field.data_len];
                let opset_fields = collect_proto_fields(opset_data);
                let mut op_domain = String::new();
                let mut op_version: u64 = 0;
                for of in &opset_fields {
                    match of.field_number {
                        1 if of.wire_type == 2 => {
                            if let Some(s) = proto_string(opset_data, of) {
                                op_domain = s;
                            }
                        }
                        2 if of.wire_type == 0 => op_version = of.varint_value,
                        _ => {}
                    }
                }
                let display_domain = if op_domain.is_empty() { "ai.onnx".to_string() } else { op_domain };
                opset_versions.push((display_domain, op_version));
            }
            _ => {}
        }
    }

    if let Some(ir) = ir_version {
        out.push_str(&format!("IR Version: {ir}\n"));
    }
    if let (Some(ref pn), Some(ref pv)) = (&producer_name, &producer_version) {
        out.push_str(&format!("Producer: {pn} {pv}\n"));
    } else if let Some(ref pn) = producer_name {
        out.push_str(&format!("Producer: {pn}\n"));
    }
    if let Some(ref d) = domain {
        if !d.is_empty() {
            out.push_str(&format!("Domain: {d}\n"));
        }
    }
    if let Some(mv) = model_version {
        if mv > 0 {
            out.push_str(&format!("Model Version: {mv}\n"));
        }
    }
    if let Some(ref ds) = doc_string {
        if !ds.is_empty() {
            let display = if ds.len() > 120 { format!("{}...", &ds[..120]) } else { ds.clone() };
            out.push_str(&format!("Doc: {display}\n"));
        }
    }

    // Opsets
    if !opset_versions.is_empty() {
        let opset_strs: Vec<String> = opset_versions.iter()
            .map(|(d, v)| format!("{d} v{v}"))
            .collect();
        out.push_str(&format!("Opset: {}\n", opset_strs.join(", ")));
    }

    // 5.20.0: hoisted out of the inner if-let so the return value can
    // expose op_counts + initializer_count to the public onnx_info
    // function for graph-node promotion. Empty when no graph proto present.
    let mut op_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut initializer_count = 0u64;

    // Parse graph
    if let Some(gdata) = graph_data {
        let gfields = collect_proto_fields(gdata);

        let mut graph_name: Option<String> = None;
        let mut node_count = 0u64;
        let mut input_names: Vec<String> = Vec::new();
        let mut output_names: Vec<String> = Vec::new();

        for gf in &gfields {
            match gf.field_number {
                1 if gf.wire_type == 2 => {
                    // NodeProto
                    node_count += 1;
                    let node_data = &gdata[gf.data_offset..gf.data_offset + gf.data_len];
                    let nfields = collect_proto_fields(node_data);
                    for nf in &nfields {
                        // op_type is field 4 in NodeProto
                        if nf.field_number == 4 && nf.wire_type == 2 {
                            if let Some(op) = proto_string(node_data, nf) {
                                *op_counts.entry(op).or_insert(0) += 1;
                            }
                        }
                    }
                }
                2 if gf.wire_type == 2 => {
                    // Graph name
                    graph_name = proto_string(gdata, gf);
                }
                5 if gf.wire_type == 2 => {
                    // Input (ValueInfoProto) - field 1 is name
                    let vi_data = &gdata[gf.data_offset..gf.data_offset + gf.data_len];
                    let vi_fields = collect_proto_fields(vi_data);
                    for vf in &vi_fields {
                        if vf.field_number == 1 && vf.wire_type == 2 {
                            if let Some(name) = proto_string(vi_data, vf) {
                                input_names.push(name);
                            }
                        }
                    }
                }
                11 if gf.wire_type == 2 => {
                    // Initializer (TensorProto)
                    initializer_count += 1;
                }
                12 if gf.wire_type == 2 => {
                    // Output (ValueInfoProto)
                    let vi_data = &gdata[gf.data_offset..gf.data_offset + gf.data_len];
                    let vi_fields = collect_proto_fields(vi_data);
                    for vf in &vi_fields {
                        if vf.field_number == 1 && vf.wire_type == 2 {
                            if let Some(name) = proto_string(vi_data, vf) {
                                output_names.push(name);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        out.push_str("\n\u{2500}\u{2500} Graph \u{2500}\u{2500}\n");
        if let Some(ref gn) = graph_name {
            if !gn.is_empty() {
                out.push_str(&format!("  Name: {gn}\n"));
            }
        }
        out.push_str(&format!("  Nodes: {node_count}\n"));
        out.push_str(&format!("  Initializers: {initializer_count}\n"));

        // Filter inputs: only show actual graph inputs (not initializers)
        // Inputs that also appear as initializers are weights, not true inputs
        if !input_names.is_empty() {
            out.push_str(&format!("  Inputs: {}\n", input_names.len()));
            for name in input_names.iter().take(10) {
                out.push_str(&format!("    {name}\n"));
            }
            if input_names.len() > 10 {
                out.push_str(&format!("    ... and {} more\n", input_names.len() - 10));
            }
        }
        if !output_names.is_empty() {
            out.push_str(&format!("  Outputs: {}\n", output_names.len()));
            for name in output_names.iter().take(10) {
                out.push_str(&format!("    {name}\n"));
            }
            if output_names.len() > 10 {
                out.push_str(&format!("    ... and {} more\n", output_names.len() - 10));
            }
        }

        // Operations
        if !op_counts.is_empty() {
            out.push_str(&format!("\n\u{2500}\u{2500} Operations ({} types) \u{2500}\u{2500}\n", op_counts.len()));
            let mut sorted_ops: Vec<_> = op_counts.iter().collect();
            sorted_ops.sort_by(|a, b| b.1.cmp(a.1));
            for (op, count) in sorted_ops.iter().take(30) {
                out.push_str(&format!("  {}: {count}\n", op));
            }
            if sorted_ops.len() > 30 {
                out.push_str(&format!("  ... and {} more op types\n", sorted_ops.len() - 30));
            }
        }
    }

    Ok((out, op_counts, initializer_count))
}

// ── 4. pyc_info ───────────────────────────────────────────────────

pub fn pyc_info(graph: &mut Graph, target: &str) -> String {
    register_ml_model(graph, target, "pyc");
    let data = match load_binary(target) {
        Ok(d) => d,
        Err(e) => return e,
    };
    // 5.15.1: walk the marshal stream looking for code objects;
    // register each as a BinaryFunction node hanging off the pyc
    // module. Minimal extraction (flat — no recursive children).
    walk_pyc_code_objects_for_graph(graph, target, &data);
    match parse_pyc(&data, target) {
        Ok(info) => info,
        Err(e) => format!("PYC parse error: {e}"),
    }
}

/// Recursive Python marshal walker. Replaces 5.15.1's heuristic byte-scan,
/// which mistook the first nearby identifier-shaped string for the function
/// name and routinely registered `co_varnames[0]` (= `self` / `cls`) as a
/// function. This walker decodes the marshal stream properly, so `co_name`
/// is read from its actual position in the CODE-object layout.
///
/// Walks the module-level CODE object recursively; nested CODE objects
/// embedded in `co_consts` surface inner functions, methods, and class
/// bodies. Lambdas and comprehensions appear as `<lambda>` / `<listcomp>` /
/// etc. and are filtered out (synthetic compiler names — not user-named).
fn walk_pyc_code_objects_for_graph(graph: &mut crate::types::Graph, target: &str, data: &[u8]) {
    use crate::types::EntityKind;
    let module_id = format!("model:{target}");
    if data.len() < 17 { return; }

    let magic = u16::from_le_bytes([data[0], data[1]]);
    let layout = pyc_magic_to_layout(magic);
    if layout == PycLayout::Unknown { return; }

    // PEP 3147 (3.3+) header is 12 bytes; PEP 552 (3.7+) extends to 16.
    // 2.x predates PEP 3147 and uses an 8-byte header (magic + timestamp).
    let header_size = if layout == PycLayout::Py27 { 8 } else { 16 };
    if data.len() <= header_size { return; }

    let mut funcs: Vec<(String, usize, u32)> = Vec::new();
    let mut reader = MarshalReader::new(&data[header_size..], layout, header_size);
    let _ = reader.read_value(&mut funcs);

    for (i, (name, offset, argcount)) in funcs.into_iter().enumerate().take(2000) {
        // Skip synthetic CPython names (`<module>`, `<lambda>`, `<listcomp>`,
        // `<genexpr>`, `<dictcomp>`, `<setcomp>`) — not user-defined functions.
        if name.starts_with('<') { continue; }
        let func_id = format!("bin_func:pyc:{target}::{i}");
        let arg_str = argcount.to_string();
        let off_str = format!("{offset:#x}");
        graph.ensure_typed_node(&func_id, EntityKind::BinaryFunction, &[
            ("name", &name),
            ("binary_format", "pyc"),
            ("kind_detail", "function"),
            ("argcount", &arg_str),
            ("offset", &off_str),
        ]);
        graph.add_edge(&module_id, &func_id);
    }
}

/// CODE-object header layout — varies by Python release.
/// See CPython `Python/marshal.c` `r_object()` for the canonical reader.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PycLayout {
    Py27,         // argcount, nlocals, stacksize, flags                                       (4 u32)
    Py34To37,     // argcount, kwonlyargcount, nlocals, stacksize, flags                       (5 u32)
    Py38To310,    // argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize, flags      (6 u32)
    Py311Plus,    // argcount, posonlyargcount, kwonlyargcount, stacksize, flags + qualname/exctab (5 u32)
    Unknown,
}

fn pyc_magic_to_layout(magic: u16) -> PycLayout {
    match magic {
        62211 => PycLayout::Py27,
        3250..=3399 => PycLayout::Py34To37,   // 3.4 - 3.7
        3400..=3439 => PycLayout::Py38To310,  // 3.8 - 3.10
        3440..=3699 => PycLayout::Py311Plus,  // 3.11+
        _ => PycLayout::Unknown,
    }
}

/// Lightweight marshal value. We only materialize what's needed to track
/// back-references and capture function names — every other payload is
/// consumed-and-discarded to keep memory + cycles down on large pycs.
#[derive(Clone)]
enum MV {
    Atom,
    Str(String),
}

struct MarshalReader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Reference table — Python 3.4+ uses FLAG_REF (0x80) on a type byte to
    /// indicate "store this object so a later TYPE_REF can point back to it".
    /// Slot ordering must be preserved even for non-string objects.
    refs: Vec<MV>,
    layout: PycLayout,
    /// Offset of `data` inside the original pyc file (for offset reporting).
    base_offset: usize,
    depth: usize,
}

const MAX_MARSHAL_DEPTH: usize = 256;

impl<'a> MarshalReader<'a> {
    fn new(data: &'a [u8], layout: PycLayout, base_offset: usize) -> Self {
        Self {
            data, pos: 0,
            refs: Vec::with_capacity(256),
            layout, base_offset, depth: 0,
        }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.data.len() { return None; }
        let v = u32::from_le_bytes([
            self.data[self.pos], self.data[self.pos + 1],
            self.data[self.pos + 2], self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Some(v)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        if end > self.data.len() { return None; }
        self.pos = end;
        Some(())
    }

    fn read_str(&mut self, n: usize) -> Option<String> {
        let end = self.pos.checked_add(n)?;
        if end > self.data.len() { return None; }
        let s = String::from_utf8_lossy(&self.data[self.pos..end]).into_owned();
        self.pos = end;
        Some(s)
    }

    /// Read one marshal value. Records (name, offset, argcount) for every
    /// CODE object encountered (recursively, so nested functions surface).
    fn read_value(&mut self, out: &mut Vec<(String, usize, u32)>) -> Option<MV> {
        if self.depth >= MAX_MARSHAL_DEPTH { return None; }
        self.depth += 1;
        let res = self.read_value_inner(out);
        self.depth -= 1;
        res
    }

    fn read_value_inner(&mut self, out: &mut Vec<(String, usize, u32)>) -> Option<MV> {
        let type_byte = self.read_u8()?;
        let has_ref_flag = type_byte & 0x80 != 0;
        let typ = type_byte & 0x7F;

        // Reserve refs slot up front — TYPE_REF indices are assigned in the
        // order FLAG_REF values appear in the stream, so the slot must exist
        // before we recurse into nested values.
        let ref_slot = if has_ref_flag {
            let idx = self.refs.len();
            self.refs.push(MV::Atom);
            Some(idx)
        } else { None };

        let value = match typ {
            // Singletons / no payload
            b'0' | b'N' | b'F' | b'T' | b'S' | b'.' => MV::Atom,
            // 4-byte int
            b'i' => { self.skip(4)?; MV::Atom }
            // 8-byte int (deprecated)
            b'I' => { self.skip(8)?; MV::Atom }
            // ascii float (deprecated): 1-byte len + ascii digits
            b'f' => { let n = self.read_u8()? as usize; self.skip(n)?; MV::Atom }
            // 8-byte IEEE 754 binary float
            b'g' => { self.skip(8)?; MV::Atom }
            // ascii complex: two ascii floats back-to-back
            b'x' => {
                let n = self.read_u8()? as usize; self.skip(n)?;
                let n = self.read_u8()? as usize; self.skip(n)?;
                MV::Atom
            }
            // 16-byte binary complex
            b'y' => { self.skip(16)?; MV::Atom }
            // long: 4-byte signed digit count, abs(n) * 2 bytes payload
            b'l' => {
                let n = self.read_u32()? as i32;
                self.skip(n.unsigned_abs() as usize * 2)?;
                MV::Atom
            }
            // 4-byte length strings: TYPE_STRING/INTERNED/UNICODE/ASCII/ASCII_INTERNED
            b's' | b't' | b'u' | b'a' | b'A' => {
                let n = self.read_u32()? as usize;
                if n > self.data.len().saturating_sub(self.pos) { return None; }
                MV::Str(self.read_str(n)?)
            }
            // 1-byte length strings: TYPE_SHORT_ASCII / SHORT_ASCII_INTERNED
            b'z' | b'Z' => {
                let n = self.read_u8()? as usize;
                MV::Str(self.read_str(n)?)
            }
            // back-reference into the refs table
            b'r' => {
                let idx = self.read_u32()? as usize;
                match self.refs.get(idx) {
                    Some(MV::Str(s)) => MV::Str(s.clone()),
                    _ => MV::Atom,
                }
            }
            // STRINGREF (Python 2): 4-byte index — we don't use it.
            b'R' => { self.skip(4)?; MV::Atom }
            // tuple, list, set, frozenset (4-byte length)
            b'(' | b'[' | b'<' | b'>' => {
                let n = self.read_u32()? as usize;
                if n > self.data.len() { return None; }
                for _ in 0..n {
                    self.read_value(out)?;
                }
                MV::Atom
            }
            // small tuple (Python 3.4+, 1-byte length)
            b')' => {
                let n = self.read_u8()? as usize;
                for _ in 0..n {
                    self.read_value(out)?;
                }
                MV::Atom
            }
            // dict: alternating key/value pairs, terminated by TYPE_NULL (0x30)
            b'{' => {
                while self.pos < self.data.len() {
                    if self.data[self.pos] == 0x30 {
                        self.pos += 1;
                        break;
                    }
                    self.read_value(out)?;  // key
                    self.read_value(out)?;  // value
                }
                MV::Atom
            }
            // CODE OBJECT — the prize.
            b'c' => {
                let code_offset = self.base_offset + self.pos - 1;
                let argcount = self.read_u32()?;
                match self.layout {
                    // Header tail (after argcount):
                    PycLayout::Py27       => self.skip(4 * 3)?,  // nlocals, stacksize, flags
                    PycLayout::Py34To37   => self.skip(4 * 4)?,  // kwonlyargcount, nlocals, stacksize, flags
                    PycLayout::Py38To310  => self.skip(4 * 5)?,  // posonlyargcount, kwonlyargcount, nlocals, stacksize, flags
                    PycLayout::Py311Plus  => self.skip(4 * 4)?,  // posonlyargcount, kwonlyargcount, stacksize, flags
                    PycLayout::Unknown    => return None,
                };
                self.read_value(out)?;       // co_code (bytes)
                self.read_value(out)?;       // co_consts — recurses into nested CODE objects
                self.read_value(out)?;       // co_names

                if self.layout == PycLayout::Py311Plus {
                    self.read_value(out)?;   // co_localsplusnames
                    self.read_value(out)?;   // co_localspluskinds
                } else {
                    self.read_value(out)?;   // co_varnames  ← v1 heuristic mistook this for co_name
                    self.read_value(out)?;   // co_freevars
                    self.read_value(out)?;   // co_cellvars
                }

                self.read_value(out)?;       // co_filename
                let name_v = self.read_value(out)?;   // co_name — the actual function name
                if self.layout == PycLayout::Py311Plus {
                    self.read_value(out)?;   // co_qualname
                }
                self.skip(4)?;               // firstlineno
                self.read_value(out)?;       // lnotab / linetable
                if self.layout == PycLayout::Py311Plus {
                    self.read_value(out)?;   // exceptiontable
                }

                if let MV::Str(name) = &name_v {
                    out.push((name.clone(), code_offset, argcount));
                }
                MV::Atom
            }
            // Unknown type byte — bail out rather than mis-read the rest.
            _ => return None,
        };

        if let Some(idx) = ref_slot {
            if let MV::Str(_) = &value {
                self.refs[idx] = value.clone();
            }
        }
        Some(value)
    }
}

fn pyc_magic_to_version(magic: u16) -> &'static str {
    match magic {
        // Python 2.x
        62211 => "2.7",
        // Python 3.x
        3250..=3259 => "3.4",
        3310..=3319 => "3.5",
        3370..=3379 => "3.6",
        3390..=3399 => "3.7",
        3400..=3413 => "3.8",
        3414..=3424 => "3.9",
        3425..=3439 => "3.10",
        3440..=3499 => "3.11",
        3500..=3539 => "3.12",
        3540..=3599 => "3.13",
        3600..=3649 => "3.14",
        _ => "Unknown",
    }
}

/// Extract printable strings from marshalled code data.
/// Looks for marshal string objects (type 's', 'z', 'Z') and unicode ('u', 't').
fn extract_marshal_strings(data: &[u8]) -> (Vec<String>, Vec<String>) {
    let mut string_constants = Vec::new();
    let mut names = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let type_byte = data[pos];
        // Strip the FLAG_REF bit (0x80)
        let base_type = type_byte & 0x7F;

        match base_type {
            // Short ASCII string (type 'z' = 0x7A): 1-byte length
            0x7A => {
                pos += 1;
                if pos >= data.len() { break; }
                let len = data[pos] as usize;
                pos += 1;
                if pos + len > data.len() { break; }
                if let Ok(s) = std::str::from_utf8(&data[pos..pos + len]) {
                    let s = s.to_string();
                    if !s.is_empty() && s.len() > 1 {
                        categorize_string(&s, &mut string_constants, &mut names);
                    }
                }
                pos += len;
            }
            // String (type 's' = 0x73) or Unicode (type 'u' = 0x75): 4-byte length
            0x73 | 0x75 => {
                pos += 1;
                if pos + 4 > data.len() { break; }
                let len = read_u32_le(data, pos).unwrap_or(0) as usize;
                pos += 4;
                if len > 10000 || pos + len > data.len() { pos = pos.saturating_add(len.min(data.len())); continue; }
                if let Ok(s) = std::str::from_utf8(&data[pos..pos + len]) {
                    let s = s.to_string();
                    if !s.is_empty() && s.len() > 1 {
                        categorize_string(&s, &mut string_constants, &mut names);
                    }
                }
                pos += len;
            }
            // Short ASCII interned (type 'Z' = 0x5A): 1-byte length
            0x5A => {
                pos += 1;
                if pos >= data.len() { break; }
                let len = data[pos] as usize;
                pos += 1;
                if pos + len > data.len() { break; }
                if let Ok(s) = std::str::from_utf8(&data[pos..pos + len]) {
                    let s = s.to_string();
                    if !s.is_empty() && s.len() > 1 {
                        categorize_string(&s, &mut string_constants, &mut names);
                    }
                }
                pos += len;
            }
            // Interned string (type 't' = 0x74): 4-byte length
            0x74 => {
                pos += 1;
                if pos + 4 > data.len() { break; }
                let len = read_u32_le(data, pos).unwrap_or(0) as usize;
                pos += 4;
                if len > 10000 || pos + len > data.len() { pos = pos.saturating_add(len.min(data.len())); continue; }
                if let Ok(s) = std::str::from_utf8(&data[pos..pos + len]) {
                    let s = s.to_string();
                    if !s.is_empty() && s.len() > 1 {
                        categorize_string(&s, &mut string_constants, &mut names);
                    }
                }
                pos += len;
            }
            _ => {
                pos += 1;
            }
        }
    }

    // Deduplicate
    string_constants.sort();
    string_constants.dedup();
    names.sort();
    names.dedup();

    (string_constants, names)
}

fn categorize_string(s: &str, constants: &mut Vec<String>, names: &mut Vec<String>) {
    // Skip dunder names and empty-like strings
    if s.starts_with("__") && s.ends_with("__") && s.len() > 4 {
        return;
    }
    // Skip single characters
    if s.len() <= 1 {
        return;
    }

    // Looks like a module/import name
    let is_identifier = s.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.');
    if is_identifier && !s.starts_with('.') && !s.ends_with('.') {
        // Common Python standard library modules or looks like a name
        if s.contains('.') || s.chars().next().is_some_and(|c| c.is_lowercase()) {
            names.push(s.to_string());
        } else if s.chars().next().is_some_and(|c| c.is_uppercase()) {
            names.push(s.to_string());
        } else {
            constants.push(format!("\"{}\"", s));
        }
    } else if s.len() >= 3 {
        constants.push(format!("\"{}\"", s));
    }
}

fn parse_pyc(data: &[u8], target: &str) -> Result<String, String> {
    if data.len() < 16 {
        return Err("File too small for Python bytecode".to_string());
    }

    let magic = read_u16_le(data, 0)?;
    let python_version = pyc_magic_to_version(magic);

    let filename = Path::new(target).file_name()
        .and_then(|n| n.to_str()).unwrap_or(target);

    let mut out = String::new();
    out.push_str("=== Python Bytecode Info ===\n\n");
    out.push_str(&format!("File: {filename}\n"));
    out.push_str(&format!("Python version: {python_version} (magic: {magic})\n"));

    // Bytes 2-3 should be 0x0D0A (\r\n)
    let flags = read_u32_le(data, 4)?;
    let mut header_size = 8;

    if flags & 0x1 == 0 {
        // Timestamp-based
        if data.len() >= 16 {
            let timestamp = read_u32_le(data, 8)?;
            let source_size = read_u32_le(data, 12)?;
            // Format timestamp
            let secs = timestamp as u64;
            // Simple date formatting (Unix epoch)
            out.push_str(&format!("Timestamp: {} (unix)\n", secs));
            out.push_str(&format!("Source size: {} bytes\n", format_size(source_size as u64)));
            header_size = 16;
        }
    } else {
        // Hash-based (PEP 552)
        out.push_str("Invalidation: hash-based\n");
        header_size = 16;
    }

    let file_size = fs::metadata(target).map(|m| m.len()).unwrap_or(0);
    out.push_str(&format!("Bytecode size: {} bytes\n", format_size(file_size)));

    // Extract strings from the marshalled code object
    if header_size < data.len() {
        let code_data = &data[header_size..];
        let (constants, names) = extract_marshal_strings(code_data);

        if !constants.is_empty() {
            out.push_str(&format!("\n\u{2500}\u{2500} String Constants ({}) \u{2500}\u{2500}\n", constants.len()));
            for s in constants.iter().take(50) {
                let display = if s.len() > 80 {
                    format!("{}...\"", &s[..77])
                } else {
                    s.clone()
                };
                out.push_str(&format!("  {display}\n"));
            }
            if constants.len() > 50 {
                out.push_str(&format!("  ... and {} more\n", constants.len() - 50));
            }
        }

        if !names.is_empty() {
            out.push_str(&format!("\n\u{2500}\u{2500} Names Referenced ({}) \u{2500}\u{2500}\n", names.len()));
            for s in names.iter().take(80) {
                out.push_str(&format!("  {s}\n"));
            }
            if names.len() > 80 {
                out.push_str(&format!("  ... and {} more\n", names.len() - 80));
            }
        }
    }

    Ok(out)
}

// ── 5. cuda_info ──────────────────────────────────────────────────

pub fn cuda_info(graph: &mut Graph, target: &str) -> String {
    use crate::types::EntityKind;
    register_ml_model(graph, target, "cuda");
    let data = match load_binary(target) {
        Ok(d) => d,
        Err(e) => return e,
    };
    // 5.17.0: each CUDA kernel is a function in the cubin — promote to a
    // BinaryFunction node so kernels participate in centrality / meta-path
    // queries the same way java/wasm/dotnet/pyc functions do. Reuses the
    // existing BinaryFunction kind via attrs["binary_format"]="cuda".
    if let Ok((kernels, sm)) = extract_cuda_kernels_from_elf(&data) {
        let module_id = format!("model:{target}");
        let sm_str = sm.to_string();
        let arch = sm_arch_name(sm);
        for (i, kernel) in kernels.iter().enumerate().take(2000) {
            let func_id = format!("bin_func:cuda:{target}::{i}");
            graph.ensure_typed_node(&func_id, EntityKind::BinaryFunction, &[
                ("name", kernel),
                ("binary_format", "cuda"),
                ("kind_detail", "kernel"),
                ("sm", &sm_str),
                ("sm_arch", arch),
            ]);
            graph.add_edge(&module_id, &func_id);
        }
    }
    match parse_cuda(&data, target) {
        Ok(info) => info,
        Err(e) => format!("CUDA binary parse error: {e}"),
    }
}

fn sm_arch_name(sm: u32) -> &'static str {
    match sm {
        20 | 21 => "Fermi",
        30 | 32 | 35 | 37 => "Kepler",
        50 | 52 | 53 => "Maxwell",
        60..=62 => "Pascal",
        70 | 72 => "Volta",
        75 => "Turing",
        80 | 86 | 87 => "Ampere",
        89 => "Ada Lovelace",
        90 | 100 => "Hopper",
        120 => "Blackwell",
        _ => "Unknown",
    }
}

/// Extract kernel names from ELF sections (cubin).
/// CUDA kernels have sections named `.text.<kernel_name>`.
fn extract_cuda_kernels_from_elf(data: &[u8]) -> Result<(Vec<String>, u32), String> {
    // Verify ELF magic
    if data.len() < 64 || data[0] != 0x7F || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
        return Err("Not an ELF file".into());
    }

    let class = data[4];
    let is_64 = class == 2;

    // Extract architecture from ELF flags (machine-specific)
    let e_flags = if is_64 {
        read_u32_le(data, 48)?
    } else {
        read_u32_le(data, 36)?
    };
    // CUDA encodes SM version in e_flags bits
    let sm = e_flags & 0xFF;

    let (sh_off, sh_entsize, sh_num, sh_strndx) = if is_64 {
        let sh_off = read_u64_le(data, 40)? as usize;
        let sh_entsize = read_u16_le(data, 58)? as usize;
        let sh_num = read_u16_le(data, 60)? as usize;
        let sh_strndx = read_u16_le(data, 62)? as usize;
        (sh_off, sh_entsize, sh_num, sh_strndx)
    } else {
        let sh_off = read_u32_le(data, 32)? as usize;
        let sh_entsize = read_u16_le(data, 46)? as usize;
        let sh_num = read_u16_le(data, 48)? as usize;
        let sh_strndx = read_u16_le(data, 50)? as usize;
        (sh_off, sh_entsize, sh_num, sh_strndx)
    };

    // Read section header string table
    let shstrtab = read_elf_shstrtab(data, sh_off, sh_entsize, sh_strndx, is_64)?;

    let mut kernels = Vec::new();

    for i in 0..sh_num {
        let base = sh_off + i * sh_entsize;
        if base + sh_entsize > data.len() { break; }

        let name_idx = read_u32_le(data, base)? as usize;
        if name_idx < shstrtab.len() {
            let name = read_cstring(&shstrtab, name_idx);
            if let Some(kernel_name) = name.strip_prefix(".text.") {
                if !kernel_name.is_empty() {
                    kernels.push(kernel_name.to_string());
                }
            }
        }
    }

    Ok((kernels, sm))
}

fn read_elf_shstrtab(
    data: &[u8], sh_off: usize, sh_entsize: usize, sh_strndx: usize, is_64: bool,
) -> Result<Vec<u8>, String> {
    let base = sh_off + sh_strndx * sh_entsize;
    if base + sh_entsize > data.len() {
        return Err("Section header string table out of bounds".to_string());
    }
    let (offset, size) = if is_64 {
        let offset = read_u64_le(data, base + 24)? as usize;
        let size = read_u64_le(data, base + 32)? as usize;
        (offset, size)
    } else {
        let offset = read_u32_le(data, base + 16)? as usize;
        let size = read_u32_le(data, base + 20)? as usize;
        (offset, size)
    };
    if offset + size > data.len() {
        return Err("Section header string data out of bounds".to_string());
    }
    Ok(data[offset..offset + size].to_vec())
}

fn parse_cuda(data: &[u8], target: &str) -> Result<String, String> {
    if data.len() < 8 {
        return Err("File too small".to_string());
    }

    let file_size = fs::metadata(target).map(|m| m.len()).unwrap_or(0);
    let filename = Path::new(target).file_name()
        .and_then(|n| n.to_str()).unwrap_or(target);

    let mut out = String::new();

    // Check if it's an ELF (cubin)
    if data[0] == 0x7F && data[1] == b'E' && data[2] == b'L' && data[3] == b'F' {
        out.push_str("=== CUDA Binary Info ===\n\n");
        out.push_str(&format!("File: {} ({})\n", filename, format_size_human(file_size)));
        out.push_str("Type: cubin (ELF)\n");

        match extract_cuda_kernels_from_elf(data) {
            Ok((kernels, sm)) => {
                out.push_str(&format!("Architecture: sm_{sm} ({})\n", sm_arch_name(sm)));
                if !kernels.is_empty() {
                    out.push_str(&format!("\n\u{2500}\u{2500} Kernels ({}) \u{2500}\u{2500}\n", kernels.len()));
                    for k in kernels.iter().take(100) {
                        out.push_str(&format!("  {k}\n"));
                    }
                    if kernels.len() > 100 {
                        out.push_str(&format!("  ... and {} more\n", kernels.len() - 100));
                    }
                } else {
                    out.push_str("\nNo kernel sections found.\n");
                }
            }
            Err(e) => {
                out.push_str(&format!("\nELF parse error: {e}\n"));
            }
        }
        return Ok(out);
    }

    // Check for fatbin magic: 0x466243BA (little-endian: BA 42 63 46 => but read as LE u32)
    // Actually the fatbin magic bytes in file order are: BA 43 62 46
    let magic = read_u32_le(data, 0)?;
    if magic != 0x466243BA {
        // Try alternative: maybe it's a different fatbin header
        // Some fatbin files start with __NV_FATBIN or similar
        // Fall back to scanning for embedded ELF or PTX
        return parse_cuda_fallback(data, filename, file_size);
    }

    // Fatbin header
    out.push_str("=== CUDA Binary Info ===\n\n");
    out.push_str(&format!("File: {} ({})\n", filename, format_size_human(file_size)));
    out.push_str("Type: fatbin\n");

    let fatbin_version = read_u16_le(data, 4)?;
    let header_size = read_u16_le(data, 6)? as usize;
    let _total_size = read_u64_le(data, 8)?;

    out.push_str(&format!("Version: {fatbin_version}\n"));

    // Parse entries after the header
    let mut pos = header_size;
    let mut entry_num = 0u32;

    while pos + 24 <= data.len() {
        // Check for entry header
        // Fatbin entry: kind(u16), version(u16), header_size(u32), padded_size(u64), ...
        let kind = read_u16_le(data, pos)?;
        let _entry_version = read_u16_le(data, pos + 2)?;
        let entry_header_size = read_u32_le(data, pos + 4)? as usize;
        let padded_size = read_u64_le(data, pos + 8)? as usize;

        // Validate
        if kind == 0 && padded_size == 0 {
            break; // End of entries
        }
        if entry_header_size == 0 || pos + entry_header_size + padded_size > data.len() {
            break;
        }

        entry_num += 1;

        // Try to read arch from the entry header (offset varies but commonly at offset 28-30)
        let arch = if pos + 30 <= data.len() {
            // The SM version is at different offsets depending on fatbin format
            // Try common locations
            let sm_try = read_u32_le(data, pos + 28).unwrap_or(0);
            if sm_try > 0 && sm_try < 200 {
                sm_try
            } else {
                let sm_try2 = read_u16_le(data, pos + 28).unwrap_or(0) as u32;
                if sm_try2 > 0 && sm_try2 < 200 { sm_try2 } else { 0 }
            }
        } else {
            0
        };

        let kind_str = match kind {
            1 => "PTX text",
            2 => "ELF (cubin)",
            _ => "Unknown",
        };

        let arch_str = if arch > 0 {
            format!("sm_{arch} ({})", sm_arch_name(arch))
        } else {
            "unknown".to_string()
        };

        out.push_str(&format!("\n\u{2500}\u{2500} Entry {entry_num}: {arch_str} \u{2500}\u{2500}\n"));
        out.push_str(&format!("  Type: {kind_str}\n"));
        out.push_str(&format!("  Size: {}\n", format_size_human(padded_size as u64)));

        if kind == 2 {
            // ELF entry - try to extract kernel names
            let elf_start = pos + entry_header_size;
            let elf_end = (elf_start + padded_size).min(data.len());
            if elf_end > elf_start {
                let elf_data = &data[elf_start..elf_end];
                if elf_data.len() >= 4 && elf_data[0] == 0x7F && elf_data[1] == b'E' {
                    if let Ok((kernels, _)) = extract_cuda_kernels_from_elf(elf_data) {
                        if !kernels.is_empty() {
                            out.push_str(&format!("  Kernels ({}):\n", kernels.len()));
                            for k in kernels.iter().take(20) {
                                out.push_str(&format!("    {k}\n"));
                            }
                            if kernels.len() > 20 {
                                out.push_str(&format!("    ... and {} more\n", kernels.len() - 20));
                            }
                        }
                    }
                }
            }
        } else if kind == 1 {
            // PTX text entry
            let ptx_start = pos + entry_header_size;
            let ptx_end = (ptx_start + padded_size).min(data.len());
            if ptx_end > ptx_start {
                let ptx_data = &data[ptx_start..ptx_end];
                // Try to find kernel declarations: .entry <kernel_name>
                let ptx_str = String::from_utf8_lossy(ptx_data);
                let mut ptx_kernels = Vec::new();
                for line in ptx_str.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with(".entry") || trimmed.starts_with(".visible .entry") {
                        // Extract kernel name
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if let Some(name) = parts.iter().find(|p| !p.starts_with('.')) {
                            let clean = name.trim_end_matches('(').trim_end_matches(')');
                            if !clean.is_empty() {
                                ptx_kernels.push(clean.to_string());
                            }
                        }
                    }
                }
                if !ptx_kernels.is_empty() {
                    out.push_str(&format!("  Kernels ({}):\n", ptx_kernels.len()));
                    for k in ptx_kernels.iter().take(20) {
                        out.push_str(&format!("    {k}\n"));
                    }
                }
            }
        }

        pos += entry_header_size + padded_size;
        // Align to 8 bytes
        pos = (pos + 7) & !7;
    }

    if entry_num == 0 {
        out.push_str("\nNo entries found.\n");
    } else {
        out.push_str(&format!("\nTotal entries: {entry_num}\n"));
    }

    Ok(out)
}

/// Fallback parsing for unrecognized CUDA binary formats.
/// Scans for embedded ELF sections and PTX text.
fn parse_cuda_fallback(data: &[u8], filename: &str, file_size: u64) -> Result<String, String> {
    let mut out = String::new();
    out.push_str("=== CUDA Binary Info ===\n\n");
    out.push_str(&format!("File: {} ({})\n", filename, format_size_human(file_size)));
    out.push_str("Type: unknown CUDA format\n");

    // Scan for embedded ELF headers
    let mut elf_offsets: Vec<usize> = Vec::new();
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0x7F && data[i + 1] == b'E' && data[i + 2] == b'L' && data[i + 3] == b'F' {
            elf_offsets.push(i);
        }
    }

    if !elf_offsets.is_empty() {
        out.push_str(&format!("\nEmbedded ELF sections: {}\n", elf_offsets.len()));
        for (idx, &offset) in elf_offsets.iter().enumerate().take(10) {
            out.push_str(&format!("\n\u{2500}\u{2500} ELF at offset 0x{offset:X} \u{2500}\u{2500}\n"));
            let remaining = &data[offset..];
            match extract_cuda_kernels_from_elf(remaining) {
                Ok((kernels, sm)) => {
                    if sm > 0 {
                        out.push_str(&format!("  Architecture: sm_{sm} ({})\n", sm_arch_name(sm)));
                    }
                    if !kernels.is_empty() {
                        out.push_str(&format!("  Kernels ({}):\n", kernels.len()));
                        for k in kernels.iter().take(20) {
                            out.push_str(&format!("    {k}\n"));
                        }
                    }
                }
                Err(e) => {
                    out.push_str(&format!("  Parse error: {e}\n"));
                }
            }
            if idx >= 9 && elf_offsets.len() > 10 {
                out.push_str(&format!("\n... and {} more embedded ELFs\n", elf_offsets.len() - 10));
            }
        }
    }

    // Scan for PTX markers
    let data_str = String::from_utf8_lossy(data);
    if data_str.contains(".entry") || data_str.contains(".version") {
        out.push_str("\nPTX text detected in file.\n");
        let mut ptx_kernels = Vec::new();
        for line in data_str.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(".entry") || trimmed.starts_with(".visible .entry") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if let Some(name) = parts.iter().find(|p| !p.starts_with('.')) {
                    let clean = name.trim_end_matches('(').trim_end_matches(')');
                    if !clean.is_empty() {
                        ptx_kernels.push(clean.to_string());
                    }
                }
            }
        }
        if !ptx_kernels.is_empty() {
            out.push_str(&format!("PTX Kernels ({}):\n", ptx_kernels.len()));
            for k in ptx_kernels.iter().take(20) {
                out.push_str(&format!("  {k}\n"));
            }
        }
    }

    if elf_offsets.is_empty() && !data_str.contains(".entry") {
        return Err("Not a recognized CUDA binary format".to_string());
    }

    Ok(out)
}
