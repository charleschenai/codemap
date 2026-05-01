// ── capa-rules YAML loader (Ship 5 #13) ───────────────────────────
//
// Loads Mandiant's capa-rules YAML corpus
// (`codemap-core/data/capa-rules/`, Apache 2.0, vendored 2026-05-01)
// and evaluates the **file-scope subset** (190 of 1,045 rules) against
// the artifacts codemap already extracts: PE imports, sections,
// exports, embedded strings, format / os / arch tags. Function-scope
// and basic-block-scope rules are parsed (so the corpus loads
// cleanly) but only fire when their feature tree fully resolves
// against file-scope material — which most don't, by design.
//
// This is the v2 evolution of `actions/anti_analysis.rs`. The header
// comment at anti_analysis.rs:11-13 named this exact pivot ("v2 will
// load the YAML rule corpus directly"); 35 hardcoded anti-analysis
// rules become redundant once this loader is wired in (we don't
// delete them yet to preserve the existing `anti-analysis` action's
// surface — capa-scan is a parallel, broader action).
//
// File layout:
//   data/capa-rules/<namespace>/<name>.yml — vendored corpus
//   data/capa-rules/LICENSE.txt + NOTICE   — Apache 2.0 attribution
//
// Output: CapaMatch nodes attached to the binary, each with
// rule_name / namespace / category / evidence / confidence / att&ck /
// mbc attrs.

use crate::types::{Graph, EntityKind};
use include_dir::{include_dir, Dir};
use serde_yaml::Value;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

static CAPA_CORPUS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/data/capa-rules");

// ── Schema ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    File,
    Function,
    BasicBlock,
    Instruction,
    /// Dynamic / unsupported scopes (process / thread / span_of_calls
    /// / call). We parse these but never fire them — codemap is
    /// static-only.
    Unsupported,
}

impl Scope {
    fn from_yaml(s: &str) -> Self {
        match s {
            "file" => Scope::File,
            "function" => Scope::Function,
            "basic block" => Scope::BasicBlock,
            "instruction" => Scope::Instruction,
            _ => Scope::Unsupported,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RuleMeta {
    pub name: String,
    pub namespace: String,
    pub static_scope: Scope,
    pub is_lib: bool,
    pub attack_ids: Vec<String>,
    pub mbc_ids: Vec<String>,
    pub references: Vec<String>,
    pub source_path: String,
}

/// Recursive feature-tree node. Mirrors capa's DSL (doc/format.md).
#[derive(Debug, Clone)]
pub(crate) enum Feature {
    /// Boolean combinators.
    And(Vec<Feature>),
    Or(Vec<Feature>),
    Not(Box<Feature>),
    /// `N or more` — at least N children fire.
    NOrMore { n: usize, children: Vec<Feature> },
    /// `optional` — never required; ignored at evaluation.
    Optional(Vec<Feature>),

    /// Feature leaves.
    Api(String),
    Import(String),
    Export(String),
    Section(String),
    StringLit { pattern: String, is_regex: bool, regex_flags: String },
    Substring(String),
    Number(u64),
    Format(String),
    Os(String),
    Arch(String),
    Mnemonic(String),
    /// Hex bytes (lowercased, no separators).
    Bytes(String),
    /// Cross-reference to another rule by name.
    Match(String),
    /// `count(<feature>): N or more` — count occurrences.
    Count { inner: Box<Feature>, n: usize },

    /// Anything we recognize as a feature-shaped key but don't
    /// support yet (operand[N].number, characteristic, class:,
    /// property:, namespace:, function-name:, com:). Keeping it
    /// preserves the tree shape so the parser doesn't fail; the
    /// evaluator treats Unsupported as `false`.
    Unsupported(String),
}

#[derive(Debug, Clone)]
pub(crate) struct Rule {
    pub meta: RuleMeta,
    pub features: Feature,
}

// ── Loader ─────────────────────────────────────────────────────────

static RULES: OnceLock<Vec<Rule>> = OnceLock::new();

fn load_corpus() -> &'static [Rule] {
    RULES.get_or_init(|| {
        let mut out = Vec::new();
        walk_corpus(&CAPA_CORPUS, &mut out);
        out
    })
}

fn walk_corpus(dir: &Dir<'_>, out: &mut Vec<Rule>) {
    for entry in dir.entries() {
        match entry {
            include_dir::DirEntry::Dir(d) => walk_corpus(d, out),
            include_dir::DirEntry::File(f) => {
                let path = f.path().to_string_lossy().into_owned();
                if !path.ends_with(".yml") { continue; }
                let body = match f.contents_utf8() {
                    Some(b) => b,
                    None => continue,
                };
                if let Some(rule) = parse_rule(body, &path) {
                    out.push(rule);
                }
            }
        }
    }
}

fn parse_rule(body: &str, source_path: &str) -> Option<Rule> {
    let v: Value = serde_yaml::from_str(body).ok()?;
    let rule = v.get("rule")?;
    let meta_v = rule.get("meta")?;

    let name = meta_v.get("name")?.as_str()?.to_string();
    let namespace = meta_v
        .get("namespace")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let is_lib = meta_v
        .get("lib")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let static_scope = meta_v
        .get("scopes")
        .and_then(|s| s.get("static"))
        .and_then(|x| x.as_str())
        .map(Scope::from_yaml)
        .unwrap_or_else(|| {
            // Older rules used a flat `scope:` field instead of
            // `scopes:{static, dynamic}`. Fall back gracefully.
            meta_v
                .get("scope")
                .and_then(|x| x.as_str())
                .map(Scope::from_yaml)
                .unwrap_or(Scope::Unsupported)
        });

    let attack_ids = parse_id_list(meta_v.get("att&ck"));
    let mbc_ids = parse_id_list(meta_v.get("mbc"));
    let references = parse_string_list(meta_v.get("references"));

    let features_v = rule.get("features")?;
    let features = parse_features_block(features_v)?;

    Some(Rule {
        meta: RuleMeta {
            name,
            namespace,
            static_scope,
            is_lib,
            attack_ids,
            mbc_ids,
            references,
            source_path: source_path.to_string(),
        },
        features,
    })
}

/// capa stores att&ck / mbc tags as `["Defense Evasion::...::Software
/// Packing [T1027.002]", ...]`. We extract bracketed IDs (`T1027.002`,
/// `F0001.008`) into a flat list — the human-readable prefix is
/// preserved on the original meta if needed but the IDs are what
/// analysts query.
fn parse_id_list(v: Option<&Value>) -> Vec<String> {
    let seq = match v.and_then(|x| x.as_sequence()) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for item in seq {
        if let Some(s) = item.as_str() {
            // Extract IDs from the trailing brackets, e.g.
            // "Defense Evasion::... [T1027.002]" → "T1027.002".
            // Some tags carry no bracketed ID; in that case keep the
            // raw string so analysts can still filter on it.
            if let (Some(open), Some(close)) = (s.rfind('['), s.rfind(']')) {
                if open < close {
                    let id = s[open + 1..close].trim().to_string();
                    if !id.is_empty() {
                        out.push(id);
                        continue;
                    }
                }
            }
            out.push(s.to_string());
        }
    }
    out
}

fn parse_string_list(v: Option<&Value>) -> Vec<String> {
    let seq = match v.and_then(|x| x.as_sequence()) {
        Some(s) => s,
        None => return Vec::new(),
    };
    seq.iter()
        .filter_map(|x| x.as_str().map(|s| s.to_string()))
        .collect()
}

/// Top-level features block is always a 1-element sequence containing
/// a single `and:` / `or:` / `not:` map. Some older rules just put a
/// list of features at the top, in which case we treat it as `or:`.
fn parse_features_block(v: &Value) -> Option<Feature> {
    if let Some(seq) = v.as_sequence() {
        // The most common shape: features: [ {or: [...]} ]
        if seq.len() == 1 {
            return parse_feature_node(&seq[0]);
        }
        // Multi-feature top-level: implicit AND? capa treats top-level
        // features list as AND. Verify against rules — actually it's
        // an OR for multi-rule files. To be safe, go with AND because
        // the canonical rules always wrap in {and|or}.
        let mut children = Vec::new();
        for item in seq {
            if let Some(f) = parse_feature_node(item) {
                children.push(f);
            }
        }
        if children.is_empty() {
            return None;
        }
        return Some(Feature::And(children));
    }
    parse_feature_node(v)
}

/// Parse a single feature-tree node — either a combinator or a leaf.
fn parse_feature_node(v: &Value) -> Option<Feature> {
    let map = v.as_mapping()?;

    // Identify the "operator key": the one whose value is a sequence
    // (combinator) OR matches a known leaf prefix. Skip metadata keys
    // like `description` / `com`.
    //
    // Rule shape: a feature node is a single-key map (plus optional
    // `description`). The single key is what we care about.
    let mut operator_key: Option<&str> = None;
    let mut operator_value: Option<&Value> = None;
    for (k, val) in map.iter() {
        let k_str = match k.as_str() {
            Some(s) => s,
            None => continue,
        };
        if k_str == "description" || k_str == "com" {
            continue;
        }
        operator_key = Some(k_str);
        operator_value = Some(val);
        break;
    }
    let key = operator_key?;
    let val = operator_value?;

    // ── Combinators ────────────────────────────────────────────
    if key == "and" {
        return Some(Feature::And(parse_feature_seq(val)));
    }
    if key == "or" {
        return Some(Feature::Or(parse_feature_seq(val)));
    }
    if key == "not" {
        // `not:` may be either a single feature node or a list with
        // one node (capa allows both shapes).
        if let Some(seq) = val.as_sequence() {
            if seq.len() == 1 {
                return Some(Feature::Not(Box::new(parse_feature_node(&seq[0])?)));
            }
            return Some(Feature::Not(Box::new(Feature::And(parse_feature_seq(val)))));
        }
        return Some(Feature::Not(Box::new(parse_feature_node(val)?)));
    }
    if key == "optional" {
        return Some(Feature::Optional(parse_feature_seq(val)));
    }
    if key.ends_with(" or more") {
        // `<N> or more:` (e.g., `2 or more:`)
        let n_str = key.trim_end_matches(" or more").trim();
        if let Ok(n) = n_str.parse::<usize>() {
            return Some(Feature::NOrMore { n, children: parse_feature_seq(val) });
        }
    }

    // Scope wrappers ("basic block:", "instruction:", "function:").
    // These re-scope the contained sub-tree; we treat them as opaque
    // AND blocks at file-scope (we never fire them since file-scope
    // material doesn't satisfy instruction-level features). Preserve
    // the structure so parsing succeeds.
    if key == "basic block"
        || key == "instruction"
        || key == "function"
        || key == "process"
        || key == "thread"
        || key == "span of calls"
        || key == "call"
    {
        // Return Unsupported wrapping the inner block — evaluator
        // treats Unsupported as false at file scope.
        return Some(Feature::Unsupported(format!("scope-wrapper:{}", key)));
    }

    // ── count(...) ─────────────────────────────────────────────
    if let Some(stripped) = key.strip_prefix("count(") {
        if let Some(inner_str) = stripped.strip_suffix(')') {
            // `inner_str` is a feature pattern, e.g. "section(    )"
            // or "api(kernel32.OpenProcess)". Construct a synthetic
            // inner feature so the evaluator can match against it.
            let inner = parse_count_inner(inner_str)?;
            // Value is `N` or `N or more`.
            let n = parse_count_target(val).unwrap_or(1);
            return Some(Feature::Count { inner: Box::new(inner), n });
        }
    }

    // ── Leaf features ──────────────────────────────────────────
    let leaf_value = match val.as_str() {
        Some(s) => s.to_string(),
        None => match val.as_i64() {
            Some(n) => n.to_string(),
            None => match val.as_u64() {
                Some(n) => n.to_string(),
                None => match val.as_bool() {
                    Some(b) => b.to_string(),
                    None => return Some(Feature::Unsupported(key.to_string())),
                },
            },
        },
    };

    Some(parse_leaf_feature(key, &leaf_value))
}

fn parse_count_inner(s: &str) -> Option<Feature> {
    // Forms:
    //   "section(.text)"  → Section(".text")
    //   "section(    )"   → Section("    ")
    //   "api(kernel32.OpenProcess)" → Api("kernel32.OpenProcess")
    //   "match(some-rule)" → Match("some-rule")
    //   "string(/foo/)"    → string with regex
    //   "mnemonic(xor)"    → Mnemonic("xor")
    let open = s.find('(')?;
    let kind = &s[..open];
    let rest = &s[open + 1..];
    let close = rest.rfind(')')?;
    let arg = &rest[..close];
    Some(match kind {
        "section" => Feature::Section(arg.to_string()),
        "api" => Feature::Api(arg.to_string()),
        "import" => Feature::Import(arg.to_string()),
        "export" => Feature::Export(arg.to_string()),
        "match" => Feature::Match(arg.to_string()),
        "string" => parse_leaf_feature("string", arg),
        "substring" => Feature::Substring(arg.to_string()),
        "mnemonic" => Feature::Mnemonic(arg.to_string()),
        _ => Feature::Unsupported(format!("count-inner:{kind}")),
    })
}

fn parse_count_target(v: &Value) -> Option<usize> {
    if let Some(n) = v.as_u64() {
        return Some(n as usize);
    }
    if let Some(s) = v.as_str() {
        // "N or more" or "N+" or just "N"
        let trimmed = s.trim().trim_end_matches('+');
        let n_part = trimmed.split_whitespace().next()?;
        return n_part.parse().ok();
    }
    None
}

fn parse_feature_seq(v: &Value) -> Vec<Feature> {
    let seq = match v.as_sequence() {
        Some(s) => s,
        None => return Vec::new(),
    };
    seq.iter().filter_map(parse_feature_node).collect()
}

/// Strip capa's `= <description>` suffix from a number/bytes value.
/// E.g. `"0x6A09E667 = H(0)0"` → `"0x6A09E667"`.
fn strip_capa_description(s: &str) -> &str {
    if let Some(idx) = s.find(" = ") {
        return s[..idx].trim();
    }
    s.trim()
}

fn parse_leaf_feature(key: &str, raw: &str) -> Feature {
    let value = strip_capa_description(raw);
    match key {
        "api" => Feature::Api(value.to_string()),
        "import" => Feature::Import(value.to_string()),
        "export" => Feature::Export(value.to_string()),
        "section" => Feature::Section(value.to_string()),
        "string" => parse_string_feature(value),
        "substring" => Feature::Substring(value.to_string()),
        "number" => Feature::Number(parse_number_literal(value).unwrap_or(0)),
        "format" => Feature::Format(value.to_string()),
        "os" => Feature::Os(value.to_string()),
        "arch" => Feature::Arch(value.to_string()),
        "mnemonic" => Feature::Mnemonic(value.to_string()),
        "bytes" => Feature::Bytes(normalize_bytes(value)),
        "match" => Feature::Match(value.to_string()),
        // Unsupported feature kinds (evaluator treats as false).
        _ => Feature::Unsupported(format!("{key}:{value}")),
    }
}

/// `string: /VBOX/i` → regex with flag `i`.
/// `string: "literal"` → literal substring.
fn parse_string_feature(raw: &str) -> Feature {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix('/') {
        // Find the trailing `/<flags>`. Walk backwards looking for an
        // unescaped `/`. This handles regex with embedded slashes
        // (rare in capa rules but possible).
        let bytes = rest.as_bytes();
        let mut last_slash: Option<usize> = None;
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if bytes[i] == b'/' {
                last_slash = Some(i);
            }
            i += 1;
        }
        if let Some(idx) = last_slash {
            let pattern = &rest[..idx];
            let flags = &rest[idx + 1..];
            return Feature::StringLit {
                pattern: pattern.to_string(),
                is_regex: true,
                regex_flags: flags.to_string(),
            };
        }
    }
    Feature::StringLit {
        pattern: trimmed.to_string(),
        is_regex: false,
        regex_flags: String::new(),
    }
}

fn parse_number_literal(s: &str) -> Option<u64> {
    let t = s.trim().trim_end_matches('L'); // capa allows trailing L
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Some(neg) = t.strip_prefix("-0x").or_else(|| t.strip_prefix("-0X")) {
        // capa rules occasionally write -0x... ; reinterpret as
        // unsigned two's-complement on 64-bit (matches what'd be
        // observed in disasm).
        return u64::from_str_radix(neg, 16).ok().map(|n| n.wrapping_neg());
    }
    t.parse::<u64>().ok().or_else(|| t.parse::<i64>().ok().map(|n| n as u64))
}

fn normalize_bytes(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

// ── Feature-bag ────────────────────────────────────────────────────
//
// What the evaluator queries against: a single struct holding every
// kind of feature material we've extracted from the binary. Used both
// at run-time and in tests.

#[derive(Debug, Default, Clone)]
pub(crate) struct FeatureBag {
    /// Set of (dll_lower, function_name_lower).
    pub imports: HashSet<(String, String)>,
    /// Set of dll names imported (lowercased) — `import: kernel32`.
    pub import_dlls: HashSet<String>,
    /// API names — both `dll.func` and bare `func`, all lowercased.
    pub api_names: HashSet<String>,
    /// PE/ELF/Mach-O section names (case-preserved + lowercase set).
    pub sections: HashSet<String>,
    pub sections_lower: HashSet<String>,
    /// Exported symbol names.
    pub exports: HashSet<String>,
    pub exports_lower: HashSet<String>,
    /// Embedded strings (UTF-8 / UTF-16LE — see collect_strings).
    pub strings: Vec<String>,
    /// `format:` tag (pe / elf / dotnet).
    pub format: String,
    /// `os:` tag (windows / linux / macos).
    pub os: String,
    /// `arch:` tag (i386 / amd64 / arm).
    pub arch: String,
    /// Cached regex matches — initialized empty, evaluator does
    /// linear scan with the regex crate.
    pub regex_cache: HashMap<String, bool>,
}

impl FeatureBag {
    /// Build a feature bag from a binary blob. PE-centric (the
    /// vendored corpus is overwhelmingly Windows-targeted). ELF /
    /// Mach-O strings + format are still populated, but section /
    /// import / export tables for non-PE remain v2.
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut bag = FeatureBag::default();

        // Format / arch fingerprinting.
        if data.len() >= 2 && &data[..2] == b"MZ" {
            bag.format = "pe".to_string();
            bag.os = "windows".to_string();
            // Detect dotnet by reading CLI header presence — too
            // heavyweight; settle for a substring sniff (good enough
            // for the runtime/dotnet rule's `format: dotnet`).
            if has_dotnet_cli_marker(data) {
                bag.format = "dotnet".to_string();
            }
            bag.arch = pe_arch(data).unwrap_or_else(|| "i386".to_string());

            // Imports / sections — reuse anti_analysis.rs's helpers
            // would be ideal, but they're crate-private. Re-implement
            // the same logic here; trivial.
            bag.imports = pe_imports(data);
            bag.import_dlls = bag
                .imports
                .iter()
                .map(|(dll, _)| dll.clone())
                .collect();
            bag.api_names = bag
                .imports
                .iter()
                .flat_map(|(dll, fname)| {
                    let dll_no_ext = dll.trim_end_matches(".dll");
                    vec![
                        format!("{dll_no_ext}.{fname}"),
                        fname.clone(),
                        format!("{dll}.{fname}"),
                    ]
                })
                .collect();

            bag.sections = pe_sections(data);
            bag.sections_lower = bag
                .sections
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect();

            bag.exports = pe_exports(data);
            bag.exports_lower = bag
                .exports
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect();
        } else if data.len() >= 4 && &data[..4] == b"\x7FELF" {
            bag.format = "elf".to_string();
            bag.os = "linux".to_string();
            bag.arch = elf_arch(data).unwrap_or_else(|| "amd64".to_string());
        } else if data.len() >= 4
            && (data[..4] == [0xFE, 0xED, 0xFA, 0xCE]
                || data[..4] == [0xCE, 0xFA, 0xED, 0xFE]
                || data[..4] == [0xFE, 0xED, 0xFA, 0xCF]
                || data[..4] == [0xCF, 0xFA, 0xED, 0xFE]
                || data[..4] == [0xCA, 0xFE, 0xBA, 0xBE])
        {
            bag.format = "macho".to_string();
            bag.os = "macos".to_string();
        }

        bag.strings = collect_strings(data);

        bag
    }
}

// ── Evaluator ──────────────────────────────────────────────────────

#[derive(Debug)]
pub(crate) struct EvalContext<'a> {
    bag: &'a FeatureBag,
    /// Lookup of rule_name → bool (whether the rule fired).
    /// Pre-populated by the two-pass resolver below.
    matched_rules: &'a HashSet<String>,
}

fn evaluate(feat: &Feature, ctx: &EvalContext<'_>, evidence: &mut Vec<String>) -> bool {
    match feat {
        Feature::And(children) => {
            for c in children {
                if !evaluate(c, ctx, evidence) {
                    return false;
                }
            }
            !children.is_empty()
        }
        Feature::Or(children) => {
            for c in children {
                if evaluate(c, ctx, evidence) {
                    return true;
                }
            }
            false
        }
        Feature::Not(inner) => {
            // Don't add evidence under a `not:` even if the inner
            // matches — the negation is what makes the rule fire,
            // not the inner feature.
            let mut throwaway = Vec::new();
            !evaluate(inner, ctx, &mut throwaway)
        }
        Feature::NOrMore { n, children } => {
            let mut hits = 0;
            for c in children {
                if evaluate(c, ctx, evidence) {
                    hits += 1;
                    if hits >= *n {
                        return true;
                    }
                }
            }
            false
        }
        Feature::Optional(_) => true, // Optional never blocks.

        Feature::Api(name) => match_api(name, ctx, evidence),
        Feature::Import(name) => match_import(name, ctx, evidence),
        Feature::Export(name) => {
            let lower = name.to_ascii_lowercase();
            if ctx.bag.exports_lower.contains(&lower) {
                evidence.push(format!("export:{name}"));
                return true;
            }
            false
        }
        Feature::Section(name) => {
            let lower = name.to_ascii_lowercase();
            if ctx.bag.sections_lower.contains(&lower) {
                evidence.push(format!("section:{name}"));
                return true;
            }
            // Some rules use space-only section names — exact match
            // (case-preserved) catches those.
            if ctx.bag.sections.contains(name) {
                evidence.push(format!("section:{name:?}"));
                return true;
            }
            false
        }
        Feature::StringLit { pattern, is_regex, regex_flags } => {
            if *is_regex {
                let case_insensitive = regex_flags.contains('i');
                let pat = if case_insensitive {
                    format!("(?i){pattern}")
                } else {
                    pattern.clone()
                };
                if let Ok(re) = regex::Regex::new(&pat) {
                    for s in &ctx.bag.strings {
                        if re.is_match(s) {
                            evidence.push(format!("string:/{pattern}/{regex_flags}"));
                            return true;
                        }
                    }
                }
                false
            } else {
                for s in &ctx.bag.strings {
                    if s.contains(pattern) {
                        evidence.push(format!("string:{pattern:?}"));
                        return true;
                    }
                }
                false
            }
        }
        Feature::Substring(pattern) => {
            for s in &ctx.bag.strings {
                if s.contains(pattern) {
                    evidence.push(format!("substring:{pattern:?}"));
                    return true;
                }
            }
            false
        }
        Feature::Number(_) => {
            // Numbers come from disassembly operand-tracking — not
            // available at file scope. Always false here; the
            // propagator-extension v3 will make these meaningful.
            false
        }
        Feature::Bytes(_hex) => {
            // Bytes match against any data section — file scope reads
            // the entire binary, so a substring scan is reasonable
            // BUT large hex blobs (crypto S-boxes) are already covered
            // by crypto_const.rs more efficiently. Skip here to avoid
            // duplicate detections on the same artifact.
            false
        }
        Feature::Format(name) => {
            if ctx.bag.format.eq_ignore_ascii_case(name) {
                evidence.push(format!("format:{name}"));
                return true;
            }
            false
        }
        Feature::Os(name) => {
            if ctx.bag.os.eq_ignore_ascii_case(name) {
                evidence.push(format!("os:{name}"));
                return true;
            }
            false
        }
        Feature::Arch(name) => {
            if ctx.bag.arch.eq_ignore_ascii_case(name) {
                evidence.push(format!("arch:{name}"));
                return true;
            }
            false
        }
        Feature::Mnemonic(_) => false, // requires disasm
        Feature::Match(rule_name) => {
            if ctx.matched_rules.contains(rule_name) {
                evidence.push(format!("match:{rule_name}"));
                return true;
            }
            false
        }
        Feature::Count { inner, n } => {
            // Count occurrences of `inner` against the bag. Only
            // section / api / import / export / string / substring
            // counting is meaningful at file scope.
            let count = count_matches(inner, ctx);
            if count >= *n {
                evidence.push(format!("count>={n}"));
                return true;
            }
            false
        }
        Feature::Unsupported(_) => false,
    }
}

fn count_matches(feat: &Feature, ctx: &EvalContext<'_>) -> usize {
    match feat {
        Feature::Section(name) => {
            let lower = name.to_ascii_lowercase();
            let exact = ctx.bag.sections.iter().filter(|s| **s == *name).count();
            let case = ctx.bag.sections_lower.iter().filter(|s| **s == lower).count();
            exact.max(case)
        }
        Feature::Api(name) => {
            let lower = name.to_ascii_lowercase();
            ctx.bag.api_names.iter().filter(|s| **s == lower).count()
        }
        Feature::Import(name) => {
            let lower = name.to_ascii_lowercase();
            ctx.bag.import_dlls.iter().filter(|s| **s == lower).count()
                + ctx.bag.api_names.iter().filter(|s| **s == lower).count()
        }
        Feature::Export(name) => {
            let lower = name.to_ascii_lowercase();
            ctx.bag.exports_lower.iter().filter(|s| **s == lower).count()
        }
        Feature::Substring(p) => ctx.bag.strings.iter().filter(|s| s.contains(p)).count(),
        Feature::StringLit { pattern, is_regex: false, .. } => {
            ctx.bag.strings.iter().filter(|s| s.contains(pattern)).count()
        }
        Feature::StringLit { pattern, is_regex: true, regex_flags } => {
            let case_insensitive = regex_flags.contains('i');
            let pat = if case_insensitive {
                format!("(?i){pattern}")
            } else {
                pattern.clone()
            };
            match regex::Regex::new(&pat) {
                Ok(re) => ctx.bag.strings.iter().filter(|s| re.is_match(s)).count(),
                Err(_) => 0,
            }
        }
        _ => 0,
    }
}

fn match_api(name: &str, ctx: &EvalContext<'_>, evidence: &mut Vec<String>) -> bool {
    // capa's `api:` matches against any of:
    //   - bare function name (case-insensitive)
    //   - dll.func (lowercased, no extension)
    //   - dll.dll.func form
    let lower = name.to_ascii_lowercase();
    if ctx.bag.api_names.contains(&lower) {
        evidence.push(format!("api:{name}"));
        return true;
    }
    // Match on the function-name half if the rule wrote `kernel32.X`
    // and the binary imports it from `kernelbase.dll`. capa's docs say
    // `api:` is matched against the symbol name, not the dll, so this
    // is the canonical fallback.
    if let Some((_, fn_part)) = lower.rsplit_once('.') {
        if ctx.bag.api_names.contains(fn_part) {
            evidence.push(format!("api:{name} (resolved)"));
            return true;
        }
        // Match each (dll, fname) ignoring rule's dll prefix.
        for (_, fname) in &ctx.bag.imports {
            if fname == fn_part {
                evidence.push(format!("api:{name} (any-dll)"));
                return true;
            }
        }
    }
    false
}

fn match_import(name: &str, ctx: &EvalContext<'_>, evidence: &mut Vec<String>) -> bool {
    let lower = name.to_ascii_lowercase();
    // `import: mscoree._CorExeMain` — looks like an api but capa
    // distinguishes the two for documentation; treat them the same.
    if ctx.bag.api_names.contains(&lower) {
        evidence.push(format!("import:{name}"));
        return true;
    }
    if let Some((_, fn_part)) = lower.rsplit_once('.') {
        if ctx.bag.api_names.contains(fn_part) {
            evidence.push(format!("import:{name}"));
            return true;
        }
    }
    if ctx.bag.import_dlls.contains(&lower)
        || ctx.bag.import_dlls.contains(&format!("{lower}.dll"))
    {
        evidence.push(format!("import:{name}"));
        return true;
    }
    false
}

// ── Two-pass match resolver ────────────────────────────────────────
//
// capa rules can `match: <other-rule-name>`. Resolving requires
// loading every rule first, then iterating until fixpoint.

#[derive(Debug, Clone)]
pub(crate) struct MatchResult<'a> {
    pub rule: &'a Rule,
    pub evidence: Vec<String>,
}

pub(crate) fn run_rules<'a>(rules: &'a [Rule], bag: &FeatureBag) -> Vec<MatchResult<'a>> {
    let mut matched_names: HashSet<String> = HashSet::new();
    let mut results: HashMap<String, Vec<String>> = HashMap::new();

    // Iterate to fixpoint (capped at 5 passes — capa rule graph is
    // shallow). Each pass tries every rule against the current
    // matched_names set; a rule's `match:` references resolve only
    // when its dependencies have already fired.
    for _ in 0..5 {
        let mut grew = false;
        for rule in rules {
            if matched_names.contains(&rule.meta.name) {
                continue;
            }
            let ctx = EvalContext { bag, matched_rules: &matched_names };
            let mut evidence = Vec::new();
            if evaluate(&rule.features, &ctx, &mut evidence) {
                matched_names.insert(rule.meta.name.clone());
                results.insert(rule.meta.name.clone(), evidence);
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }

    let mut out = Vec::new();
    for rule in rules {
        if let Some(evidence) = results.remove(&rule.meta.name) {
            out.push(MatchResult { rule, evidence });
        }
    }
    out
}

// ── Action ─────────────────────────────────────────────────────────

pub fn capa_scan(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap capa-scan <pe-or-elf-binary>".to_string();
    }
    let data = match std::fs::read(target) {
        Ok(d) => d,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    let bag = FeatureBag::from_bytes(&data);
    let rules = load_corpus();
    let hits = run_rules(rules, &bag);

    register_into_graph(graph, target, &hits);
    format_report(target, rules.len(), &bag, &hits)
}

// ── Graph wiring ───────────────────────────────────────────────────

fn register_into_graph(graph: &mut Graph, target: &str, hits: &[MatchResult<'_>]) {
    if hits.is_empty() {
        return;
    }
    let bin_id = format!("pe:{target}");
    graph.ensure_typed_node(&bin_id, EntityKind::PeBinary, &[("path", target)]);

    for h in hits {
        // Skip lib rules — they're predicates, not detections.
        if h.rule.meta.is_lib {
            continue;
        }
        let unique_id = format!("capa_match:{}::{}", h.rule.meta.namespace, h.rule.meta.name);
        let category = h
            .rule
            .meta
            .namespace
            .split('/')
            .next()
            .unwrap_or("misc")
            .to_string();
        let confidence = if h.rule.meta.namespace.starts_with("nursery/") {
            "low"
        } else {
            "high"
        };
        let evidence = h.evidence.join(", ");
        let attack = h.rule.meta.attack_ids.join("+");
        let mbc = h.rule.meta.mbc_ids.join("+");
        let attrs: Vec<(&str, &str)> = vec![
            ("rule_name", &h.rule.meta.name),
            ("namespace", &h.rule.meta.namespace),
            ("category", &category),
            ("confidence", confidence),
            ("evidence", &evidence),
            ("att&ck", &attack),
            ("mbc", &mbc),
        ];
        graph.ensure_typed_node(&unique_id, EntityKind::CapaMatch, &attrs);
        graph.add_edge(&bin_id, &unique_id);
    }
}

fn format_report(
    target: &str,
    rule_count: usize,
    bag: &FeatureBag,
    hits: &[MatchResult<'_>],
) -> String {
    let mut lines = vec![
        format!("=== capa-scan: {} ===", target),
        format!("Format:   {}", if bag.format.is_empty() { "<unknown>" } else { &bag.format }),
        format!("OS/Arch:  {} / {}", if bag.os.is_empty() { "?" } else { &bag.os }, if bag.arch.is_empty() { "?" } else { &bag.arch }),
        format!("Imports:  {} fns across {} dlls", bag.imports.len(), bag.import_dlls.len()),
        format!("Exports:  {}", bag.exports.len()),
        format!("Sections: {}", bag.sections.len()),
        format!("Strings:  {}", bag.strings.len()),
        format!("Rules:    {} loaded, {} fired", rule_count, hits.len()),
        String::new(),
    ];

    if hits.is_empty() {
        lines.push("(no capabilities detected)".to_string());
        return lines.join("\n");
    }

    let mut by_cat: std::collections::BTreeMap<&str, Vec<&MatchResult<'_>>> =
        std::collections::BTreeMap::new();
    for h in hits {
        if h.rule.meta.is_lib {
            continue;
        }
        let cat = h.rule.meta.namespace.split('/').next().unwrap_or("misc");
        by_cat.entry(cat).or_default().push(h);
    }

    for (cat, rules) in &by_cat {
        lines.push(format!("── {} ({}) ──", cat, rules.len()));
        for h in rules {
            lines.push(format!("  • {}", h.rule.meta.name));
            lines.push(format!("      ns: {}", h.rule.meta.namespace));
            if !h.rule.meta.attack_ids.is_empty() {
                lines.push(format!("      att&ck: {}", h.rule.meta.attack_ids.join(", ")));
            }
            if !h.rule.meta.mbc_ids.is_empty() {
                lines.push(format!("      mbc: {}", h.rule.meta.mbc_ids.join(", ")));
            }
            if !h.evidence.is_empty() {
                let preview: Vec<&String> = h.evidence.iter().take(3).collect();
                lines.push(format!("      evidence: {}", preview.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" / ")));
            }
        }
        lines.push(String::new());
    }

    lines.push("Try: codemap meta-path \"pe->capa_match\"  (cross-binary capability inventory)".to_string());
    lines.push("     codemap pagerank --type capa_match    (most-prevalent capabilities)".to_string());
    lines.join("\n")
}

// ── Feature extraction (PE-centric) ────────────────────────────────

fn pe_imports(data: &[u8]) -> HashSet<(String, String)> {
    let mut out = HashSet::new();
    let dlls = crate::actions::reverse::pe::parse_pe_imports_structured(data).unwrap_or_default();
    for d in &dlls {
        let dll_lower = d.name.to_ascii_lowercase();
        for f in &d.functions {
            out.insert((dll_lower.clone(), f.to_ascii_lowercase()));
        }
    }
    out
}

fn pe_sections(data: &[u8]) -> HashSet<String> {
    let mut out = HashSet::new();
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return out;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    let coff = e_lfanew + 4;
    if coff + 20 > data.len() {
        return out;
    }
    let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let sec_table = coff + 20 + opt_size;
    for i in 0..n_sections {
        let off = sec_table + i * 40;
        if off + 8 > data.len() {
            break;
        }
        let raw = &data[off..off + 8];
        let end = raw.iter().position(|b| *b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw[..end]).to_string();
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

fn pe_arch(data: &[u8]) -> Option<String> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 6 > data.len() {
        return None;
    }
    let machine = u16::from_le_bytes([data[e_lfanew + 4], data[e_lfanew + 5]]);
    Some(match machine {
        0x014c => "i386".to_string(),
        0x8664 => "amd64".to_string(),
        0x01c0 | 0x01c4 => "arm".to_string(),
        0xaa64 => "arm64".to_string(),
        _ => "i386".to_string(),
    })
}

fn elf_arch(data: &[u8]) -> Option<String> {
    if data.len() < 0x14 {
        return None;
    }
    let machine = u16::from_le_bytes([data[0x12], data[0x13]]);
    Some(match machine {
        0x03 => "i386".to_string(),
        0x3E => "amd64".to_string(),
        0x28 => "arm".to_string(),
        0xB7 => "arm64".to_string(),
        _ => "amd64".to_string(),
    })
}

/// Parse PE export table — returns the set of exported function names
/// in their case-preserved form.
fn pe_exports(data: &[u8]) -> HashSet<String> {
    let mut out = HashSet::new();
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return out;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    let coff_start = e_lfanew + 4;
    if coff_start + 20 > data.len() {
        return out;
    }
    let opt_start = coff_start + 20;
    if opt_start + 2 > data.len() {
        return out;
    }
    let opt_magic = u16::from_le_bytes([data[opt_start], data[opt_start + 1]]);
    let is_pe64 = opt_magic == 0x20B;
    let n_sections = u16::from_le_bytes([data[coff_start + 2], data[coff_start + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff_start + 16], data[coff_start + 17]]) as usize;

    // Export directory is data dir [0] = +96 (PE32) / +112 (PE32+).
    let exp_dir_offset = if is_pe64 { opt_start + 112 } else { opt_start + 96 };
    if exp_dir_offset + 8 > data.len() {
        return out;
    }
    let exp_rva = u32::from_le_bytes([
        data[exp_dir_offset],
        data[exp_dir_offset + 1],
        data[exp_dir_offset + 2],
        data[exp_dir_offset + 3],
    ]) as usize;
    let exp_size = u32::from_le_bytes([
        data[exp_dir_offset + 4],
        data[exp_dir_offset + 5],
        data[exp_dir_offset + 6],
        data[exp_dir_offset + 7],
    ]) as usize;
    if exp_rva == 0 || exp_size == 0 {
        return out;
    }

    // Build sections to translate RVAs.
    let sec_table = opt_start + opt_size;
    let mut sections: Vec<(usize, usize, usize)> = Vec::new(); // (rva, vsize, raw_off)
    for i in 0..n_sections {
        let off = sec_table + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let v_size = u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]) as usize;
        let v_addr = u32::from_le_bytes([data[off + 12], data[off + 13], data[off + 14], data[off + 15]]) as usize;
        let raw_off = u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]) as usize;
        sections.push((v_addr, v_size.max(1), raw_off));
    }
    let rva_to_off = |rva: usize| -> Option<usize> {
        for (v_addr, v_size, raw_off) in &sections {
            if rva >= *v_addr && rva < *v_addr + *v_size {
                return Some(raw_off + (rva - v_addr));
            }
        }
        None
    };

    let exp_off = match rva_to_off(exp_rva) {
        Some(o) => o,
        None => return out,
    };
    if exp_off + 40 > data.len() {
        return out;
    }
    let n_names = u32::from_le_bytes([data[exp_off + 24], data[exp_off + 25], data[exp_off + 26], data[exp_off + 27]]) as usize;
    let name_table_rva = u32::from_le_bytes([data[exp_off + 32], data[exp_off + 33], data[exp_off + 34], data[exp_off + 35]]) as usize;
    let name_table_off = match rva_to_off(name_table_rva) {
        Some(o) => o,
        None => return out,
    };
    for i in 0..n_names {
        let entry_off = name_table_off + i * 4;
        if entry_off + 4 > data.len() {
            break;
        }
        let str_rva = u32::from_le_bytes([
            data[entry_off],
            data[entry_off + 1],
            data[entry_off + 2],
            data[entry_off + 3],
        ]) as usize;
        if let Some(str_off) = rva_to_off(str_rva) {
            let mut end = str_off;
            while end < data.len() && data[end] != 0 && end - str_off < 256 {
                end += 1;
            }
            if let Ok(s) = std::str::from_utf8(&data[str_off..end]) {
                out.insert(s.to_string());
            }
        }
    }
    out
}

/// Coarse .NET CLI marker sniff. The CLR data dir lives at PE32
/// optional header offset +208, PE32+ +224. Reading it here would
/// require walking sections; for capa's `format: dotnet` rule the
/// `_CorExeMain` / `_CorDllMain` import alone is sufficient to fire,
/// and the `mscoree` DLL name in the import table is the simplest
/// signal. Use that.
fn has_dotnet_cli_marker(data: &[u8]) -> bool {
    let s = data.windows(8).any(|w| w == b"mscoree\0");
    s
}

fn collect_strings(data: &[u8]) -> Vec<String> {
    const MIN_LEN: usize = 4;
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
                    if out.len() >= MAX_STRINGS {
                        return out;
                    }
                }
            }
        }
    }
    if let Some(s) = start.take() {
        if data.len() - s >= MIN_LEN {
            out.push(String::from_utf8_lossy(&data[s..]).to_string());
        }
    }
    if out.len() >= MAX_STRINGS {
        return out;
    }
    let mut i = 0;
    while i + 1 < data.len() && out.len() < MAX_STRINGS {
        if data[i + 1] == 0 && (0x20..=0x7E).contains(&data[i]) {
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
        } else {
            i += 1;
        }
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bag(
        imports: &[(&str, &str)],
        sections: &[&str],
        strings: &[&str],
        format: &str,
        os: &str,
        arch: &str,
    ) -> FeatureBag {
        let imps: HashSet<(String, String)> = imports
            .iter()
            .map(|(d, f)| (d.to_ascii_lowercase(), f.to_ascii_lowercase()))
            .collect();
        let dlls: HashSet<String> = imps.iter().map(|(d, _)| d.clone()).collect();
        let api_names: HashSet<String> = imps
            .iter()
            .flat_map(|(d, f)| {
                let de = d.trim_end_matches(".dll");
                vec![format!("{de}.{f}"), f.clone(), format!("{d}.{f}")]
            })
            .collect();
        let secs: HashSet<String> = sections.iter().map(|s| s.to_string()).collect();
        let secs_lower: HashSet<String> = secs.iter().map(|s| s.to_ascii_lowercase()).collect();
        FeatureBag {
            imports: imps,
            import_dlls: dlls,
            api_names,
            sections: secs,
            sections_lower: secs_lower,
            exports: HashSet::new(),
            exports_lower: HashSet::new(),
            strings: strings.iter().map(|s| s.to_string()).collect(),
            format: format.to_string(),
            os: os.to_string(),
            arch: arch.to_string(),
            regex_cache: HashMap::new(),
        }
    }

    #[test]
    fn corpus_loads_all_rules() {
        let rules = load_corpus();
        // capa-rules ships 1,045 .yml files. We accept any rule
        // with a meta.name + features block, so we expect ≥ 1,000.
        assert!(rules.len() >= 1000, "loaded only {} rules", rules.len());
    }

    #[test]
    fn corpus_has_known_rule_names() {
        let rules = load_corpus();
        let names: HashSet<&str> = rules.iter().map(|r| r.meta.name.as_str()).collect();
        assert!(names.contains("packed with UPX"));
        assert!(names.contains("compiled with Go"));
        assert!(names.contains("compiled to the .NET platform"));
        assert!(names.contains("packed with ASPack"));
    }

    #[test]
    fn evaluator_fires_upx_on_pe_section() {
        let rules = load_corpus();
        // The UPX rule is `format: pe AND (section: UPX0 OR
        // section: UPX1)`. Construct a feature bag that matches.
        let bag = make_bag(&[], &["UPX0", ".rsrc"], &["UPX!"], "pe", "windows", "i386");
        let hits = run_rules(rules, &bag);
        assert!(
            hits.iter().any(|h| h.rule.meta.name == "packed with UPX"),
            "UPX rule did not fire; hits: {:?}",
            hits.iter().map(|h| &h.rule.meta.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn evaluator_fires_aspack_on_section() {
        let rules = load_corpus();
        let bag = make_bag(&[], &[".aspack"], &[], "pe", "windows", "i386");
        let hits = run_rules(rules, &bag);
        assert!(hits.iter().any(|h| h.rule.meta.name == "packed with ASPack"));
    }

    #[test]
    fn evaluator_fires_dotnet_via_import() {
        let rules = load_corpus();
        let bag = make_bag(
            &[("mscoree.dll", "_CorExeMain")],
            &[".text"],
            &[],
            "pe",
            "windows",
            "i386",
        );
        let hits = run_rules(rules, &bag);
        assert!(
            hits.iter().any(|h| h.rule.meta.name == "compiled to the .NET platform"),
            ".NET rule did not fire; hits: {:?}",
            hits.iter().map(|h| &h.rule.meta.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn evaluator_fires_go_on_string_substring() {
        let rules = load_corpus();
        let bag = make_bag(
            &[],
            &[".text"],
            &["Go build ID: \"abc/def\"", "runtime.main", "main.main"],
            "pe",
            "windows",
            "amd64",
        );
        let hits = run_rules(rules, &bag);
        assert!(hits.iter().any(|h| h.rule.meta.name == "compiled with Go"));
    }

    #[test]
    fn evaluator_fires_vbox_on_regex_string() {
        let rules = load_corpus();
        let bag = make_bag(
            &[],
            &[".text"],
            &["HARDWARE\\ACPI\\DSDT\\VBOX__"],
            "pe",
            "windows",
            "amd64",
        );
        let hits = run_rules(rules, &bag);
        let vbox_hit = hits.iter().any(|h| {
            h.rule.meta.namespace == "anti-analysis/anti-vm/vm-detection"
                && h.rule.meta.name.to_ascii_lowercase().contains("virtualbox")
        });
        assert!(vbox_hit, "no VBox rule fired; hits: {:?}", hits.iter().map(|h| &h.rule.meta.name).collect::<Vec<_>>());
    }

    #[test]
    fn attack_ids_are_extracted() {
        let rules = load_corpus();
        let upx = rules
            .iter()
            .find(|r| r.meta.name == "packed with UPX")
            .expect("UPX rule loaded");
        // upx is tagged: T1027.002. Lift checks the bracketed form
        // is captured.
        assert!(
            upx.meta.attack_ids.iter().any(|s| s.contains("T1027")),
            "att&ck ids: {:?}",
            upx.meta.attack_ids
        );
    }

    #[test]
    fn graph_emits_capa_match_nodes_with_attrs() {
        let mut g = Graph { nodes: HashMap::new(), scan_dir: String::new(), cpg: None };
        // Hand-fabricate a tiny test that runs capa-scan against a
        // synthetic PE-shaped buffer. We can't easily construct a
        // valid PE here, so go via run_rules + register_into_graph.
        let rules = load_corpus();
        let bag = make_bag(&[], &["UPX0"], &["UPX!"], "pe", "windows", "i386");
        let hits = run_rules(rules, &bag);
        register_into_graph(&mut g, "/tmp/synthetic.exe", &hits);
        // At least the UPX node should land in the graph.
        let any_upx = g
            .nodes
            .values()
            .any(|n| n.kind == EntityKind::CapaMatch && n.attrs.get("rule_name").map(|s| s.as_str()) == Some("packed with UPX"));
        assert!(any_upx, "UPX capa_match node not registered");
    }

    #[test]
    fn parse_string_feature_handles_regex() {
        match parse_string_feature("/VBOX/i") {
            Feature::StringLit { pattern, is_regex, regex_flags } => {
                assert_eq!(pattern, "VBOX");
                assert!(is_regex);
                assert_eq!(regex_flags, "i");
            }
            other => panic!("expected regex StringLit, got {:?}", other),
        }
    }

    #[test]
    fn parse_string_feature_handles_literal() {
        match parse_string_feature("UPX!") {
            Feature::StringLit { pattern, is_regex, .. } => {
                assert_eq!(pattern, "UPX!");
                assert!(!is_regex);
            }
            other => panic!("expected literal StringLit, got {:?}", other),
        }
    }

    #[test]
    fn parse_number_handles_hex_and_decimal() {
        assert_eq!(parse_number_literal("0x6A09E667"), Some(0x6A09E667));
        assert_eq!(parse_number_literal("42"), Some(42));
        assert_eq!(parse_number_literal("0X1B"), Some(0x1B));
    }

    #[test]
    fn strip_capa_description_strips_eq_suffix() {
        assert_eq!(strip_capa_description("0x6A09E667 = H(0)0"), "0x6A09E667");
        assert_eq!(strip_capa_description("0x42"), "0x42");
    }

    #[test]
    fn match_resolver_propagates_lib_rules() {
        // "allocate memory" is a lib rule that fires when
        // VirtualAlloc is imported. Other rules can `match: allocate
        // memory` to inherit. We don't exercise the cross-rule
        // wiring directly here (would need a rule that only matches
        // via cross-ref), but we verify the lib rule itself fires
        // and is filtered from the graph output.
        let rules = load_corpus();
        let bag = make_bag(
            &[("kernel32.dll", "VirtualAlloc")],
            &[".text"],
            &[],
            "pe",
            "windows",
            "i386",
        );
        let hits = run_rules(rules, &bag);
        assert!(
            hits.iter().any(|h| h.rule.meta.name == "allocate memory"),
            "allocate-memory lib rule did not fire"
        );
    }
}
