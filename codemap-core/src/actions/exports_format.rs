use crate::types::Graph;

// ── Graph Export Formats ─────────────────────────────────────────────
//
// Beyond dot/mermaid, three more "interchange" formats:
//
//   to-json    — codemap-native JSON dump (every node + edge + attrs)
//   to-graphml — XML-based, opens in yEd, Cytoscape, NodeXL
//   to-gexf    — Gephi format, includes color metadata per kind
//
// These let users round-trip codemap's heterogeneous graph into
// dedicated visualization tools when dot/mermaid aren't enough
// (force-directed layouts, interactive filtering, time-series, etc.).

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Codemap-native JSON representation: an array of nodes and an array
/// of directed edges. Includes EntityKind, attrs, and stats per node.
pub fn to_json(graph: &Graph) -> String {
    let mut ids: Vec<&String> = graph.nodes.keys().collect();
    ids.sort();

    let mut out = String::from("{\n");
    out.push_str(&format!("  \"version\": \"codemap-graph-1\",\n"));
    out.push_str(&format!("  \"node_count\": {},\n", graph.nodes.len()));
    out.push_str("  \"nodes\": [\n");
    for (i, id) in ids.iter().enumerate() {
        let n = &graph.nodes[*id];
        let mut attrs = String::from("{");
        let mut keys: Vec<&String> = n.attrs.keys().collect();
        keys.sort();
        for (k, key) in keys.iter().enumerate() {
            if k > 0 { attrs.push_str(", "); }
            attrs.push_str(&format!("\"{}\": \"{}\"",
                json_escape(key), json_escape(&n.attrs[*key])));
        }
        attrs.push('}');
        out.push_str(&format!(
            "    {{\"id\": \"{}\", \"kind\": \"{}\", \"lines\": {}, \"exports\": {}, \"functions\": {}, \"attrs\": {}}}{}\n",
            json_escape(id),
            n.kind.as_str(),
            n.lines,
            n.exports.len(),
            n.functions.len(),
            attrs,
            if i + 1 < ids.len() { "," } else { "" },
        ));
    }
    out.push_str("  ],\n");

    out.push_str("  \"edges\": [\n");
    let mut edges: Vec<(&str, &str)> = Vec::new();
    for id in &ids {
        if let Some(n) = graph.nodes.get(*id) {
            for imp in &n.imports {
                if graph.nodes.contains_key(imp) {
                    edges.push((id.as_str(), imp.as_str()));
                }
            }
        }
    }
    for (i, (from, to)) in edges.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"from\": \"{}\", \"to\": \"{}\"}}{}\n",
            json_escape(from), json_escape(to),
            if i + 1 < edges.len() { "," } else { "" },
        ));
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

/// GraphML — XML, opens in yEd / Cytoscape / NetworkX / Gephi.
/// Includes EntityKind as a custom attribute so importers can filter
/// or color by it.
pub fn to_graphml(graph: &Graph) -> String {
    let mut ids: Vec<&String> = graph.nodes.keys().collect();
    ids.sort();

    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n");
    out.push_str("  <key id=\"kind\" for=\"node\" attr.name=\"kind\" attr.type=\"string\"/>\n");
    out.push_str("  <key id=\"lines\" for=\"node\" attr.name=\"lines\" attr.type=\"int\"/>\n");
    out.push_str("  <key id=\"exports\" for=\"node\" attr.name=\"exports\" attr.type=\"int\"/>\n");
    out.push_str("  <graph edgedefault=\"directed\">\n");

    for id in &ids {
        let n = &graph.nodes[*id];
        out.push_str(&format!(
            "    <node id=\"{}\">\n      <data key=\"kind\">{}</data>\n      <data key=\"lines\">{}</data>\n      <data key=\"exports\">{}</data>\n    </node>\n",
            xml_escape(id), n.kind.as_str(), n.lines, n.exports.len()
        ));
    }
    let mut edge_id = 0;
    for id in &ids {
        if let Some(n) = graph.nodes.get(*id) {
            for imp in &n.imports {
                if graph.nodes.contains_key(imp) {
                    out.push_str(&format!(
                        "    <edge id=\"e{edge_id}\" source=\"{}\" target=\"{}\"/>\n",
                        xml_escape(id), xml_escape(imp)
                    ));
                    edge_id += 1;
                }
            }
        }
    }
    out.push_str("  </graph>\n</graphml>\n");
    out
}

/// GEXF — Gephi Exchange Format. Includes per-kind color attributes
/// matching our dot/mermaid palette so Gephi auto-renders kinds
/// distinctly.
pub fn to_gexf(graph: &Graph) -> String {
    use crate::types::EntityKind::*;

    fn kind_color(k: crate::types::EntityKind) -> (u8, u8, u8) {
        match k {
            SourceFile        => (200, 200, 200),
            PeBinary          => (227, 242, 253),
            ElfBinary         => (232, 245, 233),
            MachoBinary       => (255, 243, 224),
            JavaClass         => (251, 233, 231),
            WasmModule        => (243, 229, 245),
            Dll               => (207, 216, 220),
            Symbol            => (255, 249, 196),
            HttpEndpoint      => (200, 230, 201),
            WebForm           => (220, 237, 200),
            SchemaTable       => (255, 224, 178),
            SchemaField       => (255, 248, 225),
            ProtoMessage      => (225, 190, 231),
            GraphqlType       => (209, 196, 233),
            OpenApiPath       => (178, 223, 219),
            DockerService     => (187, 222, 251),
            TerraformResource => (179, 157, 219),
            MlModel           => (255, 204, 188),
            DotnetAssembly    => (225, 245, 254),
            DotnetType        => (224, 247, 250),
            Compiler          => (252, 228, 236),
            StringLiteral     => (245, 245, 245),
            Overlay           => (239, 154, 154),
            BinaryFunction    => (255, 249, 196),
            License           => (197, 225, 165),
            Cve               => (239, 83, 80),
            Cert              => (144, 202, 249),
            AndroidPackage    => (165, 214, 167),
            Permission        => (255, 204, 128),
            Secret            => (211, 47, 47),
            Dependency        => (179, 229, 252),
            MlTensor          => (255, 224, 178),
            MlOperator        => (206, 147, 216),
            BinarySection     => (207, 216, 220),
            AntiAnalysis      => (239, 154, 154),
            CryptoConstant    => (255, 245, 157),
            CudaKernel        => (118, 185,   0), // NVIDIA green
            SwitchTable       => (179, 157, 219),
            VTable            => (128, 203, 196),
            ComClass          => (144, 202, 249),
            ComInterface      => (179, 157, 219),
            BinaryFingerprint => (244, 143, 177),
        }
    }

    let mut ids: Vec<&String> = graph.nodes.keys().collect();
    ids.sort();
    let id_to_idx: std::collections::HashMap<&str, usize> = ids.iter().enumerate()
        .map(|(i, s)| (s.as_str(), i)).collect();

    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<gexf xmlns=\"http://www.gexf.net/1.3\" version=\"1.3\" xmlns:viz=\"http://gexf.net/1.3/viz\">\n");
    out.push_str("  <graph mode=\"static\" defaultedgetype=\"directed\">\n");
    out.push_str("    <attributes class=\"node\">\n");
    out.push_str("      <attribute id=\"kind\" title=\"kind\" type=\"string\"/>\n");
    out.push_str("      <attribute id=\"lines\" title=\"lines\" type=\"int\"/>\n");
    out.push_str("    </attributes>\n");
    out.push_str("    <nodes>\n");
    for id in &ids {
        let n = &graph.nodes[*id];
        let (r, g, b) = kind_color(n.kind);
        out.push_str(&format!(
            "      <node id=\"{}\" label=\"{}\">\n        <attvalues>\n          <attvalue for=\"kind\" value=\"{}\"/>\n          <attvalue for=\"lines\" value=\"{}\"/>\n        </attvalues>\n        <viz:color r=\"{r}\" g=\"{g}\" b=\"{b}\"/>\n      </node>\n",
            xml_escape(id), xml_escape(id), n.kind.as_str(), n.lines
        ));
    }
    out.push_str("    </nodes>\n");
    out.push_str("    <edges>\n");
    let mut eid = 0;
    for id in &ids {
        if let Some(n) = graph.nodes.get(*id) {
            for imp in &n.imports {
                if let Some(&_) = id_to_idx.get(imp.as_str()) {
                    out.push_str(&format!(
                        "      <edge id=\"{eid}\" source=\"{}\" target=\"{}\"/>\n",
                        xml_escape(id), xml_escape(imp)
                    ));
                    eid += 1;
                }
            }
        }
    }
    out.push_str("    </edges>\n");
    out.push_str("  </graph>\n</gexf>\n");
    out
}
