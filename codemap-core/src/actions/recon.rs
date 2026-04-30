use std::collections::{HashMap, BTreeSet};
use crate::types::{Graph, EntityKind};

// ── Recon Artifact Parsers (5.16.0) ────────────────────────────────
//
// Four pure-static parsers consuming captured artifacts. Codemap
// stays a static analyzer — it never makes network requests. The
// user does the curl / playwright / nuclei / etc. and feeds the
// result here.
//
//   robots-parse      <robots.txt>     classify rules, flag leaky
//   web-sitemap-parse <sitemap.xml>    extract <loc>, detect ID enum
//   web-fingerprint   <html-or-har>    Wappalyzer-style tech detect
//   crt-parse         <crt.sh-json>    subdomain harvest from CT logs
//
// All four register typed nodes in the heterogeneous graph. No new
// EntityKinds — reuse HttpEndpoint, Compiler, Cert.

// ── robots-parse ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RobotsCategory {
    Admin,        // /admin/, /wp-admin/, /administrator/
    Api,          // /api/, /v1/, /v2/, /graphql
    Sensitive,    // /.git/, /.env, /backup/, /.aws/
    Auth,         // /login, /logout, /signin, /oauth/
    Search,       // /search, /find, /q
    Asset,        // /static/, /assets/, /css/, /js/
    Generic,      // anything else
}

impl RobotsCategory {
    fn as_str(&self) -> &'static str {
        match self {
            RobotsCategory::Admin     => "admin",
            RobotsCategory::Api       => "api",
            RobotsCategory::Sensitive => "sensitive",
            RobotsCategory::Auth      => "auth",
            RobotsCategory::Search    => "search",
            RobotsCategory::Asset     => "asset",
            RobotsCategory::Generic   => "generic",
        }
    }
    fn is_leaky(&self) -> bool {
        // "Leaky" = robots.txt advertises a path that should not be
        // public knowledge. Anything admin/sensitive/api falls here.
        matches!(self, RobotsCategory::Admin | RobotsCategory::Sensitive | RobotsCategory::Api)
    }
}

fn classify_robots_path(path: &str) -> RobotsCategory {
    let p = path.to_ascii_lowercase();
    // API check goes first because Spring Actuator's /management/* and JHipster's
    // /api-docs / /actuator are well-known API surfaces — categorizing them as
    // "admin" would lose that signal. The admin check below matches generic
    // /admin/, /dashboard/, /console/ paths but explicitly excludes /management/
    // (Spring/Java-ecosystem convention for the actuator endpoint).
    if p.starts_with("/api/") || p == "/api" || p.starts_with("/v1/") || p.starts_with("/v2/") || p.starts_with("/v3/")
        || p.starts_with("/graphql") || p.starts_with("/rest/") || p.starts_with("/rpc/")
        || p.starts_with("/swagger") || p.starts_with("/openapi") || p.contains("/api-docs")
        || p.contains("/actuator") || p.starts_with("/management/") || p == "/management"
        || p.starts_with("/manage/") {
        return RobotsCategory::Api;
    }
    if p.contains("/.git") || p.contains("/.env") || p.contains("/backup") || p.contains("/.aws")
        || p.contains("/.ssh") || p.contains("/.svn") || p.contains("/.htaccess")
        || p.contains("/wp-config") || p.contains("/config.php") || p.contains("/secrets")
        || p.contains("/dump") || p.contains("/private") || p.contains("/internal") {
        return RobotsCategory::Sensitive;
    }
    if p.contains("admin") || p.contains("wp-admin") || p.contains("/administrator") || p.contains("/manager")
        || p.contains("/console") || p.contains("/dashboard") {
        return RobotsCategory::Admin;
    }
    if p.contains("/login") || p.contains("/logout") || p.contains("/signin")
        || p.contains("/oauth") || p.contains("/auth") || p.contains("/sso") {
        return RobotsCategory::Auth;
    }
    if p.contains("/search") || p.starts_with("/find") || p == "/q" || p.starts_with("/q?") {
        return RobotsCategory::Search;
    }
    if p.starts_with("/static/") || p.starts_with("/assets/") || p.starts_with("/css/")
        || p.starts_with("/js/") || p.starts_with("/img/") || p.starts_with("/images/")
        || p.starts_with("/media/") || p.starts_with("/fonts/") {
        return RobotsCategory::Asset;
    }
    RobotsCategory::Generic
}

pub fn robots_parse(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap robots-parse <robots.txt-file>".to_string();
    }
    let content = match std::fs::read_to_string(target) {
        Ok(s) => s,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    let mut current_agent: Option<String> = None;
    let mut by_category: HashMap<RobotsCategory, Vec<String>> = HashMap::new();
    let mut sitemaps: Vec<String> = Vec::new();
    let mut total_rules = 0usize;
    let mut leaky_rules: Vec<(String, RobotsCategory)> = Vec::new();

    for raw in content.lines() {
        let line = raw.split('#').next().unwrap_or(raw).trim();
        if line.is_empty() { continue; }
        let mut parts = line.splitn(2, ':');
        let directive = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let value = parts.next().unwrap_or("").trim();
        match directive.as_str() {
            "user-agent" => current_agent = Some(value.to_string()),
            "disallow" | "allow" => {
                if value.is_empty() { continue; }
                total_rules += 1;
                let cat = classify_robots_path(value);
                by_category.entry(cat).or_default().push(value.to_string());
                if cat.is_leaky() {
                    leaky_rules.push((value.to_string(), cat));
                }
                // Register the path as an HttpEndpoint node.
                let ep_id = format!("ep:robots:{value}");
                graph.ensure_typed_node(&ep_id, EntityKind::HttpEndpoint, &[
                    ("path", value),
                    ("discovered_via", "robots"),
                    ("category", cat.as_str()),
                    ("agent", current_agent.as_deref().unwrap_or("*")),
                ]);
            }
            "sitemap" => {
                sitemaps.push(value.to_string());
                let ep_id = format!("ep:sitemap:{value}");
                graph.ensure_typed_node(&ep_id, EntityKind::HttpEndpoint, &[
                    ("url", value),
                    ("discovered_via", "robots_sitemap_directive"),
                ]);
            }
            _ => {}
        }
    }

    let mut lines = vec![
        format!("=== robots.txt: {target} ==="),
        format!("Rules:    {total_rules}"),
        format!("Sitemaps: {}", sitemaps.len()),
        format!("Leaky:    {} rules advertise sensitive paths", leaky_rules.len()),
        String::new(),
    ];

    for cat in [RobotsCategory::Admin, RobotsCategory::Sensitive, RobotsCategory::Api,
                RobotsCategory::Auth, RobotsCategory::Search, RobotsCategory::Asset,
                RobotsCategory::Generic] {
        if let Some(paths) = by_category.get(&cat) {
            if paths.is_empty() { continue; }
            let marker = if cat.is_leaky() { "⚠ " } else { "  " };
            lines.push(format!("{marker}{} ({}):", cat.as_str(), paths.len()));
            for p in paths.iter().take(15) {
                lines.push(format!("    {p}"));
            }
            if paths.len() > 15 {
                lines.push(format!("    ... and {} more", paths.len() - 15));
            }
        }
    }

    if !sitemaps.is_empty() {
        lines.push(String::new());
        lines.push(format!("── Sitemaps ({}) ──", sitemaps.len()));
        for s in &sitemaps {
            lines.push(format!("    {s}"));
        }
    }

    if !leaky_rules.is_empty() {
        lines.push(String::new());
        lines.push("⚠ Leaky robots.txt — these rules advertise sensitive paths:".to_string());
        for (path, cat) in leaky_rules.iter().take(20) {
            lines.push(format!("    [{}] {}", cat.as_str(), path));
        }
    }

    lines.join("\n")
}

// ── web-sitemap-parse ──────────────────────────────────────────────

pub fn web_sitemap_parse(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap web-sitemap-parse <sitemap.xml>  (gunzip first if .xml.gz)".to_string();
    }
    let content = match std::fs::read_to_string(target) {
        Ok(s) => s,
        Err(e) => {
            // Hint if user passed a .gz file
            if target.ends_with(".gz") {
                return format!("{target} appears to be gzipped — gunzip first then re-run:\n  gunzip -k {target} && codemap web-sitemap-parse {}", target.trim_end_matches(".gz"));
            }
            return format!("Failed to read {target}: {e}");
        }
    };

    // Pull <loc>...</loc> entries — sitemaps are stable on this tag,
    // even if the document shape is sitemap-index vs urlset.
    let mut urls: Vec<String> = Vec::new();
    let lower = content.to_ascii_lowercase();
    let is_index = lower.contains("<sitemapindex");

    let mut p = 0;
    while let Some(start) = content[p..].find("<loc>") {
        let abs_start = p + start + 5;
        if let Some(end) = content[abs_start..].find("</loc>") {
            let abs_end = abs_start + end;
            let url = content[abs_start..abs_end].trim().to_string();
            if !url.is_empty() && url.len() < 4096 {
                urls.push(url);
            }
            p = abs_end + 6;
        } else { break; }
        if urls.len() > 500_000 { break; }
    }

    if urls.is_empty() {
        return format!("=== Sitemap: {target} ===\nNo <loc> entries found. Confirm this is a valid sitemap (urlset or sitemapindex).");
    }

    // Group URLs by path-pattern (last 2 segments collapsed) to detect
    // ID-enumeration patterns like `/lawyer/{P_NUMBER}`.
    let mut pattern_counts: HashMap<String, usize> = HashMap::new();
    let mut numeric_id_pattern_counts: HashMap<String, usize> = HashMap::new();

    for url in &urls {
        let path = url.splitn(4, '/').nth(3).map(|s| format!("/{s}")).unwrap_or_default();
        let pattern = path_pattern(&path);
        *pattern_counts.entry(pattern.clone()).or_insert(0) += 1;
        if pattern.contains("{ID}") {
            *numeric_id_pattern_counts.entry(pattern).or_insert(0) += 1;
        }

        // Register each URL as an HttpEndpoint
        let ep_id = format!("ep:sitemap:{url}");
        graph.ensure_typed_node(&ep_id, EntityKind::HttpEndpoint, &[
            ("url", url),
            ("discovered_via", "sitemap"),
        ]);
    }

    let kind_label = if is_index { "sitemap index" } else { "urlset" };
    let mut sorted_patterns: Vec<(&String, &usize)> = pattern_counts.iter().collect();
    sorted_patterns.sort_by_key(|(_, c)| std::cmp::Reverse(**c));

    let mut lines = vec![
        format!("=== Sitemap: {target} ==="),
        format!("Type:           {kind_label}"),
        format!("URLs extracted: {}", urls.len()),
        format!("Distinct path patterns: {}", pattern_counts.len()),
        String::new(),
        "Top patterns by URL count:".to_string(),
    ];
    for (pat, count) in sorted_patterns.iter().take(20) {
        let marker = if pat.contains("{ID}") { "⚠ " } else { "  " };
        lines.push(format!("{marker}{:>7}  {}", count, pat));
    }

    if !numeric_id_pattern_counts.is_empty() {
        lines.push(String::new());
        lines.push(format!("⚠ {} ID-enumerable pattern(s) detected — sitemap exposes a complete enumeration:", numeric_id_pattern_counts.len()));
        for (pat, count) in &numeric_id_pattern_counts {
            lines.push(format!("    {pat:<60} {count} URLs"));
        }
        lines.push("    (these patterns let you bulk-enumerate every record without scraping search)".to_string());
    }

    lines.join("\n")
}

/// Replace numeric ID segments + UUID-shaped segments with `{ID}`.
/// `/lawyer/48331-MI-Mark-Vasquez-36316` → `/lawyer/{ID}`
/// `/post/1234`                          → `/post/{ID}`
fn path_pattern(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() { return "/".to_string(); }
    let mut out = String::with_capacity(path.len());
    for seg in segments {
        out.push('/');
        if has_numeric_id(seg) || is_uuid_shaped(seg) {
            out.push_str("{ID}");
        } else {
            out.push_str(seg);
        }
    }
    out
}

fn has_numeric_id(s: &str) -> bool {
    // 4+ consecutive digits anywhere in the segment
    let mut run = 0;
    for c in s.chars() {
        if c.is_ascii_digit() {
            run += 1;
            if run >= 4 { return true; }
        } else { run = 0; }
    }
    false
}

fn is_uuid_shaped(s: &str) -> bool {
    s.len() == 36 && s.matches('-').count() == 4
        && s.chars().all(|c| c == '-' || c.is_ascii_hexdigit())
}

// ── web-fingerprint ────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct FingerprintRule {
    name: &'static str,
    category: &'static str, // cms / framework / language / server / cdn / lib / analytics
    /// Substring patterns (case-sensitive, body OR header value)
    patterns: &'static [&'static str],
}

const FINGERPRINTS: &[FingerprintRule] = &[
    // Backend frameworks
    FingerprintRule { name: "JHipster",        category: "framework", patterns: &["field.equals=", "field.in=", "swagger-ui.html", "JHipster"] },
    FingerprintRule { name: "Spring Boot",     category: "framework", patterns: &["X-Application-Context", "/actuator/", "spring-boot"] },
    FingerprintRule { name: "Django",          category: "framework", patterns: &["csrfmiddlewaretoken", "django", "__admin", "wagtail"] },
    FingerprintRule { name: "Rails",           category: "framework", patterns: &["X-Powered-By: Phusion Passenger", "rails-ujs", "csrf-token"] },
    FingerprintRule { name: "Express",         category: "framework", patterns: &["X-Powered-By: Express"] },
    FingerprintRule { name: "Laravel",         category: "framework", patterns: &["laravel_session", "_token\":", "Set-Cookie: laravel"] },
    FingerprintRule { name: "ASP.NET",         category: "framework", patterns: &["X-AspNet-Version", "__VIEWSTATE", "X-Powered-By: ASP.NET"] },
    FingerprintRule { name: "ASP.NET Core",    category: "framework", patterns: &["X-Powered-By: ASP.NET Core", ".AspNetCore."] },
    FingerprintRule { name: "FastAPI",         category: "framework", patterns: &["server: uvicorn", "/docs#/", "openapi.json"] },
    FingerprintRule { name: "Flask",           category: "framework", patterns: &["server: Werkzeug"] },
    FingerprintRule { name: "Phoenix",         category: "framework", patterns: &["phx-trace", "data-phx-"] },

    // CMSes
    FingerprintRule { name: "WordPress",       category: "cms", patterns: &["/wp-content/", "/wp-includes/", "wp-json", "wp_login"] },
    FingerprintRule { name: "Drupal",          category: "cms", patterns: &["X-Generator: Drupal", "drupal-settings-json", "/sites/default/files/"] },
    FingerprintRule { name: "Joomla",          category: "cms", patterns: &["/components/com_", "joomla", "/templates/"] },
    FingerprintRule { name: "Ghost",           category: "cms", patterns: &["X-Powered-By: Ghost", "ghost-content"] },
    FingerprintRule { name: "Sanity",          category: "cms", patterns: &["sanity-studio", "@sanity/"] },
    FingerprintRule { name: "Contentful",      category: "cms", patterns: &["cdn.contentful.com", "contentful-management"] },
    FingerprintRule { name: "Strapi",          category: "cms", patterns: &["/_strapi/", "strapi-admin"] },

    // Frontend frameworks
    FingerprintRule { name: "Next.js",         category: "framework", patterns: &["X-Powered-By: Next.js", "/_next/static/", "__NEXT_DATA__"] },
    FingerprintRule { name: "React",           category: "lib",       patterns: &["data-reactroot", "data-react-helmet", "react-dom"] },
    FingerprintRule { name: "Vue.js",          category: "lib",       patterns: &["data-v-", "v-cloak", "vue.runtime"] },
    FingerprintRule { name: "Angular",         category: "framework", patterns: &["ng-version=", "ng-app=", "angular.js"] },
    FingerprintRule { name: "Svelte",          category: "framework", patterns: &["svelte-", "__svelte"] },
    FingerprintRule { name: "Nuxt",            category: "framework", patterns: &["__NUXT__", "/_nuxt/"] },
    FingerprintRule { name: "Gatsby",          category: "framework", patterns: &["gatsby", "/page-data.json"] },
    FingerprintRule { name: "Remix",           category: "framework", patterns: &["__remixContext", "remix-run"] },

    // Servers / proxies
    FingerprintRule { name: "nginx",           category: "server", patterns: &["Server: nginx"] },
    FingerprintRule { name: "Apache",          category: "server", patterns: &["Server: Apache"] },
    FingerprintRule { name: "IIS",             category: "server", patterns: &["Server: Microsoft-IIS"] },
    FingerprintRule { name: "Caddy",           category: "server", patterns: &["Server: Caddy"] },
    FingerprintRule { name: "OpenResty",       category: "server", patterns: &["Server: openresty"] },

    // CDNs
    FingerprintRule { name: "Cloudflare",      category: "cdn", patterns: &["Server: cloudflare", "CF-RAY", "cf-cache-status"] },
    FingerprintRule { name: "CloudFront",      category: "cdn", patterns: &["X-Amz-Cf-Id", "Server: CloudFront", "Via: 1.1 cloudfront"] },
    FingerprintRule { name: "Fastly",          category: "cdn", patterns: &["X-Served-By: cache-", "X-Fastly-Request-ID"] },
    FingerprintRule { name: "Akamai",          category: "cdn", patterns: &["X-Akamai-Transformed", "Server: AkamaiGHost"] },
    FingerprintRule { name: "Vercel",          category: "cdn", patterns: &["x-vercel-id", "Server: Vercel"] },
    FingerprintRule { name: "Netlify",         category: "cdn", patterns: &["X-NF-Request-ID", "Server: Netlify"] },

    // Languages (server-side hints)
    FingerprintRule { name: "PHP",             category: "language", patterns: &["X-Powered-By: PHP", "PHPSESSID"] },

    // Search/data infra exposed
    FingerprintRule { name: "Algolia",         category: "lib", patterns: &["algolianet.com", "algoliasearch", "algolia"] },
    FingerprintRule { name: "Elasticsearch",   category: "lib", patterns: &["X-elastic-product", "_search?q="] },

    // Analytics
    FingerprintRule { name: "Google Analytics", category: "analytics", patterns: &["www.google-analytics.com", "gtag(", "GoogleAnalyticsObject"] },
    FingerprintRule { name: "Segment",         category: "analytics", patterns: &["cdn.segment.com", "analytics.identify"] },
    FingerprintRule { name: "Mixpanel",        category: "analytics", patterns: &["cdn.mxpnl.com", "mixpanel.track"] },

    // JS libs
    FingerprintRule { name: "jQuery",          category: "lib", patterns: &["jquery.min.js", "jquery-3.", "jquery-2."] },
    FingerprintRule { name: "lodash",          category: "lib", patterns: &["lodash.min.js", "lodash@"] },
    FingerprintRule { name: "Bootstrap",       category: "lib", patterns: &["bootstrap.min.css", "bootstrap.bundle"] },
    FingerprintRule { name: "Tailwind",        category: "lib", patterns: &["tailwindcss", "tailwind.config"] },
];

pub fn web_fingerprint(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap web-fingerprint <html-or-har-file>".to_string();
    }
    let content = match std::fs::read_to_string(target) {
        Ok(s) => s,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };

    // Find which fingerprints match (simple substring search)
    let mut hits: Vec<(&FingerprintRule, usize)> = Vec::new();  // (rule, anchor count)
    for rule in FINGERPRINTS {
        let n = rule.patterns.iter().filter(|p| content.contains(*p)).count();
        if n > 0 { hits.push((rule, n)); }
    }
    hits.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.name.cmp(b.0.name)));

    if hits.is_empty() {
        return format!("=== Fingerprint: {target} ===\nNo known framework / CMS / server / CDN signatures matched.\n\nThis can mean: stripped headers, custom stack, or unknown vendor. Try `codemap web-dom <file>` for structural hints.");
    }

    // Register Compiler nodes per match
    let host_id = format!("fingerprint:{target}");
    for (rule, anchors) in &hits {
        let comp_id = format!("compiler:{}", rule.name);
        let confidence = (anchors * 25).min(100);
        let conf_str = confidence.to_string();
        let anchor_str = anchors.to_string();
        graph.ensure_typed_node(&comp_id, EntityKind::Compiler, &[
            ("name", rule.name),
            ("category", rule.category),
            ("source", "web_fingerprint"),
            ("confidence", &conf_str),
            ("anchor_matches", &anchor_str),
        ]);
        graph.add_edge(&host_id, &comp_id);
    }

    let mut lines = vec![format!("=== Fingerprint: {target} ===")];
    let mut by_cat: HashMap<&str, Vec<(&FingerprintRule, usize)>> = HashMap::new();
    for (rule, n) in &hits {
        by_cat.entry(rule.category).or_default().push((rule, *n));
    }
    let order = ["cms", "framework", "lib", "server", "cdn", "language", "analytics"];
    for cat in order {
        if let Some(rules) = by_cat.get(cat) {
            lines.push(String::new());
            lines.push(format!("── {} ({}) ──", cat, rules.len()));
            for (rule, n) in rules {
                let confidence = (n * 25).min(100);
                lines.push(format!("    {:<22}  {} match{}  conf={}%",
                    rule.name, n, if *n == 1 { "" } else { "es" }, confidence));
            }
        }
    }
    lines.join("\n")
}

// ── crt-parse ──────────────────────────────────────────────────────

pub fn crt_parse(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap crt-parse <crt.sh-json>\n  (fetch first: curl 'https://crt.sh/?q=%25.example.com&output=json' -o crt.json)".to_string();
    }
    let content = match std::fs::read_to_string(target) {
        Ok(s) => s,
        Err(e) => return format!("Failed to read {target}: {e}"),
    };
    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => return format!("crt.sh JSON parse error: {e}\n  (expected an array of cert records from crt.sh ?output=json)"),
    };

    let array = match json.as_array() {
        Some(a) => a,
        None => return "Expected a top-level JSON array.".to_string(),
    };

    let mut subdomains: BTreeSet<String> = BTreeSet::new();
    let mut issuers: HashMap<String, usize> = HashMap::new();
    let mut earliest_seen: HashMap<String, String> = HashMap::new();

    for entry in array {
        if let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) {
            for name in name_value.split('\n') {
                let n = name.trim().trim_start_matches("*.");
                if n.is_empty() || !n.contains('.') { continue; }
                subdomains.insert(n.to_lowercase());
                if let Some(nb) = entry.get("not_before").and_then(|v| v.as_str()) {
                    earliest_seen.entry(n.to_lowercase())
                        .and_modify(|cur| { if nb < cur.as_str() { *cur = nb.to_string(); } })
                        .or_insert_with(|| nb.to_string());
                }
            }
        }
        if let Some(issuer) = entry.get("issuer_name").and_then(|v| v.as_str()) {
            *issuers.entry(issuer.to_string()).or_insert(0) += 1;
        }
    }

    if subdomains.is_empty() {
        return format!("=== crt.sh: {target} ===\nNo subdomains found in {} cert records.", array.len());
    }

    // Register nodes
    for sub in &subdomains {
        let host_id = format!("ep:crt:{sub}");
        let mut attrs: Vec<(&str, &str)> = vec![
            ("host", sub),
            ("discovered_via", "crt_sh"),
        ];
        let first_seen_str;
        if let Some(fs) = earliest_seen.get(sub) {
            first_seen_str = fs.clone();
            attrs.push(("first_seen", &first_seen_str));
        } else {
            first_seen_str = String::new();
        }
        graph.ensure_typed_node(&host_id, EntityKind::HttpEndpoint, &attrs);
    }
    for (issuer, _) in &issuers {
        let cert_id = format!("cert:issuer:{issuer}");
        graph.ensure_typed_node(&cert_id, EntityKind::Cert, &[
            ("issuer_cn", issuer.as_str()),
            ("source", "crt_sh"),
        ]);
    }

    let mut sorted_issuers: Vec<(&String, &usize)> = issuers.iter().collect();
    sorted_issuers.sort_by_key(|(_, c)| std::cmp::Reverse(**c));

    let mut lines = vec![
        format!("=== crt.sh: {target} ==="),
        format!("Cert records:    {}", array.len()),
        format!("Distinct hosts:  {}", subdomains.len()),
        format!("Distinct issuers: {}", issuers.len()),
        String::new(),
        format!("── Top subdomains (showing {} of {}) ──", 30.min(subdomains.len()), subdomains.len()),
    ];
    for sub in subdomains.iter().take(30) {
        if let Some(fs) = earliest_seen.get(sub) {
            lines.push(format!("  {:<50}  first seen {}", sub, &fs[..fs.len().min(10)]));
        } else {
            lines.push(format!("  {sub}"));
        }
    }

    lines.push(String::new());
    lines.push(format!("── Top issuers ({}) ──", sorted_issuers.len().min(10)));
    for (issuer, count) in sorted_issuers.iter().take(10) {
        let short = issuer.lines().next().unwrap_or(issuer);
        lines.push(format!("  {:>5}  {}", count, short.chars().take(80).collect::<String>()));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_robots_paths() {
        assert_eq!(classify_robots_path("/admin/"), RobotsCategory::Admin);
        assert_eq!(classify_robots_path("/wp-admin"), RobotsCategory::Admin);
        assert_eq!(classify_robots_path("/.git/"), RobotsCategory::Sensitive);
        assert_eq!(classify_robots_path("/api/v2/"), RobotsCategory::Api);
        assert_eq!(classify_robots_path("/management/health"), RobotsCategory::Api);
        assert_eq!(classify_robots_path("/login"), RobotsCategory::Auth);
        assert_eq!(classify_robots_path("/static/css/app.css"), RobotsCategory::Asset);
        assert_eq!(classify_robots_path("/random/path"), RobotsCategory::Generic);
    }

    #[test]
    fn category_leakiness() {
        assert!(RobotsCategory::Admin.is_leaky());
        assert!(RobotsCategory::Sensitive.is_leaky());
        assert!(RobotsCategory::Api.is_leaky());
        assert!(!RobotsCategory::Asset.is_leaky());
        assert!(!RobotsCategory::Auth.is_leaky());
    }

    #[test]
    fn path_pattern_replaces_numeric_id() {
        assert_eq!(path_pattern("/lawyer/48331-MI-Mark-Vasquez-36316"), "/lawyer/{ID}");
        assert_eq!(path_pattern("/post/12345"), "/post/{ID}");
        assert_eq!(path_pattern("/category/news"), "/category/news");
        assert_eq!(path_pattern("/foo/bar"), "/foo/bar");
    }

    #[test]
    fn path_pattern_replaces_uuid() {
        assert_eq!(
            path_pattern("/article/550e8400-e29b-41d4-a716-446655440000"),
            "/article/{ID}",
        );
    }

    #[test]
    fn fingerprint_substring_matching() {
        // Find at least one rule that matches a known signature in the corpus
        let html = r#"<html><body data-reactroot><script src="/static/jquery-3.6.0.min.js"></script></body></html>"#;
        let mut hits = 0;
        for rule in FINGERPRINTS {
            if rule.patterns.iter().any(|p| html.contains(p)) {
                hits += 1;
            }
        }
        assert!(hits >= 2, "expected ≥2 fingerprint matches (React + jQuery), got {hits}");
    }

    #[test]
    fn has_numeric_id_basic() {
        assert!(has_numeric_id("post1234"));
        assert!(has_numeric_id("48331-MI"));
        assert!(!has_numeric_id("foo"));
        assert!(!has_numeric_id("v1"));
        assert!(!has_numeric_id("abc"));
    }
}
