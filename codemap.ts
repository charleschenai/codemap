#!/usr/bin/env bun
/**
 * graph — Codebase dependency analysis CLI
 * 
 * Scans source files, builds an import graph, answers structural questions.
 * No dependencies. Single file. Works with any language.
 *
 * Usage:
 *   graph trace src/utils/auth.ts
 *   graph blast-radius src/utils/auth.ts
 *   graph phone-home
 *   graph dead-files
 *   graph circular
 *   graph coupling @anthropic-ai/sdk
 *   graph functions src/utils/auth.ts
 *   graph callers getApiKey
 *   graph stats
 *
 * Or point it at a different directory:
 *   graph --dir ~/Desktop/my-project trace src/foo.ts
 */

import { readdirSync, readFileSync, statSync } from "fs"
import { join, relative, resolve, extname, dirname } from "path"

// ── Patterns ──────────────────────────────────────────────────────────

const IMPORT_RE = /(?:import|export)\s+.*?from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\)/gm
const DYNAMIC_IMPORT_RE = /import\s*\(\s*['"]([^'"]+)['"]\s*\)/gm
const URL_RE = /['"`](https?:\/\/[^'"`\s]{5,})['"`]/gm
const EXPORT_RE = /export\s+(?:const|let|var|function|async\s+function|class|type|interface|enum)\s+(\w+)/gm
const SUPPORTED_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rs", ".go", ".java", ".rb", ".php"])

// ── Types ─────────────────────────────────────────────────────────────

interface GraphNode {
  id: string
  imports: string[]
  importedBy: string[]
  urls: string[]
  exports: string[]
  lines: number
}

interface Graph {
  nodes: Map<string, GraphNode>
  scanDir: string
}

// ── Resolution ───────────────────────────────────────────────────────

/**
 * Resolve an import specifier to a file path.
 * Uses manual resolution with tsconfig path alias support.
 * Falls back to raw specifier for unresolvable packages.
 */

let _tsconfigPaths: Map<string, string> | null = null

function loadTsconfigPaths(scanDir: string): Map<string, string> {
  if (_tsconfigPaths) return _tsconfigPaths
  _tsconfigPaths = new Map()
  // Walk up from scanDir to find tsconfig.json
  let searchDir = scanDir
  for (let i = 0; i < 5; i++) {
    try {
      const tsconfigPath = join(searchDir, "tsconfig.json")
      const tsconfig = JSON.parse(readFileSync(tsconfigPath, "utf-8"))
      const paths = tsconfig.compilerOptions?.paths || {}
      const baseUrl = tsconfig.compilerOptions?.baseUrl || "."
      const base = resolve(searchDir, baseUrl)
      for (const [alias, targets] of Object.entries(paths) as [string, string[]][]) {
        const prefix = alias.replace(/\*$/, "")
        const target = (targets[0] || "").replace(/\*$/, "")
        _tsconfigPaths.set(prefix, resolve(base, target))
      }
      break
    } catch {
      const parent = dirname(searchDir)
      if (parent === searchDir) break
      searchDir = parent
    }
  }
  return _tsconfigPaths
}

function resolveAndAdd(specifier: string, fromFile: string, scanDir: string, node: GraphNode): void {
  if (specifier.startsWith(".")) {
    // Relative import — try exact, .js→.ts swap, then extensions
    const resolved = resolve(dirname(fromFile), specifier)
    const candidates = [
      resolved,
      resolved.replace(/\.js$/, ".ts"),
      resolved.replace(/\.js$/, ".tsx"),
      resolved.replace(/\.jsx$/, ".tsx"),
      resolved.replace(/\.mjs$/, ".mts"),
    ]
    for (const base of candidates) {
      try {
        statSync(base)
        node.imports.push(relative(scanDir, base))
        return
      } catch {}
    }
    // Try adding extensions
    for (const ext of [".ts", ".tsx", ".js", ".jsx", ".mjs", "/index.ts", "/index.tsx", "/index.js"]) {
      try {
        const candidate = resolved + ext
        statSync(candidate)
        node.imports.push(relative(scanDir, candidate))
        return
      } catch {}
    }
    return
  }

  // Try tsconfig path aliases
  const paths = loadTsconfigPaths(scanDir)
  for (const [prefix, target] of paths) {
    if (specifier.startsWith(prefix)) {
      const rest = specifier.slice(prefix.length)
      const resolved = join(target, rest)
      // Try exact, then swap .js→.ts, then extensions, then index
      const candidates = [
        resolved,
        resolved.replace(/\.js$/, ".ts"),
        resolved.replace(/\.js$/, ".tsx"),
        resolved.replace(/\.jsx$/, ".tsx"),
        resolved + ".ts",
        resolved + ".tsx",
        resolved + ".js",
        resolved + "/index.ts",
        resolved + "/index.js",
      ]
      for (const candidate of candidates) {
        try {
          statSync(candidate)
          node.imports.push(relative(scanDir, candidate))
          return
        } catch {}
      }
    }
  }

  // Bare specifier — store package name only
  node.imports.push(specifier.split("/").slice(0, specifier.startsWith("@") ? 2 : 1).join("/"))
}

// ── Scanner ───────────────────────────────────────────────────────────

function scanDirectory(dir: string): Graph {
  const nodes = new Map<string, GraphNode>()
  const allFiles: string[] = []

  function walk(d: string) {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "dist" || entry.name === "build") continue
      const full = join(d, entry.name)
      if (entry.isDirectory()) {
        walk(full)
      } else if (SUPPORTED_EXTS.has(extname(entry.name))) {
        allFiles.push(full)
      }
    }
  }
  walk(dir)

  // Parse each file
  for (const file of allFiles) {
    let content: string
    try {
      content = readFileSync(file, "utf-8")
    } catch {
      continue
    }

    const id = relative(dir, file)
    const node: GraphNode = {
      id,
      imports: [],
      importedBy: [],
      urls: [],
      exports: [],
      lines: content.split("\n").length,
    }

    // Extract imports (static + re-exports)
    let m: RegExpExecArray | null
    IMPORT_RE.lastIndex = 0
    while ((m = IMPORT_RE.exec(content)) !== null) {
      const target = m[1] || m[2]
      if (!target) continue
      resolveAndAdd(target, file, dir, node)
    }

    // Extract dynamic imports: import('./foo'), await import('./foo')
    DYNAMIC_IMPORT_RE.lastIndex = 0
    while ((m = DYNAMIC_IMPORT_RE.exec(content)) !== null) {
      const target = m[1]
      if (!target) continue
      resolveAndAdd(target, file, dir, node)
    }

    // Extract URLs
    URL_RE.lastIndex = 0
    while ((m = URL_RE.exec(content)) !== null) {
      const url = m[1]
      if (!url.includes("localhost") && !url.includes("127.0.0.1") && !url.includes("example.com")) {
        node.urls.push(url.split("?")[0].substring(0, 120))
      }
    }

    // Extract exports
    EXPORT_RE.lastIndex = 0
    while ((m = EXPORT_RE.exec(content)) !== null) {
      node.exports.push(m[1])
    }

    nodes.set(id, node)
  }

  // Compute importedBy (reverse edges)
  for (const [id, node] of nodes) {
    for (const imp of node.imports) {
      const target = nodes.get(imp)
      if (target) {
        target.importedBy.push(id)
      }
    }
  }

  return { nodes, scanDir: dir }
}

// ── Actions ───────────────────────────────────────────────────────────

function trace(graph: Graph, target: string): string {
  const node = findNode(graph, target)
  if (!node) return `File not found in graph: ${target}`

  const lines = [`=== ${node.id} (${node.lines} lines) ===`, ""]

  if (node.imports.length) {
    lines.push(`Imports (${node.imports.length}):`)
    for (const imp of node.imports) lines.push(`  → ${imp}`)
    lines.push("")
  }

  if (node.importedBy.length) {
    lines.push(`Imported by (${node.importedBy.length}):`)
    for (const imp of node.importedBy) lines.push(`  ← ${imp}`)
    lines.push("")
  }

  if (node.urls.length) {
    lines.push(`URLs (${node.urls.length}):`)
    for (const url of node.urls) lines.push(`  🌐 ${url}`)
    lines.push("")
  }

  if (node.exports.length) {
    lines.push(`Exports (${node.exports.length}):`)
    for (const exp of node.exports) lines.push(`  ▸ ${exp}`)
  }

  if (!node.imports.length && !node.importedBy.length && !node.urls.length && !node.exports.length) {
    lines.push("(isolated file — no imports, no importers, no URLs, no exports)")
  }

  return lines.join("\n")
}

function blastRadius(graph: Graph, target: string): string {
  const node = findNode(graph, target)
  if (!node) return `File not found in graph: ${target}`

  const visited = new Set<string>()
  const queue = [node.id]
  visited.add(node.id)

  while (queue.length) {
    const current = queue.shift()!
    const n = graph.nodes.get(current)
    if (!n) continue
    for (const dep of n.importedBy) {
      if (!visited.has(dep)) {
        visited.add(dep)
        queue.push(dep)
      }
    }
  }

  visited.delete(node.id) // exclude self
  const sorted = [...visited].sort()
  const lines = [`Blast radius for ${node.id}: ${sorted.length} files affected`, ""]
  for (const f of sorted) lines.push(`  ${f}`)
  return lines.join("\n")
}

function phoneHome(graph: Graph): string {
  const results: { id: string; urls: string[] }[] = []
  for (const [id, node] of graph.nodes) {
    if (node.urls.length) results.push({ id, urls: node.urls })
  }

  if (!results.length) return "No external URLs found in codebase."

  results.sort((a, b) => b.urls.length - a.urls.length)
  const lines = [`${results.length} files with external URLs:`, ""]
  for (const r of results) {
    lines.push(`${r.id} (${r.urls.length} URLs):`)
    for (const url of r.urls) lines.push(`  ${url}`)
    lines.push("")
  }
  return lines.join("\n")
}

function coupling(graph: Graph, target: string): string {
  const results: string[] = []
  for (const [id, node] of graph.nodes) {
    if (node.imports.some(imp => imp.includes(target))) {
      results.push(id)
    }
  }

  if (!results.length) return `No files import "${target}".`
  results.sort()
  const lines = [`${results.length} files coupled to "${target}":`, ""]
  for (const f of results) lines.push(`  ${f}`)
  return lines.join("\n")
}

function deadFiles(graph: Graph): string {
  const dead: string[] = []
  for (const [id, node] of graph.nodes) {
    if (node.importedBy.length === 0 && !id.includes("index.") && !id.includes("main.") && !id.includes("cli.") && !id.includes("entry")) {
      dead.push(id)
    }
  }

  if (!dead.length) return "No dead files found (all files are imported by something)."
  dead.sort()
  const lines = [`${dead.length} files with zero importers:`, ""]
  for (const f of dead) lines.push(`  ${f}`)
  return lines.join("\n")
}

function circular(graph: Graph): string {
  const cycles: string[][] = []
  const visited = new Set<string>()
  const stack = new Set<string>()

  function dfs(id: string, path: string[]) {
    if (stack.has(id)) {
      const cycleStart = path.indexOf(id)
      if (cycleStart >= 0) {
        cycles.push(path.slice(cycleStart).concat(id))
      }
      return
    }
    if (visited.has(id)) return
    visited.add(id)
    stack.add(id)

    const node = graph.nodes.get(id)
    if (node) {
      for (const imp of node.imports) {
        if (graph.nodes.has(imp)) {
          dfs(imp, [...path, id])
        }
      }
    }
    stack.delete(id)
  }

  for (const id of graph.nodes.keys()) {
    if (!visited.has(id)) dfs(id, [])
  }

  if (!cycles.length) return "No circular dependencies found."
  const lines = [`${cycles.length} circular dependencies:`, ""]
  for (const cycle of cycles.slice(0, 20)) {
    lines.push(`  ${cycle.join(" → ")}`)
  }
  if (cycles.length > 20) lines.push(`  ... and ${cycles.length - 20} more`)
  return lines.join("\n")
}

function functions(graph: Graph, target: string): string {
  const node = findNode(graph, target)
  if (!node) return `File not found: ${target}`

  if (!node.exports.length) return `No exports found in ${node.id}`
  const lines = [`Exports in ${node.id} (${node.exports.length}):`, ""]
  for (const exp of node.exports) lines.push(`  ▸ ${exp}`)
  return lines.join("\n")
}

function callers(graph: Graph, target: string): string {
  const dir = graph.scanDir
  const results: { file: string; line: number; text: string }[] = []
  const re = new RegExp(`\\b${target}\\b`)

  for (const [id, node] of graph.nodes) {
    try {
      const content = readFileSync(join(dir, id), "utf-8")
      const lines = content.split("\n")
      for (let i = 0; i < lines.length; i++) {
        if (re.test(lines[i]) && !lines[i].includes("export ") && !lines[i].includes("function " + target)) {
          results.push({ file: id, line: i + 1, text: lines[i].trim().substring(0, 100) })
        }
      }
    } catch {
      // skip unreadable files
    }
  }

  if (!results.length) return `"${target}" not found in any file.`
  results.sort((a, b) => a.file.localeCompare(b.file))
  const lines = [`"${target}" found in ${results.length} locations:`, ""]
  for (const r of results) lines.push(`  ${r.file}:${r.line}  ${r.text}`)
  return lines.join("\n")
}

function stats(graph: Graph): string {
  let totalLines = 0
  let totalImports = 0
  let totalUrls = 0
  let totalExports = 0
  const exts = new Map<string, number>()

  for (const [id, node] of graph.nodes) {
    totalLines += node.lines
    totalImports += node.imports.length
    totalUrls += node.urls.length
    totalExports += node.exports.length
    const ext = extname(id)
    exts.set(ext, (exts.get(ext) || 0) + 1)
  }

  const lines = [
    `=== Graph Stats ===`,
    `Files: ${graph.nodes.size}`,
    `Lines: ${totalLines.toLocaleString()}`,
    `Import edges: ${totalImports}`,
    `External URLs: ${totalUrls}`,
    `Exports: ${totalExports}`,
    "",
    "By extension:",
  ]
  for (const [ext, count] of [...exts.entries()].sort((a, b) => b[1] - a[1])) {
    lines.push(`  ${ext}: ${count}`)
  }
  return lines.join("\n")
}

// ── Helpers ───────────────────────────────────────────────────────────

function findNode(graph: Graph, target: string): GraphNode | undefined {
  // Exact match
  if (graph.nodes.has(target)) return graph.nodes.get(target)
  // Partial match (filename without path)
  for (const [id, node] of graph.nodes) {
    if (id.endsWith(target) || id.endsWith("/" + target)) return node
  }
  return undefined
}

// ── CLI ───────────────────────────────────────────────────────────────

const args = process.argv.slice(2)

let dir = process.cwd()
let actionArgs = args

// Parse --dir flag
const dirIdx = args.indexOf("--dir")
if (dirIdx >= 0 && args[dirIdx + 1]) {
  dir = resolve(args[dirIdx + 1])
  actionArgs = [...args.slice(0, dirIdx), ...args.slice(dirIdx + 2)]
}

const action = actionArgs[0]
const target = actionArgs.slice(1).join(" ")

if (!action || action === "--help" || action === "-h") {
  console.log(`graph — Codebase dependency analysis

Usage: graph [--dir <path>] <action> [target]

Actions:
  trace <file>          Show imports and importers of a file
  blast-radius <file>   Show all files affected if a file changes
  phone-home            Find all files with external URLs
  coupling <pattern>    Find files importing a package/pattern
  dead-files            Find files nothing imports
  circular              Detect circular dependency chains
  functions <file>      List exports in a file
  callers <name>        Find where a function is used
  stats                 Show codebase statistics

Options:
  --dir <path>          Directory to scan (default: cwd)

Examples:
  graph trace src/utils/auth.ts
  graph blast-radius src/services/api/client.ts
  graph phone-home
  graph coupling @anthropic-ai/sdk
  graph dead-files
  graph callers getApiKey
  graph --dir ~/Desktop/my-project stats`)
  process.exit(0)
}

// Scan
const t0 = Date.now()
const graph = scanDirectory(dir)
const scanMs = Date.now() - t0
console.error(`Scanned ${graph.nodes.size} files in ${scanMs}ms\n`)

// Execute
switch (action) {
  case "trace": console.log(trace(graph, target)); break
  case "blast-radius": console.log(blastRadius(graph, target)); break
  case "phone-home": console.log(phoneHome(graph)); break
  case "coupling": console.log(coupling(graph, target)); break
  case "dead-files": console.log(deadFiles(graph)); break
  case "circular": console.log(circular(graph)); break
  case "functions": console.log(functions(graph, target)); break
  case "callers": console.log(callers(graph, target)); break
  case "stats": console.log(stats(graph)); break
  default: console.error(`Unknown action: ${action}. Run 'graph --help' for usage.`); process.exit(1)
}
