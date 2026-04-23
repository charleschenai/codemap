#!/usr/bin/env bun
/**
 * codemap — Codebase dependency analysis CLI
 *
 * Scans source files, builds an import graph, answers structural questions.
 * No dependencies. Single file. Works with any language.
 *
 * Usage:
 *   codemap stats                              # codebase overview
 *   codemap trace src/utils/auth.ts            # imports + importers
 *   codemap blast-radius src/api/client.ts     # all affected files
 *   codemap phone-home                         # external URLs
 *   codemap coupling @anthropic-ai/sdk         # files importing a package
 *   codemap dead-files                         # files nothing imports
 *   codemap circular                           # circular dependencies
 *   codemap functions src/utils/auth.ts        # exports in a file
 *   codemap callers getApiKey                  # find function usage
 *   codemap hotspots                           # most coupled files
 *   codemap layers                             # architectural layers
 *   codemap diff HEAD~5                        # blast radius of git changes
 *   codemap orphan-exports                     # unused exports
 *   codemap why fileA fileB                    # shortest import path
 *   codemap size                               # files by line count
 *   codemap compare ~/other-project            # structural A/B diff
 *
 * Or point it at a different directory:
 *   codemap --dir ~/Desktop/my-project stats
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
  if (!node) return `File not found: ${target}`

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
  if (!node) return `File not found: ${target}`

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
    `=== Codemap Stats ===`,
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

// ── New Actions ──────────────────────────────────────────────────────

function hotspots(graph: Graph): string {
  const scored: { id: string; imports: number; importers: number; total: number }[] = []
  for (const [id, node] of graph.nodes) {
    const total = node.imports.length + node.importedBy.length
    if (total > 0) scored.push({ id, imports: node.imports.length, importers: node.importedBy.length, total })
  }
  scored.sort((a, b) => b.total - a.total)
  const top = scored.slice(0, 30)
  if (!top.length) return "No coupling found in codebase."
  const lines = [`=== Hotspots (top ${top.length} most coupled files) ===`, ""]
  for (const s of top) {
    lines.push(`  ${s.total.toString().padStart(4)} coupling  ${s.id}  (${s.imports}→ ${s.importers}←)`)
  }
  return lines.join("\n")
}

function layers(graph: Graph): string {
  // Assign layers using BFS from entry points (files with no importers)
  // Following import edges downward. Circular deps are broken by visiting each node only once.
  const roots: string[] = []
  for (const [id, node] of graph.nodes) {
    if (node.importedBy.length === 0) roots.push(id)
  }

  const depth = new Map<string, number>()
  // BFS from roots, following imports. First visit wins (shortest path = shallowest layer).
  const queue: [string, number][] = roots.map(r => [r, 0])
  const visited = new Set<string>()

  while (queue.length) {
    const [id, d] = queue.shift()!
    if (visited.has(id)) continue
    visited.add(id)
    depth.set(id, d)
    const node = graph.nodes.get(id)
    if (node) {
      for (const imp of node.imports) {
        if (graph.nodes.has(imp) && !visited.has(imp)) {
          queue.push([imp, d + 1])
        }
      }
    }
  }
  // Files in cycles not reachable from roots
  for (const id of graph.nodes.keys()) {
    if (!depth.has(id)) depth.set(id, 0)
  }

  // Group by depth
  const layerMap = new Map<number, string[]>()
  for (const [id, d] of depth) {
    if (!layerMap.has(d)) layerMap.set(d, [])
    layerMap.get(d)!.push(id)
  }

  const sortedLayers = [...layerMap.entries()].sort((a, b) => a[0] - b[0])
  const lines = [`=== Architecture Layers (${sortedLayers.length} levels) ===`, ""]

  const labelGuess = (d: number, max: number) => {
    if (d === 0) return "entry points"
    if (d === max) return "leaf modules"
    if (d <= max * 0.3) return "orchestration"
    if (d <= max * 0.6) return "services"
    return "utilities"
  }

  const maxDepth = sortedLayers.length ? sortedLayers[sortedLayers.length - 1][0] : 0
  for (const [d, files] of sortedLayers) {
    files.sort()
    lines.push(`Layer ${d} — ${labelGuess(d, maxDepth)} (${files.length} files):`)
    for (const f of files.slice(0, 10)) lines.push(`  ${f}`)
    if (files.length > 10) lines.push(`  ... and ${files.length - 10} more`)
    lines.push("")
  }

  // Check for cross-layer violations (deeper importing shallower)
  const violations: string[] = []
  for (const [id, node] of graph.nodes) {
    const myDepth = depth.get(id) ?? 0
    for (const imp of node.imports) {
      const impDepth = depth.get(imp)
      if (impDepth !== undefined && impDepth < myDepth && (myDepth - impDepth) > 1) {
        violations.push(`  ${id} (L${myDepth}) → ${imp} (L${impDepth})`)
      }
    }
  }
  if (violations.length) {
    lines.push(`Cross-layer imports (${violations.length} — deeper importing shallower, skipping layers):`)
    for (const v of violations.slice(0, 20)) lines.push(v)
    if (violations.length > 20) lines.push(`  ... and ${violations.length - 20} more`)
  }

  return lines.join("\n")
}

function diff(graph: Graph, gitRef: string): string {
  if (!gitRef) return "Usage: codemap diff <git-ref>  (e.g. codemap diff HEAD~3, codemap diff main)"

  let changedFiles: string[]
  try {
    const result = Bun.spawnSync(["git", "diff", "--name-only", gitRef], { cwd: graph.scanDir })
    const output = result.stdout.toString().trim()
    if (!output) return `No files changed since ${gitRef}.`
    changedFiles = output.split("\n").filter(f => f.trim())
  } catch {
    return `Failed to run git diff against "${gitRef}". Make sure you're in a git repo.`
  }

  // Filter to files we scanned
  const relevant = changedFiles.filter(f => graph.nodes.has(f))
  if (!relevant.length) return `${changedFiles.length} files changed since ${gitRef}, but none are in the scanned source.`

  // Compute combined blast radius
  const allAffected = new Set<string>()
  for (const file of relevant) {
    const visited = new Set<string>()
    const queue = [file]
    visited.add(file)
    while (queue.length) {
      const current = queue.shift()!
      const n = graph.nodes.get(current)
      if (!n) continue
      for (const dep of n.importedBy) {
        if (!visited.has(dep)) { visited.add(dep); queue.push(dep) }
      }
    }
    visited.delete(file)
    for (const v of visited) allAffected.add(v)
  }

  const lines = [
    `=== Diff Analysis: ${gitRef} ===`,
    `Changed source files: ${relevant.length}`,
    `Total blast radius: ${allAffected.size} additional files affected`,
    "",
    "Changed files:"
  ]
  for (const f of relevant.sort()) lines.push(`  * ${f}`)

  if (allAffected.size) {
    lines.push("", "Affected by changes:")
    for (const f of [...allAffected].sort()) lines.push(`  ${f}`)
  }

  return lines.join("\n")
}

function orphanExports(graph: Graph): string {
  const orphans: { file: string; name: string }[] = []

  for (const [id, node] of graph.nodes) {
    if (!node.exports.length) continue
    const content = (() => {
      try { return readFileSync(join(graph.scanDir, id), "utf-8") } catch { return "" }
    })()

    for (const exp of node.exports) {
      const re = new RegExp(`\\b${exp}\\b`)
      let found = false
      for (const [otherId, otherNode] of graph.nodes) {
        if (otherId === id) continue
        // Only check files that import this file
        if (!otherNode.imports.includes(id)) continue
        try {
          const otherContent = readFileSync(join(graph.scanDir, otherId), "utf-8")
          if (re.test(otherContent)) { found = true; break }
        } catch { continue }
      }
      if (!found) orphans.push({ file: id, name: exp })
    }
  }

  if (!orphans.length) return "No orphan exports found — all exports are used somewhere."
  orphans.sort((a, b) => a.file.localeCompare(b.file) || a.name.localeCompare(b.name))
  const lines = [`${orphans.length} orphan exports (exported but never imported):`, ""]
  let lastFile = ""
  for (const o of orphans.slice(0, 100)) {
    if (o.file !== lastFile) { lines.push(`  ${o.file}:`); lastFile = o.file }
    lines.push(`    ▸ ${o.name}`)
  }
  if (orphans.length > 100) lines.push(`  ... and ${orphans.length - 100} more`)
  return lines.join("\n")
}

function why(graph: Graph, args: string): string {
  const parts = args.split(/\s+/)
  if (parts.length < 2) return "Usage: codemap why <fileA> <fileB>"
  const [a, b] = parts
  const nodeA = findNode(graph, a)
  const nodeB = findNode(graph, b)
  if (!nodeA) return `File not found: ${a}`
  if (!nodeB) return `File not found: ${b}`

  // BFS from A to B following imports
  const queue: string[][] = [[nodeA.id]]
  const visited = new Set<string>([nodeA.id])

  while (queue.length) {
    const path = queue.shift()!
    const current = path[path.length - 1]
    if (current === nodeB.id) {
      const lines = [`Shortest path (${path.length - 1} hops):`, ""]
      lines.push("  " + path.join("\n  → "))
      return lines.join("\n")
    }
    const node = graph.nodes.get(current)
    if (!node) continue
    for (const imp of node.imports) {
      if (!visited.has(imp) && graph.nodes.has(imp)) {
        visited.add(imp)
        queue.push([...path, imp])
      }
    }
  }

  // Try reverse direction
  const queue2: string[][] = [[nodeB.id]]
  const visited2 = new Set<string>([nodeB.id])
  while (queue2.length) {
    const path = queue2.shift()!
    const current = path[path.length - 1]
    if (current === nodeA.id) {
      const reversed = path.reverse()
      const lines = [`Shortest path (${reversed.length - 1} hops, reverse direction):`, ""]
      lines.push("  " + reversed.join("\n  → "))
      return lines.join("\n")
    }
    const node = graph.nodes.get(current)
    if (!node) continue
    for (const imp of node.imports) {
      if (!visited2.has(imp) && graph.nodes.has(imp)) {
        visited2.add(imp)
        queue2.push([...path, imp])
      }
    }
  }

  return `No import path found between ${nodeA.id} and ${nodeB.id}.`
}

function size(graph: Graph): string {
  const files = [...graph.nodes.entries()]
    .map(([id, node]) => ({ id, lines: node.lines }))
    .sort((a, b) => b.lines - a.lines)

  const top = files.slice(0, 30)
  if (!top.length) return "No files found."
  const total = files.reduce((s, f) => s + f.lines, 0)
  const lines = [`=== File Size Ranking (top ${top.length} of ${files.length}) ===`, `Total: ${total.toLocaleString()} lines`, ""]
  for (const f of top) {
    const pct = ((f.lines / total) * 100).toFixed(1)
    lines.push(`  ${f.lines.toString().padStart(6)} lines  (${pct.padStart(5)}%)  ${f.id}`)
  }
  return lines.join("\n")
}

function compare(graph: Graph, otherDir: string): string {
  if (!otherDir) return "Usage: codemap compare <other-dir>  (e.g. codemap compare ~/Desktop/old-version)"
  const resolvedDir = resolve(otherDir)

  let otherGraph: Graph
  try {
    otherGraph = scanDirectory(resolvedDir)
  } catch {
    return `Failed to scan directory: ${resolvedDir}`
  }

  const aFiles = new Set(graph.nodes.keys())
  const bFiles = new Set(otherGraph.nodes.keys())

  const added = [...aFiles].filter(f => !bFiles.has(f)).sort()
  const removed = [...bFiles].filter(f => !aFiles.has(f)).sort()
  const common = [...aFiles].filter(f => bFiles.has(f))

  // Compare stats
  let aLines = 0, bLines = 0, aImports = 0, bImports = 0, aUrls = 0, bUrls = 0
  for (const [, n] of graph.nodes) { aLines += n.lines; aImports += n.imports.length; aUrls += n.urls.length }
  for (const [, n] of otherGraph.nodes) { bLines += n.lines; bImports += n.imports.length; bUrls += n.urls.length }

  // Coupling changes in common files
  const couplingChanges: { id: string; before: number; after: number }[] = []
  for (const id of common) {
    const a = graph.nodes.get(id)!
    const b = otherGraph.nodes.get(id)!
    const aCoupling = a.imports.length + a.importedBy.length
    const bCoupling = b.imports.length + b.importedBy.length
    if (aCoupling !== bCoupling) {
      couplingChanges.push({ id, before: bCoupling, after: aCoupling })
    }
  }
  couplingChanges.sort((a, b) => Math.abs(b.after - b.before) - Math.abs(a.after - a.before))

  // New URLs
  const aUrlSet = new Set<string>()
  const bUrlSet = new Set<string>()
  for (const [, n] of graph.nodes) for (const u of n.urls) aUrlSet.add(u)
  for (const [, n] of otherGraph.nodes) for (const u of n.urls) bUrlSet.add(u)
  const newUrls = [...aUrlSet].filter(u => !bUrlSet.has(u)).sort()
  const removedUrls = [...bUrlSet].filter(u => !aUrlSet.has(u)).sort()

  const delta = (a: number, b: number) => {
    const d = a - b
    return d > 0 ? `+${d}` : d.toString()
  }

  const lines = [
    `=== Compare: current vs ${resolvedDir} ===`,
    "",
    `           Current    Other    Delta`,
    `Files:     ${aFiles.size.toString().padStart(7)}  ${bFiles.size.toString().padStart(7)}  ${delta(aFiles.size, bFiles.size).padStart(7)}`,
    `Lines:     ${aLines.toString().padStart(7)}  ${bLines.toString().padStart(7)}  ${delta(aLines, bLines).padStart(7)}`,
    `Imports:   ${aImports.toString().padStart(7)}  ${bImports.toString().padStart(7)}  ${delta(aImports, bImports).padStart(7)}`,
    `URLs:      ${aUrls.toString().padStart(7)}  ${bUrls.toString().padStart(7)}  ${delta(aUrls, bUrls).padStart(7)}`,
    "",
  ]

  if (added.length) {
    lines.push(`Added files (${added.length}):`)
    for (const f of added.slice(0, 20)) lines.push(`  + ${f}`)
    if (added.length > 20) lines.push(`  ... and ${added.length - 20} more`)
    lines.push("")
  }

  if (removed.length) {
    lines.push(`Removed files (${removed.length}):`)
    for (const f of removed.slice(0, 20)) lines.push(`  - ${f}`)
    if (removed.length > 20) lines.push(`  ... and ${removed.length - 20} more`)
    lines.push("")
  }

  if (couplingChanges.length) {
    lines.push(`Coupling changes (${couplingChanges.length} files):`)
    for (const c of couplingChanges.slice(0, 20)) {
      const d = c.after - c.before
      lines.push(`  ${d > 0 ? "+" : ""}${d} coupling  ${c.id}  (${c.before} → ${c.after})`)
    }
    if (couplingChanges.length > 20) lines.push(`  ... and ${couplingChanges.length - 20} more`)
    lines.push("")
  }

  if (newUrls.length) {
    lines.push(`New URLs (${newUrls.length}):`)
    for (const u of newUrls.slice(0, 15)) lines.push(`  + ${u}`)
    if (newUrls.length > 15) lines.push(`  ... and ${newUrls.length - 15} more`)
    lines.push("")
  }

  if (removedUrls.length) {
    lines.push(`Removed URLs (${removedUrls.length}):`)
    for (const u of removedUrls.slice(0, 15)) lines.push(`  - ${u}`)
    if (removedUrls.length > 15) lines.push(`  ... and ${removedUrls.length - 15} more`)
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
  console.log(`codemap — Codebase dependency analysis

Usage: codemap [--dir <path>] <action> [target]

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
  hotspots              Most coupled files (imports + importers)
  layers                Auto-detect architectural layers
  diff <ref>            Blast radius of changes since a git ref
  orphan-exports        Exports nothing uses
  why <A> <B>           Shortest import path between two files
  size                  Files ranked by line count
  compare <dir>         Structural A/B diff vs another codebase

Options:
  --dir <path>          Directory to scan (default: cwd)

Examples:
  codemap trace src/utils/auth.ts
  codemap blast-radius src/services/api/client.ts
  codemap phone-home
  codemap hotspots
  codemap diff HEAD~5
  codemap why src/cli.ts src/utils/auth.ts
  codemap compare ~/Desktop/old-version
  codemap --dir ~/Desktop/my-project stats`)
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
  case "hotspots": console.log(hotspots(graph)); break
  case "layers": console.log(layers(graph)); break
  case "diff": console.log(diff(graph, target)); break
  case "orphan-exports": console.log(orphanExports(graph)); break
  case "why": console.log(why(graph, target)); break
  case "size": console.log(size(graph)); break
  case "compare": console.log(compare(graph, target)); break
  default: console.error(`Unknown action: ${action}. Run 'codemap --help' for usage.`); process.exit(1)
}
