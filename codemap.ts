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

import { readdirSync, readFileSync, statSync, existsSync } from "fs"
import { join, relative, resolve, extname, dirname } from "path"

// ── Patterns & Constants ─────────────────────────────────────────────

const URL_RE = /['"`](https?:\/\/[^'"`\s]{5,})['"`]/gm
const IMPORT_RE = /(?:import|export)\s+.*?from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\)/gm
const DYNAMIC_IMPORT_RE = /import\s*\(\s*['"]([^'"]+)['"]\s*\)/gm
const EXPORT_RE = /export\s+(?:const|let|var|function|async\s+function|class|type|interface|enum)\s+(\w+)/gm
const SUPPORTED_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rs", ".go", ".java", ".rb", ".php"])

// ── Types ─────────────────────────────────────────────────────────────

interface FunctionInfo {
  name: string
  startLine: number
  endLine: number
  calls: string[]
  isExported: boolean
}

interface GraphNode {
  id: string
  imports: string[]
  importedBy: string[]
  urls: string[]
  exports: string[]
  lines: number
  functions: FunctionInfo[]
}

interface Graph {
  nodes: Map<string, GraphNode>
  scanDir: string
}

// ── Tree-Sitter AST ──────────────────────────────────────────────────

const TS_MOD = await import("web-tree-sitter")
const TSParser = TS_MOD.default
await TS_MOD.init()

const WASM_DIR = join(dirname(new URL(import.meta.url).pathname), "node_modules/tree-sitter-wasms/out")

const EXT_TO_GRAMMAR: Record<string, string> = {
  ".ts": "typescript", ".tsx": "tsx", ".js": "javascript", ".jsx": "javascript",
  ".mjs": "javascript", ".cjs": "javascript",
  ".py": "python", ".rs": "rust", ".go": "go", ".java": "java", ".rb": "ruby", ".php": "php",
}

// Cache loaded parsers per language
const parserCache = new Map<string, any>()

async function getParser(ext: string): Promise<any | null> {
  const grammar = EXT_TO_GRAMMAR[ext]
  if (!grammar) return null
  if (parserCache.has(grammar)) return parserCache.get(grammar)

  const wasmPath = join(WASM_DIR, `tree-sitter-${grammar}.wasm`)
  if (!existsSync(wasmPath)) return null

  try {
    const parser = new TSParser()
    const lang = await TSParser.Language.load(wasmPath)
    parser.setLanguage(lang)
    parserCache.set(grammar, parser)
    return parser
  } catch {
    return null
  }
}

// Collect all AST nodes matching given types
function collectNodes(node: any, types: string[]): any[] {
  const results: any[] = []
  if (types.includes(node.type)) results.push(node)
  for (let i = 0; i < node.childCount; i++) {
    results.push(...collectNodes(node.child(i), types))
  }
  return results
}

// ── Tree-Sitter Extractors ───────────────────────────────────────────

// Import node types per language
const IMPORT_TYPES: Record<string, string[]> = {
  typescript: ["import_statement", "export_statement"],
  tsx: ["import_statement", "export_statement"],
  javascript: ["import_statement", "export_statement"],
  python: ["import_statement", "import_from_statement"],
  rust: ["use_declaration"],
  go: ["import_declaration", "import_spec"],
  java: ["import_declaration"],
  ruby: ["call"],  // require/require_relative
  php: ["namespace_use_declaration"],
}

// Function node types per language
const FUNC_TYPES: Record<string, string[]> = {
  typescript: ["function_declaration", "method_definition", "arrow_function"],
  tsx: ["function_declaration", "method_definition", "arrow_function"],
  javascript: ["function_declaration", "method_definition", "arrow_function"],
  python: ["function_definition"],
  rust: ["function_item"],
  go: ["function_declaration", "method_declaration"],
  java: ["method_declaration", "constructor_declaration"],
  ruby: ["method", "singleton_method"],
  php: ["function_definition", "method_declaration"],
}

// Export node types per language
const EXPORT_TYPES: Record<string, string[]> = {
  typescript: ["export_statement"],
  tsx: ["export_statement"],
  javascript: ["export_statement"],
  python: [],  // Python doesn't have export syntax — all non-_ names are public
  rust: [],     // Handled via visibility_modifier
  go: [],       // Handled via capitalization
  java: [],     // Handled via access modifiers
  ruby: [],
  php: [],
}

function extractImportsFromAST(tree: any, grammar: string, content: string): string[] {
  const imports: string[] = []
  const importTypes = IMPORT_TYPES[grammar] || []

  if (["typescript", "tsx", "javascript"].includes(grammar)) {
    for (const node of collectNodes(tree.rootNode, importTypes)) {
      // Skip type-only imports
      if (node.text.startsWith("import type")) continue
      const source = node.childForFieldName("source")
      if (source) imports.push(source.text.replace(/['"]/g, ""))
      // Re-exports: export { x } from "./y"
      if (node.type === "export_statement") {
        const src = node.childForFieldName("source")
        if (src) imports.push(src.text.replace(/['"]/g, ""))
      }
    }
    // Dynamic imports
    for (const node of collectNodes(tree.rootNode, ["call_expression"])) {
      const fn = node.childForFieldName("function") || node.child(0)
      if (fn?.type === "import") {
        const args = node.childForFieldName("arguments") || node.child(1)
        if (args?.childCount) {
          const arg = args.child(1) || args.child(0)
          if (arg?.type === "string") imports.push(arg.text.replace(/['"]/g, ""))
        }
      }
    }
  } else if (grammar === "python") {
    for (const node of collectNodes(tree.rootNode, importTypes)) {
      if (node.type === "import_from_statement") {
        const mod = node.childForFieldName("module_name")
        if (mod) imports.push(mod.text)
      } else {
        // import X
        for (let i = 0; i < node.childCount; i++) {
          const child = node.child(i)
          if (child?.type === "dotted_name") imports.push(child.text)
        }
      }
    }
  } else if (grammar === "rust") {
    for (const node of collectNodes(tree.rootNode, importTypes)) {
      // Extract the path from use declarations
      const path = node.child(1) // skip 'use' keyword
      if (path) imports.push(path.text.replace(/;$/, "").split("::").slice(0, 2).join("::"))
    }
  } else if (grammar === "go") {
    for (const node of collectNodes(tree.rootNode, ["import_spec"])) {
      const path = node.childForFieldName("path")
      if (path) imports.push(path.text.replace(/"/g, ""))
    }
  } else if (grammar === "java") {
    for (const node of collectNodes(tree.rootNode, importTypes)) {
      const text = node.text.replace(/^import\s+/, "").replace(/;$/, "").trim()
      imports.push(text)
    }
  } else if (grammar === "ruby") {
    for (const node of collectNodes(tree.rootNode, ["call"])) {
      const method = node.childForFieldName("method")
      if (method && (method.text === "require" || method.text === "require_relative")) {
        const args = node.childForFieldName("arguments")
        if (args?.childCount) {
          const arg = args.child(0)
          if (arg) imports.push(arg.text.replace(/['"]/g, ""))
        }
      }
    }
  }

  return imports
}

function extractExportsFromAST(tree: any, grammar: string, content: string): string[] {
  const exports: string[] = []

  if (["typescript", "tsx", "javascript"].includes(grammar)) {
    for (const node of collectNodes(tree.rootNode, ["export_statement"])) {
      // Skip type-only exports
      if (node.text.startsWith("export type") || node.text.startsWith("export interface")) continue
      const decl = node.childForFieldName("declaration")
      if (decl) {
        const name = decl.childForFieldName("name")
        if (name) exports.push(name.text)
        // const/let/var declarations
        if (["lexical_declaration", "variable_declaration"].includes(decl.type)) {
          for (const declarator of collectNodes(decl, ["variable_declarator"])) {
            const n = declarator.childForFieldName("name")
            if (n) exports.push(n.text)
          }
        }
      }
      // export default
      if (node.text.includes("export default")) {
        const match = /export\s+default\s+(?:class|function\s*\*?)\s+(\w+)/.exec(node.text)
        exports.push(match ? match[1] : "default")
      }
    }
  } else if (grammar === "python") {
    // All top-level functions/classes not starting with _
    for (const node of collectNodes(tree.rootNode, ["function_definition", "class_definition"])) {
      if (node.parent?.type === "module") {
        const name = node.childForFieldName("name")
        if (name && !name.text.startsWith("_")) exports.push(name.text)
      }
    }
  } else if (grammar === "rust") {
    // pub items
    for (const node of collectNodes(tree.rootNode, ["function_item", "struct_item", "enum_item", "type_item", "impl_item"])) {
      if (node.child(0)?.type === "visibility_modifier") {
        const name = node.childForFieldName("name")
        if (name) exports.push(name.text)
      }
    }
  } else if (grammar === "go") {
    // Capitalized names are exported
    for (const node of collectNodes(tree.rootNode, ["function_declaration", "method_declaration", "type_declaration"])) {
      const name = node.childForFieldName("name")
      if (name && name.text[0] === name.text[0].toUpperCase()) exports.push(name.text)
    }
  } else if (grammar === "java") {
    // public methods and classes
    for (const node of collectNodes(tree.rootNode, ["method_declaration", "class_declaration"])) {
      const modifiers = node.child(0)
      if (modifiers?.type === "modifiers" && modifiers.text.includes("public")) {
        const name = node.childForFieldName("name")
        if (name) exports.push(name.text)
      }
    }
  } else if (grammar === "ruby") {
    for (const node of collectNodes(tree.rootNode, ["method", "singleton_method"])) {
      const name = node.childForFieldName("name")
      if (name && !name.text.startsWith("_")) exports.push(name.text)
    }
  }

  return exports
}

function extractFunctionsFromAST(tree: any, grammar: string, content: string): FunctionInfo[] {
  const functions: FunctionInfo[] = []
  const funcTypes = FUNC_TYPES[grammar] || []

  for (const node of collectNodes(tree.rootNode, funcTypes)) {
    let name = node.childForFieldName("name")?.text
    if (!name) {
      // Arrow functions: find parent variable declarator
      if (node.type === "arrow_function" && node.parent?.type === "variable_declarator") {
        name = node.parent.childForFieldName("name")?.text
      }
      if (!name) continue
    }

    const startLine = node.startPosition.row + 1
    const endLine = node.endPosition.row + 1

    // Extract call expressions within this function
    const callNodes = collectNodes(node, ["call_expression", "call"])
    const calls: string[] = []
    const seen = new Set<string>()
    for (const call of callNodes) {
      let callee: string | undefined
      const fn = call.childForFieldName("function") || call.childForFieldName("method") || call.child(0)
      if (fn) {
        callee = fn.type === "member_expression" || fn.type === "field_expression"
          ? fn.childForFieldName("property")?.text || fn.text
          : fn.text
      }
      if (callee && callee !== name && !seen.has(callee)) {
        seen.add(callee)
        calls.push(callee)
      }
    }

    // Determine if exported
    let isExported = false
    if (["typescript", "tsx", "javascript"].includes(grammar)) {
      isExported = node.parent?.type === "export_statement" ||
        (node.type === "arrow_function" && node.parent?.parent?.parent?.type === "export_statement")
    } else if (grammar === "python") {
      isExported = !name.startsWith("_")
    } else if (grammar === "rust") {
      isExported = node.child(0)?.type === "visibility_modifier"
    } else if (grammar === "go") {
      isExported = name[0] === name[0].toUpperCase()
    } else if (grammar === "java") {
      const modifiers = node.child(0)
      isExported = modifiers?.type === "modifiers" && modifiers.text.includes("public")
    } else if (grammar === "ruby") {
      isExported = !name.startsWith("_")
    }

    functions.push({ name, startLine, endLine, calls, isExported })
  }

  return functions
}

// ── File Parser ──────────────────────────────────────────────────────

async function parseFile(filePath: string, content: string, ext: string, scanDir: string, node: GraphNode): Promise<void> {
  const grammar = EXT_TO_GRAMMAR[ext]
  const parser = grammar ? await getParser(ext) : null

  if (parser && grammar) {
    // ── Tree-Sitter AST parsing ──
    const tree = parser.parse(content)

    // Imports
    const rawImports = extractImportsFromAST(tree, grammar, content)
    for (const imp of rawImports) resolveAndAdd(imp, filePath, scanDir, node)

    // Exports
    node.exports = extractExportsFromAST(tree, grammar, content)

    // Functions
    node.functions = extractFunctionsFromAST(tree, grammar, content)

    tree.delete()
  } else {
    // ── Regex fallback for unsupported extensions ──
    let m: RegExpExecArray | null
    IMPORT_RE.lastIndex = 0
    while ((m = IMPORT_RE.exec(content)) !== null) { const t = m[1] || m[2]; if (t) resolveAndAdd(t, filePath, scanDir, node) }
    DYNAMIC_IMPORT_RE.lastIndex = 0
    while ((m = DYNAMIC_IMPORT_RE.exec(content)) !== null) { if (m[1]) resolveAndAdd(m[1], filePath, scanDir, node) }
    EXPORT_RE.lastIndex = 0
    while ((m = EXPORT_RE.exec(content)) !== null) { node.exports.push(m[1]) }
    node.functions = []
  }

  // URLs (always regex — tree-sitter doesn't help here)
  let m: RegExpExecArray | null
  URL_RE.lastIndex = 0
  while ((m = URL_RE.exec(content)) !== null) {
    const url = m[1]
    if (!url.includes("localhost") && !url.includes("127.0.0.1") && !url.includes("example.com")) {
      node.urls.push(url.split("?")[0].substring(0, 120))
    }
  }
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

async function scanDirectory(dir: string): Promise<Graph> {
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

  // Parse each file using tree-sitter AST (with regex fallback)
  for (const file of allFiles) {
    let content: string
    try {
      content = readFileSync(file, "utf-8")
    } catch {
      continue
    }

    const id = relative(dir, file)
    const ext = extname(file)
    const node: GraphNode = {
      id,
      imports: [],
      importedBy: [],
      urls: [],
      exports: [],
      lines: content.split("\n").length,
      functions: [],
    }

    await parseFile(file, content, ext, dir, node)
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

// ── Graph Analysis Actions ───────────────────────────────────────────

function subgraph(graph: Graph, target: string): string {
  if (!target) return "Usage: codemap subgraph <file-or-pattern>"
  // Find all matching nodes
  const seeds: string[] = []
  for (const id of graph.nodes.keys()) {
    if (id.includes(target)) seeds.push(id)
  }
  if (!seeds.length) {
    const node = findNode(graph, target)
    if (node) seeds.push(node.id)
  }
  if (!seeds.length) return `No files matching "${target}".`

  // BFS in both directions to get full connected component
  const component = new Set<string>()
  const queue = [...seeds]
  for (const s of seeds) component.add(s)

  while (queue.length) {
    const current = queue.shift()!
    const node = graph.nodes.get(current)
    if (!node) continue
    for (const imp of node.imports) {
      if (graph.nodes.has(imp) && !component.has(imp)) {
        component.add(imp)
        queue.push(imp)
      }
    }
    for (const imp of node.importedBy) {
      if (!component.has(imp)) {
        component.add(imp)
        queue.push(imp)
      }
    }
  }

  const sorted = [...component].sort()
  const lines = [`=== Subgraph around "${target}" (${sorted.length} files) ===`, ""]
  for (const id of sorted) {
    const node = graph.nodes.get(id)!
    const inCount = node.imports.filter(i => component.has(i)).length
    const outCount = node.importedBy.filter(i => component.has(i)).length
    lines.push(`  ${id}  (${inCount}→ ${outCount}←)`)
  }
  return lines.join("\n")
}

function dot(graph: Graph, target: string): string {
  let nodes: Map<string, GraphNode>

  if (target) {
    // Build subgraph around target
    const seeds: string[] = []
    const node = findNode(graph, target)
    if (node) seeds.push(node.id)
    else {
      for (const id of graph.nodes.keys()) {
        if (id.includes(target)) seeds.push(id)
      }
    }
    if (!seeds.length) return `No files matching "${target}".`

    // BFS 2 hops out
    const component = new Set<string>(seeds)
    let frontier = [...seeds]
    for (let hop = 0; hop < 2; hop++) {
      const next: string[] = []
      for (const id of frontier) {
        const n = graph.nodes.get(id)
        if (!n) continue
        for (const imp of n.imports) {
          if (graph.nodes.has(imp) && !component.has(imp)) { component.add(imp); next.push(imp) }
        }
        for (const imp of n.importedBy) {
          if (!component.has(imp)) { component.add(imp); next.push(imp) }
        }
      }
      frontier = next
    }
    nodes = new Map([...graph.nodes].filter(([id]) => component.has(id)))
  } else {
    nodes = graph.nodes
  }

  const lines = ["digraph codemap {", '  rankdir=LR;', '  node [shape=box, fontsize=10];', ""]
  // Sanitize IDs for DOT
  const dotId = (s: string) => '"' + s.replace(/"/g, '\\"') + '"'
  for (const [id, node] of nodes) {
    for (const imp of node.imports) {
      if (nodes.has(imp)) {
        lines.push(`  ${dotId(id)} -> ${dotId(imp)};`)
      }
    }
  }
  lines.push("}")
  return lines.join("\n")
}

function islands(graph: Graph): string {
  // Find connected components (undirected — imports in either direction)
  const visited = new Set<string>()
  const components: string[][] = []

  for (const id of graph.nodes.keys()) {
    if (visited.has(id)) continue
    const component: string[] = []
    const queue = [id]
    visited.add(id)
    while (queue.length) {
      const current = queue.shift()!
      component.push(current)
      const node = graph.nodes.get(current)
      if (!node) continue
      for (const imp of node.imports) {
        if (graph.nodes.has(imp) && !visited.has(imp)) { visited.add(imp); queue.push(imp) }
      }
      for (const imp of node.importedBy) {
        if (!visited.has(imp)) { visited.add(imp); queue.push(imp) }
      }
    }
    components.push(component)
  }

  components.sort((a, b) => b.length - a.length)
  const lines = [`=== Islands (${components.length} disconnected components) ===`, ""]

  for (let i = 0; i < components.length; i++) {
    const c = components[i]
    c.sort()
    lines.push(`Island ${i + 1} (${c.length} files):`)
    for (const f of c.slice(0, 8)) lines.push(`  ${f}`)
    if (c.length > 8) lines.push(`  ... and ${c.length - 8} more`)
    lines.push("")
  }
  return lines.join("\n")
}

function pagerank(graph: Graph): string {
  const d = 0.85 // damping factor
  const iterations = 20
  const n = graph.nodes.size
  if (n === 0) return "No files to rank."

  const ids = [...graph.nodes.keys()]
  let scores = new Map<string, number>()
  for (const id of ids) scores.set(id, 1 / n)

  for (let iter = 0; iter < iterations; iter++) {
    const newScores = new Map<string, number>()
    for (const id of ids) newScores.set(id, (1 - d) / n)

    for (const [id, node] of graph.nodes) {
      if (node.imports.length === 0) continue
      const share = (scores.get(id) || 0) / node.imports.length
      for (const imp of node.imports) {
        if (graph.nodes.has(imp)) {
          newScores.set(imp, (newScores.get(imp) || 0) + d * share)
        }
      }
    }
    scores = newScores
  }

  const ranked = ids.map(id => ({ id, score: scores.get(id) || 0 }))
    .sort((a, b) => b.score - a.score)

  const top = ranked.slice(0, 30)
  const lines = [`=== PageRank (top ${top.length} most important files) ===`, ""]
  for (const r of top) {
    lines.push(`  ${(r.score * 1000).toFixed(2).padStart(7)} rank  ${r.id}`)
  }
  return lines.join("\n")
}

function bridges(graph: Graph): string {
  // Find articulation points using Tarjan's algorithm (iterative)
  const ids = [...graph.nodes.keys()]
  const disc = new Map<string, number>()
  const low = new Map<string, number>()
  const parent = new Map<string, string | null>()
  const articulationPoints = new Set<string>()
  let timer = 0

  // Build undirected adjacency
  const adj = new Map<string, Set<string>>()
  for (const [id, node] of graph.nodes) {
    if (!adj.has(id)) adj.set(id, new Set())
    for (const imp of node.imports) {
      if (graph.nodes.has(imp)) {
        adj.get(id)!.add(imp)
        if (!adj.has(imp)) adj.set(imp, new Set())
        adj.get(imp)!.add(id)
      }
    }
  }

  for (const startId of ids) {
    if (disc.has(startId)) continue

    // Iterative DFS using explicit stack
    const stack: { id: string; neighborIter: Iterator<string>; childCount: number }[] = []
    disc.set(startId, timer)
    low.set(startId, timer)
    timer++
    parent.set(startId, null)
    const neighbors = adj.get(startId)
    stack.push({ id: startId, neighborIter: (neighbors || new Set()).values(), childCount: 0 })

    while (stack.length) {
      const frame = stack[stack.length - 1]
      const next = frame.neighborIter.next()

      if (!next.done) {
        const v = next.value
        if (!disc.has(v)) {
          parent.set(v, frame.id)
          disc.set(v, timer)
          low.set(v, timer)
          timer++
          frame.childCount++
          const vNeighbors = adj.get(v)
          stack.push({ id: v, neighborIter: (vNeighbors || new Set()).values(), childCount: 0 })
        } else if (v !== parent.get(frame.id)) {
          low.set(frame.id, Math.min(low.get(frame.id)!, disc.get(v)!))
        }
      } else {
        // Done with this node, pop and update parent
        stack.pop()
        if (stack.length) {
          const parentFrame = stack[stack.length - 1]
          low.set(parentFrame.id, Math.min(low.get(parentFrame.id)!, low.get(frame.id)!))

          // Check articulation point conditions
          if (parent.get(parentFrame.id) !== null && low.get(frame.id)! >= disc.get(parentFrame.id)!) {
            articulationPoints.add(parentFrame.id)
          }
        } else {
          // Root node — articulation point if it has 2+ children
          if (frame.childCount > 1) {
            articulationPoints.add(frame.id)
          }
        }
      }
    }
  }

  if (!articulationPoints.size) return "No bridge files found — the graph stays connected if any single file is removed."

  // Rank by how many files depend on them
  const ranked = [...articulationPoints].map(id => {
    const node = graph.nodes.get(id)!
    return { id, connections: node.imports.length + node.importedBy.length }
  }).sort((a, b) => b.connections - a.connections)

  const lines = [`=== Bridge Files (${ranked.length} articulation points) ===`,
    "Removing any of these disconnects parts of the graph:", ""]
  for (const r of ranked.slice(0, 30)) {
    lines.push(`  ${r.connections.toString().padStart(4)} connections  ${r.id}`)
  }
  if (ranked.length > 30) lines.push(`  ... and ${ranked.length - 30} more`)
  return lines.join("\n")
}

function similar(graph: Graph, target: string): string {
  if (!target) return "Usage: codemap similar <file>"
  const node = findNode(graph, target)
  if (!node) return `File not found: ${target}`

  const myImports = new Set(node.imports)
  const myImporters = new Set(node.importedBy)

  const scores: { id: string; score: number; shared: number }[] = []
  for (const [id, other] of graph.nodes) {
    if (id === node.id) continue
    const otherImports = new Set(other.imports)
    const otherImporters = new Set(other.importedBy)

    // Jaccard similarity on imports
    const importUnion = new Set([...myImports, ...otherImports])
    const importIntersect = [...myImports].filter(i => otherImports.has(i)).length

    // Jaccard similarity on importers
    const importerUnion = new Set([...myImporters, ...otherImporters])
    const importerIntersect = [...myImporters].filter(i => otherImporters.has(i)).length

    const importJaccard = importUnion.size ? importIntersect / importUnion.size : 0
    const importerJaccard = importerUnion.size ? importerIntersect / importerUnion.size : 0

    const score = (importJaccard + importerJaccard) / 2
    const shared = importIntersect + importerIntersect
    if (score > 0) scores.push({ id, score, shared })
  }

  scores.sort((a, b) => b.score - a.score)
  const top = scores.slice(0, 20)
  if (!top.length) return `No files similar to ${node.id}.`

  const lines = [`=== Files similar to ${node.id} ===`, ""]
  for (const s of top) {
    lines.push(`  ${(s.score * 100).toFixed(1).padStart(5)}% similar  ${s.id}  (${s.shared} shared deps)`)
  }
  return lines.join("\n")
}

function hubs(graph: Graph): string {
  // HITS algorithm — iterative
  const iterations = 20
  const ids = [...graph.nodes.keys()]
  let hubScores = new Map<string, number>()
  let authScores = new Map<string, number>()
  for (const id of ids) { hubScores.set(id, 1); authScores.set(id, 1) }

  for (let iter = 0; iter < iterations; iter++) {
    // Authority = sum of hub scores of nodes pointing to it
    const newAuth = new Map<string, number>()
    for (const id of ids) newAuth.set(id, 0)
    for (const [id, node] of graph.nodes) {
      for (const imp of node.imports) {
        if (graph.nodes.has(imp)) {
          newAuth.set(imp, (newAuth.get(imp) || 0) + (hubScores.get(id) || 0))
        }
      }
    }

    // Hub = sum of authority scores of nodes it points to
    const newHub = new Map<string, number>()
    for (const [id, node] of graph.nodes) {
      let h = 0
      for (const imp of node.imports) {
        if (graph.nodes.has(imp)) h += (newAuth.get(imp) || 0)
      }
      newHub.set(id, h)
    }

    // Normalize
    let hubNorm = 0, authNorm = 0
    for (const v of newHub.values()) hubNorm += v * v
    for (const v of newAuth.values()) authNorm += v * v
    hubNorm = Math.sqrt(hubNorm) || 1
    authNorm = Math.sqrt(authNorm) || 1
    for (const id of ids) {
      newHub.set(id, (newHub.get(id) || 0) / hubNorm)
      newAuth.set(id, (newAuth.get(id) || 0) / authNorm)
    }
    hubScores = newHub
    authScores = newAuth
  }

  const topHubs = ids.map(id => ({ id, score: hubScores.get(id) || 0 }))
    .sort((a, b) => b.score - a.score).slice(0, 20)
  const topAuth = ids.map(id => ({ id, score: authScores.get(id) || 0 }))
    .sort((a, b) => b.score - a.score).slice(0, 20)

  const lines = [`=== Hubs (orchestrators — import many things) ===`, ""]
  for (const h of topHubs) {
    if (h.score < 0.001) break
    lines.push(`  ${(h.score * 100).toFixed(2).padStart(7)}  ${h.id}`)
  }
  lines.push("", `=== Authorities (core — everyone imports them) ===`, "")
  for (const a of topAuth) {
    if (a.score < 0.001) break
    lines.push(`  ${(a.score * 100).toFixed(2).padStart(7)}  ${a.id}`)
  }
  return lines.join("\n")
}

function clusters(graph: Graph): string {
  // Label propagation community detection (iterative, no randomness)
  const labels = new Map<string, string>()
  const ids = [...graph.nodes.keys()]
  for (const id of ids) labels.set(id, id) // each node starts as its own community

  // Build undirected adjacency
  const adj = new Map<string, string[]>()
  for (const [id, node] of graph.nodes) {
    if (!adj.has(id)) adj.set(id, [])
    for (const imp of node.imports) {
      if (graph.nodes.has(imp)) {
        adj.get(id)!.push(imp)
        if (!adj.has(imp)) adj.set(imp, [])
        adj.get(imp)!.push(id)
      }
    }
  }

  // Iterate — each node adopts the most common label among neighbors
  for (let iter = 0; iter < 15; iter++) {
    let changed = false
    for (const id of ids) {
      const neighbors = adj.get(id) || []
      if (!neighbors.length) continue

      const counts = new Map<string, number>()
      for (const n of neighbors) {
        const l = labels.get(n)!
        counts.set(l, (counts.get(l) || 0) + 1)
      }

      let bestLabel = labels.get(id)!
      let bestCount = 0
      for (const [l, c] of counts) {
        if (c > bestCount) { bestCount = c; bestLabel = l }
      }

      if (bestLabel !== labels.get(id)) {
        labels.set(id, bestLabel)
        changed = true
      }
    }
    if (!changed) break
  }

  // Group by label
  const groups = new Map<string, string[]>()
  for (const [id, label] of labels) {
    if (!groups.has(label)) groups.set(label, [])
    groups.get(label)!.push(id)
  }

  // Sort by size, filter out singletons
  const sorted = [...groups.values()]
    .filter(g => g.length > 1)
    .sort((a, b) => b.length - a.length)

  if (!sorted.length) return "No clusters found — all files are independent."

  const lines = [`=== Clusters (${sorted.length} communities, ${ids.length - sorted.reduce((s, g) => s + g.length, 0)} singletons excluded) ===`, ""]
  for (let i = 0; i < Math.min(sorted.length, 20); i++) {
    const cluster = sorted[i]
    cluster.sort()

    // Compute internal vs external edges
    const clusterSet = new Set(cluster)
    let internal = 0, external = 0
    for (const id of cluster) {
      const node = graph.nodes.get(id)!
      for (const imp of node.imports) {
        if (clusterSet.has(imp)) internal++
        else if (graph.nodes.has(imp)) external++
      }
    }
    const cohesion = internal + external > 0 ? ((internal / (internal + external)) * 100).toFixed(0) : "100"

    lines.push(`Cluster ${i + 1} (${cluster.length} files, ${cohesion}% internal coupling):`)
    for (const f of cluster.slice(0, 8)) lines.push(`  ${f}`)
    if (cluster.length > 8) lines.push(`  ... and ${cluster.length - 8} more`)
    lines.push("")
  }
  if (sorted.length > 20) lines.push(`... and ${sorted.length - 20} more clusters`)
  return lines.join("\n")
}

function paths(graph: Graph, args: string): string {
  const parts = args.split(/\s+/)
  if (parts.length < 2) return "Usage: codemap paths <fileA> <fileB>"
  const [a, b] = parts
  const nodeA = findNode(graph, a)
  const nodeB = findNode(graph, b)
  if (!nodeA) return `File not found: ${a}`
  if (!nodeB) return `File not found: ${b}`

  // DFS to find all paths (with depth limit to prevent explosion)
  const allPaths: string[][] = []
  const maxPaths = 20
  const maxDepth = 10

  function dfs(current: string, target: string, path: string[], visited: Set<string>) {
    if (allPaths.length >= maxPaths) return
    if (path.length > maxDepth) return
    if (current === target) { allPaths.push([...path]); return }

    const node = graph.nodes.get(current)
    if (!node) return
    for (const imp of node.imports) {
      if (graph.nodes.has(imp) && !visited.has(imp)) {
        visited.add(imp)
        path.push(imp)
        dfs(imp, target, path, visited)
        path.pop()
        visited.delete(imp)
      }
    }
  }

  // Try A→B
  dfs(nodeA.id, nodeB.id, [nodeA.id], new Set([nodeA.id]))

  // Try B→A if no paths found
  if (!allPaths.length) {
    dfs(nodeB.id, nodeA.id, [nodeB.id], new Set([nodeB.id]))
    if (allPaths.length) {
      for (const p of allPaths) p.reverse()
    }
  }

  if (!allPaths.length) return `No import paths found between ${nodeA.id} and ${nodeB.id} (searched up to ${maxDepth} hops).`

  allPaths.sort((a, b) => a.length - b.length)
  const lines = [`=== All paths: ${nodeA.id} → ${nodeB.id} (${allPaths.length} found) ===`, ""]
  for (let i = 0; i < allPaths.length; i++) {
    lines.push(`Path ${i + 1} (${allPaths[i].length - 1} hops):`)
    lines.push("  " + allPaths[i].join(" → "))
    lines.push("")
  }
  return lines.join("\n")
}

// ── Function-Level Actions ───────────────────────────────────────────

function callGraph(graph: Graph, target: string): string {
  // Build cross-file call graph: function → function (with file context)
  // If target is given, show call graph for that file only

  // Build a map of all exported function names → file
  const exportMap = new Map<string, string[]>() // funcName → [file1, file2, ...]
  for (const [id, node] of graph.nodes) {
    for (const fn of node.functions) {
      if (fn.isExported) {
        if (!exportMap.has(fn.name)) exportMap.set(fn.name, [])
        exportMap.get(fn.name)!.push(id)
      }
    }
  }

  const edges: { from: string; fromFunc: string; to: string; toFunc: string }[] = []
  const filesToScan = target ? [findNode(graph, target)].filter(Boolean).map(n => n!.id) : [...graph.nodes.keys()]

  for (const fileId of filesToScan) {
    const node = graph.nodes.get(fileId)
    if (!node) continue

    for (const fn of node.functions) {
      for (const callName of fn.calls) {
        // Check if this call resolves to an exported function in an imported file
        const importedFiles = new Set(node.imports.filter(i => graph.nodes.has(i)))
        const targets = exportMap.get(callName) || []

        for (const targetFile of targets) {
          if (importedFiles.has(targetFile) || targetFile === fileId) {
            edges.push({ from: fileId, fromFunc: fn.name, to: targetFile, toFunc: callName })
          }
        }
      }
    }
  }

  if (!edges.length) return target ? `No cross-function calls found in ${target}.` : "No cross-file function calls found."

  // Group by source
  const grouped = new Map<string, typeof edges>()
  for (const e of edges) {
    const key = `${e.from}:${e.fromFunc}`
    if (!grouped.has(key)) grouped.set(key, [])
    grouped.get(key)!.push(e)
  }

  const lines = [`=== Call Graph${target ? ` for ${target}` : ""} (${edges.length} cross-function calls) ===`, ""]
  const sorted = [...grouped.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  for (const [source, calls] of sorted.slice(0, 50)) {
    lines.push(`  ${source}:`)
    for (const c of calls) {
      lines.push(`    → ${c.to}:${c.toFunc}`)
    }
  }
  if (sorted.length > 50) lines.push(`  ... and ${sorted.length - 50} more`)
  return lines.join("\n")
}

function deadFunctions(graph: Graph): string {
  // Find exported functions that are never called from any other file
  const allCalls = new Map<string, Set<string>>() // funcName → set of files that call it

  for (const [id, node] of graph.nodes) {
    for (const fn of node.functions) {
      for (const callName of fn.calls) {
        if (!allCalls.has(callName)) allCalls.set(callName, new Set())
        allCalls.get(callName)!.add(id)
      }
    }
  }

  const dead: { file: string; name: string; line: number }[] = []

  for (const [id, node] of graph.nodes) {
    for (const fn of node.functions) {
      if (!fn.isExported) continue

      // Check if any OTHER file calls this function
      const callers = allCalls.get(fn.name)
      const calledExternally = callers ? [...callers].some(callerId => callerId !== id) : false

      if (!calledExternally) {
        dead.push({ file: id, name: fn.name, line: fn.startLine })
      }
    }
  }

  if (!dead.length) return "No dead exported functions found."
  dead.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line)

  const lines = [`${dead.length} exported functions with no external callers:`, ""]
  let lastFile = ""
  for (const d of dead.slice(0, 100)) {
    if (d.file !== lastFile) { lines.push(`  ${d.file}:`); lastFile = d.file }
    lines.push(`    L${d.line}  ${d.name}()`)
  }
  if (dead.length > 100) lines.push(`  ... and ${dead.length - 100} more`)
  return lines.join("\n")
}

function fnInfo(graph: Graph, target: string): string {
  if (!target) return "Usage: codemap fn-info <file>"
  const node = findNode(graph, target)
  if (!node) return `File not found: ${target}`

  if (!node.functions.length) return `No functions found in ${node.id}`

  const lines = [`=== Functions in ${node.id} (${node.functions.length}) ===`, ""]
  for (const fn of node.functions) {
    const exported = fn.isExported ? " [exported]" : ""
    const callList = fn.calls.length ? ` → calls: ${fn.calls.join(", ")}` : ""
    lines.push(`  L${fn.startLine}-${fn.endLine}  ${fn.name}()${exported}${callList}`)
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

Analysis:
  stats                 Codebase overview (files, lines, imports, URLs)
  trace <file>          Show imports and importers of a file
  blast-radius <file>   All files affected if this changes
  phone-home            Find all files with external URLs
  coupling <pattern>    Files importing a package/pattern
  dead-files            Files nothing imports
  circular              Detect circular dependency chains
  functions <file>      List exports in a file
  callers <name>        Find where a function is used
  hotspots              Most coupled files (imports + importers)
  size                  Files ranked by line count
  layers                Auto-detect architectural layers
  diff <ref>            Blast radius of changes since a git ref
  orphan-exports        Exports nothing uses

Navigation:
  why <A> <B>           Shortest import path between two files
  paths <A> <B>         ALL import paths between two files
  subgraph <pattern>    Connected component around a file/pattern
  similar <file>        Files with most similar import profiles

Graph Theory:
  pagerank              Recursive importance ranking
  hubs                  Hub/authority analysis (HITS algorithm)
  bridges               Articulation points (critical infrastructure)
  clusters              Community detection (natural module boundaries)
  islands               Disconnected components
  dot [target]          Export as Graphviz DOT format

Function-Level (AST):
  call-graph [file]     Cross-file function call graph
  dead-functions        Exported functions nothing calls
  fn-info <file>        Functions in a file with their calls

Comparison:
  compare <dir>         Structural A/B diff vs another codebase

Options:
  --dir <path>          Directory to scan (default: cwd)

Examples:
  codemap stats
  codemap hotspots
  codemap pagerank
  codemap bridges
  codemap call-graph src/utils/auth.ts
  codemap dead-functions
  codemap fn-info src/main.tsx
  codemap similar src/utils/auth.ts
  codemap paths src/cli.ts src/utils/auth.ts
  codemap dot src/services | dot -Tpng -o graph.png
  codemap compare ~/Desktop/old-version
  codemap --dir ~/Desktop/my-project stats`)
  process.exit(0)
}

// Scan
const t0 = Date.now()
const graph = await scanDirectory(dir)
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
  case "subgraph": console.log(subgraph(graph, target)); break
  case "dot": console.log(dot(graph, target)); break
  case "islands": console.log(islands(graph)); break
  case "pagerank": console.log(pagerank(graph)); break
  case "bridges": console.log(bridges(graph)); break
  case "similar": console.log(similar(graph, target)); break
  case "hubs": console.log(hubs(graph)); break
  case "clusters": console.log(clusters(graph)); break
  case "paths": console.log(paths(graph, target)); break
  case "call-graph": console.log(callGraph(graph, target)); break
  case "dead-functions": console.log(deadFunctions(graph)); break
  case "fn-info": console.log(fnInfo(graph, target)); break
  default: console.error(`Unknown action: ${action}. Run 'codemap --help' for usage.`); process.exit(1)
}
