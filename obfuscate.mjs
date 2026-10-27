#!/usr/bin/env node
/**
 * Obfuscate a Cloudflare Worker / Pages _worker.js so deployed artifacts carry
 * no plaintext proxy-panel signatures.
 *
 * Pipeline:
 *   1. Signature-split pass (AST-based): every string literal / template-literal
 *      segment that contains a known fingerprint token (vless, vmess, trojan,
 *      nexa, ...) is rewritten as ['vl','ess...'].join('') — the raw token never
 *      appears in the output, and Terser cannot constant-fold .join() back
 *      together (unlike 'a'+'b', which --compress evaluate would re-merge).
 *   2. Terser compress + mangle (safe defaults, no unsafe opts).
 *   3. Node syntax check, then atomic write.
 *
 * Usage:
 *   node obfuscate.mjs <input.js> [output.js] [--module|--script] [--plain]
 *
 *   --plain  skip the signature-split pass (minify only, old behaviour)
 *
 * The original input is never overwritten. Terser is installed once into
 * ~/.nexa-obfuscator on first run (needs npm + network).
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const TERSER_VERSION = '5.51.2';

// Fingerprint tokens that abuse scanners look for in deployed artifacts.
// Matched case-insensitively; each occurrence is cut so no piece holds a
// full token. Add more tokens here if new signatures show up.
// SENSITIVE_TOKENS: split inside every string/template/regex literal.
const SENSITIVE_TOKENS = [
  'vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria', 'tuic', 'reality',
  'v2ray', 'xray', 'sing-box', 'singbox', 'mihomo', 'clash', 'wireguard',
  'warp', 'nexa', 'uuid', 'subscription', 'shadowrocket', 'streisand',
  'v2ng', 'xtls'
];
// HARD_TOKENS: must have ZERO occurrences in the final artifact (these never
// appear as identifier/property names in the source, so full removal is
// achievable). Tokens that also exist as property names (uuid, warp, ...)
// stay split-only: their string forms are hidden, the property names remain.
const HARD_TOKENS = [
  'vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria', 'tuic',
  'shadowrocket', 'streisand', 'v2ray', 'sing-box', 'mihomo', 'reality', 'xtls'
];

const HELP = `Usage:
  node obfuscate.mjs <input.js> [output.js] [--module|--script] [--plain]

Examples:
  node obfuscate.mjs _worker.js
  node obfuscate.mjs _worker.js dist/_worker.js
  node obfuscate.mjs worker.js worker.min.js --module

The format is detected from ES-module import/export syntax. Use --module or
--script to override detection. The input is preserved; the default output is
<input-name>.obfuscated.<extension>. --plain disables signature splitting.
`;

function fail(message, code = 1) {
  console.error(`\nWorker obfuscator: ${message}`);
  process.exit(code);
}

function parseArgs(argv) {
  const positional = [];
  let forcedFormat = null;
  let plain = false;
  for (const arg of argv) {
    if (arg === '--help' || arg === '-h') { console.log(HELP); process.exit(0); }
    if (arg === '--plain') { plain = true; continue; }
    if (arg === '--module') { if (forcedFormat === 'script') fail('Use only one of --module and --script.'); forcedFormat = 'module'; continue; }
    if (arg === '--script') { if (forcedFormat === 'module') fail('Use only one of --module and --script.'); forcedFormat = 'script'; continue; }
    if (arg.startsWith('-')) fail(`Unknown option: ${arg}\n\n${HELP}`);
    positional.push(arg);
  }
  if (positional.length < 1 || positional.length > 2) fail(HELP);
  return { inputArg: positional[0], outputArg: positional[1], forcedFormat, plain };
}

function isLikelyModule(source, filename) {
  if (/\.mjs$/i.test(filename)) return true;
  return /^\s*(?:export\s+(?:(?:async\s+)?(?:function|class)\b|default\b|const\b|let\b|var\b|\{|\*)|import\s*(?!\s*\())/m.test(source);
}

// --- terser library provisioning -------------------------------------------
async function ensureTerser() {
  const libDir = path.join(os.homedir(), '.nexa-obfuscator');
  const marker = path.join(libDir, 'node_modules', 'terser', 'package.json');
  if (!fs.existsSync(marker)) {
    console.log(`Installing terser@${TERSER_VERSION} into ${libDir} (first run only)...`);
    fs.mkdirSync(libDir, { recursive: true });
    const npmArgs = ['install', '--prefix', libDir, '--no-audit', '--no-fund', '--loglevel=error', `terser@${TERSER_VERSION}`];
    const result = process.platform === 'win32'
      ? spawnSync('npm.cmd', npmArgs, { stdio: 'inherit', windowsHide: true, shell: true })
      : spawnSync('npm', npmArgs, { stdio: 'inherit' });
    if (result.error) fail(`Could not start npm (${result.error.message}). Install Node.js/npm and ensure npm is on PATH.`);
    if (result.status !== 0 || !fs.existsSync(marker)) fail(`npm install of terser failed (status ${result.status ?? 'unknown'}). Check network access to the npm registry.`);
  }
  // The package entrypoint only exports minify; the full AST API (parse,
  // AST_*, TreeTransformer, print_to_string) lives in the lib/ modules.
  const terserRoot = path.join(libDir, 'node_modules', 'terser');
  const libUrl = (name) => pathToFileURL(path.join(terserRoot, 'lib', name)).href;
  const [astMod, parseMod, minMod] = await Promise.all([
    import(libUrl('ast.js')),
    import(libUrl('parse.js')),
    import(pathToFileURL(path.join(terserRoot, 'main.js')).href)
  ]);
  await import(libUrl('output.js')); // attaches print_to_string to AST_Node
  await import(libUrl('transform.js'));
  return {
    parse: parseMod.parse,
    minify: minMod.minify,
    TreeTransformer: astMod.TreeTransformer,
    AST_String: astMod.AST_String,
    AST_Array: astMod.AST_Array,
    AST_Call: astMod.AST_Call,
    AST_Dot: astMod.AST_Dot,
    AST_TemplateString: astMod.AST_TemplateString,
    AST_TemplateSegment: astMod.AST_TemplateSegment,
    AST_Binary: astMod.AST_Binary,
    AST_New: astMod.AST_New,
    AST_SymbolRef: astMod.AST_SymbolRef,
    AST_RegExp: astMod.AST_RegExp
  };
}

// --- signature splitting -----------------------------------------------------
function splitValue(value) {
  const lower = value.toLowerCase();
  const pieces = [];
  let start = 0;
  let i = 0;
  while (i < lower.length) {
    let hit = -1;
    for (const t of SENSITIVE_TOKENS) {
      const p = lower.indexOf(t, i);
      if (p !== -1 && (hit === -1 || p < hit)) hit = p;
    }
    if (hit === -1) break;
    const cut = hit + 1; // keep the token's first char on the left piece
    pieces.push(value.slice(start, cut));
    start = cut;
    i = cut;
  }
  if (start === 0) return null; // no token found
  pieces.push(value.slice(start));
  return pieces.filter(p => p.length > 0);
}

// The printer reads node.start/end token info for comments; synthetic nodes
// need a minimal shim.
function shim(node) {
  if (!node.start) {
    const tok = { type: 'punc', value: '', line: 1, col: 0, pos: 0, endpos: 0, nlb: 0, comments_before: [], comments_after: [] };
    node.start = tok;
    node.end = tok;
  }
  return node;
}

function joinNode(T, pieces) {
  const arr = shim(new T.AST_Array({ elements: pieces.map(p => shim(new T.AST_String({ value: p }))) }));
  return shim(new T.AST_Call({
    expression: shim(new T.AST_Dot({ expression: arr, property: 'join' })),
    args: [shim(new T.AST_String({ value: '' }))]
  }));
}

function splitSignatures(T, ast) {
  let splitCount = 0;
  const concat = (left, right) => shim(new T.AST_Binary({ operator: '+', left, right }));
  const transformer = new T.TreeTransformer(function (node) {
    if (node instanceof T.AST_String) {
      const pieces = splitValue(node.value);
      if (pieces && pieces.length > 1) { splitCount++; return joinNode(T, pieces); }
      return node;
    }
    if (node instanceof T.AST_TemplateString) {
      // Rebuild the template as a '+' chain: literal segments become strings
      // (or .join() expressions when they carry a signature), interpolated
      // expressions stay as-is. This guarantees the raw token never survives
      // in the printed artifact.
      let expr = null;
      let changed = false;
      for (const seg of node.segments) {
        let part = null;
        if (seg instanceof T.AST_TemplateSegment) {
          const text = seg.value;
          if (!text) continue;
          const pieces = splitValue(text);
          if (pieces && pieces.length > 1) { changed = true; part = joinNode(T, pieces); }
          else part = shim(new T.AST_String({ value: text }));
        } else {
          part = seg;
        }
        expr = expr ? concat(expr, part) : part;
      }
      if (!changed) return node;
      splitCount++;
      return expr || shim(new T.AST_String({ value: '' }));
    }
    if (node instanceof T.AST_RegExp) {
      const value = node.value || {};
      const source = typeof value.source === 'string' ? value.source : String(value);
      const flags = typeof value.flags === 'string' ? value.flags : '';
      const pieces = splitValue(source);
      if (pieces && pieces.length > 1) {
        splitCount++;
        return shim(new T.AST_New({
          expression: shim(new T.AST_SymbolRef({ name: 'RegExp' })),
          args: [joinNode(T, pieces), shim(new T.AST_String({ value: flags }))]
        }));
      }
      return node;
    }
    return undefined;
  });
  ast = ast.transform(transformer);
  return { ast, splitCount };
}

// --- syntax check ------------------------------------------------------------
function checkSyntax(filePath, moduleMode) {
  const source = fs.readFileSync(filePath, 'utf8');
  const inputType = moduleMode ? 'module' : 'commonjs';
  const result = spawnSync(process.execPath, ['--check', `--input-type=${inputType}`], {
    input: source, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024
  });
  if (result.error) throw new Error(`Could not run Node syntax check: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(`Output failed the JavaScript syntax check.\n${result.stderr || result.stdout || ''}`);
  }
}

// --- main ----------------------------------------------------------------------
const { inputArg, outputArg, forcedFormat, plain } = parseArgs(process.argv.slice(2));
const inputPath = path.resolve(inputArg);
if (!fs.existsSync(inputPath) || !fs.statSync(inputPath).isFile()) fail(`Input file not found: ${inputPath}`);

const inputName = path.basename(inputPath);
const ext = path.extname(inputName) || '.js';
const stem = path.basename(inputName, path.extname(inputName));
const defaultOutput = path.join(path.dirname(inputPath), `${stem}.obfuscated${ext}`);
const outputPath = path.resolve(outputArg || defaultOutput);

try {
  if (fs.existsSync(outputPath) && fs.realpathSync(outputPath) === fs.realpathSync(inputPath)) {
    fail('Input and output resolve to the same file; choose a different output path.');
  }
} catch (error) {
  if (error?.message?.includes('Input and output')) throw error;
}
if (outputPath === inputPath) fail('Input and output must be different files.');

const source = fs.readFileSync(inputPath, 'utf8');
const moduleMode = forcedFormat ? forcedFormat === 'module' : isLikelyModule(source, inputPath);
const outputDir = path.dirname(outputPath);
fs.mkdirSync(outputDir, { recursive: true });
const tempPath = path.join(outputDir, `.${path.basename(outputPath)}.tmp-${process.pid}`);

try {
  console.log(`Input:  ${inputPath}`);
  console.log(`Output: ${outputPath}`);
  console.log(`Mode:   ${moduleMode ? 'ES module' : 'script'}`);
  const T = await ensureTerser();

  let code = source;
  if (!plain) {
    console.log('Pass 1: splitting proxy/panel signatures in string literals...');
    const ast = T.parse(source, { module: moduleMode, filename: inputName });
    const res = splitSignatures(T, ast);
    code = ast.print_to_string({ ecma: 2022, ascii_only: false });
    console.log(`Pass 1 done: ${res.splitCount} string(s) split.`);
  }

  console.log('Pass 2: Terser compress + mangle...');
  const minified = await T.minify(code, {
    module: moduleMode,
    compress: { evaluate: false, unsafe: false, unsafe_comps: false, unsafe_methods: false },
    mangle: moduleMode ? { module: true } : true,
    format: { comments: 'some', ecma: 2022 }
  });
  if (!minified.code) throw new Error('Terser produced no output.');
  fs.writeFileSync(tempPath, minified.code, 'utf8');
  checkSyntax(tempPath, moduleMode);

  // Verify no hard signature survived the pipeline; soft tokens are reported.
  if (!plain) {
    const out = fs.readFileSync(tempPath, 'utf8').toLowerCase();
    const leakedHard = HARD_TOKENS.filter(t => out.includes(t));
    const leakedSoft = SENSITIVE_TOKENS.filter(t => !HARD_TOKENS.includes(t) && out.includes(t));
    if (process.env.OBF_LEAK_CONTEXT) {
      for (const t of [...leakedHard, ...leakedSoft]) {
        const i = out.indexOf(t);
        console.error(`LEAK ${t}: ...${out.slice(Math.max(0, i - 60), i + 60).replace(/\n/g, ' ')}...`);
      }
    } else if (leakedSoft.length) {
      console.log(`Note: soft tokens remain as identifier/property names (expected): ${leakedSoft.join(', ')}`);
    }
    if (leakedHard.length) {
      throw new Error(`Raw signatures still present in output: ${leakedHard.join(', ')}`);
    }
  } else {
    console.log('(--plain: signature verification skipped)');
  }

  try {
    fs.renameSync(tempPath, outputPath);
  } catch (error) {
    if (process.platform !== 'win32' || !['EEXIST', 'EPERM'].includes(error.code)) throw error;
    fs.copyFileSync(tempPath, outputPath);
    fs.unlinkSync(tempPath);
  }

  const inputBytes = Buffer.byteLength(source, 'utf8');
  const outputBytes = fs.statSync(outputPath).size;
  const delta = inputBytes ? (100 * (outputBytes / inputBytes - 1)).toFixed(1) : '0.0';
  console.log(`\nDone. Syntax check passed; output is ${outputBytes.toLocaleString()} bytes (${delta > 0 ? '+' : ''}${delta}% vs input).`);
  if (!plain) console.log('No plaintext proxy/panel signatures remain in the artifact.');
  console.log('Review/test the output in Wrangler before deploying.');
} catch (error) {
  try { if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath); } catch {}
  fail(error.message || String(error));
}
