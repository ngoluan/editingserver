const http = require('http');
const fs = require('fs');
const path = require('path');
const { exec, execSync } = require('child_process');

const PORT = 8765;
const DIR = __dirname;
const DATA_DIR = path.join(DIR, 'data');
const SESSIONS_DIR = path.join(DATA_DIR, 'sessions');
const CONFIG_FILE = path.join(DIR, 'projects.json');

fs.mkdirSync(SESSIONS_DIR, { recursive: true });

const MIME = {
  '.js': 'text/javascript',
  '.html': 'text/html',
  '.css': 'text/css',
  '.json': 'application/json',
  '.txt': 'text/plain',
  '.svg': 'image/svg+xml',
};

function saveProjects(data) {
  writeJsonSafe(CONFIG_FILE, data);
}

function writeJsonSafe(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = filePath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, filePath);
}

function loadProjects() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch { return { projects: [] }; }
}

function findProject(id) {
  return loadProjects().projects.find(p => p.id === id) || null;
}

function json(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(JSON.stringify(data));
}

function parseBody(req) {
  return new Promise(resolve => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); }
      catch { resolve({}); }
    });
  });
}

function run(cmd, cwd) {
  return new Promise(resolve => {
    exec(cmd, { cwd, timeout: 60000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve({ code: err ? err.code || 1 : 0, stdout: stdout || '', stderr: stderr || '', error: err ? err.message : null });
    });
  });
}

function logSession(projectId, entry) {
  const file = path.join(SESSIONS_DIR, `${projectId}.json`);
  let log = [];
  try { log = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {}
  log.unshift({ timestamp: new Date().toISOString(), ...entry });
  if (log.length > 200) log = log.slice(0, 200);
  fs.writeFileSync(file, JSON.stringify(log, null, 2));
}

function serveFile(res, filePath) {
  const ext = path.extname(filePath);
  const stat = fs.statSync(filePath);
  res.writeHead(200, {
    'Content-Type': MIME[ext] || 'application/octet-stream',
    'Content-Length': stat.size,
    'Cache-Control': 'no-cache',
  });
  fs.createReadStream(filePath).pipe(res);
}

function generateCombineScript(projectPath, projectId, outputDir) {
  return `#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="\${1:-${projectPath}}"
OUTPUT_DIR="\${2:-${outputDir}}"
OUTPUT_FILE="$OUTPUT_DIR/${projectId}_combined-source.txt"

: > "$OUTPUT_FILE"

find "$SRC_DIR" -type f \\
  ! -path "*/node_modules/*" \\
  ! -path "*/.git/*" \\
  ! -path "*/target/*" \\
  ! -path "*/build/*" \\
  ! -path "*/dist/*" \\
  ! -path "*/venv/*" \\
  ! -path "*/__pycache__/*" \\
  ! -path "*/tmp/*" \\
  ! -path "*/.backup/*" \\
  ! -path "*/data/*" \\
  ! -path "*/patches/*" \\
  ! -name "package-lock.json" \\
  ! -name "yarn.lock" \\
  ! -name "*.svg" \\
  ! -name "*.png" \\
  ! -name "*.jpg" \\
  ! -name "*.gif" \\
  ! -name "*.ico" \\
  | sort \\
  | while read -r f; do
    rel="\${f#$SRC_DIR/}"
    echo "// ===== \$rel =====" >> "$OUTPUT_FILE"
    cat "\$f" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
  done

echo "Done. Combined \$(wc -l < "$OUTPUT_FILE") lines into $OUTPUT_FILE"
`;
}

async function handleApi(method, url, req, res) {
  const pathOnly = url.includes('?') ? url.slice(0, url.indexOf('?')) : url;
  const parts = pathOnly.split('/').filter(Boolean);

  function enrichProject(p) {
    const combinedPath = path.join(DIR, path.basename(p.combinedOutput));
    const patchPath = path.join(p.patchDir || DIR, `${p.id}_patch.txt`);
    const gitPath = p.path;
    p.combinedExists = fs.existsSync(combinedPath);
    p.combinedSize = p.combinedExists ? fs.statSync(combinedPath).size : 0;
    p.combinedLines = p.combinedExists ? fs.readFileSync(combinedPath, 'utf8').split('\n').length : 0;
    p.patchExists = fs.existsSync(patchPath);
    p.gitRepo = fs.existsSync(path.join(gitPath, '.git'));
    if (p.gitRepo) {
      try {
        const status = execSync('git status --porcelain', { cwd: gitPath, encoding: 'utf8', timeout: 5000 });
        p.gitDirty = status.trim().length > 0;
        const branch = execSync('git rev-parse --abbrev-ref HEAD', { cwd: gitPath, encoding: 'utf8', timeout: 5000 });
        p.gitBranch = branch.trim();
      } catch { p.gitDirty = false; p.gitBranch = 'unknown'; }
    } else { p.gitDirty = false; p.gitBranch = null; }
    return p;
  }

  // GET /api/browse?prefix=... — autocomplete paths
  if (method === 'GET' && parts.length === 2 && parts[0] === 'api' && parts[1] === 'browse') {
    const qs = url.includes('?') ? new URLSearchParams(url.slice(url.indexOf('?'))) : new URLSearchParams();
    const prefix = (qs.get('prefix') || '').trim();
    if (!prefix) return json(res, 200, { entries: [] });
    try {
      let entries = [];
      if (fs.existsSync(prefix) && fs.statSync(prefix).isDirectory()) {
        entries = fs.readdirSync(prefix)
          .filter(e => !e.startsWith('.'))
          .map(e => path.join(prefix, e))
          .filter(p => { try { return fs.statSync(p).isDirectory(); } catch { return false; } });
      } else {
        const dir = path.dirname(prefix);
        const base = path.basename(prefix);
        if (fs.existsSync(dir)) {
          entries = fs.readdirSync(dir)
            .filter(e => e.startsWith(base) && !e.startsWith('.'))
            .map(e => path.join(dir, e))
            .filter(p => { try { return fs.statSync(p).isDirectory(); } catch { return false; } });
        }
      }
      return json(res, 200, { entries: entries.slice(0, 50) });
    } catch { return json(res, 200, { entries: [] }); }
  }

  // POST /api/projects/detect — scan a folder path
  if (method === 'POST' && parts.length === 3 && parts[0] === 'api' && parts[1] === 'projects' && parts[2] === 'detect') {
    const body = await parseBody(req);
    const folderPath = (body.path || '').trim();
    if (!folderPath || !fs.existsSync(folderPath)) return json(res, 404, { error: 'Path does not exist' });
    const stat = fs.statSync(folderPath);
    if (!stat.isDirectory()) return json(res, 400, { error: 'Path is not a directory' });
    const name = path.basename(folderPath);
    const hasGit = fs.existsSync(path.join(folderPath, '.git'));
    const files = fs.readdirSync(folderPath).slice(0, 100);
    const extensions = new Set();
    for (const f of files) {
      const ext = path.extname(f).toLowerCase();
      if (ext) extensions.add(ext);
    }
    const sourceExts = ['.js', '.ts', '.jsx', '.tsx', '.py', '.kt', '.gd', '.rs', '.go', '.java', '.css', '.html', '.vue', '.svelte', '.c', '.cpp', '.h', '.hpp'];
    const found = [...extensions].filter(e => sourceExts.includes(e));
    return json(res, 200, { name, hasGit, extensions: [...extensions], sourceExtensions: found, fileCount: files.length });
  }

  // GET /api/projects
  if (method === 'GET' && parts.length === 2 && parts[0] === 'api' && parts[1] === 'projects') {
    const data = loadProjects();
    data.projects.forEach(enrichProject);
    return json(res, 200, data);
  }

  // POST /api/projects — create new project
  if (method === 'POST' && parts.length === 2 && parts[0] === 'api' && parts[1] === 'projects') {
    const body = await parseBody(req);
    const name = (body.name || '').trim();
    const folderPath = (body.path || '').trim();
    if (!name || !folderPath) return json(res, 400, { error: 'name and path required' });
    if (!fs.existsSync(folderPath)) return json(res, 400, { error: 'Path does not exist' });
    const id = name.toLowerCase().replace(/[^a-z0-9_-]/g, '_').replace(/_{2,}/g, '_').replace(/^_|_$/g, '') || 'project';
    const data = loadProjects();
    if (data.projects.find(p => p.id === id)) return json(res, 409, { error: 'Project id already exists' });
    const combinedOutput = path.join(DIR, `${id}_combined-source.txt`);
    const patchDir = path.join(DIR, 'patches');
    const combineScript = body.combineScript || null;
    const project = { id, name, path: folderPath, combineScript, combinedOutput, patchDir };
    if (!combineScript) {
      const scriptPath = path.join(DIR, `${id}_combine-source.sh`);
      const scriptContent = generateCombineScript(folderPath, id, DIR);
      fs.writeFileSync(scriptPath, scriptContent);
      fs.chmodSync(scriptPath, 0o755);
      project.combineScript = scriptPath;
    }
    data.projects.push(project);
    saveProjects(data);
    return json(res, 201, enrichProject(project));
  }

  // DELETE /api/projects/:id
  if (method === 'DELETE' && parts.length === 3 && parts[0] === 'api' && parts[1] === 'projects') {
    const data = loadProjects();
    const idx = data.projects.findIndex(p => p.id === parts[2]);
    if (idx === -1) return json(res, 404, { error: 'Not found' });
    data.projects.splice(idx, 1);
    saveProjects(data);
    return json(res, 200, { success: true });
  }

  // GET /api/projects/:id — single project detail
  if (method === 'GET' && parts.length === 3 && parts[0] === 'api' && parts[1] === 'projects') {
    const p = findProject(parts[2]);
    if (!p) return json(res, 404, { error: 'Not found' });
    return json(res, 200, enrichProject(p));
  }

  const projectMatch = pathOnly.match(/^\/api\/projects\/([^/]+)\/(.+)$/);
  if (!projectMatch) return json(res, 404, { error: 'Not found' });

  const projectId = projectMatch[1];
  const action = projectMatch[2];
  const project = findProject(projectId);
  if (!project) return json(res, 404, { error: 'Project not found' });

  // POST /api/projects/:id/combine
  if (method === 'POST' && action === 'combine') {
    try {
      const result = await run(`bash "${project.combineScript}" "${project.path}" "${DIR}"`, DIR);
      const combinedPath = path.join(DIR, path.basename(project.combinedOutput));
      let lines = 0, size = 0, content = '';
      if (fs.existsSync(combinedPath)) {
        content = fs.readFileSync(combinedPath, 'utf8');
        lines = content.split('\n').length;
        size = fs.statSync(combinedPath).size;
      }
      logSession(projectId, { action: 'combine', lines, size, exitCode: result.code });
      return json(res, result.code === 0 ? 200 : 500, {
        success: result.code === 0,
        lines,
        size,
        stdout: result.stdout,
        stderr: result.stderr,
        preview: content.slice(0, 5000),
      });
    } catch (e) {
      return json(res, 500, { error: e.message });
    }
  }

  // GET /api/projects/:id/source
  if (method === 'GET' && action === 'source') {
    const combinedPath = path.join(DIR, path.basename(project.combinedOutput));
    if (!fs.existsSync(combinedPath)) return json(res, 404, { error: 'No combined source found' });
    const content = fs.readFileSync(combinedPath, 'utf8');
    return json(res, 200, { content, lines: content.split('\n').length, size: Buffer.byteLength(content) });
  }

  // GET /api/projects/:id/patch
  if (method === 'GET' && action === 'patch') {
    const patchPath = path.join(project.patchDir || DIR, `${project.id}_patch.txt`);
    if (!fs.existsSync(patchPath)) return json(res, 200, { content: '' });
    const content = fs.readFileSync(patchPath, 'utf8');
    return json(res, 200, { content });
  }

  // POST /api/projects/:id/patch
  if (method === 'POST' && action === 'patch') {
    const body = await parseBody(req);
    const patchDir = project.patchDir || DIR;
    fs.mkdirSync(patchDir, { recursive: true });
    const patchPath = path.join(patchDir, `${project.id}_patch.txt`);
    fs.writeFileSync(patchPath, body.content || '');
    logSession(projectId, { action: 'patch_save', size: (body.content || '').length });
    return json(res, 200, { success: true });
  }

  // GET /api/projects/:id/status
  if (method === 'GET' && action === 'status') {
    if (!fs.existsSync(path.join(project.path, '.git'))) return json(res, 400, { error: 'Not a git repository' });
    const status = await run('git status', project.path);
    const porcelain = await run('git status --porcelain', project.path);
    const log = await run('git log --oneline -10', project.path);
    const branchResult = await run('git rev-parse --abbrev-ref HEAD', project.path);
    return json(res, 200, {
      branch: branchResult.stdout.trim(),
      status: status.stdout,
      porcelain: porcelain.stdout,
      log: log.stdout,
      dirty: porcelain.stdout.trim().length > 0,
    });
  }

  // POST /api/projects/:id/commit
  if (method === 'POST' && action === 'commit') {
    const body = await parseBody(req);
    const msg = (body.message || 'update').replace(/"/g, '\\"');
    const add = await run('git add -A', project.path);
    if (add.code !== 0) return json(res, 500, { error: 'git add failed', stderr: add.stderr });
    const commit = await run(`git commit -m "${msg}"`, project.path);
    logSession(projectId, { action: 'commit', message: body.message || 'update', success: commit.code === 0 });
    return json(res, commit.code === 0 ? 200 : 400, {
      success: commit.code === 0,
      stdout: commit.stdout,
      stderr: commit.stderr,
    });
  }

  // POST /api/projects/:id/merge
  if (method === 'POST' && action === 'merge') {
    const body = await parseBody(req);
    const branch = (body.branch || '').trim();
    if (!branch) return json(res, 400, { error: 'Branch name required' });
    const merge = await run(`git merge "${branch}"`, project.path);
    logSession(projectId, { action: 'merge', branch, success: merge.code === 0 });
    return json(res, merge.code === 0 ? 200 : 400, {
      success: merge.code === 0,
      stdout: merge.stdout,
      stderr: merge.stderr,
    });
  }

  // GET /api/projects/:id/sessions
  if (method === 'GET' && action === 'sessions') {
    const file = path.join(SESSIONS_DIR, `${projectId}.json`);
    let log = [];
    try { log = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {}
    return json(res, 200, { sessions: log });
  }

  // POST /api/projects/:id/sessions/clear
  if (method === 'POST' && action === 'sessions/clear') {
    const file = path.join(SESSIONS_DIR, `${projectId}.json`);
    if (fs.existsSync(file)) fs.unlinkSync(file);
    return json(res, 200, { success: true });
  }

  return json(res, 404, { error: 'Unknown action' });
}

http.createServer(async (req, res) => {
  const url = req.url;
  if (url.startsWith('/api/')) {
    return handleApi(req.method, url, req, res);
  }

  const filePath = path.join(DIR, url === '/' ? 'index.html' : url);
  const safe = filePath.startsWith(DIR);
  if (!safe) { res.writeHead(403); res.end('Forbidden'); return; }

  try {
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) {
      const files = fs.readdirSync(filePath);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<h1>Index of ${url}</h1><ul>${
        files.map(f => `<li><a href="${path.join(url, f)}">${f}</a></li>`).join('')
      }</ul>`);
    } else {
      serveFile(res, filePath);
    }
  } catch {
    res.writeHead(404); res.end('Not Found');
  }
}).listen(PORT, () => {
  console.log(`Server at http://0.0.0.0:${PORT}`);
  process.title = 'opencode-server';
});

setInterval(() => {}, 10000);
