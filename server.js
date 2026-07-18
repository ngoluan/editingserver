const http = require('http');
const fs = require('fs');
const path = require('path');
const { exec, execSync } = require('child_process');
const https = require('https');

try {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
      const [k, ...v] = line.split('=');
      if (k && v.length) process.env[k.trim()] = v.join('=').trim();
    });
  }
} catch {}

const PORT = process.env.PORT || 8765;
const DIR = __dirname;
// Activity logs are also machine-local; keeping them in runtime prevents Git
// pulls from conflicting with another server's deployment history.
const RUNTIME_DIR = path.join(DIR, 'runtime');
const SESSIONS_DIR = path.join(RUNTIME_DIR, 'sessions');
// Runtime project settings are server-specific. Keep them outside Git so a pull
// never replaces another server's project paths or deployment commands.
const LOCAL_CONFIG_FILE = path.join(DIR, 'projects.local.json');
const LEGACY_CONFIG_FILE = path.join(DIR, 'projects.json');
const activeDeployments = new Set();

const OPENCODE_SERVER_URL = process.env.OPENCODE_SERVER_URL || 'http://localhost:4096';
const OPENCODE_SERVER_USER = process.env.OPENCODE_SERVER_USERNAME || 'luan_ngo';
const OPENCODE_SERVER_PASS = process.env.OPENCODE_SERVER_PASSWORD || '';
const DEEPSEEK_API_KEY = process.env.DEEPSEEK_API_KEY || '';

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
  writeJsonSafe(LOCAL_CONFIG_FILE, data);
}

function writeJsonSafe(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = filePath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, filePath);
}

function loadProjects() {
  try {
    return JSON.parse(fs.readFileSync(LOCAL_CONFIG_FILE, 'utf8'));
  } catch {}

  // One-time migration for existing installations. Once this has run, all
  // subsequent writes use projects.local.json and are ignored by Git.
  try {
    const legacy = JSON.parse(fs.readFileSync(LEGACY_CONFIG_FILE, 'utf8'));
    if (Array.isArray(legacy.projects)) {
      saveProjects(legacy);
      return legacy;
    }
  } catch {}
  return { projects: [] };
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

function run(cmd, cwd, timeoutMs) {
  return new Promise(resolve => {
    exec(cmd, { cwd, timeout: timeoutMs || 60000, maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve({ code: err ? err.code || 1 : 0, stdout: stdout || '', stderr: stderr || '', error: err ? err.message : null });
    });
  });
}

function cleanCommand(value) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, 4000);
}

function resolveProjectFile(projectPath, requestedFile) {
  if (typeof requestedFile !== 'string' || !requestedFile.trim()) {
    throw new Error('File path required');
  }
  const relativeFile = requestedFile.trim().replace(/\\/g, '/');
  if (path.isAbsolute(relativeFile) || relativeFile.split('/').includes('..') || relativeFile.split('/').includes('.git')) {
    throw new Error('File must be inside the project and outside .git');
  }

  const root = fs.realpathSync(projectPath);
  const candidate = path.resolve(root, relativeFile);
  if (candidate !== root && !candidate.startsWith(root + path.sep)) {
    throw new Error('File must be inside the project');
  }
  if (!fs.existsSync(candidate)) throw new Error('File not found');

  const filePath = fs.realpathSync(candidate);
  if (!filePath.startsWith(root + path.sep) || !fs.statSync(filePath).isFile()) {
    throw new Error('File must be a regular file inside the project');
  }
  return { filePath, relativeFile };
}

function opencodeApi(method, endpoint, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint, OPENCODE_SERVER_URL);
    const data = body ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json' };
    if (OPENCODE_SERVER_PASS) {
      headers['Authorization'] = 'Basic ' + Buffer.from(`${OPENCODE_SERVER_USER}:${OPENCODE_SERVER_PASS}`).toString('base64');
    }
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + (url.search || ''),
      method,
      headers,
    };
    if (data) options.headers['Content-Length'] = Buffer.byteLength(data);
    const req = http.request(options, (apiRes) => {
      let responseData = '';
      apiRes.on('data', chunk => responseData += chunk);
      apiRes.on('end', () => {
        try { resolve({ status: apiRes.statusCode, data: JSON.parse(responseData) }); }
        catch { resolve({ status: apiRes.statusCode, data: responseData }); }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function opencodeEndpoint(endpoint, projectPath) {
  const separator = endpoint.includes('?') ? '&' : '?';
  return `${endpoint}${separator}directory=${encodeURIComponent(projectPath)}`;
}

async function launchOpencodeJob(project, title, prompt, jobType) {
  const sessionRes = await opencodeApi('POST', opencodeEndpoint('/session', project.path), { title });
  if (sessionRes.status !== 200 && sessionRes.status !== 201) {
    return { success: false, error: `Failed to create OpenCode session: ${sessionRes.status}` };
  }

  const sessionId = sessionRes.data.id;
  const msgRes = await opencodeApi(
    'POST',
    opencodeEndpoint(`/session/${sessionId}/prompt_async`, project.path),
    { agent: 'build', parts: [{ type: 'text', text: prompt }] },
  );
  const success = msgRes.status === 200 || msgRes.status === 204;
  if (!success) return { success: false, sessionId, error: `OpenCode rejected prompt: ${msgRes.status}` };

  const data = loadProjects();
  const savedProject = data.projects.find(p => p.id === project.id);
  if (savedProject) {
    savedProject.opencodeSessionId = sessionId;
    savedProject.opencodeSessionStartedAt = new Date().toISOString();
    savedProject.opencodeJobType = jobType;
    saveProjects(data);
  }
  return { success: true, sessionId, jobType };
}

async function opencodeApplyPatch(projectPath, projectId, patchContent) {
  try {
    const project = findProject(projectId) || { id: projectId, path: projectPath };
    return await launchOpencodeJob(project, `patch-${projectId}`, `You are working in the project directory ${projectPath}.
Apply the uploaded patch below to this project. Inspect the repository, implement every requested change, resolve context differences safely, and verify the result. Do not merely explain the patch; edit the project files.

UPLOADED PATCH:
${patchContent}`, 'patch');
  } catch (e) {
    return { success: false, error: e.message };
  }
}

function generateCommitMessage(diff) {
  return new Promise((resolve, reject) => {
    const prompt = `Generate a concise git commit message for the following diff. Respond with ONLY the commit message (subject line, max 72 chars), no explanation, no backticks, no quotes.\n\n${diff.slice(0, 8000)}`;
    const data = JSON.stringify({
      model: 'deepseek-chat',
      messages: [
        { role: 'system', content: 'You are a helpful assistant that generates concise git commit messages.' },
        { role: 'user', content: prompt },
      ],
      max_tokens: 100,
      temperature: 0.3,
    });
    const options = {
      hostname: 'api.deepseek.com',
      path: '/v1/chat/completions',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${DEEPSEEK_API_KEY}`,
        'Content-Length': Buffer.byteLength(data),
      },
    };
    const req = https.request(options, apiRes => {
      let body = '';
      apiRes.on('data', chunk => body += chunk);
      apiRes.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          const msg = (parsed.choices?.[0]?.message?.content || 'update').trim().replace(/^['"]|['"]$/g, '');
          resolve(msg);
        } catch (e) {
          reject(new Error(`DeepSeek API error: ${body.slice(0, 200)}`));
        }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
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

function scanDirectory(dir, maxDepth = 3, currentDepth = 0) {
  const results = { dirs: [], files: [] };
  if (currentDepth > maxDepth) return results;
  try {
    const entries = fs.readdirSync(dir);
    for (const entry of entries) {
      if (entry.startsWith('.')) continue;
      const fullPath = path.join(dir, entry);
      try {
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
          results.dirs.push(fullPath);
          const sub = scanDirectory(fullPath, maxDepth, currentDepth + 1);
          results.dirs.push(...sub.dirs);
          results.files.push(...sub.files);
        } else {
          results.files.push(fullPath);
        }
      } catch {}
    }
  } catch {}
  return results;
}

function scanProjectForCombineScript(projectPath) {
  const dirsToIgnore = new Set();
  const extensions = new Set();
  const binaryExts = new Set(['.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.gz', '.tar', '.tgz', '.jar', '.class', '.pyc', '.pyo', '.so', '.dll', '.dylib', '.exe', '.obj', '.o', '.a', '.lib', '.DS_Store']);
  const sourceExtPriority = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.kt', '.kts', '.swift', '.rs', '.go', '.rb', '.php', '.c', '.cpp', '.h', '.hpp', '.css', '.html', '.vue', '.svelte', '.gd', '.scala', '.dart', '.zig', '.nim', '.r', '.m', '.mm', '.prisma', '.graphql', '.sql'];

  const topEntries = [];
  try {
    const entries = fs.readdirSync(projectPath);
    for (const e of entries) {
      if (e.startsWith('.')) continue;
      try {
        const full = path.join(projectPath, e);
        if (fs.statSync(full).isDirectory()) topEntries.push(e);
      } catch {}
    }
  } catch {}

  const commonIgnoreDirs = ['node_modules', '.git', 'target', 'build', 'dist', 'venv', '.venv', '__pycache__', 'tmp', '.backup', 'data', 'patches', 'old', 'archive', '.next', '.nuxt', 'out', '.output', 'coverage', '.nyc_output', 'vendor', '.bundle', '.gradle', 'Pods', '.build', 'elm-stuff', '_build', 'deps', '*.egg-info', '.tox', '.mypy_cache', '.pytest_cache', '.serverless', '.terraform', '.next', 'cache', 'logs', '.env', 'env'];
  const detectedIgnores = commonIgnoreDirs.filter(d => topEntries.includes(d));

  const allFiles = scanDirectory(projectPath, 6);
  const sourceFiles = [];
  const lockFiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'Cargo.lock', 'Gemfile.lock', 'poetry.lock', 'composer.lock'];

  for (const f of allFiles.files) {
    const ext = path.extname(f).toLowerCase();
    const base = path.basename(f);
    if (binaryExts.has(ext)) continue;
    if (lockFiles.includes(base)) continue;
    extensions.add(ext);
    if (ext) sourceFiles.push(f);
  }

  const detectedSourceExts = sourceExtPriority.filter(e => extensions.has(e));

  let fullExtList = detectedSourceExts.slice(0, 20);

  if (fullExtList.length === 0) fullExtList = ['.js', '.ts', '.py'];

  let includePattern = '';
  if (fullExtList.length <= 8) {
    includePattern = fullExtList.map(e => `  -name "${e}"`).join(' -o \\\n');
  }

  let gitignoreDirPatterns = [];
  try {
    const gitignorePath = path.join(projectPath, '.gitignore');
    if (fs.existsSync(gitignorePath)) {
      const content = fs.readFileSync(gitignorePath, 'utf8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) continue;
        const dirMatch = trimmed.replace(/\/+$/, '');
        if (dirMatch && !dirMatch.startsWith('*') && !dirMatch.startsWith('.')) {
          gitignoreDirPatterns.push(dirMatch);
        }
      }
    }
  } catch {}

  const allIgnores = [...new Set([...detectedIgnores, ...gitignoreDirPatterns])];

  return {
    detectedIgnores,
    gitignoreDirPatterns,
    detectedSourceExts,
    allExts: [...extensions].filter(Boolean),
    fullExtList,
    allIgnores,
    topEntries,
    fileCount: allFiles.files.length,
  };
}

function generateSmartCombineScript(projectPath, projectId, outputDir, scanResult) {
  const ignores = scanResult.allIgnores;
  const exts = scanResult.fullExtList;
  const lockFiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'Cargo.lock', 'Gemfile.lock', 'poetry.lock', 'composer.lock'];
  const binaryNames = ['*.svg', '*.png', '*.jpg', '*.jpeg', '*.gif', '*.ico', '*.woff', '*.woff2', '*.ttf', '*.eot', '*.pdf', '*.zip', '*.gz', '*.tar', '*.tgz', '*.jar', '*.class', '*.pyc', '*.pyo', '*.so', '*.dll', '*.dylib', '*.exe', '*.obj', '*.o'];

  const excludeLines = [
    ...ignores.map(d => `  ! -path "*/${d}/*"`),
    ...lockFiles.map(f => `  ! -name "${f}"`),
    ...binaryNames.map(f => `  ! -name "${f}"`),
  ];

  let findBlock;
  if (exts.length <= 10) {
    const nameTests = exts.map(e => `  -name "*${e}"`).join(' -o \\\n') + ' \\';
    const prefix = `find "$SRC_DIR" -type f \\( \\\n${nameTests}\n\\) \\\n`;
    if (excludeLines.length) {
      const last = excludeLines.pop();
      findBlock = prefix + excludeLines.join(' \\\n') + ' \\\n' + last;
    } else {
      findBlock = prefix;
    }
  } else {
    const prefix = `find "$SRC_DIR" -type f \\\n`;
    if (excludeLines.length) {
      const last = excludeLines.pop();
      findBlock = prefix + excludeLines.join(' \\\n') + ' \\\n' + last;
    } else {
      findBlock = prefix;
    }
  }

  return `#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="\${1:-${projectPath}}"
OUTPUT_DIR="\${2:-${outputDir}}"
OUTPUT_FILE="$OUTPUT_DIR/${projectId}_combined-source.txt"

: > "$OUTPUT_FILE"

${findBlock} \\
  | sort \\
  | while read -r f; do
    mod=\$(stat -c '%y' "\$f")
    echo "// ===== \$f (\${mod%%.*}) =====" >> "\$OUTPUT_FILE"
    cat "\$f" >> "\$OUTPUT_FILE"
    echo "" >> "\$OUTPUT_FILE"
  done

echo "Done. Combined \$(wc -l < "\$OUTPUT_FILE") lines into \$OUTPUT_FILE"
`;
}

async function scanAndGenerateCombineScript(projectPath, projectId, outputDir) {
  const scanResult = scanProjectForCombineScript(projectPath);
  const script = generateSmartCombineScript(projectPath, projectId, outputDir, scanResult);
  return {
    script,
    summary: {
      ignoredDirs: scanResult.detectedIgnores,
      gitignorePatterns: scanResult.gitignoreDirPatterns,
      sourceExtensions: scanResult.detectedSourceExts,
      fileCount: scanResult.fileCount,
      totalIgnoreDirs: scanResult.allIgnores.length,
    },
    ignores: scanResult.detectedIgnores,
    gitignorePatterns: scanResult.gitignoreDirPatterns,
    extensions: scanResult.detectedSourceExts,
    allExtensions: scanResult.allExts,
  };
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
  ! -path "*/old/*" \\
  ! -path "*/archive/*" \\
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
    mod=\$(stat -c '%y' "\$f")
    echo "// ===== \$f (\${mod%%.*}) =====" >> "\$OUTPUT_FILE"
    cat "\$f" >> "\$OUTPUT_FILE"
    echo "" >> "\$OUTPUT_FILE"
  done

echo "Done. Combined \$(wc -l < "\$OUTPUT_FILE") lines into \$OUTPUT_FILE"
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
    if (p.combinedExists && p.combinedSize < 500 * 1024 * 1024) {
      p.combinedLines = fs.readFileSync(combinedPath, 'utf8').split('\n').length;
    } else {
      p.combinedLines = p.combinedExists ? 0 : 0;
    }
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

  // GET /api/activity — recent actions across all projects
  if (method === 'GET' && parts.length === 2 && parts[0] === 'api' && parts[1] === 'activity') {
    return handleActivity(method, url, req, res);
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
    const buildCommand = cleanCommand(body.buildCommand);
    const restartCommand = cleanCommand(body.restartCommand);
    const project = { id, name, path: folderPath, combineScript, combinedOutput, patchDir, buildCommand, restartCommand };
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

  // DELETE /api/projects — remove all dashboard project registrations only
  if (method === 'DELETE' && parts.length === 2 && parts[0] === 'api' && parts[1] === 'projects') {
    const data = loadProjects();
    const removed = data.projects.length;
    saveProjects({ projects: [] });
    return json(res, 200, { success: true, removed });
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

  // POST /api/projects/:id/deploy-config — update project-specific build/restart commands
  if (method === 'POST' && action === 'deploy-config') {
    const body = await parseBody(req);
    const data = loadProjects();
    const savedProject = data.projects.find(p => p.id === projectId);
    if (!savedProject) return json(res, 404, { error: 'Project not found' });
    savedProject.buildCommand = cleanCommand(body.buildCommand);
    savedProject.restartCommand = cleanCommand(body.restartCommand);
    saveProjects(data);
    return json(res, 200, {
      success: true,
      buildCommand: savedProject.buildCommand,
      restartCommand: savedProject.restartCommand,
    });
  }

  // GET/POST /api/projects/:id/file — read or manually update a project source file before deploy
  if ((method === 'GET' || method === 'POST') && action === 'file') {
    try {
      const body = method === 'POST' ? await parseBody(req) : null;
      const url = method === 'GET' ? new URL(req.url, 'http://localhost') : null;
      const requestedFile = method === 'POST' ? body.file : url.searchParams.get('file');
      const { filePath, relativeFile } = resolveProjectFile(project.path, requestedFile);
      const stat = fs.statSync(filePath);
      if (stat.size > 2 * 1024 * 1024) return json(res, 413, { error: 'Files larger than 2 MB cannot be edited here.' });

      if (method === 'GET') {
        const content = fs.readFileSync(filePath, 'utf8');
        if (content.includes('\0')) return json(res, 415, { error: 'Binary files cannot be edited here.' });
        return json(res, 200, { file: relativeFile, content, size: stat.size });
      }

      if (typeof body.content !== 'string') return json(res, 400, { error: 'File content required' });
      if (Buffer.byteLength(body.content, 'utf8') > 2 * 1024 * 1024) return json(res, 413, { error: 'Edited files must be 2 MB or smaller.' });
      if (body.content.includes('\0')) return json(res, 415, { error: 'Binary file content is not supported.' });
      fs.writeFileSync(filePath, body.content, 'utf8');
      logSession(projectId, { action: 'manual_file_edit', file: relativeFile, size: Buffer.byteLength(body.content, 'utf8') });
      return json(res, 200, { success: true, file: relativeFile, size: Buffer.byteLength(body.content, 'utf8') });
    } catch (e) {
      return json(res, 400, { error: e.message });
    }
  }

  // POST /api/projects/:id/rebuild-restart — build, then restart only after a successful build
  if (method === 'POST' && action === 'rebuild-restart') {
    const buildCommand = cleanCommand(project.buildCommand);
    const restartCommand = cleanCommand(project.restartCommand);
    if (!buildCommand || !restartCommand) {
      return json(res, 400, { error: 'Configure both the build and restart commands first.' });
    }
    if (activeDeployments.has(projectId)) {
      return json(res, 409, { error: 'A rebuild and restart is already running for this project.' });
    }

    activeDeployments.add(projectId);
    const startedAt = Date.now();
    try {
      const build = await run(buildCommand, project.path, 10 * 60 * 1000);
      if (build.code !== 0) {
        logSession(projectId, { action: 'rebuild_restart', success: false, stage: 'build', exitCode: build.code, durationMs: Date.now() - startedAt });
        return json(res, 500, { success: false, stage: 'build', build });
      }

      const restart = await run(restartCommand, project.path, 2 * 60 * 1000);
      const success = restart.code === 0;
      logSession(projectId, { action: 'rebuild_restart', success, stage: success ? 'complete' : 'restart', exitCode: restart.code, durationMs: Date.now() - startedAt });
      return json(res, success ? 200 : 500, {
        success,
        stage: success ? 'complete' : 'restart',
        durationMs: Date.now() - startedAt,
        build,
        restart,
      });
    } catch (e) {
      logSession(projectId, { action: 'rebuild_restart', success: false, stage: 'server', error: e.message, durationMs: Date.now() - startedAt });
      return json(res, 500, { success: false, stage: 'server', error: e.message });
    } finally {
      activeDeployments.delete(projectId);
    }
  }

  // POST /api/projects/:id/deploy — Combine → patch → build/restart → Git commit/push
  if (method === 'POST' && action === 'deploy') {
    const body = await parseBody(req);
    const buildCommand = cleanCommand(project.buildCommand);
    const restartCommand = cleanCommand(project.restartCommand);
    const commitMessage = cleanCommand(body.commitMessage) || 'deploy update';
    const patchPath = path.join(project.patchDir || DIR, `${project.id}_patch.txt`);
    if (!project.combineScript || !fs.existsSync(project.combineScript)) {
      return json(res, 400, { error: 'Configure a valid combine script first.' });
    }
    if (!buildCommand || !restartCommand) {
      return json(res, 400, { error: 'Configure both the build and restart commands first.' });
    }
    if (!fs.existsSync(path.join(project.path, '.git'))) {
      return json(res, 400, { error: 'This workflow requires the project to be a git repository.' });
    }
    if (activeDeployments.has(projectId)) {
      return json(res, 409, { error: 'A deployment is already running for this project.' });
    }

    activeDeployments.add(projectId);
    const startedAt = Date.now();
    const steps = {};
    const fail = (stage, result, status = 500) => {
      logSession(projectId, { action: 'deploy', success: false, stage, exitCode: result?.code, durationMs: Date.now() - startedAt });
      return json(res, status, { success: false, stage, steps, durationMs: Date.now() - startedAt });
    };
    try {
      steps.combine = await run(`bash "${project.combineScript}" "${project.path}" "${DIR}"`, DIR, 10 * 60 * 1000);
      if (steps.combine.code !== 0) return fail('combine', steps.combine);

      if (fs.existsSync(patchPath) && fs.statSync(patchPath).size > 0) {
        steps.patch = await run(`git apply "${patchPath}"`, project.path, 2 * 60 * 1000);
        if (steps.patch.code !== 0) return fail('patch', steps.patch);
      } else {
        steps.patch = { code: 0, skipped: true, stdout: 'No saved patch; skipped.' };
      }

      steps.build = await run(buildCommand, project.path, 10 * 60 * 1000);
      if (steps.build.code !== 0) return fail('build', steps.build);
      steps.restart = await run(restartCommand, project.path, 2 * 60 * 1000);
      if (steps.restart.code !== 0) return fail('restart', steps.restart);

      const status = await run('git status --porcelain', project.path);
      if (status.code !== 0) return fail('git-status', status);
      if (!status.stdout.trim()) {
        steps.git = { code: 0, skipped: true, stdout: 'Working tree clean; nothing to commit or push.' };
      } else {
        steps.gitAdd = await run('git add -A', project.path);
        if (steps.gitAdd.code !== 0) return fail('git-add', steps.gitAdd);
        const safeMessage = commitMessage.replace(/[\\"$`]/g, '\\$&');
        steps.gitCommit = await run(`git commit -m "${safeMessage}"`, project.path);
        if (steps.gitCommit.code !== 0) return fail('git-commit', steps.gitCommit);
        steps.gitPush = await run('git push', project.path, 2 * 60 * 1000);
        if (steps.gitPush.code !== 0) return fail('git-push', steps.gitPush);
        steps.git = { code: 0, stdout: 'Changes committed and pushed.' };
      }

      logSession(projectId, { action: 'deploy', success: true, stage: 'complete', durationMs: Date.now() - startedAt });
      return json(res, 200, { success: true, stage: 'complete', steps, durationMs: Date.now() - startedAt });
    } catch (e) {
      return fail('server', { code: 1, error: e.message });
    } finally {
      activeDeployments.delete(projectId);
    }
  }

  // POST /api/projects/:id/update-combine-script — smart scan and regenerate combine script
  if (method === 'POST' && action === 'update-combine-script') {
    try {
      const projectPath = project.path;
      const result = await scanAndGenerateCombineScript(projectPath, projectId, DIR);
      if (project.combineScript) {
        fs.writeFileSync(project.combineScript, result.script);
        fs.chmodSync(project.combineScript, 0o755);
      }
      logSession(projectId, { action: 'update_combine_script', ...result.summary });
      return json(res, 200, result);
    } catch (e) {
      return json(res, 500, { error: e.message });
    }
  }

  // POST /api/projects/:id/ai-smart-update — use opencode web API to generate a combine script
  if (method === 'POST' && action === 'ai-smart-update') {
    try {
      const projectPath = project.path;
      const scriptPath = project.combineScript || path.join(DIR, `${projectId}_combine-source.sh`);
      const combinedOutput = project.combinedOutput;
      const outputBasename = path.basename(combinedOutput);

      const prompt = `You are working in the project directory ${projectPath}.
Update the existing combine script at this exact path: ${scriptPath}. Inspect the project only to discover reusable file-selection rules; do not add individual project file paths to the script.

REQUIREMENTS:
- The finished script MUST select files using wildcard and exclusion rules. Use find with -name WILDCARDS like -name "*.ts" -o -name "*.jsx". NEVER list individual source file paths.
- First scan the project to discover which source extensions exist, then use those extensions as wildcards.
- Combine wildcards inside \\( ... \\) to match ONLY source code file types.
- Accept SRC_DIR (default: ${projectPath}) and OUTPUT_DIR (default: ${DIR}) as $1 and $2.
- Set OUTPUT_FILE="\${OUTPUT_DIR}/${outputBasename}".
- Empty OUTPUT_FILE with ": > \"\${OUTPUT_FILE}\"" at the start.
- Exclude with ! -path for: node_modules .git build dist target __pycache__ venv vendor coverage tmp old archive .next .nuxt .gradle .backup data patches
- Exclude with ! -name for: package-lock.json yarn.lock pnpm-lock.yaml bun.lock Cargo.lock Gemfile.lock poetry.lock composer.lock *.svg *.png *.jpg *.jpeg *.gif *.ico *.woff *.woff2 *.ttf *.eot *.pdf *.zip *.gz *.tar *.tgz *.jar *.class *.pyc *.pyo *.so *.dll *.dylib *.exe *.obj *.o
- Sort output. For each file, get last modified time via \$(stat -c '%y' "\$f"), then prepend "// ===== \$f (\${mod%%.*}) =====" header before each file, then cat the file.
- End with: echo "Done. Combined \$(wc -l < \"\${OUTPUT_FILE}\") lines into \${OUTPUT_FILE}"
- Preserve useful existing rules when safe, replace any per-file list with wildcard rules, and mark the script executable with chmod +x.
- Make the edits now and verify the resulting shell script with bash -n.`;

      const result = await launchOpencodeJob(project, `smart-combine-${projectId}`, prompt, 'combine-script');
      logSession(projectId, { action: 'ai_smart_update', sessionId: result.sessionId, success: result.success });
      return json(res, result.success ? 200 : 500, result);
    } catch (e) {
      return json(res, 500, { error: e.message });
    }
  }

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
    const stat = fs.statSync(combinedPath);
    if (stat.size > 500 * 1024 * 1024) return json(res, 413, { error: 'Combined source too large for inline viewing', size: stat.size });
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

  // POST /api/projects/:id/apply-patch — run git apply
  if (method === 'POST' && action === 'apply-patch') {
    const patchPath = path.join(project.patchDir || DIR, `${project.id}_patch.txt`);
    if (!fs.existsSync(patchPath)) return json(res, 400, { error: 'No patch file saved. Save the patch first.' });
    const result = await run(`git apply "${patchPath}"`, project.path);
    logSession(projectId, { action: 'apply_patch', success: result.code === 0 });
    return json(res, result.code === 0 ? 200 : 400, {
      success: result.code === 0,
      stdout: result.stdout,
      stderr: result.stderr,
    });
  }

  // POST /api/projects/:id/apply-opencode — use opencode web API to implement the patch
  if (method === 'POST' && action === 'apply-opencode') {
    const body = await parseBody(req);
    const patchDir = project.patchDir || DIR;
    fs.mkdirSync(patchDir, { recursive: true });
    const patchPath = path.join(patchDir, `${project.id}_patch.txt`);
    if (body.content) {
      fs.writeFileSync(patchPath, body.content);
    }
    if (!fs.existsSync(patchPath)) return json(res, 400, { error: 'No patch content' });

    const patchContent = fs.readFileSync(patchPath, 'utf8');
    const result = await opencodeApplyPatch(project.path, projectId, patchContent);
    logSession(projectId, { action: 'apply_opencode', ...result });
    return json(res, result.success ? 200 : 500, result);
  }

  // GET /api/projects/:id/opencode-session — check opencode session progress
  if (method === 'GET' && action === 'opencode-session') {
    const sid = project.opencodeSessionId;
    if (!sid) return json(res, 200, { active: false });
    try {
      const [todoRes, msgRes, statusRes] = await Promise.all([
        opencodeApi('GET', opencodeEndpoint(`/session/${sid}/todo`, project.path)),
        opencodeApi('GET', opencodeEndpoint(`/session/${sid}/message?limit=12`, project.path)),
        opencodeApi('GET', opencodeEndpoint('/session/status', project.path)),
      ]);
      const todos = (todoRes.status === 200 && todoRes.data) ? todoRes.data : [];
      const messages = (msgRes.status === 200 && msgRes.data) ? msgRes.data.map(m => ({
        role: m.info ? m.info.role : 'unknown',
        parts: m.parts || m.info?.parts || [],
        time: m.info ? m.info.time : null,
      })) : [];
      const sessionStatus = statusRes.status === 200 && statusRes.data ? statusRes.data[sid] : null;
      const active = sessionStatus ? sessionStatus.type !== 'idle' : true;
      if (!active) {
        const data = loadProjects();
        const savedProject = data.projects.find(p => p.id === projectId);
        if (savedProject && savedProject.opencodeSessionId === sid) {
          delete savedProject.opencodeSessionId;
          delete savedProject.opencodeSessionStartedAt;
          delete savedProject.opencodeJobType;
          saveProjects(data);
        }
      }
      return json(res, 200, {
        active,
        sessionId: sid,
        jobType: project.opencodeJobType || 'patch',
        status: sessionStatus || { type: 'running' },
        startedAt: project.opencodeSessionStartedAt || null,
        todos,
        messages,
      });
    } catch (e) {
      return json(res, 200, { active: true, sessionId: sid, error: e.message });
    }
  }

  // GET /api/projects/:id/status
  if (method === 'GET' && action === 'status') {
    if (!fs.existsSync(path.join(project.path, '.git'))) return json(res, 400, { error: 'Not a git repository' });
    const [porcelainBranch, diffNumstat, diffCachedNumstat, diffShortstat, logResult] = await Promise.all([
      run('git status --porcelain -b', project.path),
      run('git diff --numstat', project.path),
      run('git diff --cached --numstat', project.path),
      run('git diff --shortstat', project.path),
      run('git log --oneline -15', project.path),
    ]);

    let branch = '';
    let ahead = 0;
    let behind = 0;
    const staged = [];
    const unstaged = [];
    const untracked = [];

    const porcelainLines = porcelainBranch.stdout.split('\n').filter(l => l.trim());
    for (const line of porcelainLines) {
      if (line.startsWith('##')) {
        const m = line.match(/## (.+?)(?:\.\.\.|$)/);
        if (m) branch = m[1].trim();
        const aheadM = line.match(/ahead (\d+)/);
        if (aheadM) ahead = parseInt(aheadM[1]);
        const behindM = line.match(/behind (\d+)/);
        if (behindM) behind = parseInt(behindM[1]);
        continue;
      }
      if (line.length < 3) continue;
      const index = line[0];
      const worktree = line[1];
      const file = line.slice(3).trim();

      if (index === '?' && worktree === '?') {
        untracked.push({ file });
      } else {
        if (index !== ' ') staged.push({ status: index, file, additions: 0, deletions: 0 });
        if (worktree !== ' ') unstaged.push({ status: worktree, file, additions: 0, deletions: 0 });
      }
    }

    function parseNumstat(output) {
      const map = {};
      const lines = output.split('\n').filter(l => l.trim());
      for (const ln of lines) {
        const parts = ln.split('\t');
        if (parts.length >= 3) {
          const a = parts[0] === '-' ? 0 : parseInt(parts[0]) || 0;
          const d = parts[1] === '-' ? 0 : parseInt(parts[1]) || 0;
          map[parts[2]] = { additions: a, deletions: d };
        }
      }
      return map;
    }

    const unstagedNumstatMap = parseNumstat(diffNumstat.stdout);
    const stagedNumstatMap = parseNumstat(diffCachedNumstat.stdout);

    for (const entry of unstaged) {
      const ns = unstagedNumstatMap[entry.file];
      if (ns) { entry.additions = ns.additions; entry.deletions = ns.deletions; }
    }
    for (const entry of staged) {
      const ns = stagedNumstatMap[entry.file];
      if (ns) { entry.additions = ns.additions; entry.deletions = ns.deletions; }
    }

    const dirty = staged.length > 0 || unstaged.length > 0 || untracked.length > 0;

    return json(res, 200, {
      branch,
      ahead,
      behind,
      dirty,
      staged,
      unstaged,
      untracked,
      log: logResult.stdout,
      shortstat: diffShortstat.stdout,
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

  // POST /api/projects/:id/ai-commit-message
  if (method === 'POST' && action === 'ai-commit-message') {
    if (!DEEPSEEK_API_KEY) return json(res, 400, { error: 'DEEPSEEK_API_KEY not configured on server' });
    const diff = await run('git diff', project.path);
    const diffCached = await run('git diff --cached', project.path);
    const combinedDiff = (diff.stdout + diffCached.stdout).trim();
    if (!combinedDiff) {
      const status = await run('git status --porcelain', project.path);
      if (status.stdout.trim()) return json(res, 200, { message: 'update' });
      return json(res, 400, { error: 'No changes to commit' });
    }
    try {
      const message = await generateCommitMessage(combinedDiff);
      return json(res, 200, { message });
    } catch (e) {
      return json(res, 500, { error: e.message });
    }
  }

  // POST /api/projects/:id/push
  if (method === 'POST' && action === 'push') {
    const result = await run('git push', project.path);
    logSession(projectId, { action: 'push', success: result.code === 0 });
    return json(res, result.code === 0 ? 200 : 400, {
      success: result.code === 0,
      stdout: result.stdout,
      stderr: result.stderr,
    });
  }

  // POST /api/projects/:id/pull
  if (method === 'POST' && action === 'pull') {
    const result = await run('git pull --rebase', project.path);
    logSession(projectId, { action: 'pull', success: result.code === 0 });
    return json(res, result.code === 0 ? 200 : 400, {
      success: result.code === 0,
      stdout: result.stdout,
      stderr: result.stderr,
    });
  }

  // POST /api/projects/:id/stage
  if (method === 'POST' && action === 'stage') {
    const body = await parseBody(req);
    const file = (body.file || '').replace(/"/g, '\\"');
    if (!file) return json(res, 400, { error: 'File path required' });
    const result = await run(`git add "${file}"`, project.path);
    return json(res, result.code === 0 ? 200 : 400, {
      success: result.code === 0,
      stdout: result.stdout,
      stderr: result.stderr,
    });
  }

  // POST /api/projects/:id/unstage
  if (method === 'POST' && action === 'unstage') {
    const body = await parseBody(req);
    const file = (body.file || '').replace(/"/g, '\\"');
    if (!file) return json(res, 400, { error: 'File path required' });
    const result = await run(`git reset HEAD "${file}"`, project.path);
    return json(res, result.code === 0 ? 200 : 400, {
      success: result.code === 0,
      stdout: result.stdout,
      stderr: result.stderr,
    });
  }

  // POST /api/projects/:id/discard
  if (method === 'POST' && action === 'discard') {
    const body = await parseBody(req);
    const file = (body.file || '').replace(/"/g, '\\"');
    if (!file) return json(res, 400, { error: 'File path required' });
    const result = await run(`git checkout -- "${file}"`, project.path);
    return json(res, result.code === 0 ? 200 : 400, {
      success: result.code === 0,
      stdout: result.stdout,
      stderr: result.stderr,
    });
  }

  // POST /api/projects/:id/fetch
  if (method === 'POST' && action === 'fetch') {
    const result = await run('git fetch', project.path);
    logSession(projectId, { action: 'fetch', success: result.code === 0 });
    return json(res, result.code === 0 ? 200 : 400, {
      success: result.code === 0,
      stdout: result.stdout,
      stderr: result.stderr,
    });
  }

  // GET /api/projects/:id/diff
  if (method === 'GET' && action === 'diff') {
    const url = new URL(req.url, 'http://localhost');
    const file = url.searchParams.get('file') || '';
    const staged = url.searchParams.get('staged') === 'true';
    if (!file) return json(res, 400, { error: 'File parameter required' });
    const safeFile = file.replace(/"/g, '\\"');
    const cmd = staged ? `git diff --cached -- "${safeFile}"` : `git diff -- "${safeFile}"`;
    const result = await run(cmd, project.path);
    return json(res, 200, { diff: result.stdout, stderr: result.stderr });
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

async function handleActivity(method, url, req, res) {
  if (method !== 'GET') return json(res, 405, { error: 'Method not allowed' });

  const data = loadProjects();
  const projectMap = {};
  for (const p of data.projects) {
    projectMap[p.id] = { id: p.id, name: p.name };
  }

  const entries = [];
  try {
    const files = fs.readdirSync(SESSIONS_DIR).filter(f => f.endsWith('.json'));
    for (const f of files) {
      const projectId = f.replace(/\.json$/, '');
      const proj = projectMap[projectId] || { id: projectId, name: projectId };
      try {
        const log = JSON.parse(fs.readFileSync(path.join(SESSIONS_DIR, f), 'utf8'));
        for (const entry of log) {
          if (entry.action === 'update_combine_script') continue;
          entries.push({ projectId: proj.id, projectName: proj.name, ...entry });
        }
      } catch {}
    }
  } catch {}

  entries.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  return json(res, 200, { entries: entries.slice(0, 60) });
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
