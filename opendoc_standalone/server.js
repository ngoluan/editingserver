const express = require('express');
const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');
const crypto = require('crypto');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3004;

// Path Constants
const DATA_DIR = path.join(__dirname, 'data');
const DOCS_DIR = path.join(DATA_DIR, 'docs');
const REVISIONS_DIR = path.join(DATA_DIR, 'revisions');
const INDEX_FILE = path.join(DATA_DIR, 'index.json');
const ASSETS_INDEX_FILE = path.join(DATA_DIR, 'assets.json');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit.jsonl');
const TRASH_DIR = path.join(DATA_DIR, 'trash');
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOADS_DIR = path.join(PUBLIC_DIR, 'uploads');
const MAX_REVISIONS_PER_DOC = 100;

let pdfBrowserPromise = null;
async function getPdfBrowser() {
    if (!pdfBrowserPromise) {
        pdfBrowserPromise = puppeteer.launch({ headless: 'new' }).catch(error => {
            pdfBrowserPromise = null;
            throw error;
        });
    }
    const browser = await pdfBrowserPromise;
    if (!browser.connected) {
        pdfBrowserPromise = null;
        return getPdfBrowser();
    }
    return browser;
}

async function closePdfBrowser() {
    if (!pdfBrowserPromise) return;
    const promise = pdfBrowserPromise;
    pdfBrowserPromise = null;
    const browser = await promise.catch(() => null);
    if (browser) await browser.close().catch(() => undefined);
}
process.once('SIGINT', () => closePdfBrowser().finally(() => process.exit(0)));
process.once('SIGTERM', () => closePdfBrowser().finally(() => process.exit(0)));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const DIST_DIR = path.join(PUBLIC_DIR, 'dist');
if (fs.existsSync(DIST_DIR)) app.use(express.static(DIST_DIR));
app.use(express.static(PUBLIC_DIR));
app.use('/uploads', express.static(UPLOADS_DIR));

function writeJsonSafe(filePath, data) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(tempPath, JSON.stringify(data, null, 2));
    fs.renameSync(tempPath, filePath);
}

function readJsonSafe(filePath, fallback) {
    try {
        if (!fs.existsSync(filePath)) return fallback;
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (error) {
        console.error(`Unable to read ${filePath}:`, error.message);
        return fallback;
    }
}

function initDataDir() {
    [DATA_DIR, DOCS_DIR, REVISIONS_DIR, UPLOADS_DIR, TRASH_DIR].forEach(dir => fs.mkdirSync(dir, { recursive: true }));
    if (!fs.existsSync(INDEX_FILE)) writeJsonSafe(INDEX_FILE, { version: 2, docs: [] });
    if (!fs.existsSync(ASSETS_INDEX_FILE)) writeJsonSafe(ASSETS_INDEX_FILE, { version: 1, assets: [] });
    if (!fs.existsSync(AUTH_FILE)) writeJsonSafe(AUTH_FILE, { version: 1, users: [], sessions: [], shareLinks: [] });
}
initDataDir();

function loadAuthStore() {
    const store = readJsonSafe(AUTH_FILE, { version: 1, users: [], sessions: [], shareLinks: [] });
    store.users ||= []; store.sessions ||= []; store.shareLinks ||= [];
    return store;
}

function saveAuthStore(store) { writeJsonSafe(AUTH_FILE, { ...store, version: 1 }); }
function authId(prefix) { return `${prefix}_${crypto.randomBytes(12).toString('hex')}`; }
function normalizeEmail(value) { return String(value || '').trim().toLowerCase(); }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    return { salt, hash: crypto.scryptSync(String(password), salt, 64).toString('hex') };
}
function verifyPassword(password, user) {
    try {
        const actual = crypto.scryptSync(String(password), user.passwordSalt, 64);
        const expected = Buffer.from(user.passwordHash, 'hex');
        return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
    } catch (_) { return false; }
}
function parseCookies(request) {
    return Object.fromEntries(String(request.headers.cookie || '').split(';').map(part => part.trim()).filter(Boolean).map(part => {
        const index = part.indexOf('=');
        return [decodeURIComponent(index >= 0 ? part.slice(0, index) : part), decodeURIComponent(index >= 0 ? part.slice(index + 1) : '')];
    }));
}
function getSessionUser(request) {
    const store = loadAuthStore();
    const token = parseCookies(request).openword_session || String(request.get('x-openword-session-token') || '');
    const now = Date.now();
    const activeSessions = store.sessions.filter(session => Date.parse(session.expiresAt || 0) > now);
    if (activeSessions.length !== store.sessions.length) {
        store.sessions = activeSessions;
        saveAuthStore(store);
    }
    const session = store.sessions.find(item => item.token === token);
    if (session) {
        const user = store.users.find(item => item.id === session.userId);
        if (user) return { user, store, session };
    }
    return { user: { id: 'local', email: '', name: 'Local User', local: true }, store, session: null };
}
function publicUser(user) { return user ? { id: user.id, email: user.email, name: user.name, createdAt: user.createdAt, local: !!user.local } : null; }
function roleRank(role) { return ({ viewer: 1, commenter: 2, editor: 3, owner: 4 })[role] || 0; }
function documentRole(document, user, shareToken = null) {
    const ownerId = document.ownerId || 'local';
    if (user?.id === ownerId) return 'owner';
    const member = (document.members || []).find(entry => entry.userId === user?.id || (entry.email && normalizeEmail(entry.email) === normalizeEmail(user?.email)));
    if (member) return member.role || 'viewer';
    if (shareToken) {
        const store = loadAuthStore();
        const link = store.shareLinks.find(entry => entry.token === shareToken && entry.documentId === document.id && !entry.revokedAt && (!entry.expiresAt || Date.parse(entry.expiresAt) > Date.now()));
        if (link) return link.role || 'viewer';
    }
    return null;
}
function requestShareToken(request) {
    return String(request.query.share || request.get('x-openword-share-token') || parseCookies(request).openword_share || '').slice(0, 256) || null;
}

const rateBuckets = new Map();
function rateLimitKey(req, scope) { return `${scope}:${req.ip || req.socket?.remoteAddress || 'unknown'}`; }
function rateLimit(scope, maxHits, windowMs) {
    return (req, res, next) => {
        const key = rateLimitKey(req, scope);
        const now = Date.now();
        const bucket = rateBuckets.get(key) || { count: 0, resetAt: now + windowMs };
        if (bucket.resetAt < now) { bucket.count = 0; bucket.resetAt = now + windowMs; }
        bucket.count += 1;
        rateBuckets.set(key, bucket);
        res.setHeader('X-RateLimit-Limit', String(maxHits));
        res.setHeader('X-RateLimit-Remaining', String(Math.max(0, maxHits - bucket.count)));
        if (bucket.count > maxHits) return res.status(429).json({ error: 'rate_limited', retryAfterMs: bucket.resetAt - now });
        next();
    };
}

function auditEvent(req, outcome = {}) {
    try {
        const entry = {
            at: new Date().toISOString(),
            method: req.method,
            path: req.originalUrl,
            userId: req.authUser?.id || getSessionUser(req).user?.id || 'anonymous',
            ip: req.ip || req.socket?.remoteAddress || '',
            status: outcome.statusCode || 0,
            role: req.documentRole || null
        };
        fs.appendFileSync(AUDIT_FILE, JSON.stringify(entry) + '\n');
    } catch (_) { /* audit must never break the request */ }
}

function securityHeaders(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    const cookies = parseCookies(req);
    if (!cookies.openword_csrf) {
        const token = authId('csrf');
        appendSetCookie(res, `openword_csrf=${encodeURIComponent(token)}; Path=/; SameSite=Lax; Max-Age=${30 * 86400}`);
    }
    next();
}

function requireSameOriginAndCsrf(req, res, next) {
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
    const origin = req.get('origin');
    if (origin) {
        try {
            if (new URL(origin).host !== req.get('host')) return res.status(403).json({ error: 'bad_origin' });
        } catch (_) { return res.status(403).json({ error: 'bad_origin' }); }
    }
    if (/^\/api\/auth\/(login|register|logout)$/.test(req.path)) return next();
    const cookies = parseCookies(req);
    const cookieToken = cookies.openword_csrf;
    const headerToken = String(req.get('x-openword-csrf') || '');
    if (cookieToken && headerToken && cookieToken === headerToken) return next();
    if (!cookies.openword_session && !cookieToken) return next();
    return res.status(403).json({ error: 'csrf_required' });
}

app.use(securityHeaders);
app.use('/api/auth', rateLimit('auth', 80, 15 * 60 * 1000));
app.use('/api/upload', rateLimit('upload', 60, 15 * 60 * 1000));
app.use('/api', requireSameOriginAndCsrf);
app.use('/api', (req, res, next) => { res.on('finish', () => { if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) auditEvent(req, { statusCode: res.statusCode }); }); next(); });
function requireDocumentRole(requiredRole) {
    return (req, res, next) => {
        const document = DocumentStore.loadDoc(req.params.id);
        if (!document) return res.status(404).json({ error: 'Document not found' });
        const auth = getSessionUser(req);
        const role = documentRole(document, auth.user, requestShareToken(req));
        if (roleRank(role) < roleRank(requiredRole)) return res.status(403).json({ error: 'forbidden', requiredRole, role });
        req.authUser = auth.user; req.document = document; req.documentRole = role;
        next();
    };
}
function appendSetCookie(res, cookie) {
    const existing = res.getHeader('Set-Cookie');
    if (!existing) res.setHeader('Set-Cookie', cookie);
    else if (Array.isArray(existing)) res.setHeader('Set-Cookie', [...existing, cookie]);
    else res.setHeader('Set-Cookie', [existing, cookie]);
}

function setSessionCookie(res, token, maxAgeSeconds) {
    appendSetCookie(res, `openword_session=${encodeURIComponent(token || '')}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.max(0, maxAgeSeconds || 0)}`);
}

function safeDocId(value) {
    const id = String(value || '');
    return /^[A-Za-z0-9_-]{3,128}$/.test(id) ? id : null;
}

function parseExpectedRevision(req, body) {
    if (Number.isFinite(Number(body?.baseRevision))) return Number(body.baseRevision);
    const ifMatch = String(req.get('if-match') || '');
    const match = ifMatch.match(/:(\d+)"?$/);
    return match ? Number(match[1]) : null;
}


const collaborationRooms = new Map();
const PRESENCE_TTL_MS = 45_000;

function getCollaborationRoom(documentId) {
    const id = safeDocId(documentId);
    if (!id) return null;
    if (!collaborationRooms.has(id)) collaborationRooms.set(id, { presence: new Map(), listeners: new Set(), transactionLog: [], sequence: 0 });
    return collaborationRooms.get(id);
}

function prunePresence(room) {
    const cutoff = Date.now() - PRESENCE_TTL_MS;
    for (const [sessionId, entry] of room.presence) if (entry.lastSeen < cutoff) room.presence.delete(sessionId);
}

function publicPresence(room) {
    prunePresence(room);
    return [...room.presence.values()].map(({ lastSeen, ...entry }) => entry);
}

function sendSse(response, event, payload) {
    response.write(`event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`);
}

function broadcastCollaboration(documentId, event, payload) {
    const room = getCollaborationRoom(documentId);
    if (!room) return;
    for (const response of room.listeners) {
        try { sendSse(response, event, payload); } catch (_) { room.listeners.delete(response); }
    }
}

function broadcastPresence(documentId) {
    const room = getCollaborationRoom(documentId);
    if (!room) return;
    broadcastCollaboration(documentId, 'presence', publicPresence(room));
}

function findServerBlockIndex(document, operation) {
    if (operation.blockId) return (document.blocks || []).findIndex(block => block.id === operation.blockId);
    return Number.isInteger(operation.index) ? operation.index : -1;
}

function applyServerOperation(document, operation) {
    document.blocks ||= [];
    if (!operation || typeof operation !== 'object') return false;
    if (operation.type === 'ADD_BLOCK') {
        let index = Number.isInteger(operation.index) ? operation.index : document.blocks.length;
        if (operation.previousBlockId) {
            const previous = document.blocks.findIndex(block => block.id === operation.previousBlockId);
            if (previous >= 0) index = previous + 1;
        } else if (operation.nextBlockId) {
            const next = document.blocks.findIndex(block => block.id === operation.nextBlockId);
            if (next >= 0) index = next;
        }
        document.blocks.splice(Math.max(0, Math.min(document.blocks.length, index)), 0, JSON.parse(JSON.stringify(operation.block)));
        return true;
    }
    const index = findServerBlockIndex(document, operation);
    if (index < 0 || index >= document.blocks.length) return false;
    if (operation.type === 'UPDATE_BLOCK') document.blocks[index].content = operation.content;
    else if (operation.type === 'REMOVE_BLOCK') document.blocks.splice(index, 1);
    else if (operation.type === 'REPLACE_BLOCK_STATE') document.blocks[index] = JSON.parse(JSON.stringify(operation.block));
    else if (operation.type === 'SPLIT_BLOCK') {
        document.blocks[index] = JSON.parse(JSON.stringify(operation.block));
        document.blocks.splice(index + 1, 0, JSON.parse(JSON.stringify(operation.newBlock)));
    } else if (operation.type === 'UNSPLIT_BLOCK') {
        document.blocks[index] = JSON.parse(JSON.stringify(operation.prevBlock));
        document.blocks.splice(index + 1, 1);
    } else if (operation.type === 'MOVE_BLOCK') {
        const [block] = document.blocks.splice(index, 1);
        const target = Math.max(0, Math.min(document.blocks.length, Number(operation.toIndex) || 0));
        document.blocks.splice(target, 0, block);
    } else if (operation.type === 'MERGE_BLOCKS') {
        if (index <= 0) return false;
        const current = document.blocks[index];
        document.blocks[index - 1].content = `${document.blocks[index - 1].content || ''}${current.content || ''}`;
        document.blocks.splice(index, 1);
    } else return false;
    return true;
}

function applyServerTransaction(document, transaction) {
    const next = JSON.parse(JSON.stringify(document));
    for (const operation of transaction?.operations || []) {
        if (!applyServerOperation(next, operation)) return { error: `unsupported_or_stale_operation:${operation?.type || 'unknown'}` };
    }
    return { document: next };
}

function rememberTransaction(room, entry) {
    room.sequence += 1;
    room.transactionLog.push({ sequence: room.sequence, ...entry });
    if (room.transactionLog.length > 250) room.transactionLog.splice(0, room.transactionLog.length - 250);
    return room.sequence;
}

function setDocumentEtag(res, doc) {
    if (doc?.id && Number.isFinite(Number(doc.revision))) {
        res.set('ETag', `W/"${doc.id}:${doc.revision}"`);
    }
}

const DocumentStore = {
    generateId: () => `doc_${crypto.randomBytes(6).toString('hex')}${Date.now().toString(36)}`,
    generateNodeId: (prefix = 'blk') => `${prefix}_${crypto.randomBytes(10).toString('hex')}`,
    docPath: (docId) => path.join(DOCS_DIR, `${docId}.json`),
    revisionDir: (docId) => path.join(REVISIONS_DIR, docId),
    revisionPath: (docId, revision) => path.join(REVISIONS_DIR, docId, `${String(revision).padStart(8, '0')}.json`),

    loadIndex: () => readJsonSafe(INDEX_FILE, { version: 2, docs: [] }),
    saveIndex: (index) => writeJsonSafe(INDEX_FILE, { ...index, version: 2 }),

    loadDoc(docId) {
        const id = safeDocId(docId);
        if (!id) return null;
        const doc = readJsonSafe(this.docPath(id), null);
        if (doc && !Number.isFinite(Number(doc.revision))) doc.revision = 0;
        return doc;
    },

    saveSnapshot(doc, reason = 'save') {
        if (!doc?.id || !Number.isFinite(Number(doc.revision))) return;
        const snapshot = JSON.parse(JSON.stringify(doc));
        snapshot.snapshotMeta = {
            reason,
            createdAt: new Date().toISOString()
        };
        writeJsonSafe(this.revisionPath(doc.id, doc.revision), snapshot);
        this.pruneSnapshots(doc.id);
    },

    pruneSnapshots(docId) {
        const dir = this.revisionDir(docId);
        if (!fs.existsSync(dir)) return;
        const files = fs.readdirSync(dir).filter(name => /^\d+\.json$/.test(name)).sort();
        const excess = files.length - MAX_REVISIONS_PER_DOC;
        if (excess > 0) files.slice(0, excess).forEach(name => fs.unlinkSync(path.join(dir, name)));
    },

    updateIndexEntry(doc) {
        const index = this.loadIndex();
        const entry = index.docs.find(item => item.id === doc.id);
        const summary = {
            id: doc.id,
            title: doc.title,
            createdAt: doc.createdAt,
            updatedAt: doc.updatedAt,
            revision: doc.revision
        };
        if (entry) Object.assign(entry, summary);
        else index.docs.unshift(summary);
        this.saveIndex(index);
    },

    createDoc(meta = {}) {
        const id = this.generateId();
        const now = new Date().toISOString();
        const doc = {
            version: 1,
            schemaVersion: 2,
            storageVersion: 2,
            revision: 1,
            id,
            title: typeof meta.title === 'string' && meta.title.trim() ? meta.title.trim() : 'Untitled Document',
            createdAt: now,
            updatedAt: now,
            settings: { pageSize: 'letter', margins: { top: 1, bottom: 1, left: 1, right: 1 }, trackChanges: false },
            header: { left: '', center: '', right: '' },
            footer: { left: '', center: 'Page {n}', right: '' },
            blocks: [{ id: this.generateNodeId('blk'), type: 'text', style: 'normal', content: '<br>' }],
            footnotes: [],
            endnotes: [],
            history: [],
            ownerId: meta.ownerId || 'local',
            members: []
        };
        writeJsonSafe(this.docPath(id), doc);
        this.saveSnapshot(doc, 'created');
        this.updateIndexEntry(doc);
        return doc;
    },

    saveDoc(docId, incoming, { expectedRevision = null, force = false, reason = 'save' } = {}) {
        const id = safeDocId(docId);
        if (!id || !incoming || typeof incoming !== 'object') return { error: 'invalid_document' };

        const current = this.loadDoc(id);
        if (!current) return { error: 'not_found' };
        const currentRevision = Number(current.revision) || 0;
        if (!force && Number.isFinite(expectedRevision) && expectedRevision !== currentRevision) {
            return {
                conflict: true,
                expectedRevision,
                current: {
                    id: current.id,
                    title: current.title,
                    revision: currentRevision,
                    updatedAt: current.updatedAt
                }
            };
        }

        const now = new Date().toISOString();
        const next = JSON.parse(JSON.stringify(incoming));
        delete next.baseRevision;
        delete next.snapshotMeta;
        delete next._role;
        delete next.permissions;
        next.id = id;
        next.createdAt = current.createdAt || next.createdAt || now;
        next.updatedAt = now;
        next.storageVersion = 2;
        next.revision = currentRevision + 1;
        if (!Array.isArray(next.blocks)) next.blocks = current.blocks || [];
        if (!next.settings) next.settings = current.settings || {};
        if (!next.header) next.header = current.header || { left: '', center: '', right: '' };
        if (!next.footer) next.footer = current.footer || { left: '', center: 'Page {n}', right: '' };
        if (!Array.isArray(next.footnotes)) next.footnotes = [];
        if (!Array.isArray(next.endnotes)) next.endnotes = [];
        if (!next.ownerId) next.ownerId = current.ownerId || 'local';
        if (!Array.isArray(next.members)) next.members = current.members || [];

        writeJsonSafe(this.docPath(id), next);
        this.saveSnapshot(next, reason);
        this.updateIndexEntry(next);
        return { document: next };
    },

    listRevisions(docId) {
        const id = safeDocId(docId);
        const dir = id ? this.revisionDir(id) : null;
        if (!dir || !fs.existsSync(dir)) return [];
        return fs.readdirSync(dir)
            .filter(name => /^\d+\.json$/.test(name))
            .sort().reverse()
            .map(name => readJsonSafe(path.join(dir, name), null))
            .filter(Boolean)
            .map(snapshot => ({
                revision: Number(snapshot.revision) || 0,
                title: snapshot.title,
                updatedAt: snapshot.updatedAt,
                createdAt: snapshot.snapshotMeta?.createdAt || snapshot.updatedAt,
                reason: snapshot.snapshotMeta?.reason || 'save'
            }));
    },

    loadRevision(docId, revision) {
        const id = safeDocId(docId);
        const rev = Number(revision);
        if (!id || !Number.isInteger(rev) || rev < 1) return null;
        return readJsonSafe(this.revisionPath(id, rev), null);
    },

    restoreRevision(docId, revision, expectedRevision) {
        const snapshot = this.loadRevision(docId, revision);
        if (!snapshot) return { error: 'revision_not_found' };
        const restored = JSON.parse(JSON.stringify(snapshot));
        delete restored.snapshotMeta;
        return this.saveDoc(docId, restored, {
            expectedRevision,
            reason: `restored revision ${revision}`
        });
    },

    deleteDoc(docId) {
        const id = safeDocId(docId);
        if (!id) return false;
        const docPath = this.docPath(id);
        const now = new Date().toISOString();
        if (fs.existsSync(docPath)) {
            const document = readJsonSafe(docPath, null);
            if (document) {
                document.deletedAt = now;
                writeJsonSafe(path.join(TRASH_DIR, `${id}.json`), document);
            }
            fs.unlinkSync(docPath);
        }
        const index = this.loadIndex();
        index.docs = index.docs.filter(doc => doc.id !== id);
        this.saveIndex(index);
        return true;
    },

    listTrash() {
        if (!fs.existsSync(TRASH_DIR)) return [];
        return fs.readdirSync(TRASH_DIR).filter(name => name.endsWith('.json')).map(name => readJsonSafe(path.join(TRASH_DIR, name), null)).filter(Boolean).map(doc => ({ id: doc.id, title: doc.title, deletedAt: doc.deletedAt, updatedAt: doc.updatedAt }));
    },

    restoreDeletedDoc(docId) {
        const id = safeDocId(docId);
        if (!id) return null;
        const trashPath = path.join(TRASH_DIR, `${id}.json`);
        const document = readJsonSafe(trashPath, null);
        if (!document) return null;
        delete document.deletedAt;
        document.updatedAt = new Date().toISOString();
        writeJsonSafe(this.docPath(id), document);
        fs.unlinkSync(trashPath);
        this.updateIndexEntry(document);
        return document;
    },

    renameDoc(docId, title) {
        const current = this.loadDoc(docId);
        if (!current) return { error: 'not_found' };
        return this.saveDoc(docId, { ...current, title: String(title || '').trim() || 'Untitled' }, {
            expectedRevision: Number(current.revision) || 0,
            reason: 'renamed'
        });
    },

    duplicateDoc(docId, ownerId = null) {
        const source = this.loadDoc(docId);
        if (!source) return null;
        const created = this.createDoc({ title: `Copy of ${source.title || 'Untitled'}`, ownerId: ownerId || source.ownerId || 'local' });
        const copy = JSON.parse(JSON.stringify(source));
        copy.id = created.id;
        copy.title = created.title;
        copy.createdAt = created.createdAt;
        copy.revision = created.revision;
        copy.ownerId = ownerId || created.ownerId || source.ownerId || 'local';
        copy.members = [];
        const saved = this.saveDoc(created.id, copy, {
            expectedRevision: created.revision,
            reason: `duplicated from ${source.id}`
        });
        return saved.document;
    }
};

const allowedImageTypes = new Map([
    ['image/png', '.png'],
    ['image/jpeg', '.jpg'],
    ['image/gif', '.gif'],
    ['image/webp', '.webp']
]);

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
        const extension = allowedImageTypes.get(file.mimetype) || path.extname(file.originalname).toLowerCase();
        cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${extension}`);
    }
});
const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (!allowedImageTypes.has(file.mimetype)) return cb(new Error('Unsupported image type'));
        cb(null, true);
    }
});

function recordAsset(file) {
    const index = readJsonSafe(ASSETS_INDEX_FILE, { version: 1, assets: [] });
    const asset = {
        id: `asset_${crypto.randomBytes(6).toString('hex')}`,
        filename: file.filename,
        originalName: file.originalname,
        mimeType: file.mimetype,
        size: file.size,
        createdAt: new Date().toISOString(),
        url: `/uploads/${file.filename}`
    };
    index.assets.unshift(asset);
    writeJsonSafe(ASSETS_INDEX_FILE, index);
    return asset;
}

app.post('/api/upload/image', (req, res) => {
    upload.single('image')(req, res, error => {
        if (error) return res.status(400).json({ error: error.message });
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        const asset = recordAsset(req.file);
        res.json({ url: asset.url, asset });
    });
});

app.get('/api/auth/me', (req, res) => {
    const auth = getSessionUser(req);
    res.set('Cache-Control', 'no-store');
    res.json({ user: publicUser(auth.user), authenticated: !auth.user.local });
});

app.post('/api/auth/register', (req, res) => {
    const email = normalizeEmail(req.body?.email), password = String(req.body?.password || ''), name = String(req.body?.name || '').trim();
    if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 8) return res.status(400).json({ error: 'Use a valid email and a password of at least 8 characters.' });
    const store = loadAuthStore();
    if (store.users.some(user => user.email === email)) return res.status(409).json({ error: 'Email already registered' });
    const passwordData = hashPassword(password);
    const user = { id: authId('usr'), email, name: name || email.split('@')[0], passwordSalt: passwordData.salt, passwordHash: passwordData.hash, createdAt: new Date().toISOString() };
    store.users.push(user);
    if (store.users.length === 1) {
        const index = DocumentStore.loadIndex();
        for (const summary of index.docs || []) {
            const document = DocumentStore.loadDoc(summary.id);
            if (document && (!document.ownerId || document.ownerId === 'local')) {
                document.ownerId = user.id;
                document.members ||= [];
                DocumentStore.saveDoc(document.id, document, { expectedRevision: document.revision, reason: 'claimed by first account' });
            }
        }
    }
    const token = authId('ses');
    store.sessions.push({ token, userId: user.id, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 30 * 86400000).toISOString() });
    saveAuthStore(store); setSessionCookie(res, token, 30 * 86400);
    res.status(201).json({ user: publicUser(user) });
});

app.post('/api/auth/login', (req, res) => {
    const email = normalizeEmail(req.body?.email), password = String(req.body?.password || '');
    const store = loadAuthStore(); const user = store.users.find(item => item.email === email);
    if (!user || !verifyPassword(password, user)) return res.status(401).json({ error: 'Invalid email or password' });
    const token = authId('ses');
    store.sessions.push({ token, userId: user.id, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 30 * 86400000).toISOString() });
    saveAuthStore(store); setSessionCookie(res, token, 30 * 86400);
    res.json({ user: publicUser(user) });
});

app.post('/api/auth/logout', (req, res) => {
    const token = parseCookies(req).openword_session;
    const store = loadAuthStore(); store.sessions = store.sessions.filter(session => session.token !== token); saveAuthStore(store);
    setSessionCookie(res, '', 0); res.status(204).end();
});

app.get('/s/:token', (req, res) => {
    const store = loadAuthStore();
    const link = store.shareLinks.find(item => item.token === req.params.token && !item.revokedAt && (!item.expiresAt || Date.parse(item.expiresAt) > Date.now()));
    if (!link) return res.status(404).send('Share link not found or expired');
    res.setHeader('Set-Cookie', `openword_share=${encodeURIComponent(link.token)}; Path=/; SameSite=Lax; Max-Age=${7 * 86400}`);
    res.redirect(`/?doc=${encodeURIComponent(link.documentId)}&share=${encodeURIComponent(link.token)}`);
});

app.get('/api/trash', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ docs: DocumentStore.listTrash() });
});

app.post('/api/trash/:id/restore', (req, res) => {
    const restored = DocumentStore.restoreDeletedDoc(req.params.id);
    if (!restored) return res.status(404).json({ error: 'Document not found in trash' });
    setDocumentEtag(res, restored);
    res.json(restored);
});

app.get('/api/audit', rateLimit('audit', 60, 15 * 60 * 1000), (req, res) => {
    const lines = fs.existsSync(AUDIT_FILE) ? fs.readFileSync(AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean).slice(-250).map(line => { try { return JSON.parse(line); } catch (_) { return null; } }).filter(Boolean) : [];
    res.set('Cache-Control', 'no-store');
    res.json({ events: lines });
});

app.get('/api/docs', (req, res) => {
    const auth = getSessionUser(req);
    const index = DocumentStore.loadIndex();
    const docs = index.docs.map(summary => {
        const document = DocumentStore.loadDoc(summary.id);
        const role = document ? documentRole(document, auth.user, requestShareToken(req)) : null;
        return role ? { ...summary, role } : null;
    }).filter(Boolean);
    docs.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
    res.set('Cache-Control', 'no-store');
    res.json(docs);
});

app.post('/api/docs', (req, res) => {
    const auth = getSessionUser(req);
    const doc = DocumentStore.createDoc({ ...(req.body || {}), ownerId: auth.user.id });
    setDocumentEtag(res, doc);
    res.status(201).json(doc);
});

app.get('/api/docs/:id/access', requireDocumentRole('viewer'), (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({
        role: req.documentRole,
        permissions: {
            view: true,
            comment: roleRank(req.documentRole) >= roleRank('commenter'),
            edit: roleRank(req.documentRole) >= roleRank('editor'),
            share: req.documentRole === 'owner'
        }
    });
});

app.get('/api/docs/:id/revisions', requireDocumentRole('viewer'), (req, res) => {
    const doc = DocumentStore.loadDoc(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Document not found' });
    res.set('Cache-Control', 'no-store');
    res.json({ documentId: doc.id, currentRevision: doc.revision, revisions: DocumentStore.listRevisions(doc.id) });
});

app.get('/api/docs/:id/revisions/:revision', requireDocumentRole('viewer'), (req, res) => {
    const snapshot = DocumentStore.loadRevision(req.params.id, req.params.revision);
    if (!snapshot) return res.status(404).json({ error: 'Revision not found' });
    res.set('Cache-Control', 'no-store');
    res.json(snapshot);
});

app.post('/api/docs/:id/revisions/:revision/restore', requireDocumentRole('editor'), (req, res) => {
    const result = DocumentStore.restoreRevision(
        req.params.id,
        req.params.revision,
        Number.isFinite(Number(req.body?.baseRevision)) ? Number(req.body.baseRevision) : null
    );
    if (result.conflict) return res.status(409).json({ error: 'revision_conflict', ...result });
    if (result.error === 'revision_not_found') return res.status(404).json({ error: 'Revision not found' });
    if (result.error) return res.status(400).json({ error: result.error });
    setDocumentEtag(res, result.document);
    res.json(result);
});

app.get('/api/docs/:id/transactions', requireDocumentRole('viewer'), (req, res) => {
    const doc = DocumentStore.loadDoc(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Document not found' });
    const room = getCollaborationRoom(doc.id);
    const afterRevision = Number(req.query.afterRevision || 0);
    res.set('Cache-Control', 'no-store');
    res.json({ revision: doc.revision, transactions: room.transactionLog.filter(entry => Number(entry.revision) > afterRevision) });
});

app.post('/api/docs/:id/transactions', requireDocumentRole('editor'), (req, res) => {
    const current = DocumentStore.loadDoc(req.params.id);
    if (!current) return res.status(404).json({ error: 'Document not found' });
    const body = req.body || {};
    const baseRevision = Number(body.baseRevision);
    if (!Number.isFinite(baseRevision) || baseRevision !== Number(current.revision || 0)) {
        return res.status(409).json({ error: 'revision_conflict', currentRevision: Number(current.revision || 0), current });
    }
    const transaction = body.transaction;
    if (!transaction || !Array.isArray(transaction.operations) || transaction.operations.length > 500) return res.status(400).json({ error: 'Invalid transaction' });
    const applied = applyServerTransaction(current, transaction);
    if (applied.error) return res.status(409).json({ error: applied.error, currentRevision: Number(current.revision || 0), current });
    const saved = DocumentStore.saveDoc(current.id, applied.document, { expectedRevision: baseRevision, reason: `collaborative transaction ${transaction.id || ''}` });
    if (saved.conflict) return res.status(409).json({ error: 'revision_conflict', ...saved });
    if (saved.error) return res.status(400).json({ error: saved.error });
    const room = getCollaborationRoom(current.id);
    const payload = {
        documentId: current.id,
        revision: saved.document.revision,
        updatedAt: saved.document.updatedAt,
        sessionId: String(body.sessionId || '').slice(0, 160),
        transaction
    };
    payload.sequence = rememberTransaction(room, payload);
    broadcastCollaboration(current.id, 'transaction', payload);
    setDocumentEtag(res, saved.document);
    res.json({ revision: saved.document.revision, updatedAt: saved.document.updatedAt, sequence: payload.sequence });
});

app.get('/api/docs/:id/presence', requireDocumentRole('viewer'), (req, res) => {
    const doc = DocumentStore.loadDoc(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Document not found' });
    const room = getCollaborationRoom(doc.id);
    res.set('Cache-Control', 'no-store');
    res.json({ presence: publicPresence(room) });
});

app.post('/api/docs/:id/presence', requireDocumentRole('viewer'), (req, res) => {
    const doc = DocumentStore.loadDoc(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Document not found' });
    const sessionId = String(req.body?.sessionId || '').slice(0, 160);
    if (!/^[A-Za-z0-9_-]{4,160}$/.test(sessionId)) return res.status(400).json({ error: 'Invalid session ID' });
    const room = getCollaborationRoom(doc.id);
    room.presence.set(sessionId, {
        sessionId,
        name: String(req.body?.name || 'Guest').slice(0, 80),
        color: String(req.body?.color || '#2563eb').slice(0, 40),
        selection: req.body?.selection && typeof req.body.selection === 'object' ? req.body.selection : null,
        revision: Number(req.body?.revision) || 0,
        visible: req.body?.visible !== false,
        lastSeen: Date.now()
    });
    const presence = publicPresence(room);
    broadcastCollaboration(doc.id, 'presence', presence);
    res.json({ presence });
});

app.delete('/api/docs/:id/presence/:sessionId', requireDocumentRole('viewer'), (req, res) => {
    const room = getCollaborationRoom(req.params.id);
    if (!room) return res.status(400).json({ error: 'Invalid document ID' });
    room.presence.delete(String(req.params.sessionId));
    broadcastPresence(req.params.id);
    res.json({ status: 'removed' });
});

app.post('/api/docs/:id/presence/:sessionId', requireDocumentRole('viewer'), (req, res) => {
    const room = getCollaborationRoom(req.params.id);
    if (room) { room.presence.delete(String(req.params.sessionId)); broadcastPresence(req.params.id); }
    res.status(204).end();
});

app.get('/api/docs/:id/events', requireDocumentRole('viewer'), (req, res) => {
    const doc = DocumentStore.loadDoc(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Document not found' });
    const room = getCollaborationRoom(doc.id);
    res.set({
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no'
    });
    res.flushHeaders?.();
    room.listeners.add(res);
    sendSse(res, 'connected', { documentId: doc.id, revision: doc.revision, presence: publicPresence(room) });
    const heartbeat = setInterval(() => res.write(': heartbeat\n\n'), 20_000);
    req.on('close', () => { clearInterval(heartbeat); room.listeners.delete(res); });
});

function saveCommentMutation(req, res, reason, mutate) {
    const current = DocumentStore.loadDoc(req.params.id);
    if (!current) return res.status(404).json({ error: 'Document not found' });
    const baseRevision = Number(req.body?.baseRevision ?? req.query?.baseRevision);
    if (Number.isFinite(baseRevision) && baseRevision !== Number(current.revision || 0)) {
        return res.status(409).json({ error: 'revision_conflict', currentRevision: Number(current.revision || 0) });
    }
    const next = JSON.parse(JSON.stringify(current));
    next.comments ||= [];
    const result = mutate(next, req.authUser);
    if (result?.error) return res.status(result.status || 400).json({ error: result.error });
    const saved = DocumentStore.saveDoc(next.id, next, { expectedRevision: Number(current.revision || 0), reason });
    if (saved.conflict) return res.status(409).json({ error: 'revision_conflict', ...saved });
    if (saved.error) return res.status(400).json({ error: saved.error });
    const payload = {
        documentId: saved.document.id,
        revision: saved.document.revision,
        updatedAt: saved.document.updatedAt,
        sessionId: String(req.get('x-openword-session') || ''),
        reason
    };
    broadcastCollaboration(saved.document.id, 'document-updated', payload);
    setDocumentEtag(res, saved.document);
    return res.json({ comments: saved.document.comments || [], revision: saved.document.revision, updatedAt: saved.document.updatedAt, result: result?.value || null });
}

app.post('/api/docs/:id/comments', requireDocumentRole('commenter'), (req, res) => saveCommentMutation(req, res, 'comment added', (document, user) => {
    const body = String(req.body?.body || '').trim();
    const anchor = req.body?.anchor;
    if (!body || !anchor?.start?.blockId || !anchor?.end?.blockId) return { error: 'Comment text and a valid anchor are required.' };
    const now = new Date().toISOString();
    const comment = {
        id: authId('comment'),
        threadId: authId('thread'),
        authorId: user?.id || 'local',
        author: user?.name || user?.email || 'User',
        anchor,
        messages: [{ id: authId('message'), authorId: user?.id || 'local', author: user?.name || 'User', body: body.slice(0, 10000), createdAt: now }],
        status: 'open',
        createdAt: now,
        updatedAt: now
    };
    document.comments.push(comment);
    return { value: comment };
}));

app.post('/api/docs/:id/comments/:commentId/replies', requireDocumentRole('commenter'), (req, res) => saveCommentMutation(req, res, 'comment replied', (document, user) => {
    const comment = document.comments.find(item => item.id === req.params.commentId);
    const body = String(req.body?.body || '').trim();
    if (!comment) return { status: 404, error: 'Comment not found' };
    if (!body) return { error: 'Reply text is required.' };
    const message = { id: authId('message'), authorId: user?.id || 'local', author: user?.name || 'User', body: body.slice(0, 10000), createdAt: new Date().toISOString() };
    comment.messages ||= []; comment.messages.push(message); comment.updatedAt = message.createdAt;
    return { value: message };
}));

app.patch('/api/docs/:id/comments/:commentId', requireDocumentRole('commenter'), (req, res) => saveCommentMutation(req, res, 'comment status changed', document => {
    const comment = document.comments.find(item => item.id === req.params.commentId);
    if (!comment) return { status: 404, error: 'Comment not found' };
    const status = String(req.body?.status || '');
    if (!['open', 'resolved'].includes(status)) return { error: 'Invalid comment status' };
    comment.status = status; comment.updatedAt = new Date().toISOString();
    return { value: comment };
}));

app.delete('/api/docs/:id/comments/:commentId', requireDocumentRole('commenter'), (req, res) => saveCommentMutation(req, res, 'comment deleted', document => {
    const index = document.comments.findIndex(item => item.id === req.params.commentId);
    if (index < 0) return { status: 404, error: 'Comment not found' };
    const [removed] = document.comments.splice(index, 1);
    return { value: removed };
}));

app.get('/api/docs/:id/members', requireDocumentRole('owner'), (req, res) => {
    const store = loadAuthStore();
    const members = (req.document.members || []).map(member => {
        const user = store.users.find(item => item.id === member.userId || item.email === member.email);
        return { ...member, name: user?.name || member.name || member.email, email: user?.email || member.email };
    });
    res.json({ ownerId: req.document.ownerId || 'local', members });
});

app.post('/api/docs/:id/members', requireDocumentRole('owner'), (req, res) => {
    const email = normalizeEmail(req.body?.email), role = String(req.body?.role || 'viewer');
    if (!/^\S+@\S+\.\S+$/.test(email) || !['viewer', 'commenter', 'editor'].includes(role)) return res.status(400).json({ error: 'Invalid member or role' });
    const store = loadAuthStore(); const user = store.users.find(item => item.email === email);
    const document = req.document; document.members ||= [];
    const existing = document.members.find(member => member.userId === user?.id || member.email === email);
    const entry = { userId: user?.id || null, email, role, addedAt: new Date().toISOString(), addedBy: req.authUser.id };
    if (existing) Object.assign(existing, entry); else document.members.push(entry);
    const saved = DocumentStore.saveDoc(document.id, document, { expectedRevision: document.revision, reason: 'member updated' });
    if (saved.conflict) return res.status(409).json(saved);
    res.json({ member: entry, revision: saved.document.revision });
});

app.delete('/api/docs/:id/members/:memberId', requireDocumentRole('owner'), (req, res) => {
    const document = req.document; document.members ||= [];
    document.members = document.members.filter(member => member.userId !== req.params.memberId && member.email !== normalizeEmail(req.params.memberId));
    const saved = DocumentStore.saveDoc(document.id, document, { expectedRevision: document.revision, reason: 'member removed' });
    if (saved.conflict) return res.status(409).json(saved);
    res.json({ status: 'removed', revision: saved.document.revision });
});

app.get('/api/docs/:id/share-links', requireDocumentRole('owner'), (req, res) => {
    const store = loadAuthStore();
    res.json({ links: store.shareLinks.filter(link => link.documentId === req.document.id && !link.revokedAt).map(link => ({ id: link.id, token: link.token, role: link.role, createdAt: link.createdAt, expiresAt: link.expiresAt, url: `/s/${link.token}` })) });
});

app.post('/api/docs/:id/share-links', requireDocumentRole('owner'), (req, res) => {
    const role = String(req.body?.role || 'viewer');
    if (!['viewer', 'commenter', 'editor'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
    const store = loadAuthStore();
    const link = { id: authId('link'), token: crypto.randomBytes(24).toString('base64url'), documentId: req.document.id, role, createdAt: new Date().toISOString(), createdBy: req.authUser.id, expiresAt: req.body?.expiresAt || null, revokedAt: null };
    store.shareLinks.push(link); saveAuthStore(store);
    res.status(201).json({ ...link, url: `/s/${link.token}` });
});

app.delete('/api/docs/:id/share-links/:linkId', requireDocumentRole('owner'), (req, res) => {
    const store = loadAuthStore(); const link = store.shareLinks.find(item => item.id === req.params.linkId && item.documentId === req.document.id);
    if (!link) return res.status(404).json({ error: 'Share link not found' });
    link.revokedAt = new Date().toISOString(); saveAuthStore(store); res.json({ status: 'revoked' });
});

app.get('/api/docs/:id', requireDocumentRole('viewer'), (req, res) => {
    const doc = DocumentStore.loadDoc(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Document not found' });
    setDocumentEtag(res, doc);
    res.set('Cache-Control', 'no-store');
    res.json(doc);
});

app.put('/api/docs/:id', requireDocumentRole('editor'), (req, res) => {
    const body = req.body || {};
    const incoming = body.document || body;
    const result = DocumentStore.saveDoc(req.params.id, incoming, {
        expectedRevision: parseExpectedRevision(req, body),
        force: req.query.force === '1',
        reason: String(req.get('x-openword-save-reason') || 'save').slice(0, 120)
    });
    if (result.conflict) return res.status(409).json({ error: 'revision_conflict', ...result });
    if (result.error === 'not_found') return res.status(404).json({ error: 'Document not found' });
    if (result.error) return res.status(400).json({ error: result.error });
    setDocumentEtag(res, result.document);
    broadcastCollaboration(result.document.id, 'document-updated', {
        documentId: result.document.id,
        revision: result.document.revision,
        updatedAt: result.document.updatedAt,
        sessionId: String(req.get('x-openword-session') || '')
    });
    res.json(result);
});

app.patch('/api/docs/:id/title', requireDocumentRole('editor'), (req, res) => {
    const result = DocumentStore.renameDoc(req.params.id, req.body?.title);
    if (result.error === 'not_found') return res.status(404).json({ error: 'Document not found' });
    setDocumentEtag(res, result.document);
    res.json(result.document);
});

app.post('/api/docs/:id/duplicate', requireDocumentRole('editor'), (req, res) => {
    const copy = DocumentStore.duplicateDoc(req.params.id, req.authUser?.id);
    if (!copy) return res.status(404).json({ error: 'Document not found' });
    setDocumentEtag(res, copy);
    res.status(201).json(copy);
});

app.delete('/api/docs/:id', requireDocumentRole('owner'), (req, res) => {
    if (!DocumentStore.deleteDoc(req.params.id)) return res.status(400).json({ error: 'Invalid document ID' });
    res.json({ status: 'Deleted' });
});

app.post('/api/docs/:id/export/pdf', requireDocumentRole('viewer'), async (req, res) => {
    let page;
    try {
        const doc = DocumentStore.loadDoc(req.params.id);
        if (!doc) return res.status(404).json({ error: 'Document not found' });
        const settings = doc.settings || { pageSize: 'letter', margins: { top: 1, bottom: 1, left: 1, right: 1 } };
        const { generatePageHtml } = await import('./public/page-layout.mjs');
        const fullHtml = generatePageHtml(doc.blocks || [], settings, doc);
        const browser = await getPdfBrowser();
        page = await browser.newPage();
        await page.setContent(fullHtml, { waitUntil: 'networkidle0', timeout: 30000 });
        await page.evaluate(async () => {
            await document.fonts?.ready;
            await Promise.all([...document.images].map(image => image.complete ? Promise.resolve() : new Promise(resolve => {
                image.addEventListener('load', resolve, { once: true });
                image.addEventListener('error', resolve, { once: true });
                setTimeout(resolve, 5000);
            })));
        });
        const pdfBuffer = Buffer.from(await page.pdf({ printBackground: true, preferCSSPageSize: true }));
        res.set('Content-Type', 'application/pdf');
        res.set('Content-Disposition', `inline; filename="${String(doc.title || 'document').replace(/["\r\n]/g, '')}.pdf"`);
        res.send(pdfBuffer);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'PDF Generation Failed' });
    } finally {
        if (page) await page.close().catch(() => undefined);
    }
});

app.listen(PORT, '0.0.0.0', () => console.log(`Server running at http://0.0.0.0:${PORT}`));
