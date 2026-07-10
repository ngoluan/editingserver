// ================================================================
// COMBINED SOURCE - 2026-07-03T16:42:01Z
// ================================================================


// ================================================================
// FILE: /home/luanngo/opendoc/server.js
// ================================================================
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
    [DATA_DIR, DOCS_DIR, REVISIONS_DIR, UPLOADS_DIR].forEach(dir => fs.mkdirSync(dir, { recursive: true }));
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
function setSessionCookie(res, token, maxAgeSeconds) {
    res.setHeader('Set-Cookie', `openword_session=${encodeURIComponent(token || '')}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.max(0, maxAgeSeconds || 0)}`);
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
            blocks: [{ id: this.generateNodeId('blk'), type: 'text', style: 'normal', content: 'Start typing...' }],
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
        if (fs.existsSync(docPath)) fs.unlinkSync(docPath);
        fs.rmSync(this.revisionDir(id), { recursive: true, force: true });
        const index = this.loadIndex();
        index.docs = index.docs.filter(doc => doc.id !== id);
        this.saveIndex(index);
        return true;
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


// ================================================================
// FILE: /home/luanngo/opendoc/fixes.js
// ================================================================
// apply-fixes.js
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const readline = require('readline'); // Required for prompting the user

const PROJECT_ROOT = __dirname;
const FIXES_DIR = path.join(PROJECT_ROOT, 'fixes');
const TEMP_EXTRACT_DIR = path.join(PROJECT_ROOT, '.temp_extracted_fixes');
const BACKUP_ROOT = path.join(PROJECT_ROOT, '.backup');

function exists(p) {
  return fs.existsSync(p);
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

// Helper to count lines in a file
function getLineCount(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    return content.split('\n').length;
  } catch (error) {
    return 0; // Fallback in case of an issue reading the file
  }
}

function expandZip(zipPath, destinationPath) {
  ensureDir(destinationPath);
  try {
    // Uses standard Linux unzip command
    execFileSync('unzip', ['-q', '-o', zipPath, '-d', destinationPath], { stdio: 'inherit' });
  } catch (error) {
    throw new Error(`Failed to unzip file. Ensure 'unzip' is installed on your system. Error: ${error.message}`);
  }
}

function walkDirs(startDir, out = []) {
  const entries = fs.readdirSync(startDir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(startDir, entry.name);
    if (entry.isDirectory()) {
      out.push(fullPath);
      walkDirs(fullPath, out);
    }
  }
  return out;
}

function findExtractedProjectRoot(startDir) {
  const dirs = [startDir, ...walkDirs(startDir)];
  
  // Get top-level items (files AND directories) in the project, excluding hidden ones, node_modules, and this script
  const projectItems = fs.readdirSync(PROJECT_ROOT)
    .filter(name => !name.startsWith('.') && name !== 'node_modules' && name !== 'apply-fixes.js' && name !== 'fixes');

  for (const dir of dirs) {
    const extractedItems = fs.readdirSync(dir);

    // If this directory contains any item that matches a project root item (e.g., 'src', 'public', 'server.js', 'package.json')
    if (extractedItems.some(item => projectItems.includes(item))) {
      return dir;
    }
  }

  throw new Error(`Could not find a valid project root inside the extracted zip. Expected to find items like src, public, server.js, or package.json.`);
}

function collectFiles(dir, baseDir = dir, out = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectFiles(fullPath, baseDir, out);
    } else if (entry.isFile()) {
      out.push({
        fullPath,
        relativePath: path.relative(baseDir, fullPath)
      });
    }
  }

  return out;
}

function filesAreEqual(fileA, fileB) {
  if (!exists(fileA) || !exists(fileB)) return false;
  const statA = fs.statSync(fileA);
  const statB = fs.statSync(fileB);
  if (statA.size !== statB.size) return false;
  
  const bufA = fs.readFileSync(fileA);
  const bufB = fs.readFileSync(fileB);
  return bufA.equals(bufB);
}

// applyFixes is now async to handle user input pausing
async function applyFixes(zipFileName) {
  ensureDir(FIXES_DIR); // Ensure fixes dir exists
  
  const zipPath = path.join(FIXES_DIR, zipFileName);
  if (!exists(zipPath)) {
    throw new Error(`ZIP file not found: ${zipPath}\nPlease place your zip file in the '${FIXES_DIR}' directory.`);
  }

  cleanupTempDir();
  console.log(`\nExtracting ZIP: ${zipPath}`);
  expandZip(zipPath, TEMP_EXTRACT_DIR);

  const extractedProjectRoot = findExtractedProjectRoot(TEMP_EXTRACT_DIR);
  console.log(`Found extracted project root: ${extractedProjectRoot}`);

  const sourceFiles = collectFiles(extractedProjectRoot);
  const results = [];
  const TIMESTAMP = new Date().toISOString().replace(/[:.]/g, '-');
  const CURRENT_BACKUP_DIR = path.join(BACKUP_ROOT, TIMESTAMP);

  // Setup readline for interactive prompts
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  const askQuestion = (query) => new Promise(resolve => rl.question(query, resolve));

  for (const file of sourceFiles) {
    const sourceFile = file.fullPath;
    const destFile = path.join(PROJECT_ROOT, file.relativePath);
    const relativeToProject = path.relative(PROJECT_ROOT, destFile);

    const result = { action: 'skipped', file: relativeToProject, error: null };

    if (!exists(destFile)) {
      // Prompt user if they want to create the missing file
      const answer = await askQuestion(`\n[?] File not found in project: ${relativeToProject}\n    Do you want to create a new one? (y/n): `);
      
      if (answer.toLowerCase() !== 'y' && answer.toLowerCase() !== 'yes') {
        result.action = 'error';
        result.error = `File does not exist and creation was declined.`;
        results.push(result);
        continue;
      }

      // User chose to create the new file
      ensureDir(path.dirname(destFile));
      fs.copyFileSync(sourceFile, destFile);
      
      result.action = 'created';
      result.oldLines = 0;
      result.newLines = getLineCount(sourceFile);
      results.push(result);
      continue;
    }

    if (filesAreEqual(sourceFile, destFile)) {
      results.push(result);
      continue;
    }

    // Capture line counts before overwriting
    const oldLines = getLineCount(destFile);
    const newLines = getLineCount(sourceFile);

    // Backup existing file
    ensureDir(path.dirname(path.join(CURRENT_BACKUP_DIR, relativeToProject)));
    fs.copyFileSync(destFile, path.join(CURRENT_BACKUP_DIR, relativeToProject));

    // Apply new file
    ensureDir(path.dirname(destFile));
    fs.copyFileSync(sourceFile, destFile);
    
    result.action = 'updated';
    result.oldLines = oldLines;
    result.newLines = newLines;
    results.push(result);
  }

  rl.close();
  cleanupTempDir();
  printResults(results, CURRENT_BACKUP_DIR);
}

function revertFixes(timestamp) {
  const targetBackupDir = path.join(BACKUP_ROOT, timestamp);
  
  if (!exists(targetBackupDir)) {
    console.error(`\nAvailable backups in ${BACKUP_ROOT}:`);
    if (exists(BACKUP_ROOT)) {
      fs.readdirSync(BACKUP_ROOT).forEach(dir => console.log(` - ${dir}`));
    } else {
      console.log('  (No backups found)');
    }
    throw new Error(`Backup folder not found: ${targetBackupDir}`);
  }

  console.log(`\nReverting files from backup: ${timestamp}`);
  const backupFiles = collectFiles(targetBackupDir);
  const results = [];

  for (const file of backupFiles) {
    const backupFile = file.fullPath;
    const destFile = path.join(PROJECT_ROOT, file.relativePath);
    const relativeToProject = path.relative(PROJECT_ROOT, destFile);

    ensureDir(path.dirname(destFile));
    fs.copyFileSync(backupFile, destFile);

    results.push({ action: 'reverted', file: relativeToProject });
  }

  for (const res of results) {
    console.log(`REVERTED  ${res.file}`);
  }
  console.log(`\nSuccessfully reverted ${results.length} files.`);
}

function cleanupTempDir() {
  if (exists(TEMP_EXTRACT_DIR)) {
    fs.rmSync(TEMP_EXTRACT_DIR, { recursive: true, force: true });
  }
}

function printResults(results, backupDir) {
  const updatedCount = results.filter(r => r.action === 'updated').length;
  const createdCount = results.filter(r => r.action === 'created').length;
  const skippedCount = results.filter(r => r.action === 'skipped').length;
  const errorResults = results.filter(r => r.action === 'error');

  console.log('\n--- Operations Log ---');
  for (const res of results) {
    if (res.action === 'updated') {
      let warning = '';
      // Check if line count dropped by more than 10%
      if (res.oldLines > 0) {
        const decrease = res.oldLines - res.newLines;
        const percentDecrease = decrease / res.oldLines;
        if (percentDecrease > 0.10) {
          warning = '  ⚠️ WARNING: Line count reduced by > 10%';
        }
      }
      console.log(`UPDATED   ${res.file} (Lines: ${res.oldLines} -> ${res.newLines})${warning}`);
    } else if (res.action === 'created') {
      console.log(`CREATED   ${res.file} (Lines: ${res.newLines})`);
    } else if (res.action === 'skipped') {
      console.log(`SKIPPED   ${res.file} (no changes)`);
    } else if (res.action === 'error') {
      console.error(`ERROR     ${res.file} -> ${res.error}`);
    }
  }

  console.log('\n--- Summary ---');
  console.log(`Updated: ${updatedCount}`);
  console.log(`Created: ${createdCount}`);
  console.log(`Skipped: ${skippedCount}`);
  console.log(`Errors:  ${errorResults.length}`);

  if (updatedCount > 0 || createdCount > 0) {
    console.log(`\nBackup saved. To revert, run:\nnode apply-fixes.js revert ${path.basename(backupDir)}`);
  } else {
    console.log('\nNo files were changed, so no backup was created.');
    // Remove empty backup dir if created
    if (exists(backupDir) && fs.readdirSync(backupDir).length === 0) {
      fs.rmSync(backupDir, { recursive: true, force: true });
    }
  }

  if (errorResults.length > 0) process.exitCode = 1;
}

// main is now async
async function main() {
  const command = process.argv[2];
  const target = process.argv[3];

  if (command === 'apply' && target) {
    await applyFixes(target);
  } else if (command === 'revert' && target) {
    revertFixes(target);
  } else {
    console.error('Usage:');
    console.error('  Apply a fix:  node apply-fixes.js apply <zip-file-in-fixes-dir>');
    console.error('  Revert a fix: node apply-fixes.js revert <timestamp-folder-name>');
    console.error('\nExample:');
    console.error('  node apply-fixes.js apply my-patch.zip');
    console.error('  node apply-fixes.js revert 2026-03-23T12-30-00-000Z');
    process.exit(1);
  }
}

// Top-level execution wrapper
async function run() {
  try {
    await main();
  } catch (error) {
    console.error('\nERROR:', error.message);
    process.exitCode = 1;
  } finally {
    cleanupTempDir();
  }
}

run();

// ================================================================
// FILE: /home/luanngo/opendoc/public/collaboration-manager.js
// ================================================================
function createSessionId() {
    if (globalThis.crypto?.randomUUID) return `session_${crypto.randomUUID()}`;
    return `session_${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
}

function hashColor(value) {
    let hash = 0;
    for (const character of String(value)) hash = ((hash << 5) - hash + character.charCodeAt(0)) | 0;
    return `hsl(${Math.abs(hash) % 360} 65% 45%)`;
}

export class CollaborationManager {
    constructor(controller) {
        this.ctrl = controller;
        this.state = controller.state;
        this.engine = controller.engine;
        this.sessionId = this.loadOrCreate('openword_collaboration_session', createSessionId);
        this.userName = this.loadOrCreate('openword_collaboration_name', () => `Guest ${this.sessionId.slice(-4)}`);
        this.color = hashColor(this.sessionId);
        this.presence = [];
        this.eventSource = null;
        this.heartbeatTimer = null;
        this.selectionTimer = null;
        this.currentDocumentId = null;
        this.lastRemoteRevision = null;
        this.transactionQueue = Promise.resolve();
        this.pendingLocalTransactions = 0;
        this.seenTransactionIds = new Set();
        this.applyingRemote = false;
    }

    loadOrCreate(key, factory) {
        try {
            const existing = localStorage.getItem(key);
            if (existing) return existing;
            const value = factory();
            localStorage.setItem(key, value);
            return value;
        } catch (_) { return factory(); }
    }

    setup() {
        this.state.currentUserName = this.userName;
        this.state.collaborationSessionId = this.sessionId;
        this.ensureUi();
        this.state.subscribeTo('DOCUMENT_LOADED', ({ documentId }) => this.connect(documentId));
        this.state.subscribeTo('SAVE_SUCCEEDED', () => this.sendPresence());
        this.state.subscribeTo('TRANSACTION_APPLIED', ({ transaction, remote }) => {
            if (remote || this.applyingRemote || transaction?.meta?.remote) return;
            this.enqueueLocalTransaction(transaction);
        });
        document.addEventListener('selectionchange', () => {
            clearTimeout(this.selectionTimer);
            this.selectionTimer = setTimeout(() => this.sendPresence(), 180);
        });
        window.addEventListener('resize', () => this.paintRemoteSelections());
        window.addEventListener('scroll', () => this.paintRemoteSelections(), true);
        window.addEventListener('pagehide', () => this.disconnect({ beacon: true }));
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') this.sendPresence();
        });
    }

    ensureUi() {
        const spacer = document.querySelector('.ribbon-bar-spacer');
        if (spacer && !document.getElementById('collaboration-presence')) {
            const container = document.createElement('div');
            container.id = 'collaboration-presence';
            container.className = 'collaboration-presence';
            container.setAttribute('aria-label', 'People viewing this document');
            spacer.insertAdjacentElement('afterend', container);
        }
        if (!document.getElementById('remote-update-banner')) {
            const banner = document.createElement('div');
            banner.id = 'remote-update-banner';
            banner.className = 'remote-update-banner hidden';
            banner.innerHTML = '<span><strong>This document changed elsewhere.</strong> Reload to see the latest saved version.</span><div><button data-action="dismiss">Dismiss</button><button class="btn-primary" data-action="reload">Reload</button></div>';
            document.body.appendChild(banner);
            banner.addEventListener('click', async event => {
                const action = event.target.dataset.action;
                if (action === 'dismiss') banner.classList.add('hidden');
                if (action === 'reload') {
                    if (this.state.isDirty && !window.confirm('Reloading will discard local unsaved changes. Continue?')) return;
                    await this.state.loadDoc(this.currentDocumentId);
                    banner.classList.add('hidden');
                }
            });
        }
    }

    async connect(documentId) {
        if (!documentId || documentId === this.currentDocumentId) {
            if (documentId) this.sendPresence();
            return;
        }
        await this.disconnect();
        this.currentDocumentId = documentId;
        this.state.collaborationOwnsPersistence = true;
        this.openEventStream();
        await this.sendPresence();
        clearInterval(this.heartbeatTimer);
        this.heartbeatTimer = setInterval(() => this.sendPresence(), 20_000);
    }

    openEventStream() {
        if (typeof EventSource === 'undefined' || !this.currentDocumentId) return;
        const url = `/api/docs/${encodeURIComponent(this.currentDocumentId)}/events?sessionId=${encodeURIComponent(this.sessionId)}`;
        this.eventSource = new EventSource(url);
        this.eventSource.addEventListener('presence', event => this.handlePresence(JSON.parse(event.data)));
        this.eventSource.addEventListener('document-updated', event => this.handleRemoteUpdate(JSON.parse(event.data)));
        this.eventSource.addEventListener('transaction', event => this.handleRemoteTransaction(JSON.parse(event.data)));
        this.eventSource.addEventListener('connected', event => {
            const payload = JSON.parse(event.data);
            if (payload.presence) this.handlePresence(payload.presence);
        });
        this.eventSource.onerror = () => {
            // EventSource reconnects automatically. Presence heartbeats remain active.
        };
    }

    serializeSelection() {
        const selection = this.engine.captureSelection();
        if (!selection) return null;
        return JSON.parse(JSON.stringify(selection));
    }

    async sendPresence() {
        if (!this.currentDocumentId || typeof fetch !== 'function') return;
        const payload = {
            sessionId: this.sessionId,
            name: this.userName,
            color: this.color,
            selection: this.serializeSelection(),
            revision: Number(this.state.doc.revision) || 0,
            visible: document.visibilityState !== 'hidden'
        };
        try {
            const response = await fetch(`/api/docs/${encodeURIComponent(this.currentDocumentId)}/presence`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                keepalive: true
            });
            if (response.ok) this.handlePresence((await response.json()).presence || []);
        } catch (_) { /* offline presence is non-critical */ }
    }

    handlePresence(entries) {
        this.presence = (entries || []).filter(entry => entry.sessionId !== this.sessionId);
        this.renderPresence();
        this.paintRemoteSelections();
        this.state.signal('COLLABORATION_PRESENCE_CHANGED', { presence: this.presence });
    }

    renderPresence() {
        const container = document.getElementById('collaboration-presence');
        if (!container) return;
        const entries = [{ sessionId: this.sessionId, name: this.userName, color: this.color, self: true }, ...this.presence].slice(0, 6);
        container.innerHTML = entries.map(entry => `<button class="presence-avatar ${entry.self ? 'self' : ''}" title="${this.escape(entry.name)}${entry.self ? ' (you)' : ''}" style="--presence-color:${this.escape(entry.color)}">${this.escape(this.initials(entry.name))}</button>`).join('') + (this.presence.length > 5 ? `<span class="presence-more">+${this.presence.length - 5}</span>` : '');
        container.querySelector('.presence-avatar.self')?.addEventListener('click', () => {
            const name = window.prompt('Your display name', this.userName)?.trim();
            if (!name) return;
            this.userName = name.slice(0, 80);
            try { localStorage.setItem('openword_collaboration_name', this.userName); } catch (_) { /* ignore */ }
            this.state.currentUserName = this.userName;
            this.sendPresence();
        });
    }

    paintRemoteSelections() {
        document.querySelectorAll('.remote-caret').forEach(element => element.remove());
        for (const entry of this.presence) {
            const selection = entry.selection;
            if (!selection?.anchor) continue;
            const position = this.engine.selectionBridge.resolvePosition(selection.focus || selection.anchor);
            if (!position?.container) continue;
            try {
                const range = document.createRange();
                range.setStart(position.container, position.offset);
                range.collapse(true);
                const rect = range.getClientRects()[0] || range.getBoundingClientRect();
                if (!rect || (!rect.width && !rect.height)) continue;
                const caret = document.createElement('div');
                caret.className = 'remote-caret';
                caret.style.left = `${rect.left}px`;
                caret.style.top = `${rect.top}px`;
                caret.style.height = `${Math.max(16, rect.height)}px`;
                caret.style.setProperty('--presence-color', entry.color || '#2563eb');
                caret.innerHTML = `<span>${this.escape(entry.name || 'Guest')}</span>`;
                document.body.appendChild(caret);
            } catch (_) { /* stale remote selection */ }
        }
    }

    enqueueLocalTransaction(transaction) {
        if (!transaction || !this.currentDocumentId || this.seenTransactionIds.has(transaction.id)) return;
        const serialized = typeof transaction.toJSON === 'function' ? transaction.toJSON() : JSON.parse(JSON.stringify(transaction));
        this.pendingLocalTransactions += 1;
        this.transactionQueue = this.transactionQueue.catch(() => undefined).then(() => this.sendLocalTransaction(serialized)).finally(() => {
            this.pendingLocalTransactions = Math.max(0, this.pendingLocalTransactions - 1);
        });
    }

    async sendLocalTransaction(transaction) {
        if (!this.currentDocumentId) return;
        const baseRevision = Number(this.state.doc.revision) || 0;
        try {
            const response = await fetch(`/api/docs/${encodeURIComponent(this.currentDocumentId)}/transactions`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-OpenWord-Session': this.sessionId },
                body: JSON.stringify({ sessionId: this.sessionId, baseRevision, transaction })
            });
            if (response.status === 409) {
                const conflict = await response.json();
                this.state.writeRecoveryBackup?.();
                this.state.setSaveStatus('Conflict', 'A collaborator changed this document before your transaction was accepted.');
                this.state.signal('SAVE_CONFLICT', { ...conflict, collaborative: true });
                document.getElementById('remote-update-banner')?.classList.remove('hidden');
                return;
            }
            if (!response.ok) throw new Error(`Collaborative save failed (${response.status})`);
            const result = await response.json();
            this.seenTransactionIds.add(transaction.id);
            this.trimSeenTransactions();
            if (this.pendingLocalTransactions > 1) {
                this.state.doc.revision = Number(result.revision) || this.state.doc.revision;
                if (result.updatedAt) this.state.doc.updatedAt = result.updatedAt;
                this.state.isDirty = true;
                this.state.setSaveStatus('Unsaved changes');
            } else this.state.acknowledgeCollaborativeRevision(result.revision, result.updatedAt);
            this.sendPresence();
        } catch (error) {
            this.state.collaborationOwnsPersistence = false;
            this.state.markDirty();
            this.state.setSaveStatus('Save failed', error.message);
            this.state.signal('SAVE_FAILED', { error, reason: 'collaborative-transaction' });
        }
    }

    handleRemoteTransaction(payload) {
        const transaction = payload?.transaction;
        if (!transaction?.id || this.seenTransactionIds.has(transaction.id)) return;
        this.seenTransactionIds.add(transaction.id);
        this.trimSeenTransactions();
        if (payload.sessionId === this.sessionId) {
            this.state.acknowledgeCollaborativeRevision(payload.revision, payload.updatedAt);
            return;
        }
        const expected = (Number(this.state.doc.revision) || 0) + 1;
        if (this.pendingLocalTransactions > 0 || Number(payload.revision) !== expected || this.state.isDirty) {
            this.handleRemoteUpdate(payload);
            return;
        }
        this.applyingRemote = true;
        try {
            this.state.applyRemoteTransaction(transaction, payload.revision, payload.updatedAt);
            this.engine.selection = this.engine.positionMapper.mapSelection(this.engine.selection, transaction.operations || [], { documentAfter: this.state.doc });
            if (this.engine.selection) this.engine.restoreSelectionSoon(this.engine.selection);
            this.state.signal('REMOTE_TRANSACTION_APPLIED', payload);
        } finally {
            this.applyingRemote = false;
        }
    }

    trimSeenTransactions() {
        if (this.seenTransactionIds.size <= 500) return;
        this.seenTransactionIds = new Set([...this.seenTransactionIds].slice(-300));
    }

    handleRemoteUpdate(payload) {
        if (!payload || payload.sessionId === this.sessionId) return;
        const revision = Number(payload.revision) || 0;
        if (revision <= (Number(this.state.doc.revision) || 0) || revision === this.lastRemoteRevision) return;
        this.lastRemoteRevision = revision;
        document.getElementById('remote-update-banner')?.classList.remove('hidden');
        this.state.signal('REMOTE_DOCUMENT_UPDATED', payload);
    }

    async disconnect({ beacon = false } = {}) {
        clearInterval(this.heartbeatTimer);
        this.heartbeatTimer = null;
        this.eventSource?.close();
        this.eventSource = null;
        const documentId = this.currentDocumentId;
        this.currentDocumentId = null;
        this.state.collaborationOwnsPersistence = false;
        document.querySelectorAll('.remote-caret').forEach(element => element.remove());
        if (!documentId) return;
        const url = `/api/docs/${encodeURIComponent(documentId)}/presence/${encodeURIComponent(this.sessionId)}`;
        if (beacon && navigator.sendBeacon) navigator.sendBeacon(url, new Blob([], { type: 'application/json' }));
        else await fetch(url, { method: 'DELETE', keepalive: true }).catch(() => undefined);
    }

    initials(name) { return String(name || '?').split(/\s+/).filter(Boolean).slice(0, 2).map(part => part[0]).join('').toUpperCase(); }
    escape(value) { const div = document.createElement('div'); div.textContent = String(value || ''); return div.innerHTML; }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/context-menu.js
// ================================================================
export class ContextMenu {
    constructor(ctrl) {
        this.ctrl = ctrl;
        this._longPressTimer = null;
        this._longPressPos = null;
        this.context = null;
    }

    setup() {
        const ctrl = this.ctrl;
        const menu = document.getElementById('context-menu');
        if (!menu) return;

        document.addEventListener('contextmenu', (event) => {
            const blockEl = ctrl.resolveBlockElementFromNode(event.target);
            if (!blockEl && !event.target.closest('#workspace')) return;
            event.preventDefault();
            this.context = this.buildContext(blockEl, event.target);
            this.configureMenu(menu, this.context);
            this.showMenu(menu, event.clientX, event.clientY);
        });

        document.addEventListener('touchstart', (event) => {
            if (event.touches.length > 1) {
                this._clearLongPress();
                return;
            }
            const touch = event.touches[0];
            const blockEl = ctrl.resolveBlockElementFromNode(event.target);
            if (!blockEl && !event.target.closest('#workspace')) return;

            this._clearLongPress();
            this._longPressPos = { x: touch.clientX, y: touch.clientY };
            this._longPressTimer = setTimeout(() => {
                this.context = this.buildContext(blockEl, event.target);
                this.configureMenu(menu, this.context);
                this.showMenu(menu, this._longPressPos.x, this._longPressPos.y);
                this._clearLongPress();
            }, 500);
        }, { passive: false });

        document.addEventListener('touchmove', () => this._clearLongPress());
        document.addEventListener('touchend', () => this._clearLongPress());
        document.addEventListener('click', (event) => {
            if (!menu.contains(event.target)) menu.classList.add('hidden');
        });

        menu.addEventListener('mousedown', (event) => {
            event.preventDefault();
        });

        menu.addEventListener('click', (event) => {
            const item = event.target.closest('.context-menu-item');
            if (!item || item.classList.contains('hidden')) return;
            const action = item.dataset.action;
            menu.classList.add('hidden');
            this.runAction(action);
        });
    }

    buildContext(blockEl, target) {
        const blockId = blockEl?.dataset?.blockId || null;
        const index = blockId ? this.ctrl.state.getBlockIndexById(blockId)
            : (blockEl?.dataset?.index !== undefined ? parseInt(blockEl.dataset.index, 10) : null);
        const block = Number.isInteger(index) ? this.ctrl.state.doc.blocks[index] : null;
        const selection = window.getSelection();
        const hasSelection = !!(selection && !selection.isCollapsed && selection.toString().trim());
        const cell = target?.closest?.('td');
        return {
            blockEl,
            index,
            blockId: block?.id || blockId,
            block,
            type: block?.type || 'workspace',
            hasSelection,
            cell: cell ? { id: cell.dataset.cellId || null, row: parseInt(cell.dataset.row, 10), col: parseInt(cell.dataset.col, 10) } : null
        };
    }

    configureMenu(menu, context) {
        const common = new Set(['cut', 'copy', 'paste']);
        const text = new Set(['bold', 'italic', 'underline', 'strikethrough', 'code', 'link', 'removeFormat', 'footnote', 'endnote']);
        const image = new Set(['image-left', 'image-center', 'image-right', 'delete-block']);
        const table = new Set(['table-row', 'table-col', 'delete-block']);
        const list = new Set(['toggle-list', 'list-to-text', 'delete-block']);
        const allowed = new Set(common);

        if (context.type === 'text') text.forEach(action => allowed.add(action));
        if (context.type === 'image' || (context.type === 'object' && context.block?.objectType === 'image')) image.forEach(action => allowed.add(action));
        if (context.type === 'object' && context.block?.objectType === 'textBox') new Set(['delete-block']).forEach(action => allowed.add(action));
        if (context.type === 'table') table.forEach(action => allowed.add(action));
        if (['ul', 'ol', 'checklist'].includes(context.type)) list.forEach(action => allowed.add(action));

        menu.querySelectorAll('.context-menu-item').forEach(item => {
            const action = item.dataset.action;
            item.classList.toggle('hidden', !allowed.has(action));
            if (['bold', 'italic', 'underline', 'strikethrough', 'code', 'link'].includes(action)) {
                item.classList.toggle('context-menu-muted', !context.hasSelection);
            }
        });

        menu.querySelectorAll('.context-menu-separator').forEach(separator => {
            const previousVisible = [...menu.children].slice(0, [...menu.children].indexOf(separator)).reverse().find(el => !el.classList.contains('hidden') && !el.classList.contains('context-menu-separator'));
            const nextVisible = [...menu.children].slice([...menu.children].indexOf(separator) + 1).find(el => !el.classList.contains('hidden') && !el.classList.contains('context-menu-separator'));
            separator.classList.toggle('hidden', !previousVisible || !nextVisible);
        });
    }

    runAction(action) {
        const ctrl = this.ctrl;
        const context = this.context || {};
        switch (action) {
            case 'cut': ctrl.clipboard.cut(); break;
            case 'copy': ctrl.clipboard.copy(); break;
            case 'paste': ctrl.clipboard.paste(); break;
            case 'bold': ctrl.engine.dispatch('toggleBold'); break;
            case 'italic': ctrl.engine.dispatch('toggleItalic'); break;
            case 'underline': ctrl.engine.dispatch('toggleUnderline'); break;
            case 'strikethrough': ctrl.engine.dispatch('toggleStrikethrough'); break;
            case 'code': ctrl.engine.dispatch('toggleInlineCode'); break;
            case 'link': ctrl.engine.dispatch('createLink'); break;
            case 'removeFormat': ctrl.engine.dispatch('clearFormatting'); break;
            case 'footnote': ctrl.insertNoteAtSelection('footnote'); break;
            case 'endnote': ctrl.insertNoteAtSelection('endnote'); break;
            case 'image-left': context.block?.type === 'object' ? ctrl.engine.dispatch('updateObject', { objectId: context.blockId, patch: { wrap: { type: 'square', side: 'right' }, layout: { mode: 'floating' } } }, { restoreSelection: false }) : ctrl.state.updateImageProps(context.blockId || context.index, { align: 'left' }); break;
            case 'image-center': context.block?.type === 'object' ? ctrl.engine.dispatch('updateObject', { objectId: context.blockId, patch: { wrap: { type: 'inline', side: 'both' }, layout: { mode: 'inline' } } }, { restoreSelection: false }) : ctrl.state.updateImageProps(context.blockId || context.index, { align: 'center' }); break;
            case 'image-right': context.block?.type === 'object' ? ctrl.engine.dispatch('updateObject', { objectId: context.blockId, patch: { wrap: { type: 'square', side: 'left' }, layout: { mode: 'floating' } } }, { restoreSelection: false }) : ctrl.state.updateImageProps(context.blockId || context.index, { align: 'right' }); break;
            case 'table-row': ctrl.state.insertTableRow(context.blockId || context.index, context.cell?.id || (context.cell ? context.cell.row + 1 : undefined)); break;
            case 'table-col': ctrl.state.insertTableCol(context.blockId || context.index, context.cell?.id || (context.cell ? context.cell.col + 1 : undefined)); break;
            case 'toggle-list': ctrl.state.toggleListType(context.blockId || context.index); break;
            case 'list-to-text': ctrl.state.convertBlockToText(context.blockId || context.index); break;
            case 'delete-block':
                if (Number.isInteger(context.index)) ctrl.engine.dispatch('removeBlock', { blockId: context.blockId, index: context.index });
                break;
        }
    }

    _clearLongPress() {
        if (this._longPressTimer) {
            clearTimeout(this._longPressTimer);
            this._longPressTimer = null;
        }
        this._longPressPos = null;
    }

    showMenu(menu, x, y) {
        menu.style.left = `${x}px`;
        menu.style.top = `${y}px`;
        menu.classList.remove('hidden');
        const rect = menu.getBoundingClientRect();
        if (rect.right > window.innerWidth) menu.style.left = `${window.innerWidth - rect.width - 8}px`;
        if (rect.bottom > window.innerHeight) menu.style.top = `${window.innerHeight - rect.height - 8}px`;
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/controller.js
// ================================================================
import { Formatter } from './formatter.js';
import { ToolbarManager } from './toolbar-manager.js';
import { KeyboardManager } from './keyboard-manager.js';
import { OutlineManager } from './outline-manager.js';
import { PasteHandler } from './paste-handler.js';
import { ContextMenu } from './context-menu.js';
import { SidebarManager } from './sidebar-manager.js';
import { ModalManager } from './modal-manager.js';
import { RulerManager } from './ruler-manager.js';
import { ExportImport } from './export-import.js';
import { SmartInputManager } from './smart-input-manager.js';
import { EditorEngine } from './editor/editor-engine.js';
import { ClipboardManager } from './editor/clipboard/clipboard-manager.js';
import { TableManager } from './editor/table/table-manager.js';
import { ReviewManager } from './editor/review/review-manager.js';
import { CollaborationManager } from './collaboration-manager.js';
import { ObjectManager } from './editor/objects/object-manager.js';
import { SharingManager } from './sharing-manager.js';
import { PaginationManager } from './layout/pagination-manager.js';
 
export class EditorController {
    constructor(stateManager, renderer) {
        this.state = stateManager;
        this.renderer = renderer;
        this.activeBlockIndex = null;
        this.activeBlockId = null;
        this.savedSelection = null;
        this.supportsBeforeInput = 'onbeforeinput' in document;
        this.lastFocusedBlockEl = null;
        this.splitViewActive = false;
        this.splitRenderers = null;

        if (typeof window.DEBUG_PAGINATION === 'undefined') window.DEBUG_PAGINATION = true;
        if (typeof window.DEBUG_PASTE === 'undefined') window.DEBUG_PASTE = true;
        if (typeof window.DEBUG_ENTER === 'undefined') window.DEBUG_ENTER = true;

        this._pasteSeq = 0;
        this.pendingInsertIndex = null;
        this.docMetaUpdateTimer = null;

        this.toolbar = new ToolbarManager(this);
        this.keyboard = new KeyboardManager(this);
        this.outline = new OutlineManager(this);
        this.pasteHandler = new PasteHandler(this);
        this.contextMenu = new ContextMenu(this);
        this.sidebar = new SidebarManager(this);
        this.modal = new ModalManager(this);
        this.ruler = new RulerManager(this);
        this.exportImport = new ExportImport(this);
        this.smartInput = new SmartInputManager(this);
        this.engine = new EditorEngine(stateManager, this, renderer);
        this.clipboard = new ClipboardManager(this);
        this.tableManager = new TableManager(this);
        this.reviewManager = new ReviewManager(this);
        this.collaboration = new CollaborationManager(this);
        this.objectManager = new ObjectManager(this);
        this.state._objectManager = this.objectManager;
        this.sharing = new SharingManager(this);
        this.paginationManager = new PaginationManager(this);
    }

    async init() {
        this._renderBatchTimer = null;
        this._pendingOp = null;

        this.state.subscribe((doc, hfMode, op) => {
            this.saveSelectionSnapshot();

            if (op && op.type === 'UPDATE_BLOCK' && op.source === 'typing') {
                this._pendingOp = op;
                if (!this._renderBatchTimer) {
                    this._renderBatchTimer = requestAnimationFrame(() => {
                        this._renderBatchTimer = null;
                        this._flushRender();
                    });
                }
                this.savedSelection = null;
                this.updateDocumentMeta(doc, { ...op });
                document.getElementById('doc-title-display').innerText = doc.title;
                return;
            }

            this._flushRender();
        });

        this.state.subscribeTo('RENAME_DOC', () => {
            document.getElementById('doc-title-display').innerText = this.state.doc.title;
        });

        document.addEventListener('opendoc:deferred-pagination', () => {
            this.saveSelectionSnapshot();
            this.renderer.render(this.state.doc, this.state.hfMode, { type: 'DEFERRED_PAGINATION' });
            this.restoreSelectionSnapshot();
        });

        this.engine.setup();
        this.clipboard.setup();
        this.tableManager.setup();
        this.reviewManager.setup();
        this.collaboration.setup();
        this.objectManager.setup();
        await this.sharing.setup();
        this.paginationManager.setup();
        this.toolbar.setup();
        this.setupBeforeInput();
        this.keyboard.setup();
        this.ruler.setup();
        this.pasteHandler.setup();
        this.smartInput.setup();
        this.sidebar.setup();
        this.modal.setup();
        this.contextMenu.setup();
        this.setupFocusTracking();
        this.outline.setupInteractions();
        this.toolbar.setupContextualToolbar();
        this.initPersistence();

        document.addEventListener('selectionchange', () => {
            this.toolbar.updateToolbarState();
            this.toolbar.updateContextualToolbar();
            const modelSelection = this.engine.captureSelection();
            const ctx = this.getActiveBlockContextFromSelection();
            if (ctx) {
                this.activeBlockIndex = ctx.index;
                this.activeBlockId = ctx.blockId;
                this.lastFocusedBlockEl = ctx.el;
            } else if (modelSelection?.anchor?.blockId) {
                this.activeBlockId = modelSelection.anchor.blockId;
                this.activeBlockIndex = this.state.getBlockIndexById(this.activeBlockId);
            }
        });

        document.getElementById('doc-title-display').onblur = (e) => {
            this.state.renameDoc(e.target.innerText);
        };

        this.setupWelcomePage();
        this.setupStatusBarViewButtons();
        this.setupMobileNav();
        this.setupPersistenceUi();

        const docs = await this.state.loadDocsList();
        const requestedDocumentId = new URLSearchParams(window.location.search).get('doc');
        if (requestedDocumentId && docs.some(doc => doc.id === requestedDocumentId)) await this.state.loadDoc(requestedDocumentId);
        else if (docs.length) await this.state.loadDoc(docs[0].id);
        else await this.state.createNewDoc();

        const welcome = document.getElementById('welcome-page');
        if (welcome) welcome.classList.add('hidden');
    }

    _flushRender() {
        if (this._renderBatchTimer) {
            cancelAnimationFrame(this._renderBatchTimer);
            this._renderBatchTimer = null;
        }
        this.saveSelectionSnapshot();
        const didFullRender = this.renderer.render(this.state.doc, this.state.hfMode, this._pendingOp || null);
        if (didFullRender) this.restoreSelectionSnapshot();
        else this.savedSelection = null;
        this.updateDocumentMeta(this.state.doc, this._pendingOp);
        document.getElementById('doc-title-display').innerText = this.state.doc.title;
        this._pendingOp = null;
    }

    printDocument() { return this.exportImport.printDocument(); }
    exportPDF() { return this.exportImport.exportPDF(); }
    exportDOCX() { return this.exportImport.exportDOCX(); }
    importDOCX(file) { return this.exportImport.importDOCX(file); }

    insertNoteAtSelection(type = 'footnote', content = '') {
        const ctx = this.getActiveBlockContextFromSelection();
        if (!ctx) return null;
        const block = this.state.doc.blocks[ctx.index];
        if (!block || block.type !== 'text') return null;

        const local = this.getCaretTextOffsetInElement(ctx.el);
        let offset = local?.start ?? Formatter.getTextLengthFromDom(ctx.el);
        if (ctx.isSplit) {
            for (let i = 0; i < ctx.partIndex; i++) offset += Formatter.getTextLengthFromDom(ctx.parts[i]);
        }

        const note = type === 'endnote'
            ? this.state.addEndnote(ctx.index, content, offset)
            : this.state.addFootnote(ctx.index, content, offset);

        const targetId = type === 'endnote' ? `en-content-${note.id}` : `fn-content-${note.id}`;
        setTimeout(() => {
            const content = document.getElementById(targetId)?.querySelector?.('.endnote-content, .footnote-content')
                || document.getElementById(targetId);
            if (content) {
                content.scrollIntoView({ behavior: 'smooth', block: 'center' });
                content.focus();
            }
        }, 60);
        return note;
    }

    setupPersistenceUi() {
        const conflictDialog = document.getElementById('save-conflict-dialog');
        const recoveryDialog = document.getElementById('recovery-dialog');
        const conflictDetail = document.getElementById('save-conflict-detail');
        const recoveryDetail = document.getElementById('recovery-detail');

        const setBusy = (dialog, busy) => {
            dialog?.querySelectorAll('button').forEach(button => { button.disabled = busy; });
        };
        const closeConflict = () => conflictDialog?.classList.add('hidden');
        const closeRecovery = () => recoveryDialog?.classList.add('hidden');

        this.state.subscribeTo('SAVE_CONFLICT', (conflict) => {
            const current = conflict?.current || {};
            if (conflictDetail) {
                const updated = current.updatedAt ? new Date(current.updatedAt).toLocaleString() : 'recently';
                conflictDetail.textContent = `The server is on revision ${current.revision ?? 'unknown'}, updated ${updated}. Your unsaved version is safely backed up in this browser.`;
            }
            conflictDialog?.classList.remove('hidden');
        });

        this.state.subscribeTo('RECOVERY_AVAILABLE', (recovery) => {
            if (recoveryDetail) {
                const savedAt = recovery?.savedAt ? new Date(recovery.savedAt).toLocaleString() : 'an earlier session';
                recoveryDetail.textContent = `A newer local draft from ${savedAt} was found for this document.`;
            }
            recoveryDialog?.classList.remove('hidden');
        });

        document.getElementById('btn-conflict-reload')?.addEventListener('click', async () => {
            setBusy(conflictDialog, true);
            try { await this.state.resolveSaveConflict('reload'); closeConflict(); }
            finally { setBusy(conflictDialog, false); }
        });
        document.getElementById('btn-conflict-copy')?.addEventListener('click', async () => {
            setBusy(conflictDialog, true);
            try {
                await this.state.resolveSaveConflict('copy');
                closeConflict();
                this.toolbar.showShellToast('Recovered copy created');
            } finally { setBusy(conflictDialog, false); }
        });
        document.getElementById('btn-conflict-overwrite')?.addEventListener('click', async () => {
            setBusy(conflictDialog, true);
            try {
                await this.state.resolveSaveConflict('overwrite');
                closeConflict();
                this.toolbar.showShellToast('Server version replaced');
            } finally { setBusy(conflictDialog, false); }
        });

        document.getElementById('btn-recovery-restore')?.addEventListener('click', () => {
            if (this.state.recoverLocalDraft()) this.toolbar.showShellToast('Local draft restored');
            closeRecovery();
        });
        document.getElementById('btn-recovery-discard')?.addEventListener('click', () => {
            this.state.discardLocalRecovery();
            closeRecovery();
        });

        this.state.subscribeTo('SAVE_FAILED', ({ error }) => {
            this.toolbar.showShellToast(error?.message || 'Document could not be saved');
        });
        this.state.subscribeTo('REVISION_RESTORED', ({ revision }) => {
            this.toolbar.showShellToast(`Revision ${revision} restored`);
        });
    }

    updateDocumentMeta(doc, op = null) {
        if (this.docMetaUpdateTimer) {
            clearTimeout(this.docMetaUpdateTimer);
            this.docMetaUpdateTimer = null;
        }
        if (op && ((op.type === 'UPDATE_BLOCK' && op.source === 'typing') || op.source === 'enter')) {
            this.docMetaUpdateTimer = setTimeout(() => {
                this.docMetaUpdateTimer = null;
                this.updateStats(doc.blocks);
                this.outline.updateOutline(doc.blocks);
            }, 250);
            return;
        }
        this.updateStats(doc.blocks);
        this.outline.updateOutline(doc.blocks);
    }

    saveSelectionSnapshot() {
        const selection = this.engine?.captureSelection();
        if (selection) this.savedSelection = selection;
    }

    restoreSelectionSnapshot() {
        if (!this.savedSelection) return;
        const selection = this.savedSelection;
        this.savedSelection = null;
        this.engine?.setSelection(selection);
        this.engine?.selectionBridge.restore(selection, { preventScroll: true });
    }

    setSelectionByTextOffsets(el, start, end) {
        const range = document.createRange();
        const sel = window.getSelection();

        const startPos = Formatter.resolveDomPositionFromTextOffset(el, start);
        const endPos = Formatter.resolveDomPositionFromTextOffset(el, end);

        if (!startPos || !startPos.container) {
            range.selectNodeContents(el);
            range.collapse(true);
        } else {
            range.setStart(startPos.container, startPos.offset);
            if (endPos && endPos.container) range.setEnd(endPos.container, endPos.offset);
            else range.collapse(true);
        }

        sel.removeAllRanges();
        sel.addRange(range);
    }

    setSelectionAcrossPartsByTextOffsets(parts, startGlobal, endGlobal) {
        let running = 0;
        let startPart = parts[0];
        let endPart = parts[0];
        let startLocal = 0;
        let endLocal = 0;

        for (let i = 0; i < parts.length; i++) {
            const len = Formatter.getTextLengthFromDom(parts[i]);
            if (startGlobal >= running && startGlobal <= running + len) {
                startPart = parts[i];
                startLocal = startGlobal - running;
            }
            if (endGlobal >= running && endGlobal <= running + len) {
                endPart = parts[i];
                endLocal = endGlobal - running;
            }
            running += len;
        }

        if (startPart === endPart) {
            startPart.focus();
            this.setSelectionByTextOffsets(startPart, startLocal, endLocal);
        } else {
            startPart.focus();
            const startPos = Formatter.resolveDomPositionFromTextOffset(startPart, startLocal);
            const endPos = Formatter.resolveDomPositionFromTextOffset(endPart, endLocal);
            if (!startPos || !startPos.container || !endPos || !endPos.container) {
                this.setSelectionByTextOffsets(startPart, startLocal, startLocal);
                return;
            }
            const range = document.createRange();
            const sel = window.getSelection();
            range.setStart(startPos.container, startPos.offset);
            range.setEnd(endPos.container, endPos.offset);
            sel.removeAllRanges();
            sel.addRange(range);
        }
    }

    resolveBlockElementFromNode(node) {
        let current = node;
        if (!current) return null;
        if (current.nodeType === 3) current = current.parentElement;
        if (!current || current.nodeType !== 1) return null;
        return current.closest('[data-block-id], [data-index]');
    }

    getBlockIdFromElement(element) {
        if (!element) return null;
        if (element.dataset?.blockId) return String(element.dataset.blockId);
        const index = Number.parseInt(element.dataset?.index, 10);
        return Number.isInteger(index) ? this.state.doc.blocks[index]?.id || null : null;
    }

    getFallbackBlockElement() {
        const selection = window.getSelection();
        const fromSelection = this.resolveBlockElementFromNode(selection?.anchorNode || null);
        if (fromSelection) return fromSelection;

        const activeEl = document.activeElement;
        const fromActive = this.resolveBlockElementFromNode(activeEl);
        if (fromActive) return fromActive;

        if (this.lastFocusedBlockEl && document.contains(this.lastFocusedBlockEl)) return this.lastFocusedBlockEl;

        if (this.activeBlockId) {
            const found = document.querySelector(`[data-block-id="${this.activeBlockId}"]`);
            if (found) return found;
        }
        if (this.activeBlockIndex !== null) {
            const found = document.querySelector(`[data-index="${this.activeBlockIndex}"]`);
            if (found) return found;
        }

        return null;
    }

    getActiveBlockContextFromSelection() {
        const blockEl = this.getFallbackBlockElement();
        if (!blockEl) {
            this.debugEnter('getActiveBlockContextFromSelection: no blockEl', {
                activeBlockIndex: this.activeBlockIndex,
                activeBlockId: this.activeBlockId,
                hasLastFocused: !!this.lastFocusedBlockEl,
                activeElementTag: document.activeElement?.tagName ?? null
            });
            return null;
        }

        const blockId = this.getBlockIdFromElement(blockEl);
        const index = blockId ? this.state.getBlockIndexById(blockId) : Number.parseInt(blockEl.dataset.index, 10);
        if (!Number.isInteger(index) || index < 0) return null;

        const parts = blockId
            ? Array.from(document.querySelectorAll(`[data-block-id="${blockId}"].block-text`))
            : Array.from(document.querySelectorAll(`[data-index="${index}"].block-text`));
        if (parts.length > 1) {
            parts.sort((a, b) => parseInt(a.dataset.splitPart || '0') - parseInt(b.dataset.splitPart || '0'));

            let currentEl = this.resolveBlockElementFromNode(window.getSelection()?.anchorNode || null);
            if (!currentEl || this.getBlockIdFromElement(currentEl) !== blockId) currentEl = blockEl;

            let partIndex = parts.indexOf(currentEl);
            if (partIndex === -1) partIndex = 0;

            return { index, blockId, el: currentEl, isSplit: true, parts, partIndex };
        }

        return { index, blockId, el: blockEl, isSplit: false, parts: [blockEl], partIndex: 0 };
    }

    getCaretTextOffsetInElement(el) {
        const sel = window.getSelection();
        if (!sel.rangeCount) return null;

        const range = sel.getRangeAt(0);
        if (!el.contains(range.startContainer) && range.startContainer !== el) return null;

        const start = Formatter.getTextOffsetFromDomPosition(el, range.startContainer, range.startOffset);
        const end = Formatter.getTextOffsetFromDomPosition(el, range.endContainer, range.endOffset);
        if (start === null || end === null) return null;

        return {
            start,
            selectionLen: Math.max(0, end - start),
            collapsed: range.collapsed,
            fullLen: Formatter.getTextLengthFromDom(el)
        };
    }

    isCaretAtStart(el) {
        const o = this.getCaretTextOffsetInElement(el);
        return !!o && o.collapsed && o.start === 0;
    }

    isCaretAtEnd(el) {
        const o = this.getCaretTextOffsetInElement(el);
        return !!o && o.collapsed && o.start === o.fullLen;
    }

    focusEditableElement(el, position = 'start') {
        if (!el) return false;
        if (typeof this.renderer?.ensureCaretPlaceholder === 'function' && el.isContentEditable) {
            this.renderer.ensureCaretPlaceholder(el);
        }

        el.focus();
        const sel = window.getSelection();
        const range = document.createRange();
        const textLen = Formatter.getTextLengthFromDom(el);
        const targetOffset = position === 'end' ? textLen : 0;
        const domPos = Formatter.resolveDomPositionFromTextOffset(el, targetOffset);

        if (domPos && domPos.container) {
            range.setStart(domPos.container, domPos.offset);
            range.collapse(true);
        } else {
            range.selectNodeContents(el);
            range.collapse(position === 'start');
        }

        sel.removeAllRanges();
        sel.addRange(range);
        el.scrollIntoView({ block: 'nearest' });
        return true;
    }

    focusListItem(blockIndex, itemIndex, position = 'start', attempt = 0) {
        const listEl = document.querySelector(`[data-index="${blockIndex}"]`);
        const li = listEl ? listEl.querySelector(`li[data-idx="${itemIndex}"]`) : null;
        if (!li) {
            if (attempt < 10) {
                setTimeout(() => this.focusListItem(blockIndex, itemIndex, position, attempt + 1), 16);
                return false;
            }
            this.debugEnter('focusListItem abort: no li', { blockIndex, itemIndex, position, attempt });
            return false;
        }
        const editable = li.querySelector('.checklist-text') || li;
        return this.focusEditableElement(editable, position);
    }

    focusBlockById(blockId, position = 'start', attempt = 0) {
        const index = this.state.getBlockIndexById(blockId);
        if (index < 0) {
            if (attempt < 8) setTimeout(() => this.focusBlockById(blockId, position, attempt + 1), 16);
            return false;
        }
        this.focusBlock(index, position, attempt);
        return true;
    }

    focusBlock(index, position, attempt = 0) {
        const els = Array.from(document.querySelectorAll(`[data-index="${index}"]`));
        if (!els.length) {
            if (attempt < 8) {
                setTimeout(() => this.focusBlock(index, position, attempt + 1), 16);
                return;
            }
            this.debugEnter('focusBlock abort: no els', { index, position, attempt });
            return;
        }

        let el = els[0];
        const splitParts = els.filter((x) => x.classList && x.classList.contains('block-text') && x.dataset.splitPart !== undefined);
        if (splitParts.length) {
            splitParts.sort((a, b) => parseInt(a.dataset.splitPart || '0') - parseInt(b.dataset.splitPart || '0'));
            el = (position === 'start') ? splitParts[0] : splitParts[splitParts.length - 1];
        } else {
            el = (position === 'start') ? els[0] : els[els.length - 1];
        }

        this.activeBlockIndex = index;
        this.activeBlockId = this.state.doc.blocks[index]?.id || this.getBlockIdFromElement(el);
        this.lastFocusedBlockEl = el;

        this.debugEnter('focusBlock', {
            index, position,
            tagName: el.tagName,
            className: el.className,
            innerHTML: el.innerHTML
        });

        if (el.classList.contains('block-image')) {
            el.focus();
            return;
        }

        if (typeof this.renderer?.ensureCaretPlaceholder === 'function') {
            this.renderer.ensureCaretPlaceholder(el);
        }

        el.focus();

        const range = document.createRange();
        const sel = window.getSelection();
        const textLen = Formatter.getTextLengthFromDom(el);
        const targetOffset = (position === 'start') ? 0 : textLen;
        const domPos = Formatter.resolveDomPositionFromTextOffset(el, targetOffset);

        if (domPos && domPos.container) {
            range.setStart(domPos.container, domPos.offset);
            range.collapse(true);
        } else {
            range.selectNodeContents(el);
            range.collapse(position === 'start');
        }

        sel.removeAllRanges();
        sel.addRange(range);

        this.debugEnter('focusBlock selection applied', {
            index, position, textLen,
            anchorNodeType: sel.anchorNode?.nodeType ?? null,
            anchorNodeText: sel.anchorNode?.textContent ?? null,
            anchorOffset: sel.anchorOffset ?? null
        });

        el.scrollIntoView({ block: 'nearest' });
    }

    focusInsertedBlock(index, kind = 'text') {
        const tryFocus = () => {
            if (kind === 'list') {
                const li = document.querySelector(`[data-index="${index}"] li`);
                if (li) return this.focusEditableElement(li, 'start');
            }
            if (kind === 'table') {
                const td = document.querySelector(`[data-index="${index}"] td`);
                if (td) return this.focusEditableElement(td, 'start');
            }
            if (kind === 'floating') {
                const boxText = document.querySelector(`.floating-box[data-index="${index}"] .box-text-content`);
                if (boxText) return this.focusEditableElement(boxText, 'start');
            }
            if (kind === 'image') {
                const imgBlock = document.querySelector(`.block-image[data-index="${index}"]`);
                if (imgBlock) {
                    imgBlock.focus();
                    imgBlock.scrollIntoView({ block: 'nearest' });
                    return true;
                }
            }
            this.focusBlock(index, 'start');
            return true;
        };
        setTimeout(tryFocus, 30);
    }

    getInsertBaseIndex() {
        const ctx = this.getActiveBlockContextFromSelection();
        if (ctx) return ctx.index;

        if (this.lastFocusedBlockEl && document.contains(this.lastFocusedBlockEl)) {
            return parseInt(this.lastFocusedBlockEl.dataset.index);
        }

        if (this.activeBlockId) {
            const index = this.state.getBlockIndexById(this.activeBlockId);
            if (index >= 0) return index;
        }
        if (Number.isInteger(this.activeBlockIndex)) return this.activeBlockIndex;
        return (this.state.doc.blocks?.length || 1) - 1;
    }

    getCurrentPageIndex() {
        const blockEl = this.getFallbackBlockElement();
        const pageEl = blockEl && blockEl.closest ? blockEl.closest('.page') : null;
        if (pageEl && pageEl.dataset && pageEl.dataset.pageNum) {
            return Math.max(0, parseInt(pageEl.dataset.pageNum) - 1);
        }
        return 0;
    }

    syncCurrentTextBlockFromDom() {
        const ctx = this.getActiveBlockContextFromSelection();
        if (!ctx) return;
        const block = this.state.doc.blocks[ctx.index];
        if (!block || block.type !== 'text') return;
        this.state.updateBlockContent(ctx.index, this.getMergedHtmlForBlock(ctx.index), 'typing');
    }

    normalizeTextBlockHtml(html) {
        return Formatter.normalizeTextBlockHtml(html, { emptyAsBr: true });
    }

    isBlankBlockHtml(html) {
        return Formatter.isMeaningfullyEmptyHtml(html);
    }

    getCleanBlockHtmlFromElement(el) {
        if (!el) return '<br>';
        const clone = el.cloneNode(true);
        const highlights = clone.querySelectorAll('.find-highlight');
        highlights.forEach((h) => {
            const t = document.createTextNode(h.textContent || '');
            h.parentNode.replaceChild(t, h);
        });
        clone.querySelectorAll('.footnote-anchor, .endnote-anchor').forEach((anchor) => anchor.remove());
        return this.normalizeTextBlockHtml(clone.innerHTML || '');
    }

    getMergedHtmlForBlock(index) {
        const parts = Array.from(document.querySelectorAll(`[data-index="${index}"].block-text`));
        if (!parts.length) return this.normalizeTextBlockHtml(this.state.doc.blocks[index]?.content || '');
        if (parts.length === 1) return this.getCleanBlockHtmlFromElement(parts[0]);
        parts.sort((a, b) => parseInt(a.dataset.splitPart || '0') - parseInt(b.dataset.splitPart || '0'));
        return this.normalizeTextBlockHtml(parts.map((p) => this.getCleanBlockHtmlFromElement(p)).join(''));
    }

    getPartIndexForNode(parts, node) {
        let el = node;
        if (el && el.nodeType === 3) el = el.parentElement;
        if (!el || el.nodeType !== 1) return -1;
        const host = el.closest('[data-index]');
        if (!host) return -1;
        return parts.indexOf(host);
    }

    getSplitHtmlFromSelection(ctx) {
        const sel = window.getSelection();
        if (!sel.rangeCount) return null;

        const range = sel.getRangeAt(0).cloneRange();
        const parts = (ctx.parts && ctx.parts.length ? [...ctx.parts] : [ctx.el]).sort(
            (a, b) => parseInt(a.dataset.splitPart || '0') - parseInt(b.dataset.splitPart || '0')
        );

        let startPartIndex = this.getPartIndexForNode(parts, range.startContainer);
        let endPartIndex = this.getPartIndexForNode(parts, range.endContainer);

        if (startPartIndex === -1 && ctx.el.contains(range.startContainer)) startPartIndex = ctx.partIndex;
        if (endPartIndex === -1 && ctx.el.contains(range.endContainer)) endPartIndex = ctx.partIndex;

        if (startPartIndex === -1 || endPartIndex === -1) {
            if (range.startContainer === ctx.el || range.endContainer === ctx.el) {
                startPartIndex = ctx.partIndex;
                endPartIndex = ctx.partIndex;
            } else {
                this.debugEnter('getSplitHtmlFromSelection: failed to resolve part indexes', {
                    startPartIndex, endPartIndex, partCount: parts.length,
                    startContainerType: range.startContainer?.nodeType ?? null,
                    endContainerType: range.endContainer?.nodeType ?? null
                });
                return null;
            }
        }

        const startPart = parts[startPartIndex];
        const endPart = parts[endPartIndex];

        const beforePartsHtml = parts.slice(0, startPartIndex).map((p) => this.getCleanBlockHtmlFromElement(p)).join('');
        const afterPartsHtml = parts.slice(endPartIndex + 1).map((p) => this.getCleanBlockHtmlFromElement(p)).join('');

        const leftRange = document.createRange();
        leftRange.selectNodeContents(startPart);
        leftRange.setEnd(range.startContainer, range.startOffset);

        const rightRange = document.createRange();
        rightRange.selectNodeContents(endPart);
        rightRange.setStart(range.endContainer, range.endOffset);

        const leftLocalHtml = Formatter.rangeToHtml(leftRange);
        const rightLocalHtml = Formatter.rangeToHtml(rightRange);

        const result = {
            leftHtml: this.normalizeTextBlockHtml(beforePartsHtml + leftLocalHtml),
            rightHtml: this.normalizeTextBlockHtml(rightLocalHtml + afterPartsHtml)
        };

        this.debugEnter('getSplitHtmlFromSelection result', {
            leftHtml: result.leftHtml, rightHtml: result.rightHtml,
            selectionText: sel.toString(), startPartIndex, endPartIndex
        });

        return result;
    }

    splitBlock(index) {
        const ctx = this.getActiveBlockContextFromSelection() || {
            index, el: this.getFallbackBlockElement(),
            isSplit: false, parts: [], partIndex: 0
        };

        this.debugEnter('splitBlock start', {
            requestedIndex: index, ctxIndex: ctx?.index ?? null, hasEl: !!ctx?.el,
            isSplit: !!ctx?.isSplit, partIndex: ctx?.partIndex ?? null,
            partCount: ctx?.parts?.length ?? 0, activeBlockIndex: this.activeBlockIndex
        });

        if (ctx.index !== index) {
            this.debugEnter('splitBlock abort: ctx.index mismatch', { requestedIndex: index, ctxIndex: ctx.index });
            return;
        }

        const sourceBlock = this.state.doc.blocks[index];
        if (!sourceBlock || sourceBlock.type !== 'text') {
            this.debugEnter('splitBlock abort: invalid source block', { index, blockType: sourceBlock?.type ?? null });
            return;
        }

        const style = sourceBlock.style || 'normal';
        const fullHtml = this.normalizeTextBlockHtml(typeof sourceBlock.content === 'string' ? sourceBlock.content : '');
        const domSplit = ctx.el ? this.getSplitHtmlFromSelection(ctx) : null;

        this.debugEnter('splitBlock source', { index, fullHtml, style, domSplit });

        if (this.isBlankBlockHtml(fullHtml)) {
            this.debugEnter('splitBlock empty source branch', { index, fullHtml });
            this.engine.dispatch('insertBlock', {
                index: index + 1,
                source: 'enter',
                block: {
                    type: 'text', style, content: '<br>',
                    preserveWhitespace: !!sourceBlock.preserveWhitespace
                }
            });
            this.debugEnter('splitBlock empty source focus target', { focusIndex: index + 1, reason: 'current block already blank' });
            setTimeout(() => this.focusBlock(index + 1, 'start'), 0);
            return;
        }

        if (domSplit) {
            const leftHtml = this.normalizeTextBlockHtml(domSplit.leftHtml);
            const rightHtml = this.normalizeTextBlockHtml(domSplit.rightHtml);
            const splitAtStart = this.isBlankBlockHtml(leftHtml) && !this.isBlankBlockHtml(rightHtml);
            const targetIndex = splitAtStart ? index : index + 1;

            this.debugEnter('splitBlock domSplit branch', { index, leftHtml, rightHtml, splitAtStart, focusIndex: targetIndex });

            this.engine.dispatch('splitTextBlock', {
                index,
                blockId: sourceBlock.id,
                block: { ...sourceBlock, content: leftHtml },
                newBlock: {
                    type: 'text', style, content: rightHtml,
                    preserveWhitespace: !!sourceBlock.preserveWhitespace
                },
                source: 'enter',
                meta: { splitAtStart, targetIndex }
            });

            setTimeout(() => this.focusBlock(targetIndex, 'start'), 0);
            return;
        }

        const sel = window.getSelection();
        if (!sel.rangeCount) {
            this.debugEnter('splitBlock no rangeCount branch', { index });
            this.engine.dispatch('insertBlock', {
                index: index + 1,
                source: 'enter',
                block: {
                    type: 'text', style, content: '<br>',
                    preserveWhitespace: !!sourceBlock.preserveWhitespace
                }
            });
            this.debugEnter('splitBlock no rangeCount focus target', { focusIndex: index + 1 });
            setTimeout(() => this.focusBlock(index + 1, 'start'), 0);
            return;
        }

        const local = ctx.el ? this.getCaretTextOffsetInElement(ctx.el) : null;
        if (!local) {
            this.debugEnter('splitBlock no local caret branch', { index, hasEl: !!ctx.el });
            this.engine.dispatch('insertBlock', {
                index: index + 1,
                source: 'enter',
                block: {
                    type: 'text', style, content: '<br>',
                    preserveWhitespace: !!sourceBlock.preserveWhitespace
                }
            });
            this.debugEnter('splitBlock no local caret focus target', { focusIndex: index + 1 });
            setTimeout(() => this.focusBlock(index + 1, 'start'), 0);
            return;
        }

        let base = 0;
        if (ctx.isSplit) {
            for (let i = 0; i < ctx.partIndex; i++) {
                base += Formatter.getTextLengthFromDom(ctx.parts[i]);
            }
        }

        const globalTextOffset = base + local.start;
        const parts = Formatter.splitHtmlByTextOffset(fullHtml, globalTextOffset);
        const leftHtml = this.normalizeTextBlockHtml(parts.a);
        const rightHtml = this.normalizeTextBlockHtml(parts.b);
        const splitAtStart = this.isBlankBlockHtml(leftHtml) && !this.isBlankBlockHtml(rightHtml);
        const targetIndex = splitAtStart ? index : index + 1;

        this.debugEnter('splitBlock textOffset branch', {
            index, base, local, globalTextOffset, parts, leftHtml, rightHtml, splitAtStart, focusIndex: targetIndex
        });

        this.engine.dispatch('splitTextBlock', {
            index,
            blockId: sourceBlock.id,
            block: { ...sourceBlock, content: leftHtml },
            newBlock: {
                type: 'text', style, content: rightHtml,
                preserveWhitespace: !!sourceBlock.preserveWhitespace
            },
            source: 'enter',
            splitOffset: globalTextOffset,
            meta: { splitAtStart, targetIndex }
        });

        setTimeout(() => this.focusBlock(targetIndex, 'start'), 0);
    }

    setupBeforeInput() {
        if (!this.supportsBeforeInput) return;

        document.addEventListener('beforeinput', (e) => {
            if (e.defaultPrevented) return;
            if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) return;
            if (this.engine?.inputManager?.handlesModelInput(e.target)) return;
            if (e.inputType !== 'insertParagraph') return;

            const ctx = this.getActiveBlockContextFromSelection();
            this.debugEnter('beforeinput insertParagraph', {
                inputType: e.inputType, activeBlockIndex: this.activeBlockIndex,
                ctxIndex: ctx?.index ?? null, isCollapsed: window.getSelection()?.isCollapsed ?? null,
                anchorNodeType: window.getSelection()?.anchorNode?.nodeType ?? null,
                anchorText: window.getSelection()?.anchorNode?.textContent ?? null,
                anchorOffset: window.getSelection()?.anchorOffset ?? null
            });

            if (!ctx) { this.debugEnter('beforeinput aborted: no context'); return; }

            const idx = ctx.index;
            const block = this.state.doc.blocks[idx];
            if (!block || block.type !== 'text') {
                this.debugEnter('beforeinput aborted: non-text block', { idx, blockType: block?.type ?? null });
                return;
            }

            e.preventDefault();
            this.splitBlock(idx);
        });
    }

    setupFocusTracking() {
        document.addEventListener('focusin', (e) => {
            const blockEl = this.resolveBlockElementFromNode(e.target);
            if (blockEl) {
                this.lastFocusedBlockEl = blockEl;
                this.activeBlockId = this.getBlockIdFromElement(blockEl);
                this.activeBlockIndex = this.activeBlockId
                    ? this.state.getBlockIndexById(this.activeBlockId)
                    : parseInt(blockEl.dataset.index);
                this.debugEnter('focusin', {
                    activeBlockIndex: this.activeBlockIndex,
                    activeBlockId: this.activeBlockId,
                    datasetIndex: blockEl.dataset.index,
                    className: blockEl.className
                });
            }
        });

        document.addEventListener('mousedown', (e) => {
            const blockEl = this.resolveBlockElementFromNode(e.target);
            if (blockEl) {
                this.lastFocusedBlockEl = blockEl;
                this.activeBlockId = this.getBlockIdFromElement(blockEl);
                this.activeBlockIndex = this.activeBlockId
                    ? this.state.getBlockIndexById(this.activeBlockId)
                    : parseInt(blockEl.dataset.index);
                this.debugEnter('mousedown', {
                    activeBlockIndex: this.activeBlockIndex,
                    activeBlockId: this.activeBlockId,
                    datasetIndex: blockEl.dataset.index,
                    className: blockEl.className
                });
            }
        });
    }

    initPersistence() {
        const savedZoom = this.loadPreference('zoom');
        if (savedZoom) this.renderer.setZoom(parseFloat(savedZoom));

        const savedMode = this.loadPreference('viewMode');
        if (savedMode && savedMode !== 'page') {
            this.renderer.setMode(savedMode === 'pageless');
        }

        this.outline._outlineCollapseState = this.loadPreference('outlineCollapse') || {};
    }

    savePreference(key, value) {
        try { localStorage.setItem(`opendoc_${key}`, JSON.stringify(value)); } catch (e) { /* ignore */ }
    }

    loadPreference(key) {
        try { const val = localStorage.getItem(`opendoc_${key}`); return val ? JSON.parse(val) : null; } catch (e) { return null; }
    }

    updateStats(blocks) {
        const tmp = document.createElement('div');
        let text = "";
        let charCount = 0;

        (blocks || []).forEach((b) => {
            if (b.type === 'text' && typeof b.content === 'string') {
                tmp.innerHTML = b.content;
                const t = (tmp.textContent || '');
                text += t + " ";
                charCount += t.length;
            } else if (typeof b.content === 'string') {
                text += b.content + " ";
                charCount += b.content.length;
            }
        });

        const wordCount = text.split(/\s+/).filter((w) => w.length > 0).length;
        document.getElementById('word-count').innerText = `${wordCount.toLocaleString()} words`;
        const charEl = document.getElementById('char-count');
        if (charEl) charEl.innerText = `${charCount.toLocaleString()} chars`;
    }

    debugEnter(label, data = {}) {
        if (!window.DEBUG_ENTER) return;
        try { console.log(`[ENTER DEBUG] ${label}`, data); } catch (err) { console.log(`[ENTER DEBUG] ${label}`); }
    }

    setupWelcomePage() {
        const welcome = document.getElementById('welcome-page');
        const btnNew = document.getElementById('btn-welcome-new');
        const btnOpen = document.getElementById('btn-welcome-open');
        const recentList = document.getElementById('welcome-recent-list');
        const recentSection = document.getElementById('welcome-recent');

        if (btnNew) {
            btnNew.addEventListener('click', async () => {
                await this.state.createNewDoc();
                if (welcome) welcome.classList.add('hidden');
            });
        }

        if (btnOpen) {
            btnOpen.addEventListener('click', () => {
                const sb = document.getElementById('doc-sidebar');
                if (sb) {
                    sb.classList.remove('hidden');
                    const btnDocs = document.getElementById('btn-docs');
                    if (btnDocs) btnDocs.click();
                }
            });
        }

        document.addEventListener('click', (e) => {
            const card = e.target.closest('.welcome-template-card');
            if (!card) return;
            const template = card.dataset.template;
            this.createFromTemplate(template);
            if (welcome) welcome.classList.add('hidden');
        });

        if (recentList && recentSection) {
            this.loadRecentDocs(recentList, recentSection);
        }
    }

    async loadRecentDocs(recentList, recentSection) {
        try {
            const docs = await this.state.loadDocsList();
            if (!docs || docs.length === 0) {
                recentSection.style.display = 'none';
                return;
            }

            const sorted = docs.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
            const recent = sorted.slice(0, 5);
            recentList.innerHTML = '';

            recent.forEach(doc => {
                const item = document.createElement('div');
                item.className = 'welcome-recent-item';
                item.innerHTML = `
                    <div>
                        <div class="welcome-recent-item-name">${doc.title}</div>
                    </div>
                    <div class="welcome-recent-item-date">${new Date(doc.updatedAt).toLocaleDateString()}</div>
                `;
                item.addEventListener('click', async () => {
                    await this.state.loadDoc(doc.id);
                    const welcome = document.getElementById('welcome-page');
                    if (welcome) welcome.classList.add('hidden');
                });
                recentList.appendChild(item);
            });
        } catch (e) {
            recentSection.style.display = 'none';
        }
    }

    createFromTemplate(template) {
        if (template === 'blank') {
            this.state.createNewDoc();
            return;
        }

        const templateContent = {
            report: {
                title: 'Report',
                blocks: [
                    { type: 'text', style: 'h1', content: 'Report Title', id: Date.now() + Math.random() },
                    { type: 'text', style: 'h2', content: 'Executive Summary', id: Date.now() + Math.random() + 1 },
                    { type: 'text', style: 'normal', content: 'Enter your executive summary here.', id: Date.now() + Math.random() + 2 },
                    { type: 'text', style: 'h2', content: 'Findings', id: Date.now() + Math.random() + 3 },
                    { type: 'text', style: 'normal', content: 'Details of your findings here.', id: Date.now() + Math.random() + 4 },
                ]
            },
            letter: {
                title: 'Letter',
                blocks: [
                    { type: 'text', style: 'normal', content: 'Dear Recipient,<br><br>', id: Date.now() + Math.random() },
                    { type: 'text', style: 'normal', content: 'Body of your letter here.', id: Date.now() + Math.random() + 1 },
                    { type: 'text', style: 'normal', content: '<br>Sincerely,<br>Your Name', id: Date.now() + Math.random() + 2 },
                ]
            },
            notes: {
                title: 'Meeting Notes',
                blocks: [
                    { type: 'text', style: 'h1', content: 'Meeting Notes', id: Date.now() + Math.random() },
                    { type: 'ul', items: [{ text: 'Date: ', level: 0 }, { text: 'Attendees: ', level: 0 }, { text: 'Location: ', level: 0 }], id: Date.now() + Math.random() + 1 },
                    { type: 'text', style: 'h2', content: 'Agenda', id: Date.now() + Math.random() + 2 },
                    { type: 'ol', items: [{ text: 'Item 1', level: 0 }, { text: 'Item 2', level: 0 }], id: Date.now() + Math.random() + 3 },
                ]
            }
        }[template];

        if (templateContent) {
            this.state.createNewDoc({ title: templateContent.title, blocks: templateContent.blocks });
        } else {
            this.state.createNewDoc();
        }
    }

    setupStatusBarViewButtons() {
        const btnPage = document.getElementById('btn-view-page-sb');
        const btnWeb = document.getElementById('btn-view-web-sb');
        const btnSplit = document.getElementById('btn-split-view-sb');
        const btnViewPage = document.getElementById('btn-view-page');
        const btnViewWeb = document.getElementById('btn-view-web');

        const updateViewBtns = () => {
            if (btnPage) btnPage.classList.toggle('active', this.renderer.isPageView);
            if (btnWeb) btnWeb.classList.toggle('active', !this.renderer.isPageView);
        };

        if (btnPage) btnPage.addEventListener('click', () => this.renderer.setMode(true));
        if (btnWeb) btnWeb.addEventListener('click', () => this.renderer.setMode(false));
        if (btnSplit) btnSplit.addEventListener('click', () => this.toggleSplitView());
        if (btnViewPage) {
            btnViewPage.addEventListener('click', () => { this.renderer.setMode(true); updateViewBtns(); });
        }
        if (btnViewWeb) {
            btnViewWeb.addEventListener('click', () => { this.renderer.setMode(false); updateViewBtns(); });
        }

        this.state.subscribe(() => updateViewBtns());
    }

    toggleSplitView() {
        const splitWrapper = document.getElementById('workspace-split-wrapper');
        const mainWrapper = document.getElementById('workspace-wrapper');
        if (!splitWrapper || !mainWrapper) return;

        if (this.splitViewActive) {
            splitWrapper.classList.add('hidden');
            mainWrapper.style.display = '';
            this.splitViewActive = false;
        } else {
            mainWrapper.style.display = 'none';
            splitWrapper.classList.remove('hidden');
            this.splitViewActive = true;
            this.setupSplitViewDragDrop();
        }
    }

    setupSplitViewDragDrop() {
        const leftPane = document.getElementById('workspace-split-l');
        const rightPane = document.getElementById('workspace-split-r');
        if (!leftPane || !rightPane || leftPane.dataset._splitSetup) return;

        leftPane.dataset._splitSetup = '1';
        rightPane.dataset._splitSetup = '1';

        this.renderer.render(this.state.doc, this.state.hfMode);
        const leftClone = document.getElementById('workspace').cloneNode(true);
        leftPane.innerHTML = '';
        leftPane.appendChild(leftClone);

        const closeBtns = document.querySelectorAll('.split-close-btn');
        closeBtns.forEach(btn => {
            btn.addEventListener('click', () => this.toggleSplitView());
        });
    }

    updatePageCount(count) {
        const el = document.getElementById('page-count');
        if (el) el.innerText = `Page ${count || 1}`;
    }

    updateReviewPanel() {
        this.reviewManager?.renderReviewPanel();
    }

    setupMobileNav() {
        const navItems = document.querySelectorAll('.mobile-nav-item');
        const overlay = document.getElementById('mobile-sheet-overlay');
        const sheetOutline = document.getElementById('mobile-sheet-outline');
        const sheetCloseBtn = sheetOutline?.querySelector('.mobile-sheet-close-btn');

        if (!navItems.length) return;

        const closeSheet = () => {
            overlay?.classList.remove('open');
            sheetOutline?.classList.remove('open');
            document.body.style.overflow = '';
        };

        const openSheet = (sheet) => {
            closeSheet();
            if (sheet) {
                overlay?.classList.add('open');
                sheet.classList.add('open');
                document.body.style.overflow = 'hidden';
            }
        };

        navItems.forEach(item => {
            item.addEventListener('click', () => {
                const nav = item.dataset.nav;
                navItems.forEach(n => n.classList.remove('active'));
                item.classList.add('active');

                switch (nav) {
                    case 'docs': {
                        const sb = document.getElementById('doc-sidebar');
                        if (sb) sb.classList.remove('hidden');
                        const btnDocs = document.getElementById('btn-docs');
                        if (btnDocs) btnDocs.click();
                        break;
                    }
                    case 'outline': {
                        if (this.state.doc && this.state.doc.blocks) {
                            this.outline.updateOutline(this.state.doc.blocks);
                        }
                        openSheet(sheetOutline);
                        break;
                    }
                    case 'find': {
                        this.modal.openFind();
                        break;
                    }
                    case 'review': {
                        const rp = document.getElementById('review-panel');
                        if (rp) {
                            rp.classList.toggle('hidden');
                            this.updateReviewPanel();
                        }
                        break;
                    }
                    case 'more': {
                        const toggle = document.getElementById('btn-toolbar-toggle');
                        if (toggle) toggle.click();
                        break;
                    }
                }
            });
        });

        if (overlay) {
            overlay.addEventListener('click', (e) => {
                if (e.target === overlay) closeSheet();
            });
        }

        if (sheetCloseBtn) {
            sheetCloseBtn.addEventListener('click', closeSheet);
        }

        if (sheetOutline) {
            const searchInput = document.getElementById('inp-mob-outline-search');
            if (searchInput) {
                searchInput.addEventListener('input', () => {
                    const query = searchInput.value.trim();
                    const container = document.getElementById('mob-outline-content');
                    if (!container) return;
                    const items = container.querySelectorAll('.outline-item');
                    items.forEach(item => {
                        const text = item.textContent || '';
                        item.style.display = (!query || text.toLowerCase().includes(query.toLowerCase())) ? '' : 'none';
                    });
                });
            }
        }
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/clipboard/clipboard-manager.js
// ================================================================
import { Transaction } from '../transaction.js';
import { cloneDocumentValue } from '../schema.js';
import { createStableId, ensureBlockIdentity } from '../id.js';
import { ensureBlockRuns, getBlockRuns, getBlockText, withBlockRuns } from '../inline/block-inline.js';
import { concatRuns, splitRunsAtOffset, splitRunsAtRange } from '../inline/inline-operations.js';
import { getRunsText } from '../inline/inline-model.js';
import { runsToHtml } from '../inline/runs-to-html.js';
import { Formatter } from '../../formatter.js';

export const OPENWORD_CLIPBOARD_TYPE = 'application/x-openword-fragment';

function cloneBlock(block) {
    const next = cloneDocumentValue(block);
    next.id = createStableId('blk');
    if (Array.isArray(next.children)) next.children.forEach(run => { run.id = createStableId('run'); });
    if (Array.isArray(next.items)) next.items.forEach(item => { if (item && typeof item === 'object') item.id = createStableId('item'); });
    if (next.type === 'table') {
        next.rowIds = (next.rows || []).map(() => createStableId('row'));
        next.cellIds = (next.rows || []).map(row => (row || []).map(() => createStableId('cell')));
        next.cellMeta = {};
    }
    return ensureBlockIdentity(next).block;
}

function sanitizeHtml(html) {
    if (typeof document === 'undefined') return String(html || '');
    const root = document.createElement('div');
    root.innerHTML = String(html || '');
    root.querySelectorAll('script,style,iframe,object,embed,form,input,button,textarea,select,meta,link').forEach(node => node.remove());
    root.querySelectorAll('*').forEach(node => [...node.attributes].forEach(attr => {
        if (attr.name.toLowerCase().startsWith('on') || (/^(href|src)$/i.test(attr.name) && /^javascript:/i.test(attr.value.trim()))) node.removeAttribute(attr.name);
    }));
    return root.innerHTML;
}

export class ClipboardManager {
    constructor(controller) {
        this.ctrl = controller;
        this.state = controller.state;
        this.engine = controller.engine;
        this.lastInternal = null;
    }

    setup() {
        document.addEventListener('copy', event => this.handleCopy(event));
        document.addEventListener('cut', event => this.handleCut(event));
        document.addEventListener('paste', event => this.handlePaste(event), true);
    }

    isEditorTarget(target) { return !!target?.closest?.('#workspace, #workspace-split-wrapper'); }

    extract(selection = this.engine.captureSelection()) {
        if (!selection) return null;
        if (selection.type === 'table') return this.extractTable(selection);
        const normalized = this.engine.normalizeTextSelection(selection);
        if (!normalized) return null;
        const blocks = [];
        for (let index = normalized.startIndex; index <= normalized.endIndex; index += 1) {
            const block = this.state.doc.blocks[index];
            if (!block) continue;
            if (block.type !== 'text') { blocks.push(cloneDocumentValue(block)); continue; }
            const runs = getBlockRuns(block);
            const from = index === normalized.startIndex ? normalized.start.offset : 0;
            const to = index === normalized.endIndex ? normalized.end.offset : getRunsText(runs).length;
            blocks.push(withBlockRuns({ ...block }, splitRunsAtRange(runs, from, to).selected));
        }
        return { schemaVersion: 2, sourceDocumentId: this.state.doc.id, selectionType: 'text', blocks };
    }

    extractTable(selection) {
        const table = this.state.getBlockById(selection.tableId);
        const a = this.state.getTableCellPosition(table, selection.anchorCellId);
        const f = this.state.getTableCellPosition(table, selection.focusCellId);
        if (!table || !a || !f) return null;
        const top = Math.min(a.row, f.row), bottom = Math.max(a.row, f.row);
        const left = Math.min(a.col, f.col), right = Math.max(a.col, f.col);
        return { schemaVersion: 2, selectionType: 'table', table: { rows: table.rows.slice(top, bottom + 1).map(row => row.slice(left, right + 1)) } };
    }

    toText(fragment) {
        if (fragment?.selectionType === 'table') return (fragment.table.rows || []).map(row => row.join('\t')).join('\n');
        return (fragment?.blocks || []).map(block => block.type === 'text' ? getBlockText(block)
            : ['ul', 'ol', 'checklist'].includes(block.type) ? (block.items || []).map(item => item.text || '').join('\n')
            : block.type === 'table' ? (block.rows || []).map(row => row.join('\t')).join('\n') : String(block.content || '')).join('\n');
    }

    toHtml(fragment) {
        if (fragment?.selectionType === 'table') return `<table>${fragment.table.rows.map(row => `<tr>${row.map(cell => `<td>${cell || ''}</td>`).join('')}</tr>`).join('')}</table>`;
        return (fragment?.blocks || []).map(block => {
            if (block.type === 'text') { const tag = /^h[1-6]$/.test(block.style || '') ? block.style : block.style === 'quote' ? 'blockquote' : 'p'; return `<${tag}>${runsToHtml(getBlockRuns(block))}</${tag}>`; }
            if (block.type === 'ul' || block.type === 'ol') return `<${block.type}>${(block.items || []).map(item => `<li>${item.text || ''}</li>`).join('')}</${block.type}>`;
            if (block.type === 'table') return `<table>${(block.rows || []).map(row => `<tr>${row.map(cell => `<td>${cell || ''}</td>`).join('')}</tr>`).join('')}</table>`;
            return '';
        }).join('');
    }

    setData(event, fragment) {
        if (!fragment || !event.clipboardData) return false;
        const payload = JSON.stringify(fragment);
        event.clipboardData.setData(OPENWORD_CLIPBOARD_TYPE, payload);
        event.clipboardData.setData('text/plain', this.toText(fragment));
        event.clipboardData.setData('text/html', this.toHtml(fragment));
        this.lastInternal = payload;
        event.preventDefault();
        return true;
    }

    handleCopy(event) { if (this.isEditorTarget(event.target)) this.setData(event, this.extract()); }
    handleCut(event) {
        if (!this.isEditorTarget(event.target)) return;
        const selection = this.engine.captureSelection();
        if (!this.setData(event, this.extract(selection))) return;
        if (selection?.type === 'text') this.engine.dispatch('replaceSelection', { text: '', source: 'cut' }, { selection });
        else this.clearTable(selection);
    }

    handlePaste(event) {
        if (!this.isEditorTarget(event.target)) return;
        const data = event.clipboardData;
        if (!data) return;
        const internal = data.getData(OPENWORD_CLIPBOARD_TYPE);
        if (internal) {
            try { event.preventDefault(); this.insert(JSON.parse(internal)); return; } catch (_) { /* fallback */ }
        }
        const html = data.getData('text/html');
        if (html) {
            event.preventDefault();
            const blocks = Formatter.parseHTMLToBlocks(sanitizeHtml(html));
            if (blocks.length) this.insert({ schemaVersion: 2, selectionType: 'text', blocks });
            return;
        }
        const text = data.getData('text/plain');
        if (text) {
            const selection = this.engine.captureSelection();
            const raw = text.trim();
            if (selection?.type === 'text' && selection.anchor?.offset !== selection.focus?.offset && /^https?:\/\/\S+$/i.test(raw)) {
                event.preventDefault();
                this.engine.dispatch('createLink', { url: raw }, { selection });
                return;
            }
            event.preventDefault();
            this.engine.dispatch('replaceSelection', { text, source: 'paste' }, { selection });
        }
    }

    async copy() {
        const fragment = this.extract();
        if (!fragment) return false;
        this.lastInternal = JSON.stringify(fragment);
        await navigator.clipboard?.writeText?.(this.toText(fragment));
        return true;
    }
    async cut() { const selection = this.engine.captureSelection(); const ok = await this.copy(); if (ok && selection?.type === 'text') this.engine.dispatch('replaceSelection', { text: '', source: 'cut' }, { selection }); return ok; }
    async paste() { if (!navigator.clipboard?.readText) return false; const text = await navigator.clipboard.readText(); this.engine.dispatch('replaceSelection', { text, source: 'paste' }); return true; }

    insert(fragment) {
        if (fragment.selectionType === 'table') return this.pasteTable(fragment);
        const selection = this.engine.captureSelection();
        const transaction = this.createTransaction(selection, fragment);
        if (!transaction) return false;
        this.state.applyTransaction(transaction, true);
        this.engine.setSelection(transaction.selectionAfter, { restore: true });
        return true;
    }

    createTransaction(selection, fragment) {
        const normalized = this.engine.normalizeTextSelection(selection);
        const sourceBlocks = (fragment.blocks || []).map(cloneBlock);
        if (!normalized || !sourceBlocks.length) return null;
        if (this.engine.isTrackingChanges() && sourceBlocks.length > 1) {
            return this.engine.createReplaceSelectionTransaction(selection, { text: this.toText(fragment), source: 'paste' });
        }
        if (sourceBlocks.length === 1 && sourceBlocks[0].type === 'text') return this.engine.createReplaceSelectionTransaction(selection, { runs: getBlockRuns(sourceBlocks[0]), source: 'paste' });
        const startBlock = this.state.doc.blocks[normalized.startIndex];
        const endBlock = this.state.doc.blocks[normalized.endIndex];
        if (startBlock?.type !== 'text' || endBlock?.type !== 'text') return null;
        const left = splitRunsAtOffset(getBlockRuns(startBlock), normalized.start.offset).left;
        const right = splitRunsAtOffset(getBlockRuns(endBlock), normalized.end.offset).right;
        if (sourceBlocks[0].type === 'text') sourceBlocks[0] = withBlockRuns(sourceBlocks[0], concatRuns(left, getBlockRuns(sourceBlocks[0])));
        else sourceBlocks.unshift(withBlockRuns({ ...ensureBlockRuns(startBlock), id: createStableId('blk') }, left));
        const lastIndex = sourceBlocks.length - 1;
        if (sourceBlocks[lastIndex].type === 'text') sourceBlocks[lastIndex] = withBlockRuns(sourceBlocks[lastIndex], concatRuns(getBlockRuns(sourceBlocks[lastIndex]), right));
        else sourceBlocks.push(withBlockRuns({ ...ensureBlockRuns(endBlock), id: createStableId('blk') }, right));
        sourceBlocks[0].id = startBlock.id;
        const operations = [{ type: 'REPLACE_BLOCK_STATE', blockId: startBlock.id, index: normalized.startIndex, block: sourceBlocks[0], prevBlock: cloneDocumentValue(startBlock), source: 'paste' }];
        for (let index = normalized.endIndex; index > normalized.startIndex; index -= 1) { const block = this.state.doc.blocks[index]; operations.push({ type: 'REMOVE_BLOCK', blockId: block.id, index, block: cloneDocumentValue(block), source: 'paste' }); }
        sourceBlocks.slice(1).forEach((block, offset) => operations.push({ type: 'ADD_BLOCK', index: normalized.startIndex + offset + 1, blockId: block.id, block, source: 'paste' }));
        const final = sourceBlocks[sourceBlocks.length - 1];
        const offset = final.type === 'text' ? Math.max(0, getBlockText(final).length - getRunsText(right).length) : 0;
        const after = final.type === 'text' ? { type: 'text', anchor: { blockId: final.id, offset, affinity: 'forward' }, focus: { blockId: final.id, offset, affinity: 'forward' }, direction: 'forward' } : selection;
        return new Transaction({ source: 'paste', operations, selectionBefore: selection, selectionAfter: after, meta: { inputType: 'paste', mergeable: false } });
    }

    clearTable(selection) {
        const table = this.state.getBlockById(selection?.tableId);
        const a = this.state.getTableCellPosition(table, selection?.anchorCellId), f = this.state.getTableCellPosition(table, selection?.focusCellId);
        if (!table || !a || !f) return false;
        const next = cloneDocumentValue(table);
        for (let r = Math.min(a.row, f.row); r <= Math.max(a.row, f.row); r += 1) for (let c = Math.min(a.col, f.col); c <= Math.max(a.col, f.col); c += 1) next.rows[r][c] = '';
        return this.state.replaceBlockById(table.id, next, 'cut');
    }

    pasteTable(fragment) {
        const selection = this.engine.captureSelection();
        const table = this.state.getBlockById(selection?.tableId);
        const start = this.state.getTableCellPosition(table, selection?.anchorCellId);
        if (!table || !start) return false;
        const next = cloneDocumentValue(table);
        (fragment.table?.rows || []).forEach((row, r) => row.forEach((cell, c) => { if (next.rows[start.row + r]?.[start.col + c] !== undefined) next.rows[start.row + r][start.col + c] = cell; }));
        return this.state.replaceBlockById(table.id, next, 'paste');
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/command-registry.js
// ================================================================
export class CommandRegistry {
    constructor() {
        this.commands = new Map();
    }

    register(name, handler, options = {}) {
        if (!name || typeof handler !== 'function') {
            throw new TypeError('Command registration requires a name and handler.');
        }
        if (this.commands.has(name) && !options.replace) {
            throw new Error(`Command already registered: ${name}`);
        }
        this.commands.set(name, { handler, options: { ...options } });
        return () => this.unregister(name, handler);
    }

    unregister(name, handler = null) {
        const entry = this.commands.get(name);
        if (!entry) return false;
        if (handler && entry.handler !== handler) return false;
        return this.commands.delete(name);
    }

    has(name) {
        return this.commands.has(name);
    }

    get(name) {
        return this.commands.get(name) || null;
    }

    execute(name, context) {
        const entry = this.commands.get(name);
        if (!entry) throw new Error(`Unknown editor command: ${name}`);
        return entry.handler(context);
    }

    list() {
        return [...this.commands.keys()];
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/editor-engine.js
// ================================================================
import { CommandRegistry } from './command-registry.js';
import { PositionMapper } from './position-mapper.js';
import { ModelInputManager } from './model-input-manager.js';
import { SelectionBridge } from './selection-bridge.js';
import { cloneSelection } from './selection-model.js';
import { Transaction, isTransaction } from './transaction.js';
import { cloneDocumentValue } from './schema.js';
import { ensureBlockRuns, getBlockRuns, getBlockText, getBlockTextLength, withBlockRuns } from './inline/block-inline.js';
import { applyMark, clearMarks, concatRuns, deleteRange, insertText as insertInlineText, replaceRange, splitRunsAtOffset, splitRunsAtRange } from './inline/inline-operations.js';
import { createRun, getCommonMarks, getMarksAtOffset, getRunsLength, normalizeRuns } from './inline/inline-model.js';
import { createTextPosition, createTextSelection } from './selection-model.js';
import { createStableId } from './id.js';
 
export class EditorEngine {
    constructor(stateManager, controller, renderer = null) {
        this.state = stateManager;
        this.controller = controller;
        this.renderer = renderer;
        this.commands = new CommandRegistry();
        this.selectionBridge = new SelectionBridge(controller, stateManager);
        this.positionMapper = new PositionMapper(stateManager);
        this.inputManager = new ModelInputManager(this);
        this.selection = null;
        this.storedMarks = null;
        this._setupComplete = false;
        this.registerCoreCommands();
    }

    setup() {
        if (this._setupComplete) return;
        this._setupComplete = true;
        this.inputManager.setup();
        this.state.subscribeTo('HISTORY_SELECTION_REQUEST', ({ selection }) => {
            if (!selection) return;
            this.selection = cloneSelection(selection);
            this.restoreSelectionSoon(selection);
        });
        this.state.subscribeTo('DOCUMENT_LOADED', () => {
            this.selection = null;
            this.selectionBridge.current = null;
        });
    }

    registerCommand(name, handler, options = {}) {
        return this.commands.register(name, handler, options);
    }

    captureSelection() {
        const selection = this.selectionBridge.capture();
        if (selection) this.selection = cloneSelection(selection);
        return cloneSelection(this.selection);
    }

    setSelection(selection, { restore = false } = {}) {
        this.selection = cloneSelection(selection);
        this.selectionBridge.current = cloneSelection(selection);
        if (restore) return this.selectionBridge.restore(this.selection);
        return true;
    }

    dispatch(name, payload = {}, options = {}) {
        const selectionBefore = options.selection || this.captureSelection();
        const documentBefore = cloneDocumentValue(this.state.doc);
        const context = {
            engine: this,
            state: this.state,
            controller: this.controller,
            renderer: this.renderer,
            payload,
            selection: cloneSelection(selectionBefore),
            document: this.state.doc
        };

        const result = this.commands.execute(name, context);
        if (!result) return null;
        if (typeof result.then === 'function') {
            return result.then(value => this.commitCommandResult(value, {
                name, selectionBefore, documentBefore, options
            }));
        }
        return this.commitCommandResult(result, { name, selectionBefore, documentBefore, options });
    }

    buildInverseOperations(operations) {
        const inverse = [];
        [...(operations || [])].reverse().forEach(operation => {
            inverse.push(...this.state.history.getInverseOperations(operation));
        });
        return inverse;
    }

    buildRenderImpact(operations) {
        const dirty = new Set();
        const inserted = new Set();
        const removed = new Set();
        let layoutInvalidFromBlockId = null;
        const markLayout = (blockId) => {
            if (!layoutInvalidFromBlockId && blockId) layoutInvalidFromBlockId = blockId;
        };
        for (const operation of operations || []) {
            const blockId = operation.blockId || operation.block?.id || null;
            if (operation.type === 'ADD_BLOCK') {
                if (blockId) inserted.add(blockId);
                markLayout(operation.previousBlockId || blockId);
            } else if (operation.type === 'REMOVE_BLOCK') {
                if (blockId) removed.add(blockId);
                markLayout(operation.previousBlockId || operation.nextBlockId || blockId);
            } else if (operation.type === 'SPLIT_BLOCK') {
                if (blockId) dirty.add(blockId);
                if (operation.newBlockId || operation.newBlock?.id) inserted.add(operation.newBlockId || operation.newBlock.id);
                markLayout(blockId);
            } else if (operation.type === 'MOVE_BLOCK') {
                if (blockId) dirty.add(blockId);
                markLayout(blockId);
            } else {
                if (blockId) dirty.add(blockId);
                markLayout(blockId);
            }
        }
        return {
            dirtyBlockIds: [...dirty],
            insertedBlockIds: [...inserted],
            removedBlockIds: [...removed],
            layoutInvalidFromBlockId
        };
    }

    commitCommandResult(result, { name, selectionBefore, documentBefore, options }) {
        if (result?.handled && !result.transaction) {
            this.captureSelection();
            return result;
        }

        let transaction;
        if (isTransaction(result)) transaction = Transaction.from(result);
        else if (Array.isArray(result)) transaction = new Transaction({ operations: result });
        else if (result?.type) transaction = new Transaction({ operations: [result] });
        else if (result?.transaction) transaction = Transaction.from(result.transaction);
        else return result;

        transaction.source ||= name;
        if (!transaction.selectionBefore) transaction.selectionBefore = cloneSelection(selectionBefore);
        if (!transaction.selectionAfter) {
            transaction.selectionAfter = this.positionMapper.mapSelection(
                selectionBefore,
                transaction.operations,
                { documentBefore, documentAfter: this.state.doc }
            );
        }

        if (!transaction.inverseOperations?.length) {
            transaction.inverseOperations = this.buildInverseOperations(transaction.operations);
        }
        if (!transaction.renderImpact) transaction.renderImpact = this.buildRenderImpact(transaction.operations);
        transaction.mergeKey ||= transaction.meta?.mergeKey || transaction.operations[0]?.blockId || null;

        if (!transaction.isEmpty) {
            this.state.applyTransaction(transaction, options.recordHistory !== false);
        }
        this.selection = cloneSelection(transaction.selectionAfter || transaction.selectionBefore);
        if (this.selection && options.restoreSelection !== false) this.restoreSelectionSoon(this.selection);
        return transaction;
    }

    restoreSelectionSoon(selection) {
        const restore = () => this.selectionBridge.restore(selection, { preventScroll: true });
        if (typeof requestAnimationFrame === 'function') requestAnimationFrame(() => requestAnimationFrame(restore));
        else setTimeout(restore, 0);
    }

    createTransaction(source, operations = [], selectionBefore = this.selection) {
        return new Transaction({ source, operations, selectionBefore });
    }

    registerCoreCommands() {
        const toggle = (name, key, value = true) => {
            this.registerCommand(name, ({ engine, selection }) => engine.createMarkTransaction(name, selection, key, value, 'toggle'));
        };
        toggle('toggleBold', 'bold');
        toggle('toggleItalic', 'italic');
        toggle('toggleUnderline', 'underline');
        toggle('toggleStrikethrough', 'strikethrough');
        toggle('toggleInlineCode', 'code');
        toggle('toggleSuperscript', 'superscript');
        toggle('toggleSubscript', 'subscript');

        this.registerCommand('clearFormatting', ({ engine, selection }) => engine.createClearFormattingTransaction(selection));
        this.registerCommand('createLink', ({ engine, selection, payload }) => {
            let url = payload?.url || null;
            if (!url && typeof window !== 'undefined' && selection?.anchor?.offset !== selection?.focus?.offset) {
                url = window.prompt?.('Enter URL') || null;
            }
            if (!url) return null;
            return engine.createMarkTransaction('createLink', selection, 'link', { href: url }, 'set');
        });
        this.registerCommand('removeLink', ({ engine, selection }) => engine.createMarkTransaction('removeLink', selection, 'link', null, 'set'));
        this.registerCommand('setFontFamily', ({ engine, selection, payload }) => engine.createMarkTransaction('setFontFamily', selection, 'fontFamily', payload.fontFamily, 'set'));
        this.registerCommand('setFontSize', ({ engine, selection, payload }) => engine.createMarkTransaction('setFontSize', selection, 'fontSize', payload.fontSize, 'set'));
        this.registerCommand('setTextColor', ({ engine, selection, payload }) => engine.createMarkTransaction('setTextColor', selection, 'color', payload.color, 'set'));
        this.registerCommand('setHighlightColor', ({ engine, selection, payload }) => engine.createMarkTransaction('setHighlightColor', selection, 'highlight', payload.color, 'set'));
        this.registerCommand('setHighlight', ({ engine, selection, payload }) => engine.createMarkTransaction('setHighlight', selection, 'highlight', payload.color, 'set'));
        this.registerCommand('applyInlineStyle', ({ engine, selection, payload }) => engine.createInlineStyleTransaction(selection, payload));

        this.registerCommand('replaceSelection', ({ engine, selection, payload }) => engine.createReplaceSelectionTransaction(selection, payload));
        this.registerCommand('insertText', ({ engine, selection, payload }) => engine.createReplaceSelectionTransaction(selection, payload));
        this.registerCommand('insertLineBreak', ({ engine, selection }) => engine.createReplaceSelectionTransaction(selection, { text: '\n', source: 'input' }));
        this.registerCommand('deleteBackward', ({ engine, selection, payload }) => engine.createDeleteTransaction(selection, 'backward', payload?.unit || 'character'));
        this.registerCommand('deleteForward', ({ engine, selection, payload }) => engine.createDeleteTransaction(selection, 'forward', payload?.unit || 'character'));
        this.registerCommand('splitParagraph', ({ engine, selection }) => engine.createSplitParagraphTransaction(selection));
        this.registerCommand('acceptRevision', ({ engine, payload, selection }) => engine.createResolveRevisionTransaction(payload.revisionId, true, payload.blockId, selection));
        this.registerCommand('rejectRevision', ({ engine, payload, selection }) => engine.createResolveRevisionTransaction(payload.revisionId, false, payload.blockId, selection));
        this.registerCommand('acceptAllRevisions', ({ engine, selection }) => engine.createResolveAllRevisionsTransaction(true, selection));
        this.registerCommand('rejectAllRevisions', ({ engine, selection }) => engine.createResolveAllRevisionsTransaction(false, selection));

        this.registerCommand('setBlockStyle', ({ state, payload, selection }) => {
            const blockId = payload.blockId || selection?.anchor?.blockId || selection?.blockId;
            const index = blockId ? state.getBlockIndexById(blockId) : payload.index;
            const previous = state.doc.blocks[index];
            if (!previous) return null;
            return new Transaction({
                source: 'setBlockStyle',
                selectionBefore: selection,
                selectionAfter: selection,
                operations: [{
                    type: 'REPLACE_BLOCK_STATE',
                    blockId: previous.id,
                    index,
                    block: { ...cloneDocumentValue(previous), style: payload.style },
                    prevBlock: cloneDocumentValue(previous),
                    source: 'command'
                }]
            });
        });

        this.registerCommand('insertBlock', ({ state, payload, selection }) => {
            const index = Number.isInteger(payload.index) ? payload.index : state.doc.blocks.length;
            const block = state.ensureBlockId(cloneDocumentValue(payload.block));
            if (this.isTrackingChanges() && !block.revision) {
                block.revision = this.createRevision('insertion', { kind: 'block' });
            }
            return new Transaction({
                source: payload.source || 'insertBlock',
                selectionBefore: selection,
                operations: [{
                    type: 'ADD_BLOCK',
                    index,
                    blockId: block.id,
                    block,
                    previousBlockId: state.doc.blocks[index - 1]?.id || null,
                    nextBlockId: state.doc.blocks[index]?.id || null,
                    source: payload.source || 'structure'
                }]
            });
        });

        this.registerCommand('removeBlock', ({ state, payload, selection }) => {
            const index = payload.blockId ? state.getBlockIndexById(payload.blockId) : payload.index;
            const block = state.doc.blocks[index];
            if (!block) return null;
            if (this.isTrackingChanges()) {
                if (block.revision?.type === 'deletion') return { handled: true };
                if (block.revision?.type !== 'insertion') {
                    const next = cloneDocumentValue(block);
                    next.revision = this.createRevision('deletion', { kind: 'block' });
                    return new Transaction({
                        source: 'removeBlock',
                        selectionBefore: selection,
                        operations: [{
                            type: 'REPLACE_BLOCK_STATE',
                            index,
                            blockId: block.id,
                            block: next,
                            prevBlock: cloneDocumentValue(block),
                            source: 'removeBlock'
                        }],
                        meta: { inputType: 'review', mergeable: false }
                    });
                }
            }
            return new Transaction({
                source: 'removeBlock',
                selectionBefore: selection,
                operations: [{
                    type: 'REMOVE_BLOCK',
                    index,
                    blockId: block.id,
                    block: cloneDocumentValue(block),
                    previousBlockId: state.doc.blocks[index - 1]?.id || null,
                    nextBlockId: state.doc.blocks[index + 1]?.id || null
                }]
            });
        });

        this.registerCommand('moveBlock', ({ state, payload, selection }) => {
            const fromIndex = payload.blockId ? state.getBlockIndexById(payload.blockId) : payload.fromIndex;
            const block = state.doc.blocks[fromIndex];
            if (!block || !Number.isInteger(payload.toIndex)) return null;
            return new Transaction({
                source: 'moveBlock',
                selectionBefore: selection,
                selectionAfter: selection,
                operations: [{
                    type: 'MOVE_BLOCK',
                    blockId: block.id,
                    fromIndex,
                    toIndex: payload.toIndex
                }]
            });
        });

        this.registerCommand('splitTextBlock', ({ state, payload, selection }) => {
            const index = payload.blockId ? state.getBlockIndexById(payload.blockId) : payload.index;
            const previous = state.doc.blocks[index];
            if (!previous) return null;
            const left = state.ensureBlockId(cloneDocumentValue(payload.block), previous.id);
            const right = state.ensureBlockId(cloneDocumentValue(payload.newBlock));
            return new Transaction({
                source: payload.source || 'enter',
                selectionBefore: selection,
                operations: [{
                    type: 'SPLIT_BLOCK',
                    index,
                    blockId: previous.id,
                    newBlockId: right.id,
                    block: left,
                    newBlock: right,
                    prevBlock: cloneDocumentValue(previous),
                    splitOffset: payload.splitOffset,
                    source: payload.source || 'enter',
                    ...payload.meta
                }]
            });
        });

        const resolveBlock = (state, payload, selection) => {
            const blockId = payload.blockId || selection?.anchor?.blockId || selection?.blockId || null;
            const index = blockId ? state.getBlockIndexById(blockId) : payload.index;
            return { index, block: state.doc.blocks[index] || null };
        };
        const replaceBlock = (source, state, selection, index, previous, next) => {
            if (!previous || !next) return null;
            return new Transaction({
                source,
                selectionBefore: selection,
                selectionAfter: selection,
                operations: [{
                    type: 'REPLACE_BLOCK_STATE',
                    index,
                    blockId: previous.id,
                    block: state.ensureBlockId(cloneDocumentValue(next)),
                    prevBlock: cloneDocumentValue(previous),
                    source
                }],
                meta: { inputType: 'structure', mergeable: false }
            });
        };

        this.registerCommand('toggleListType', ({ state, payload, selection }) => {
            const { index, block } = resolveBlock(state, payload, selection);
            if (!block || !['ul', 'ol', 'checklist'].includes(block.type)) return null;
            const nextType = payload.listType || (block.type === 'ul' ? 'ol' : 'ul');
            return replaceBlock('toggleListType', state, selection, index, block, { ...block, type: nextType });
        });
        this.registerCommand('convertBlockToText', ({ state, payload, selection }) => {
            const { index, block } = resolveBlock(state, payload, selection);
            if (!block || !['ul', 'ol', 'checklist'].includes(block.type)) return null;
            const lines = (block.items || []).map(item => String(item.text || '')).filter(Boolean);
            const next = { id: block.id, type: 'text', style: 'normal', content: lines.length ? lines.join('<br>') : '<br>' };
            return replaceBlock('convertBlockToText', state, selection, index, block, next);
        });
        this.registerCommand('convertBlockToList', ({ state, payload, selection }) => {
            const { index, block } = resolveBlock(state, payload, selection);
            if (!block || block.type !== 'text') return null;
            const lines = getBlockText(block).split(/\r?\n/).filter(line => line.trim().length > 0);
            const items = (lines.length ? lines : ['']).map(text => ({ id: createStableId('item'), text, level: 0, checked: false }));
            const next = { id: block.id, type: payload.listType || 'ul', items };
            return replaceBlock('convertBlockToList', state, selection, index, block, next);
        });
        this.registerCommand('updateImageProps', ({ state, payload, selection }) => {
            const { index, block } = resolveBlock(state, payload, selection);
            if (!block || block.type !== 'image') return null;
            return replaceBlock('updateImageProps', state, selection, index, block, { ...block, ...(payload.props || {}) });
        });
        this.registerCommand('updateBlockProps', ({ state, payload, selection }) => {
            const { index, block } = resolveBlock(state, payload, selection);
            if (!block || !payload.props || typeof payload.props !== 'object') return null;
            return replaceBlock('updateBlockProps', state, selection, index, block, { ...block, ...cloneDocumentValue(payload.props) });
        });

        const mutateTable = (source, state, payload, selection, mutator) => {
            const { index, block } = resolveBlock(state, payload, selection);
            if (!block || block.type !== 'table' || !Array.isArray(block.rows)) return null;
            const next = cloneDocumentValue(block);
            if (mutator(next) === false) return null;
            return replaceBlock(source, state, selection, index, block, next);
        };
        this.registerCommand('insertTableRow', ({ state, payload, selection }) => mutateTable('insertTableRow', state, payload, selection, table => {
            const cols = table.rows[0]?.length || 1;
            const position = typeof payload.cellId === 'string' ? state.getTableCellPosition(table, payload.cellId) : null;
            const insertAt = position ? position.row + 1 : Math.max(0, Math.min(table.rows.length, Number.isInteger(payload.rowIdx) ? payload.rowIdx : table.rows.length));
            table.rows.splice(insertAt, 0, new Array(cols).fill(''));
            table.rowIds ||= [];
            table.rowIds.splice(insertAt, 0, createStableId('row'));
            table.cellIds ||= [];
            table.cellIds.splice(insertAt, 0, Array.from({ length: cols }, () => createStableId('cell')));
            table.cellMeta = {};
            return true;
        }));
        this.registerCommand('removeTableRow', ({ state, payload, selection }) => mutateTable('removeTableRow', state, payload, selection, table => {
            if (table.rows.length <= 1) return false;
            const position = typeof payload.cellId === 'string' ? state.getTableCellPosition(table, payload.cellId) : null;
            const removeAt = position ? position.row : Math.max(0, Math.min(table.rows.length - 1, Number.isInteger(payload.rowIdx) ? payload.rowIdx : table.rows.length - 1));
            table.rows.splice(removeAt, 1);
            table.rowIds?.splice(removeAt, 1);
            table.cellIds?.splice(removeAt, 1);
            table.cellMeta = {};
            return true;
        }));
        this.registerCommand('insertTableCol', ({ state, payload, selection }) => mutateTable('insertTableCol', state, payload, selection, table => {
            const position = typeof payload.cellId === 'string' ? state.getTableCellPosition(table, payload.cellId) : null;
            const colCount = table.rows[0]?.length || 0;
            const insertAt = position ? position.col + 1 : Math.max(0, Math.min(colCount, Number.isInteger(payload.colIdx) ? payload.colIdx : colCount));
            table.rows.forEach(row => row.splice(insertAt, 0, ''));
            table.cellIds ||= table.rows.map(row => row.map(() => createStableId('cell')));
            table.cellIds.forEach(row => row.splice(insertAt, 0, createStableId('cell')));
            table.cellMeta = {};
            if (Array.isArray(table.colWidths)) table.colWidths.splice(insertAt, 0, table.colWidths[insertAt - 1] || 10);
            return true;
        }));
        this.registerCommand('removeTableCol', ({ state, payload, selection }) => mutateTable('removeTableCol', state, payload, selection, table => {
            const colCount = table.rows[0]?.length || 0;
            if (colCount <= 1) return false;
            const position = typeof payload.cellId === 'string' ? state.getTableCellPosition(table, payload.cellId) : null;
            const removeAt = position ? position.col : Math.max(0, Math.min(colCount - 1, Number.isInteger(payload.colIdx) ? payload.colIdx : colCount - 1));
            table.rows.forEach(row => row.splice(removeAt, 1));
            table.cellIds?.forEach(row => row.splice(removeAt, 1));
            table.cellMeta = {};
            table.colWidths?.splice(removeAt, 1);
            return true;
        }));
    }

    getAffectedTextBlockIds(selection = this.selection) {
        if (!selection) return [];
        if (selection.type !== 'text') {
            const blockId = selection.blockId || selection.tableId;
            return blockId ? [String(blockId)] : [];
        }
        const anchorIndex = this.state.getBlockIndexById(selection.anchor?.blockId);
        const focusIndex = this.state.getBlockIndexById(selection.focus?.blockId);
        if (anchorIndex < 0 || focusIndex < 0) {
            return [selection.anchor?.blockId, selection.focus?.blockId].filter(Boolean);
        }
        const start = Math.min(anchorIndex, focusIndex);
        const end = Math.max(anchorIndex, focusIndex);
        return this.state.doc.blocks
            .slice(start, end + 1)
            .filter(block => block?.type === 'text')
            .map(block => String(block.id));
    }


    createRevision(type, extra = {}) {
        return {
            id: createStableId('rev'),
            type,
            author: this.state.currentUserName || 'User',
            createdAt: new Date().toISOString(),
            ...extra
        };
    }

    isTrackingChanges() {
        return this.state.doc.settings?.editingMode === 'suggesting'
            || this.state.doc.settings?.trackChanges === true;
    }

    markRunsAsDeletion(runs, revision) {
        const output = [];
        for (const run of normalizeRuns(runs, { preserveEmpty: false })) {
            const existing = run.marks?.revision;
            if (existing?.type === 'insertion') continue;
            if (existing?.type === 'deletion') {
                output.push(run);
                continue;
            }
            output.push({ ...run, marks: { ...run.marks, revision } });
        }
        return normalizeRuns(output, { preserveEmpty: false });
    }

    createInlineStyleTransaction(selection, styleMap = {}) {
        const normalized = this.normalizeTextSelection(selection);
        if (!normalized || !styleMap || typeof styleMap !== 'object') return null;
        const markMap = {};
        if (styleMap.fontFamily) markMap.fontFamily = styleMap.fontFamily;
        if (styleMap.fontSize) markMap.fontSize = styleMap.fontSize;
        if (styleMap.color) markMap.color = styleMap.color;
        if (styleMap.backgroundColor) markMap.highlight = styleMap.backgroundColor;
        if (styleMap.fontWeight && String(styleMap.fontWeight) !== '400' && String(styleMap.fontWeight) !== 'normal') markMap.bold = true;
        if (styleMap.fontStyle === 'italic') markMap.italic = true;
        if (styleMap.verticalAlign === 'super') markMap.superscript = true;
        if (styleMap.verticalAlign === 'sub') markMap.subscript = true;
        if (String(styleMap.textDecoration || '').includes('underline')) markMap.underline = true;
        if (String(styleMap.textDecoration || '').includes('line-through')) markMap.strikethrough = true;

        const operations = [];
        for (let index = normalized.startIndex; index <= normalized.endIndex; index += 1) {
            const previous = this.state.doc.blocks[index];
            if (!previous || previous.type !== 'text') continue;
            const { from, to } = this.getBlockSelectionRange(previous, index, normalized);
            if (from === to) continue;
            let children = getBlockRuns(previous);
            for (const [key, value] of Object.entries(markMap)) children = applyMark(children, from, to, key, value, 'set');
            const next = withBlockRuns(ensureBlockRuns(previous), children);
            operations.push({
                type: 'REPLACE_BLOCK_STATE',
                blockId: previous.id,
                index,
                block: next,
                prevBlock: cloneDocumentValue(previous),
                source: 'applyInlineStyle'
            });
        }
        return new Transaction({
            source: 'applyInlineStyle',
            operations,
            selectionBefore: selection,
            selectionAfter: selection,
            meta: { inputType: 'format', mergeable: false }
        });
    }

    createResolveRevisionTransaction(revisionId, accept, preferredBlockId = null, selection = this.selection) {
        if (!revisionId) return null;
        const operations = [];
        const blocks = this.state.doc.blocks || [];

        for (let index = 0; index < blocks.length; index += 1) {
            const previous = blocks[index];
            if (!previous) continue;

            const legacyRevision = (previous.revisions || []).find(revision => revision.id === revisionId);
            if (legacyRevision) {
                const next = cloneDocumentValue(previous);
                next.revisions = (next.revisions || []).filter(revision => revision.id !== revisionId);
                if (accept && legacyRevision.type === 'deletion' && legacyRevision.oldContent !== undefined) next.content = legacyRevision.oldContent;
                if (!accept && legacyRevision.type === 'insertion' && legacyRevision.oldContent !== undefined) next.content = legacyRevision.oldContent;
                operations.push({ type: 'REPLACE_BLOCK_STATE', blockId: previous.id, index, block: next, prevBlock: cloneDocumentValue(previous), source: accept ? 'acceptRevision' : 'rejectRevision' });
                continue;
            }

            if (previous.type === 'text') {
                let changed = false;
                const nextRuns = [];
                for (const run of getBlockRuns(previous)) {
                    const revision = run.marks?.revision;
                    if (!revision || revision.id !== revisionId) {
                        nextRuns.push(run);
                        continue;
                    }
                    changed = true;
                    const keep = revision.type === 'insertion' ? accept : !accept;
                    if (keep) {
                        const marks = { ...run.marks };
                        delete marks.revision;
                        nextRuns.push({ ...run, marks });
                    }
                }
                if (changed) {
                    operations.push({
                        type: 'REPLACE_BLOCK_STATE',
                        blockId: previous.id,
                        index,
                        block: withBlockRuns(ensureBlockRuns(previous), normalizeRuns(nextRuns)),
                        prevBlock: cloneDocumentValue(previous),
                        source: accept ? 'acceptRevision' : 'rejectRevision'
                    });
                }
            }

            if (previous.revision?.id === revisionId) {
                const keep = previous.revision.type === 'insertion' ? accept : !accept;
                if (keep) {
                    const next = cloneDocumentValue(previous);
                    delete next.revision;
                    operations.push({ type: 'REPLACE_BLOCK_STATE', blockId: previous.id, index, block: next, prevBlock: cloneDocumentValue(previous), source: accept ? 'acceptRevision' : 'rejectRevision' });
                } else {
                    operations.push({ type: 'REMOVE_BLOCK', blockId: previous.id, index, block: cloneDocumentValue(previous), previousBlockId: blocks[index - 1]?.id || null, nextBlockId: blocks[index + 1]?.id || null, source: accept ? 'acceptRevision' : 'rejectRevision' });
                }
            }

            if (previous.breakRevision?.id === revisionId) {
                const revision = previous.breakRevision;
                const keepBreak = revision.type === 'insertion' ? accept : !accept;
                if (keepBreak) {
                    const next = cloneDocumentValue(previous);
                    delete next.breakRevision;
                    operations.push({ type: 'REPLACE_BLOCK_STATE', blockId: previous.id, index, block: next, prevBlock: cloneDocumentValue(previous), source: accept ? 'acceptRevision' : 'rejectRevision' });
                } else if (index > 0 && blocks[index - 1]?.type === 'text' && previous.type === 'text') {
                    const target = blocks[index - 1];
                    const merged = withBlockRuns(ensureBlockRuns(target), concatRuns(getBlockRuns(target), getBlockRuns(previous)));
                    operations.push({ type: 'REPLACE_BLOCK_STATE', blockId: target.id, index: index - 1, block: merged, prevBlock: cloneDocumentValue(target), source: accept ? 'acceptRevision' : 'rejectRevision' });
                    operations.push({ type: 'REMOVE_BLOCK', blockId: previous.id, index, block: cloneDocumentValue(previous), previousBlockId: target.id, nextBlockId: blocks[index + 1]?.id || null, source: accept ? 'acceptRevision' : 'rejectRevision' });
                }
            }
        }

        if (!operations.length) return { handled: true, missingRevision: revisionId };
        const blockId = preferredBlockId || operations[0]?.blockId || null;
        return new Transaction({
            source: accept ? 'acceptRevision' : 'rejectRevision',
            operations,
            selectionBefore: selection,
            mergeKey: blockId,
            meta: { inputType: 'review', mergeable: false, revisionId, accept }
        });
    }

    createResolveAllRevisionsTransaction(accept, selection = this.selection) {
        const working = cloneDocumentValue(this.state.doc.blocks || []);
        const operations = [];

        for (let index = 0; index < working.length; index += 1) {
            let block = working[index];
            if (!block) continue;

            if (block.revision) {
                const keep = block.revision.type === 'insertion' ? accept : !accept;
                if (!keep) {
                    operations.push({
                        type: 'REMOVE_BLOCK',
                        blockId: block.id,
                        index,
                        block: cloneDocumentValue(block),
                        previousBlockId: working[index - 1]?.id || null,
                        nextBlockId: working[index + 1]?.id || null,
                        source: accept ? 'acceptAllRevisions' : 'rejectAllRevisions'
                    });
                    working.splice(index, 1);
                    index -= 1;
                    continue;
                }
                const previous = cloneDocumentValue(block);
                delete block.revision;
                operations.push({ type: 'REPLACE_BLOCK_STATE', blockId: block.id, index, block: cloneDocumentValue(block), prevBlock: previous, source: accept ? 'acceptAllRevisions' : 'rejectAllRevisions' });
            }

            if (block.breakRevision) {
                const keepBreak = block.breakRevision.type === 'insertion' ? accept : !accept;
                if (keepBreak) {
                    const previous = cloneDocumentValue(block);
                    delete block.breakRevision;
                    operations.push({ type: 'REPLACE_BLOCK_STATE', blockId: block.id, index, block: cloneDocumentValue(block), prevBlock: previous, source: accept ? 'acceptAllRevisions' : 'rejectAllRevisions' });
                } else if (index > 0 && working[index - 1]?.type === 'text' && block.type === 'text') {
                    const target = working[index - 1];
                    const previousTarget = cloneDocumentValue(target);
                    const merged = withBlockRuns(ensureBlockRuns(target), concatRuns(getBlockRuns(target), getBlockRuns(block)));
                    working[index - 1] = merged;
                    operations.push({ type: 'REPLACE_BLOCK_STATE', blockId: target.id, index: index - 1, block: cloneDocumentValue(merged), prevBlock: previousTarget, source: accept ? 'acceptAllRevisions' : 'rejectAllRevisions' });
                    operations.push({ type: 'REMOVE_BLOCK', blockId: block.id, index, block: cloneDocumentValue(block), previousBlockId: target.id, nextBlockId: working[index + 1]?.id || null, source: accept ? 'acceptAllRevisions' : 'rejectAllRevisions' });
                    working.splice(index, 1);
                    index -= 1;
                    continue;
                }
            }

            block = working[index];
            if (block?.revisions?.length) {
                const previous = cloneDocumentValue(block);
                for (const revision of block.revisions) {
                    if (accept && revision.type === 'deletion' && revision.oldContent !== undefined) block.content = revision.oldContent;
                    if (!accept && revision.type === 'insertion' && revision.oldContent !== undefined) block.content = revision.oldContent;
                }
                block.revisions = [];
                working[index] = block;
                operations.push({ type: 'REPLACE_BLOCK_STATE', blockId: block.id, index, block: cloneDocumentValue(block), prevBlock: previous, source: accept ? 'acceptAllRevisions' : 'rejectAllRevisions' });
            }

            block = working[index];
            if (block?.type === 'text') {
                let changed = false;
                const nextRuns = [];
                for (const run of getBlockRuns(block)) {
                    const revision = run.marks?.revision;
                    if (!revision) {
                        nextRuns.push(run);
                        continue;
                    }
                    changed = true;
                    const keep = revision.type === 'insertion' ? accept : !accept;
                    if (keep) {
                        const marks = { ...run.marks };
                        delete marks.revision;
                        nextRuns.push({ ...run, marks });
                    }
                }
                if (changed) {
                    const previous = cloneDocumentValue(block);
                    const next = withBlockRuns(ensureBlockRuns(block), normalizeRuns(nextRuns));
                    working[index] = next;
                    operations.push({ type: 'REPLACE_BLOCK_STATE', blockId: block.id, index, block: cloneDocumentValue(next), prevBlock: previous, source: accept ? 'acceptAllRevisions' : 'rejectAllRevisions' });
                }
            }
        }

        if (!operations.length) return { handled: true };
        return new Transaction({
            source: accept ? 'acceptAllRevisions' : 'rejectAllRevisions',
            operations,
            selectionBefore: selection,
            meta: { inputType: 'review', mergeable: false, acceptAll: accept }
        });
    }

    createReplaceSelectionTransaction(selection, payload = {}) {
        const normalized = this.normalizeTextSelection(selection);
        if (!normalized) return null;
        const text = String(payload.text ?? '');
        const source = payload.source || 'input';
        const startBlock = this.state.doc.blocks[normalized.startIndex];
        const endBlock = this.state.doc.blocks[normalized.endIndex];
        if (!startBlock || startBlock.type !== 'text' || !endBlock || endBlock.type !== 'text') return null;

        const start = ensureBlockRuns(startBlock);
        const hasSelection = normalized.startIndex !== normalized.endIndex || normalized.start.offset !== normalized.end.offset;
        const inheritedMarks = this.storedMarks || getMarksAtOffset(start.children, normalized.start.offset);
        let replacement = payload.runs
            ? normalizeRuns(payload.runs, { preserveEmpty: false })
            : (text ? [createRun(text, inheritedMarks)] : []);
        if (this.isTrackingChanges() && replacement.some(run => run.text)) {
            const revision = !hasSelection && inheritedMarks?.revision?.type === 'insertion'
                ? inheritedMarks.revision
                : this.createRevision('insertion');
            replacement = replacement.map(run => ({ ...run, marks: { ...run.marks, revision } }));
        }

        const operations = [];
        if (this.isTrackingChanges() && hasSelection) {
            const deletionRevision = this.createRevision('deletion');
            if (normalized.startIndex === normalized.endIndex) {
                const parts = splitRunsAtRange(start.children, normalized.start.offset, normalized.end.offset);
                const deleted = this.markRunsAsDeletion(parts.selected, deletionRevision);
                const nextBlock = withBlockRuns(start, concatRuns(parts.before, replacement, deleted, parts.after));
                operations.push({
                    type: 'REPLACE_BLOCK_STATE',
                    blockId: startBlock.id,
                    index: normalized.startIndex,
                    block: nextBlock,
                    prevBlock: cloneDocumentValue(startBlock),
                    source
                });
            } else {
                for (let index = normalized.startIndex; index <= normalized.endIndex; index += 1) {
                    const previous = this.state.doc.blocks[index];
                    if (!previous) continue;
                    if (previous.type !== 'text') {
                        const next = cloneDocumentValue(previous);
                        next.revision = deletionRevision;
                        operations.push({ type: 'REPLACE_BLOCK_STATE', blockId: previous.id, index, block: next, prevBlock: cloneDocumentValue(previous), source });
                        continue;
                    }
                    const block = ensureBlockRuns(previous);
                    let nextRuns;
                    if (index === normalized.startIndex) {
                        const parts = splitRunsAtOffset(block.children, normalized.start.offset);
                        nextRuns = concatRuns(parts.left, replacement, this.markRunsAsDeletion(parts.right, deletionRevision));
                    } else if (index === normalized.endIndex) {
                        const parts = splitRunsAtOffset(block.children, normalized.end.offset);
                        nextRuns = concatRuns(this.markRunsAsDeletion(parts.left, deletionRevision), parts.right);
                    } else {
                        nextRuns = this.markRunsAsDeletion(block.children, deletionRevision);
                    }
                    operations.push({
                        type: 'REPLACE_BLOCK_STATE',
                        blockId: previous.id,
                        index,
                        block: withBlockRuns(block, nextRuns),
                        prevBlock: cloneDocumentValue(previous),
                        source
                    });
                }
            }
        } else {
            let nextBlock;
            if (normalized.startIndex === normalized.endIndex) {
                nextBlock = withBlockRuns(start, replaceRange(start.children, normalized.start.offset, normalized.end.offset, replacement));
            } else {
                const end = ensureBlockRuns(endBlock);
                const left = splitRunsAtOffset(start.children, normalized.start.offset).left;
                const right = splitRunsAtOffset(end.children, normalized.end.offset).right;
                nextBlock = withBlockRuns(start, concatRuns(left, replacement, right));
            }
            operations.push({
                type: 'REPLACE_BLOCK_STATE',
                blockId: startBlock.id,
                index: normalized.startIndex,
                block: nextBlock,
                prevBlock: cloneDocumentValue(startBlock),
                source
            });
            for (let index = normalized.endIndex; index > normalized.startIndex; index -= 1) {
                const block = this.state.doc.blocks[index];
                operations.push({
                    type: 'REMOVE_BLOCK',
                    blockId: block.id,
                    index,
                    block: cloneDocumentValue(block),
                    previousBlockId: this.state.doc.blocks[index - 1]?.id || null,
                    nextBlockId: this.state.doc.blocks[index + 1]?.id || null,
                    source
                });
            }
        }

        const offset = normalized.start.offset + getRunsLength(replacement);
        const after = createTextSelection(createTextPosition(startBlock.id, offset), createTextPosition(startBlock.id, offset));
        this.storedMarks = null;
        return new Transaction({
            source,
            operations,
            selectionBefore: selection,
            selectionAfter: after,
            meta: { inputType: source === 'input' ? 'insertText' : source, mergeable: source === 'input' && !hasSelection, mergeKey: startBlock.id }
        });
    }

    getWordBoundary(text, offset, direction) {
        const value = String(text || '');
        let cursor = Math.max(0, Math.min(value.length, offset));
        if (direction === 'backward') {
            while (cursor > 0 && /\s/.test(value[cursor - 1])) cursor -= 1;
            while (cursor > 0 && !/\s/.test(value[cursor - 1])) cursor -= 1;
            return cursor;
        }
        while (cursor < value.length && /\s/.test(value[cursor])) cursor += 1;
        while (cursor < value.length && !/\s/.test(value[cursor])) cursor += 1;
        return cursor;
    }

    createDeleteTransaction(selection, direction = 'backward', unit = 'character') {
        const normalized = this.normalizeTextSelection(selection);
        if (!normalized) return null;
        if (normalized.startIndex !== normalized.endIndex || normalized.start.offset !== normalized.end.offset) {
            return this.createReplaceSelectionTransaction(selection, { text: '', source: 'delete' });
        }
        const index = normalized.startIndex;
        const block = this.state.doc.blocks[index];
        if (!block || block.type !== 'text') return null;
        const offset = normalized.start.offset;
        const runs = getBlockRuns(block);
        const length = getRunsLength(runs);

        const createWithinBlock = (from, to) => {
            let nextRuns;
            if (this.isTrackingChanges()) {
                const parts = splitRunsAtRange(runs, from, to);
                nextRuns = concatRuns(parts.before, this.markRunsAsDeletion(parts.selected, this.createRevision('deletion')), parts.after);
            } else {
                nextRuns = deleteRange(runs, from, to);
            }
            const next = withBlockRuns(ensureBlockRuns(block), nextRuns);
            const after = createTextSelection(createTextPosition(block.id, from), createTextPosition(block.id, from));
            return new Transaction({
                source: 'delete',
                operations: [{ type: 'REPLACE_BLOCK_STATE', blockId: block.id, index, block: next, prevBlock: cloneDocumentValue(block), source: 'delete' }],
                selectionBefore: selection,
                selectionAfter: after,
                meta: { inputType: 'delete', mergeable: !this.isTrackingChanges() && unit === 'character', mergeKey: block.id }
            });
        };

        if (direction === 'backward' && offset > 0) {
            const from = unit === 'word' ? this.getWordBoundary(getBlockText(block), offset, 'backward') : offset - 1;
            return createWithinBlock(from, offset);
        }
        if (direction === 'forward' && offset < length) {
            const to = unit === 'word' ? this.getWordBoundary(getBlockText(block), offset, 'forward') : offset + 1;
            return createWithinBlock(offset, to);
        }

        const adjacentIndex = direction === 'backward' ? index - 1 : index + 1;
        const adjacent = this.state.doc.blocks[adjacentIndex];
        if (!adjacent || adjacent.type !== 'text') return { handled: true };

        if (this.isTrackingChanges()) {
            const laterIndex = direction === 'backward' ? index : adjacentIndex;
            const later = this.state.doc.blocks[laterIndex];
            if (later.breakRevision?.type === 'deletion') return { handled: true };
            const next = cloneDocumentValue(later);
            next.breakRevision = this.createRevision('deletion', { kind: 'paragraphBreak' });
            return new Transaction({
                source: 'deleteParagraphBreak',
                operations: [{ type: 'REPLACE_BLOCK_STATE', blockId: later.id, index: laterIndex, block: next, prevBlock: cloneDocumentValue(later), source: 'deleteParagraphBreak' }],
                selectionBefore: selection,
                selectionAfter: selection,
                meta: { inputType: 'review', mergeable: false }
            });
        }

        const target = direction === 'backward' ? adjacent : block;
        const removed = direction === 'backward' ? block : adjacent;
        const targetIndex = direction === 'backward' ? adjacentIndex : index;
        const removedIndex = direction === 'backward' ? index : adjacentIndex;
        const targetRuns = getBlockRuns(target);
        const targetLength = getRunsLength(targetRuns);
        const merged = withBlockRuns(ensureBlockRuns(target), concatRuns(targetRuns, getBlockRuns(removed)));
        const afterOffset = direction === 'backward' ? targetLength : offset;
        const after = createTextSelection(createTextPosition(target.id, afterOffset), createTextPosition(target.id, afterOffset));
        return new Transaction({
            source: 'merge',
            operations: [
                { type: 'REPLACE_BLOCK_STATE', blockId: target.id, index: targetIndex, block: merged, prevBlock: cloneDocumentValue(target), source: 'merge' },
                { type: 'REMOVE_BLOCK', blockId: removed.id, index: removedIndex, block: cloneDocumentValue(removed), previousBlockId: this.state.doc.blocks[removedIndex - 1]?.id || null, nextBlockId: this.state.doc.blocks[removedIndex + 1]?.id || null, source: 'merge' }
            ],
            selectionBefore: selection,
            selectionAfter: after,
            meta: { inputType: 'merge', mergeable: false }
        });
    }

    createSplitParagraphTransaction(selection) {
        const normalized = this.normalizeTextSelection(selection);
        if (!normalized) return null;
        if (normalized.startIndex !== normalized.endIndex || normalized.start.offset !== normalized.end.offset) {
            const deletion = this.createReplaceSelectionTransaction(selection, { text: '', source: 'delete' });
            if (!deletion) return null;
            const collapsed = deletion.selectionAfter;
            const documentCopy = cloneDocumentValue(this.state.doc);
            const startBlock = deletion.operations[0]?.block;
            if (!startBlock) return deletion;
            const split = splitRunsAtOffset(getBlockRuns(startBlock), collapsed.anchor.offset);
            const left = withBlockRuns(startBlock, split.left);
            const right = this.state.ensureBlockId(withBlockRuns({ ...startBlock, id: undefined, style: startBlock.style || 'normal' }, split.right));
            if (this.isTrackingChanges()) right.breakRevision = this.createRevision('insertion', { kind: 'paragraphBreak' });
            deletion.operations[0].block = left;
            deletion.operations.push({ type: 'ADD_BLOCK', index: normalized.startIndex + 1, blockId: right.id, block: right, previousBlockId: left.id, nextBlockId: documentCopy.blocks[normalized.endIndex + 1]?.id || null, source: 'enter' });
            deletion.selectionAfter = createTextSelection(createTextPosition(right.id, 0), createTextPosition(right.id, 0));
            deletion.source = 'enter';
            deletion.meta = { inputType: 'enter', mergeable: false };
            return deletion;
        }
        const index = normalized.startIndex;
        const previous = this.state.doc.blocks[index];
        if (!previous || previous.type !== 'text') return null;
        const block = ensureBlockRuns(previous);
        const parts = splitRunsAtOffset(block.children, normalized.start.offset);
        const left = withBlockRuns(block, parts.left);
        const right = this.state.ensureBlockId(withBlockRuns({ ...block, id: undefined }, parts.right));
        if (this.isTrackingChanges()) right.breakRevision = this.createRevision('insertion', { kind: 'paragraphBreak' });
        const after = createTextSelection(createTextPosition(right.id, 0), createTextPosition(right.id, 0));
        return new Transaction({
            source: 'enter',
            operations: [{
                type: 'SPLIT_BLOCK',
                index,
                blockId: previous.id,
                newBlockId: right.id,
                block: left,
                newBlock: right,
                prevBlock: cloneDocumentValue(previous),
                splitOffset: normalized.start.offset,
                source: 'enter'
            }],
            selectionBefore: selection,
            selectionAfter: after,
            meta: { inputType: 'enter', mergeable: false }
        });
    }

    normalizeTextSelection(selection = this.selection) {
        if (!selection || selection.type !== 'text' || !selection.anchor?.blockId || !selection.focus?.blockId) return null;
        const anchorIndex = this.state.getBlockIndexById(selection.anchor.blockId);
        const focusIndex = this.state.getBlockIndexById(selection.focus.blockId);
        if (anchorIndex < 0 || focusIndex < 0) return null;
        const forward = anchorIndex < focusIndex || (anchorIndex === focusIndex && selection.anchor.offset <= selection.focus.offset);
        return {
            start: forward ? selection.anchor : selection.focus,
            end: forward ? selection.focus : selection.anchor,
            startIndex: forward ? anchorIndex : focusIndex,
            endIndex: forward ? focusIndex : anchorIndex,
            direction: selection.direction || (forward ? 'forward' : 'backward')
        };
    }

    getBlockSelectionRange(block, blockIndex, normalizedSelection) {
        const length = getBlockTextLength(block);
        const from = blockIndex === normalizedSelection.startIndex ? Math.max(0, normalizedSelection.start.offset) : 0;
        const to = blockIndex === normalizedSelection.endIndex ? Math.min(length, normalizedSelection.end.offset) : length;
        return { from: Math.min(from, to), to: Math.max(from, to) };
    }

    createMarkTransaction(source, selection, key, value = true, mode = 'set') {
        const normalized = this.normalizeTextSelection(selection);
        if (!normalized) return null;
        if (normalized.startIndex === normalized.endIndex && normalized.start.offset === normalized.end.offset) {
            const block = this.state.doc.blocks[normalized.startIndex];
            const current = this.storedMarks || getMarksAtOffset(getBlockRuns(block), normalized.start.offset);
            const next = { ...current };
            if (mode === 'toggle' && next[key]) delete next[key];
            else if (value == null || value === false) delete next[key];
            else next[key] = value;
            this.storedMarks = next;
            return { handled: true };
        }

        const operations = [];
        for (let index = normalized.startIndex; index <= normalized.endIndex; index += 1) {
            const previous = this.state.doc.blocks[index];
            if (!previous || previous.type !== 'text') continue;
            const block = ensureBlockRuns(previous);
            const { from, to } = this.getBlockSelectionRange(block, index, normalized);
            if (from === to) continue;
            const children = applyMark(block.children, from, to, key, value, mode);
            const next = withBlockRuns(block, children);
            operations.push({
                type: 'REPLACE_BLOCK_STATE',
                blockId: previous.id,
                index,
                block: next,
                prevBlock: cloneDocumentValue(previous),
                source
            });
        }
        return new Transaction({ source, operations, selectionBefore: selection, selectionAfter: selection, meta: { inputType: 'format', mergeable: false } });
    }

    createClearFormattingTransaction(selection) {
        const normalized = this.normalizeTextSelection(selection);
        if (!normalized) return null;
        if (normalized.startIndex === normalized.endIndex && normalized.start.offset === normalized.end.offset) {
            this.storedMarks = {};
            return { handled: true };
        }
        const operations = [];
        for (let index = normalized.startIndex; index <= normalized.endIndex; index += 1) {
            const previous = this.state.doc.blocks[index];
            if (!previous || previous.type !== 'text') continue;
            const block = ensureBlockRuns(previous);
            const { from, to } = this.getBlockSelectionRange(block, index, normalized);
            const next = withBlockRuns(block, clearMarks(block.children, from, to));
            operations.push({ type: 'REPLACE_BLOCK_STATE', blockId: previous.id, index, block: next, prevBlock: cloneDocumentValue(previous), source: 'clearFormatting' });
        }
        return new Transaction({ source: 'clearFormatting', operations, selectionBefore: selection, selectionAfter: selection, meta: { inputType: 'format', mergeable: false } });
    }

    getSelectionMarks(selection = this.selection) {
        const normalized = this.normalizeTextSelection(selection);
        if (!normalized) return {};
        const block = this.state.doc.blocks[normalized.startIndex];
        if (!block || block.type !== 'text') return {};
        if (normalized.startIndex === normalized.endIndex && normalized.start.offset === normalized.end.offset) {
            return this.storedMarks || getMarksAtOffset(getBlockRuns(block), normalized.start.offset);
        }
        if (normalized.startIndex === normalized.endIndex) {
            return getCommonMarks(getBlockRuns(block), normalized.start.offset, normalized.end.offset);
        }
        let common = null;
        for (let index = normalized.startIndex; index <= normalized.endIndex; index += 1) {
            const current = this.state.doc.blocks[index];
            if (!current || current.type !== 'text') continue;
            const { from, to } = this.getBlockSelectionRange(current, index, normalized);
            const marks = getCommonMarks(getBlockRuns(current), from, to);
            if (common === null) common = { ...marks };
            else for (const key of Object.keys(common)) if (JSON.stringify(common[key]) !== JSON.stringify(marks[key])) delete common[key];
        }
        return common || {};
    }

}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/id.js
// ================================================================
const SAFE_ID = /^[A-Za-z][A-Za-z0-9_-]*$/;

function randomPart() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID().replace(/-/g, '');
    }
    const time = Date.now().toString(36);
    const rand = Math.random().toString(36).slice(2, 12);
    return `${time}${rand}`;
}

export function createStableId(prefix = 'node') {
    return `${prefix}_${randomPart()}`;
}

export function isStableStringId(value) {
    return typeof value === 'string' && value.length > 0 && SAFE_ID.test(value);
}

export function normalizeStableId(value, prefix = 'node', used = null) {
    let id = isStableStringId(value) ? value : createStableId(prefix);
    if (used) {
        while (used.has(id)) id = createStableId(prefix);
        used.add(id);
    }
    return id;
}

export function ensureBlockIdentity(block, used = new Set()) {
    if (!block || typeof block !== 'object') return { changed: false, block };
    let changed = false;
    const nextId = normalizeStableId(block.id, 'blk', used);
    if (block.id !== nextId) {
        block.id = nextId;
        changed = true;
    }

    if (Array.isArray(block.items)) {
        const itemUsed = new Set();
        block.items.forEach((item, index) => {
            if (typeof item === 'string') return;
            if (!item || typeof item !== 'object') return;
            const itemId = normalizeStableId(item.id, 'item', itemUsed);
            if (item.id !== itemId) {
                item.id = itemId;
                changed = true;
            }
            if (!Number.isFinite(Number(item.order))) item.order = index;
        });
    }

    if (block.type === 'table' && Array.isArray(block.rows)) {
        if (!Array.isArray(block.rowIds)) {
            block.rowIds = [];
            changed = true;
        }
        if (!Array.isArray(block.cellIds)) {
            block.cellIds = [];
            changed = true;
        }
        const rowUsed = new Set();
        const cellUsed = new Set();
        block.rows.forEach((row, rowIndex) => {
            const rowId = normalizeStableId(block.rowIds[rowIndex], 'row', rowUsed);
            if (block.rowIds[rowIndex] !== rowId) {
                block.rowIds[rowIndex] = rowId;
                changed = true;
            }
            if (!Array.isArray(block.cellIds[rowIndex])) {
                block.cellIds[rowIndex] = [];
                changed = true;
            }
            (row || []).forEach((cell, colIndex) => {
                const cellId = normalizeStableId(block.cellIds[rowIndex][colIndex], 'cell', cellUsed);
                if (block.cellIds[rowIndex][colIndex] !== cellId) {
                    block.cellIds[rowIndex][colIndex] = cellId;
                    changed = true;
                }
            });
            if (block.cellIds[rowIndex].length > (row || []).length) {
                block.cellIds[rowIndex].length = row.length;
                changed = true;
            }
        });
        if (block.rowIds.length > block.rows.length) {
            block.rowIds.length = block.rows.length;
            changed = true;
        }
        if (block.cellIds.length > block.rows.length) {
            block.cellIds.length = block.rows.length;
            changed = true;
        }
    }

    return { changed, block };
}

export function ensureDocumentIdentity(document) {
    if (!document || typeof document !== 'object') return { changed: false, document };
    let changed = false;
    const used = new Set();
    (document.blocks || []).forEach((block) => {
        const result = ensureBlockIdentity(block, used);
        changed = changed || result.changed;
    });

    const migrateNotes = (notes, prefix) => {
        (notes || []).forEach((note) => {
            const noteId = normalizeStableId(note.id, prefix);
            if (note.id !== noteId) {
                note.id = noteId;
                changed = true;
            }
            if (!note.blockId && Number.isInteger(note.blockIndex)) {
                const block = document.blocks?.[note.blockIndex];
                if (block?.id) {
                    note.blockId = block.id;
                    changed = true;
                }
            }
        });
    };
    migrateNotes(document.footnotes, 'fn');
    migrateNotes(document.endnotes, 'en');

    return { changed, document };
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/inline/block-inline.js
// ================================================================
import { htmlToRuns } from './html-to-runs.js';
import { cloneRuns, getRunsLength, getRunsText, normalizeRuns } from './inline-model.js';
import { runsToHtml } from './runs-to-html.js';

export function blockUsesRuns(block) {
    return !!block && block.type === 'text' && block.contentFormat === 'runs' && Array.isArray(block.children);
}

export function getBlockRuns(block) {
    if (!block || block.type !== 'text') return [];
    if (blockUsesRuns(block)) return normalizeRuns(block.children);
    return htmlToRuns(block.content || '');
}

export function withBlockRuns(block, runs) {
    const children = normalizeRuns(runs);
    return {
        ...block,
        contentFormat: 'runs',
        children: cloneRuns(children),
        content: runsToHtml(children)
    };
}

export function ensureBlockRuns(block) {
    return blockUsesRuns(block) ? withBlockRuns(block, block.children) : withBlockRuns(block, getBlockRuns(block));
}

export function getBlockHtml(block) {
    if (!block) return '';
    return blockUsesRuns(block) ? runsToHtml(block.children) : String(block.content || '');
}

export function getBlockText(block) {
    return getRunsText(getBlockRuns(block));
}

export function getBlockTextLength(block) {
    return getRunsLength(getBlockRuns(block));
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/inline/html-to-runs.js
// ================================================================
import { createRun, normalizeRuns, normalizeMarks } from './inline-model.js';

function parseStyle(styleText = '') {
    const style = {};
    String(styleText).split(';').forEach(part => {
        const [rawKey, ...rest] = part.split(':');
        if (!rawKey || !rest.length) return;
        style[rawKey.trim().toLowerCase()] = rest.join(':').trim();
    });
    return style;
}

function deriveMarks(node, inherited) {
    const marks = { ...inherited };
    if (!node || node.nodeType !== 1) return marks;
    const tag = node.tagName.toLowerCase();
    if (tag === 'b' || tag === 'strong') marks.bold = true;
    if (tag === 'i' || tag === 'em') marks.italic = true;
    if (tag === 'u') marks.underline = true;
    if (tag === 's' || tag === 'strike' || tag === 'del') marks.strikethrough = true;
    if (tag === 'code') marks.code = true;
    if (tag === 'sup') marks.superscript = true;
    if (tag === 'sub') marks.subscript = true;
    if (tag === 'a' && node.getAttribute('href')) marks.link = { href: node.getAttribute('href'), title: node.getAttribute('title') || undefined };

    const style = parseStyle(node.getAttribute('style') || '');
    if (style['font-family']) marks.fontFamily = style['font-family'].replace(/["']/g, '').split(',')[0].trim();
    if (style['font-size']) marks.fontSize = style['font-size'];
    if (style.color) marks.color = style.color;
    if (style['background-color']) marks.highlight = style['background-color'];
    if (style['font-weight'] && (/bold/i.test(style['font-weight']) || Number(style['font-weight']) >= 600)) marks.bold = true;
    if (style['font-style'] === 'italic') marks.italic = true;
    if (style['text-decoration']) {
        if (style['text-decoration'].includes('underline')) marks.underline = true;
        if (style['text-decoration'].includes('line-through')) marks.strikethrough = true;
    }
    if (style['vertical-align'] === 'super') marks.superscript = true;
    if (style['vertical-align'] === 'sub') marks.subscript = true;
    return normalizeMarks(marks);
}

export function htmlToRuns(html = '') {
    if (typeof document === 'undefined') return normalizeRuns([createRun(String(html || '').replace(/<br\s*\/?\s*>/gi, '\n').replace(/<[^>]+>/g, ''))]);
    const root = document.createElement('div');
    root.innerHTML = html || '';
    const runs = [];

    const walk = (node, marks = {}) => {
        if (node.nodeType === Node.TEXT_NODE) {
            if (node.nodeValue) runs.push(createRun(node.nodeValue, marks));
            return;
        }
        if (node.nodeType !== Node.ELEMENT_NODE) return;
        const tag = node.tagName.toLowerCase();
        if (tag === 'br') {
            runs.push(createRun('\n', marks));
            return;
        }
        const nextMarks = deriveMarks(node, marks);
        node.childNodes.forEach(child => walk(child, nextMarks));
    };

    root.childNodes.forEach(node => walk(node, {}));
    return normalizeRuns(runs);
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/inline/inline-model.js
// ================================================================
import { createStableId } from '../id.js';

export const EMPTY_MARKS = Object.freeze({});

export function normalizeMarks(marks = {}) {
    const next = {};
    if (!marks || typeof marks !== 'object') return next;
    for (const [key, value] of Object.entries(marks)) {
        if (value === undefined || value === null || value === false || value === '') continue;
        if (key === 'link' && typeof value === 'string') next.link = { href: value };
        else if (key === 'link' && typeof value === 'object' && value.href) next.link = { ...value, href: String(value.href) };
        else next[key] = value;
    }
    return next;
}

export function marksEqual(a = {}, b = {}) {
    return JSON.stringify(normalizeMarks(a)) === JSON.stringify(normalizeMarks(b));
}

export function createRun(text = '', marks = {}, id = null) {
    return {
        id: id || createStableId('run'),
        text: String(text ?? ''),
        marks: normalizeMarks(marks)
    };
}

export function normalizeRuns(runs = [], { preserveEmpty = true } = {}) {
    const out = [];
    for (const value of Array.isArray(runs) ? runs : []) {
        if (!value || typeof value !== 'object') continue;
        const run = createRun(value.text ?? '', value.marks || {}, value.id);
        if (!run.text) continue;
        const previous = out[out.length - 1];
        if (previous && marksEqual(previous.marks, run.marks)) previous.text += run.text;
        else out.push(run);
    }
    if (!out.length && preserveEmpty) out.push(createRun(''));
    return out;
}

export function getRunsText(runs = []) {
    return normalizeRuns(runs).map(run => run.text).join('');
}

export function getRunsLength(runs = []) {
    return getRunsText(runs).length;
}

export function cloneRuns(runs = []) {
    return normalizeRuns(runs).map(run => ({ id: run.id, text: run.text, marks: { ...run.marks, ...(run.marks.link ? { link: { ...run.marks.link } } : {}) } }));
}

export function getMarksAtOffset(runs = [], offset = 0, affinity = 'backward') {
    const normalized = normalizeRuns(runs);
    let cursor = 0;
    const target = Math.max(0, Number(offset) || 0);
    for (let index = 0; index < normalized.length; index += 1) {
        const run = normalized[index];
        const end = cursor + run.text.length;
        if (target < end || (target === end && affinity === 'backward' && run.text.length)) return { ...run.marks };
        cursor = end;
    }
    return { ...(normalized[normalized.length - 1]?.marks || {}) };
}

export function getCommonMarks(runs = [], from = 0, to = null) {
    const normalized = normalizeRuns(runs);
    const endTarget = to == null ? getRunsLength(normalized) : Math.max(from, Number(to) || 0);
    let cursor = 0;
    let common = null;
    for (const run of normalized) {
        const end = cursor + run.text.length;
        if (end > from && cursor < endTarget) {
            const marks = normalizeMarks(run.marks);
            if (common === null) common = { ...marks };
            else {
                for (const key of Object.keys(common)) {
                    if (JSON.stringify(common[key]) !== JSON.stringify(marks[key])) delete common[key];
                }
            }
        }
        cursor = end;
    }
    return common || {};
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/inline/inline-operations.js
// ================================================================
import { createRun, getCommonMarks, getMarksAtOffset, getRunsLength, marksEqual, normalizeMarks, normalizeRuns } from './inline-model.js';

export function splitRunsAtOffset(runs, offset) {
    const source = normalizeRuns(runs);
    const target = Math.max(0, Math.min(getRunsLength(source), Number(offset) || 0));
    const left = [];
    const right = [];
    let cursor = 0;
    for (const run of source) {
        const end = cursor + run.text.length;
        if (end <= target) left.push({ ...run, marks: { ...run.marks } });
        else if (cursor >= target) right.push({ ...run, marks: { ...run.marks } });
        else {
            const local = target - cursor;
            if (local > 0) left.push(createRun(run.text.slice(0, local), run.marks, run.id));
            if (local < run.text.length) right.push(createRun(run.text.slice(local), run.marks));
        }
        cursor = end;
    }
    return { left: normalizeRuns(left), right: normalizeRuns(right) };
}

export function splitRunsAtRange(runs, from, to) {
    const first = splitRunsAtOffset(runs, from);
    const second = splitRunsAtOffset(first.right, Math.max(0, to - from));
    return { before: first.left, selected: second.left, after: second.right };
}

export function replaceRange(runs, from, to, replacement = []) {
    const { before, after } = splitRunsAtRange(runs, from, to);
    return normalizeRuns([...before, ...normalizeRuns(replacement, { preserveEmpty: false }), ...after]);
}

export function insertText(runs, offset, text, marks = null) {
    if (!text) return normalizeRuns(runs);
    const inherited = marks == null ? getMarksAtOffset(runs, offset) : normalizeMarks(marks);
    return replaceRange(runs, offset, offset, [createRun(text, inherited)]);
}

export function deleteRange(runs, from, to) {
    return replaceRange(runs, from, to, []);
}

export function applyMark(runs, from, to, key, value = true, mode = 'set') {
    if (from === to) return normalizeRuns(runs);
    const parts = splitRunsAtRange(runs, from, to);
    let resolvedValue = value;
    if (mode === 'toggle') {
        const common = getCommonMarks(parts.selected, 0, getRunsLength(parts.selected));
        resolvedValue = common[key] ? null : value;
    }
    const selected = parts.selected.map(run => {
        const marks = { ...run.marks };
        if (resolvedValue === null || resolvedValue === false || resolvedValue === undefined) delete marks[key];
        else marks[key] = resolvedValue;
        return { ...run, marks };
    });
    return normalizeRuns([...parts.before, ...selected, ...parts.after]);
}

export function clearMarks(runs, from, to) {
    if (from === to) return normalizeRuns(runs);
    const parts = splitRunsAtRange(runs, from, to);
    return normalizeRuns([...parts.before, ...parts.selected.map(run => ({ ...run, marks: {} })), ...parts.after]);
}

export function concatRuns(...groups) {
    return normalizeRuns(groups.flat());
}

export function runsEqual(a, b) {
    const left = normalizeRuns(a);
    const right = normalizeRuns(b);
    if (left.length !== right.length) return false;
    return left.every((run, index) => run.text === right[index].text && marksEqual(run.marks, right[index].marks));
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/inline/runs-to-html.js
// ================================================================
import { normalizeRuns } from './inline-model.js';

function escapeHtml(text) {
    return String(text ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function escapeAttr(text) {
    return escapeHtml(text).replace(/'/g, '&#39;');
}

export function runToHtml(run) {
    const marks = run.marks || {};
    let html = escapeHtml(run.text).replace(/\n/g, '<br>');
    if (marks.code) html = `<code>${html}</code>`;
    if (marks.bold) html = `<strong>${html}</strong>`;
    if (marks.italic) html = `<em>${html}</em>`;
    if (marks.underline) html = `<u>${html}</u>`;
    if (marks.strikethrough) html = `<s>${html}</s>`;
    if (marks.superscript) html = `<sup>${html}</sup>`;
    if (marks.subscript) html = `<sub>${html}</sub>`;
    if (marks.revision?.type === 'insertion') html = `<ins class="rev-insertion" data-revision-id="${escapeAttr(marks.revision.id || '')}">${html}</ins>`;
    if (marks.revision?.type === 'deletion') html = `<del class="rev-deletion" data-revision-id="${escapeAttr(marks.revision.id || '')}">${html}</del>`;

    const styles = [];
    if (marks.fontFamily) styles.push(`font-family:${marks.fontFamily}`);
    if (marks.fontSize) styles.push(`font-size:${typeof marks.fontSize === 'number' ? `${marks.fontSize}pt` : marks.fontSize}`);
    if (marks.color) styles.push(`color:${marks.color}`);
    if (marks.highlight) styles.push(`background-color:${marks.highlight}`);
    if (styles.length) html = `<span style="${escapeAttr(styles.join(';'))}">${html}</span>`;
    if (marks.link?.href) html = `<a href="${escapeAttr(marks.link.href)}"${marks.link.title ? ` title="${escapeAttr(marks.link.title)}"` : ''}>${html}</a>`;
    return html;
}

export function runsToHtml(runs = []) {
    return normalizeRuns(runs).map(runToHtml).join('');
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/model-input-manager.js
// ================================================================
import { htmlToRuns } from './inline/html-to-runs.js';
import { getRunsText } from './inline/inline-model.js';

const SUPPORTED_INPUTS = new Set([
    'insertText',
    'insertReplacementText',
    'insertParagraph',
    'insertLineBreak',
    'deleteContentBackward',
    'deleteContentForward',
    'deleteWordBackward',
    'deleteWordForward',
    'insertFromPaste',
    'historyUndo',
    'historyRedo'
]);

export class ModelInputManager {
    constructor(engine) {
        this.engine = engine;
        this.composing = false;
        this.compositionTarget = null;
        this.compositionSelection = null;
        this._setup = false;
    }

    setup() {
        if (this._setup) return;
        this._setup = true;
        document.addEventListener('beforeinput', event => this.onBeforeInput(event), true);
        document.addEventListener('compositionstart', event => this.onCompositionStart(event), true);
        document.addEventListener('compositionend', event => this.onCompositionEnd(event), true);
    }

    getTextBlockElement(target) {
        const block = target?.closest?.('.block-text[data-block-id], .block-text[data-index]');
        if (!block) return null;
        const blockId = block.dataset.blockId || this.engine.state.doc.blocks[Number(block.dataset.index)]?.id;
        const model = blockId ? this.engine.state.getBlockById(blockId) : null;
        return model?.type === 'text' ? block : null;
    }

    handlesModelInput(contextOrTarget) {
        const target = contextOrTarget?.el || contextOrTarget;
        return !!this.getTextBlockElement(target);
    }

    onBeforeInput(event) {
        const blockEl = this.getTextBlockElement(event.target);
        if (!blockEl || this.composing || event.isComposing) return;
        if (!SUPPORTED_INPUTS.has(event.inputType)) return;

        const selection = this.engine.captureSelection();
        if (!selection || selection.type !== 'text') return;

        if (event.inputType === 'historyUndo') {
            event.preventDefault();
            this.engine.state.history.undo();
            return;
        }
        if (event.inputType === 'historyRedo') {
            event.preventDefault();
            this.engine.state.history.redo();
            return;
        }

        event.preventDefault();
        switch (event.inputType) {
            case 'insertText':
            case 'insertReplacementText':
                this.engine.dispatch('replaceSelection', { text: event.data || '' }, { selection });
                break;
            case 'insertParagraph':
                this.engine.dispatch('splitParagraph', {}, { selection });
                break;
            case 'insertLineBreak':
                this.engine.dispatch('insertLineBreak', {}, { selection });
                break;
            case 'deleteContentBackward':
                this.engine.dispatch('deleteBackward', { unit: 'character' }, { selection });
                break;
            case 'deleteContentForward':
                this.engine.dispatch('deleteForward', { unit: 'character' }, { selection });
                break;
            case 'deleteWordBackward':
                this.engine.dispatch('deleteBackward', { unit: 'word' }, { selection });
                break;
            case 'deleteWordForward':
                this.engine.dispatch('deleteForward', { unit: 'word' }, { selection });
                break;
            case 'insertFromPaste': {
                const transfer = event.dataTransfer || event.clipboardData;
                const html = transfer?.getData?.('text/html') || '';
                const text = transfer?.getData?.('text/plain') || event.data || '';
                this.engine.dispatch('replaceSelection', {
                    text: html ? getRunsText(htmlToRuns(html)) : text,
                    runs: html ? htmlToRuns(html) : null,
                    source: 'paste'
                }, { selection });
                break;
            }
        }
    }

    onCompositionStart(event) {
        const blockEl = this.getTextBlockElement(event.target);
        if (!blockEl) return;
        this.composing = true;
        this.compositionTarget = blockEl;
        this.compositionSelection = this.engine.captureSelection();
        blockEl.dataset.modelComposing = '1';
    }

    onCompositionEnd(event) {
        if (!this.composing) return;
        const target = this.compositionTarget;
        const selection = this.compositionSelection;
        this.composing = false;
        this.compositionTarget = null;
        this.compositionSelection = null;
        if (target) delete target.dataset.modelComposing;
        const text = event.data || '';
        if (selection && text) this.engine.dispatch('replaceSelection', { text, source: 'composition' }, { selection });
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/objects/object-manager.js
// ================================================================
import { cloneDocumentValue } from '../schema.js';
import { createImageObject, createTextBoxObject, isObjectBlock, WRAP_TYPES } from './object-model.js';

const HANDLE_NAMES = ['nw', 'n', 'ne', 'e', 'se', 's', 'sw', 'w'];

function clamp(value, min, max) { return Math.max(min, Math.min(max, Number(value) || 0)); }

export class ObjectManager {
    constructor(controller) {
        this.ctrl = controller;
        this.state = controller.state;
        this.engine = controller.engine;
        this.selectedObjectId = null;
        this.cropMode = false;
        this.guideLayer = null;
    }

    setup() {
        this.registerCommands();
        this.ensureUi();
        document.addEventListener('pointerdown', event => {
            const host = event.target.closest?.('[data-object-id]');
            if (host) this.select(host.dataset.objectId);
            else if (!event.target.closest?.('.object-format-panel')) this.clearSelection();
        });
        document.addEventListener('keydown', event => this.onKeyDown(event));
        this.state.subscribeTo('DOCUMENT_LOADED', () => this.clearSelection());
        this.state.subscribeTo('TRANSACTION_APPLIED', () => this.refreshUi());
    }

    registerCommands() {
        this.engine.registerCommand('insertImageObject', ({ payload, selection }) => {
            const block = createImageObject({
                image: { src: payload.src || '', assetId: payload.assetId || null, altText: payload.altText || '' },
                layout: { mode: payload.mode || 'inline', width: payload.width || 320, height: payload.height || null },
                wrap: { type: payload.wrapType || (payload.mode === 'floating' ? 'square' : 'inline'), side: payload.side || 'right' },
                anchor: { blockId: payload.anchorBlockId || selection?.anchor?.blockId || null }
            });
            return this.engine.commands.execute('insertBlock', { engine: this.engine, state: this.state, payload: { block, index: payload.index, source: 'object' }, selection, document: this.state.doc, controller: this.ctrl, renderer: this.ctrl.renderer });
        });
        this.engine.registerCommand('insertTextBoxObject', ({ payload, selection }) => {
            const block = createTextBoxObject({
                content: payload.content || 'Text box',
                layout: { x: payload.x || 48, y: payload.y || 48, width: payload.width || 220, height: payload.height || 110 },
                anchor: { blockId: payload.anchorBlockId || selection?.anchor?.blockId || null }
            });
            return this.engine.commands.execute('insertBlock', { engine: this.engine, state: this.state, payload: { block, index: payload.index, source: 'object' }, selection, document: this.state.doc, controller: this.ctrl, renderer: this.ctrl.renderer });
        });
        this.engine.registerCommand('updateObject', ({ state, payload, selection }) => {
            const index = state.getBlockIndexById(payload.objectId);
            const previous = state.doc.blocks[index];
            if (!isObjectBlock(previous)) return null;
            const next = cloneDocumentValue(previous);
            this.deepAssign(next, payload.patch || {});
            return this.engine.createTransaction(payload.source || 'object', [{
                type: 'REPLACE_BLOCK_STATE', blockId: previous.id, index,
                block: next, prevBlock: cloneDocumentValue(previous), source: payload.source || 'object'
            }], selection);
        });
        this.engine.registerCommand('duplicateObject', ({ state, payload, selection }) => {
            const index = state.getBlockIndexById(payload.objectId);
            const source = state.doc.blocks[index];
            if (!isObjectBlock(source)) return null;
            const copy = cloneDocumentValue(source);
            copy.id = `obj_${globalThis.crypto?.randomUUID?.() || `${Date.now()}${Math.random()}`}`.replace(/[^A-Za-z0-9_-]/g, '');
            copy.layout.x = Number(copy.layout.x || 0) + 18;
            copy.layout.y = Number(copy.layout.y || 0) + 18;
            return this.engine.commands.execute('insertBlock', { engine: this.engine, state, payload: { block: copy, index: index + 1, source: 'objectDuplicate' }, selection, document: state.doc, controller: this.ctrl, renderer: this.ctrl.renderer });
        });
    }

    deepAssign(target, patch) {
        Object.entries(patch || {}).forEach(([key, value]) => {
            if (value && typeof value === 'object' && !Array.isArray(value)) {
                if (!target[key] || typeof target[key] !== 'object') target[key] = {};
                this.deepAssign(target[key], value);
            } else target[key] = value;
        });
        return target;
    }

    select(objectId) {
        if (!this.state.getBlockById(objectId)) return;
        this.selectedObjectId = objectId;
        document.querySelectorAll('[data-object-id].object-selected').forEach(el => el.classList.remove('object-selected'));
        document.querySelectorAll(`[data-object-id="${CSS.escape(objectId)}"]`).forEach(el => el.classList.add('object-selected'));
        document.body.classList.add('object-selection-active');
        this.refreshUi();
        this.state.signal('OBJECT_SELECTED', { objectId });
    }

    clearSelection() {
        this.selectedObjectId = null;
        this.cropMode = false;
        document.querySelectorAll('[data-object-id].object-selected').forEach(el => el.classList.remove('object-selected'));
        document.body.classList.remove('object-selection-active');
        document.getElementById('object-format-panel')?.classList.add('hidden');
    }

    get selectedObject() { return this.selectedObjectId ? this.state.getBlockById(this.selectedObjectId) : null; }

    ensureUi() {
        if (document.getElementById('object-format-panel')) return;
        const panel = document.createElement('div');
        panel.id = 'object-format-panel';
        panel.className = 'object-format-panel hidden';
        panel.innerHTML = `
            <div class="object-panel-row object-panel-title"><strong>Object Format</strong><button data-action="close" title="Close">×</button></div>
            <label>Wrap <select data-field="wrap.type">${WRAP_TYPES.map(type => `<option value="${type}">${this.wrapLabel(type)}</option>`).join('')}</select></label>
            <label>Side <select data-field="wrap.side"><option value="both">Both sides</option><option value="left">Text left</option><option value="right">Text right</option><option value="largest">Largest side</option></select></label>
            <div class="object-panel-grid">
              <label>X <input data-field="layout.x" type="number" step="1"></label><label>Y <input data-field="layout.y" type="number" step="1"></label>
              <label>W <input data-field="layout.width" type="number" min="12" step="1"></label><label>H <input data-field="layout.height" type="number" min="12" step="1"></label>
              <label>Rotate <input data-field="layout.rotation" type="number" step="1"></label><label>Layer <input data-field="layout.zIndex" type="number" step="1"></label>
            </div>
            <div class="object-panel-row"><button data-action="front">Bring front</button><button data-action="back">Send back</button><button data-action="duplicate">Duplicate</button></div>
            <div class="object-panel-row image-actions"><button data-action="replace">Replace</button><button data-action="crop">Crop</button><button data-action="rotate-left">↶ 90°</button><button data-action="flip-x">Flip</button><button data-action="flip-y">Flip V</button></div>
            <label class="image-actions">Alt text <input data-field="image.altText" type="text"></label>
            <label class="image-actions">Caption <input data-field="image.caption" type="text"></label>
            <label class="image-actions">Link <input data-field="image.hyperlink" type="url"></label>
            <label class="image-actions"><input data-field="image.decorative" type="checkbox"> Decorative</label>
            <div class="object-panel-grid image-actions">
              <label>Crop L <input data-field="image.crop.left" type="number" min="0" max="0.95" step="0.01"></label><label>Crop R <input data-field="image.crop.right" type="number" min="0" max="0.95" step="0.01"></label>
              <label>Crop T <input data-field="image.crop.top" type="number" min="0" max="0.95" step="0.01"></label><label>Crop B <input data-field="image.crop.bottom" type="number" min="0" max="0.95" step="0.01"></label>
              <label>Brightness <input data-field="image.filters.brightness" type="number" min="0" max="3" step="0.05"></label><label>Contrast <input data-field="image.filters.contrast" type="number" min="0" max="3" step="0.05"></label>
              <label>Saturation <input data-field="image.filters.saturate" type="number" min="0" max="3" step="0.05"></label><label>Opacity <input data-field="image.filters.opacity" type="number" min="0" max="1" step="0.05"></label>
              <label>Radius <input data-field="image.cornerRadius" type="number" min="0" step="1"></label><label>Border <input data-field="image.border.width" type="number" min="0" step="1"></label>
            </div>
            <div class="textbox-actions">
              <div class="object-panel-grid"><label>Padding <input data-field="textBox.margins.top" type="number" min="0"></label><label>Columns <input data-field="textBox.columns" type="number" min="1" max="6"></label></div>
              <label>Vertical align <select data-field="textBox.verticalAlign"><option value="top">Top</option><option value="middle">Middle</option><option value="bottom">Bottom</option></select></label>
              <label>Auto fit <select data-field="textBox.autoFit"><option value="none">Do not autofit</option><option value="shrinkText">Shrink text</option><option value="resizeShape">Resize shape</option><option value="scroll">Scroll</option></select></label>
              <label>Fill <input data-field="appearance.fill" type="color"></label>
              <div class="object-panel-grid"><label>Border width <input data-field="appearance.borderWidth" type="number" min="0"></label><label>Corner radius <input data-field="appearance.cornerRadius" type="number" min="0"></label></div>
            </div>
            <div class="object-panel-row"><button data-action="wrap-distance">Text distance</button><button data-action="lock-anchor">Lock anchor</button><button data-action="delete" class="btn-danger-outline">Delete</button></div>`;
        document.body.appendChild(panel);
        panel.addEventListener('input', event => this.handleFieldInput(event));
        panel.addEventListener('change', event => this.handleFieldInput(event));
        panel.addEventListener('click', event => this.handleAction(event));
        this.guideLayer = document.createElement('div');
        this.guideLayer.className = 'object-guide-layer';
        document.body.appendChild(this.guideLayer);
    }

    wrapLabel(type) {
        return ({ inline: 'Inline', square: 'Square', topBottom: 'Top and bottom', behindText: 'Behind text', inFrontOfText: 'In front of text', tight: 'Tight', through: 'Through' })[type] || type;
    }

    refreshUi() {
        const panel = document.getElementById('object-format-panel');
        const block = this.selectedObject;
        if (!panel || !block) { panel?.classList.add('hidden'); return; }
        panel.classList.remove('hidden');
        panel.classList.toggle('is-textbox', block.objectType === 'textBox');
        panel.querySelectorAll('.image-actions').forEach(el => el.classList.toggle('hidden', block.objectType !== 'image'));
        panel.querySelectorAll('.textbox-actions').forEach(el => el.classList.toggle('hidden', block.objectType !== 'textBox'));
        panel.querySelectorAll('[data-field]').forEach(input => {
            const value = this.readPath(block, input.dataset.field);
            if (input.type === 'checkbox') input.checked = !!value;
            else if (document.activeElement !== input) input.value = value ?? '';
        });
    }

    readPath(object, path) { return path.split('.').reduce((value, key) => value?.[key], object); }
    pathPatch(path, value) {
        const root = {}; let cursor = root; const parts = path.split('.');
        parts.forEach((part, index) => { if (index === parts.length - 1) cursor[part] = value; else cursor = cursor[part] = {}; });
        return root;
    }

    handleFieldInput(event) {
        const input = event.target.closest('[data-field]');
        if (!input || !this.selectedObjectId) return;
        let value = input.type === 'checkbox' ? input.checked : input.value;
        if (input.type === 'number') value = Number(value);
        let patch = this.pathPatch(input.dataset.field, value);
        if (input.dataset.field === 'textBox.margins.top') patch = { textBox: { margins: { top: value, right: value, bottom: value, left: value } } };
        if (input.dataset.field === 'wrap.type') {
            patch.layout = { mode: value === 'inline' ? 'inline' : 'floating' };
        }
        this.engine.dispatch('updateObject', { objectId: this.selectedObjectId, patch, source: 'objectProperty' }, { restoreSelection: false });
    }

    async handleAction(event) {
        const action = event.target.closest('[data-action]')?.dataset.action;
        if (!action) return;
        const block = this.selectedObject;
        if (action === 'close') return this.clearSelection();
        if (!block) return;
        if (action === 'delete') return this.engine.dispatch('removeBlock', { blockId: block.id }, { restoreSelection: false });
        if (action === 'duplicate') return this.engine.dispatch('duplicateObject', { objectId: block.id }, { restoreSelection: false });
        if (action === 'front' || action === 'back') {
            const zIndex = action === 'front' ? Number(block.layout?.zIndex || 1) + 1 : Number(block.layout?.zIndex || 1) - 1;
            return this.engine.dispatch('updateObject', { objectId: block.id, patch: { layout: { zIndex } }, source: 'arrange' }, { restoreSelection: false });
        }
        if (action === 'rotate-left') {
            const rotation = (Number(block.layout?.rotation || 0) - 90) % 360;
            return this.engine.dispatch('updateObject', { objectId: block.id, patch: { layout: { rotation } }, source: 'rotate' }, { restoreSelection: false });
        }
        if (action === 'flip-x') return this.engine.dispatch('updateObject', { objectId: block.id, patch: { image: { flipX: !block.image?.flipX } }, source: 'flip' }, { restoreSelection: false });
        if (action === 'flip-y') return this.engine.dispatch('updateObject', { objectId: block.id, patch: { image: { flipY: !block.image?.flipY } }, source: 'flip' }, { restoreSelection: false });
        if (action === 'crop') { this.cropMode = !this.cropMode; this.paintCropMode(); return; }
        if (action === 'replace') return this.replaceSelectedImage();
        if (action === 'wrap-distance') return this.editWrapDistance();
        if (action === 'lock-anchor') return this.engine.dispatch('updateObject', { objectId: block.id, patch: { anchor: { lockAnchor: !block.anchor?.lockAnchor } }, source: 'anchor' }, { restoreSelection: false });
    }

    async replaceSelectedImage() {
        const input = document.getElementById('inp-image-upload');
        if (!input) return;
        input.dataset.replaceObjectId = this.selectedObjectId;
        input.click();
    }

    editWrapDistance() {
        const block = this.selectedObject; if (!block) return;
        const current = block.wrap?.distance || {};
        const value = window.prompt('Distance from text in pixels (top,right,bottom,left)', `${current.top || 0},${current.right || 0},${current.bottom || 0},${current.left || 0}`);
        if (!value) return;
        const [top, right, bottom, left] = value.split(',').map(Number);
        if ([top, right, bottom, left].some(number => !Number.isFinite(number))) return;
        this.engine.dispatch('updateObject', { objectId: block.id, patch: { wrap: { distance: { top, right, bottom, left } } }, source: 'wrapDistance' }, { restoreSelection: false });
    }

    decorateElement(element, block) {
        element.dataset.objectId = block.id;
        element.tabIndex = 0;
        if (this.selectedObjectId === block.id) element.classList.add('object-selected');
        if (!element.querySelector('.object-transform-handles')) {
            const handles = document.createElement('div');
            handles.className = 'object-transform-handles';
            handles.innerHTML = HANDLE_NAMES.map(name => `<span class="object-handle ${name}" data-handle="${name}"></span>`).join('') + '<span class="object-rotate-handle" data-handle="rotate"></span><span class="object-wrap-button" title="Wrap text">☰</span>';
            element.appendChild(handles);
            handles.querySelectorAll('[data-handle]').forEach(handle => handle.addEventListener('pointerdown', event => this.startTransform(event, element, block, handle.dataset.handle)));
            handles.querySelector('.object-wrap-button')?.addEventListener('click', event => { event.stopPropagation(); this.select(block.id); document.getElementById('object-format-panel')?.querySelector('[data-field="wrap.type"]')?.focus(); });
        }
        if (block.anchor?.blockId && !element.querySelector('.object-anchor-indicator')) {
            const anchor = document.createElement('span'); anchor.className = 'object-anchor-indicator'; anchor.title = `Anchored to ${block.anchor.blockId}`; anchor.textContent = '⚓'; element.appendChild(anchor);
        }
    }

    startTransform(event, element, block, handle) {
        event.preventDefault(); event.stopPropagation(); this.select(block.id);
        const start = { x: event.clientX, y: event.clientY, width: element.offsetWidth, height: element.offsetHeight, left: Number(block.layout?.x || 0), top: Number(block.layout?.y || 0), rotation: Number(block.layout?.rotation || 0) };
        const ratio = start.width / Math.max(1, start.height);
        const move = moveEvent => {
            const dx = moveEvent.clientX - start.x, dy = moveEvent.clientY - start.y;
            if (handle === 'rotate') {
                const rect = element.getBoundingClientRect();
                const angle = Math.atan2(moveEvent.clientY - (rect.top + rect.height / 2), moveEvent.clientX - (rect.left + rect.width / 2)) * 180 / Math.PI + 90;
                element.style.transform = this.objectTransform(block, angle);
                element.dataset.previewRotation = String(Math.round(angle));
                return;
            }
            let width = start.width, height = start.height, left = start.left, top = start.top;
            if (handle.includes('e')) width += dx;
            if (handle.includes('s')) height += dy;
            if (handle.includes('w')) { width -= dx; left += dx; }
            if (handle.includes('n')) { height -= dy; top += dy; }
            width = clamp(width, 24, 2000); height = clamp(height, 24, 2000);
            if (block.objectType === 'image' && block.image?.lockAspectRatio && !moveEvent.altKey) {
                if (Math.abs(dx) > Math.abs(dy)) height = width / ratio; else width = height * ratio;
            }
            element.style.width = `${width}px`; element.style.height = `${height}px`;
            if (block.layout?.mode === 'floating') { element.style.left = `${left}px`; element.style.top = `${top}px`; }
            element.dataset.previewGeometry = JSON.stringify({ width, height, left, top });
            this.showSnapGuides(element);
        };
        const up = () => {
            document.removeEventListener('pointermove', move); document.removeEventListener('pointerup', up);
            this.clearGuides();
            if (element.dataset.previewRotation) {
                const rotation = Number(element.dataset.previewRotation); delete element.dataset.previewRotation;
                this.engine.dispatch('updateObject', { objectId: block.id, patch: { layout: { rotation } }, source: 'objectTransform' }, { restoreSelection: false });
            } else {
                let geometry = {}; try { geometry = JSON.parse(element.dataset.previewGeometry || '{}'); } catch (_) {}
                delete element.dataset.previewGeometry;
                this.engine.dispatch('updateObject', { objectId: block.id, patch: { layout: { width: geometry.width || element.offsetWidth, height: geometry.height || element.offsetHeight, x: geometry.left ?? block.layout.x, y: geometry.top ?? block.layout.y } }, source: 'objectTransform' }, { restoreSelection: false });
            }
        };
        document.addEventListener('pointermove', move); document.addEventListener('pointerup', up, { once: true });
    }

    objectTransform(block, rotation = block.layout?.rotation || 0) {
        const sx = block.image?.flipX ? -1 : 1, sy = block.image?.flipY ? -1 : 1;
        return `rotate(${Number(rotation) || 0}deg) scale(${sx},${sy})`;
    }

    showSnapGuides(element) {
        if (!this.guideLayer) return;
        const page = element.closest('.page, .mode-pageless'); if (!page) return;
        const pageRect = page.getBoundingClientRect(), rect = element.getBoundingClientRect();
        const guides = [];
        if (Math.abs((rect.left + rect.width / 2) - (pageRect.left + pageRect.width / 2)) < 8) guides.push(`<i class="guide-v" style="left:${pageRect.left + pageRect.width / 2}px"></i>`);
        if (Math.abs((rect.top + rect.height / 2) - (pageRect.top + pageRect.height / 2)) < 8) guides.push(`<i class="guide-h" style="top:${pageRect.top + pageRect.height / 2}px"></i>`);
        this.guideLayer.innerHTML = guides.join('');
    }
    clearGuides() { if (this.guideLayer) this.guideLayer.innerHTML = ''; }

    paintCropMode() {
        document.querySelectorAll(`[data-object-id="${CSS.escape(this.selectedObjectId || '')}"]`).forEach(element => element.classList.toggle('object-crop-mode', this.cropMode));
    }

    onKeyDown(event) {
        const block = this.selectedObject;
        if (!block || event.target.closest('input,select,textarea,[contenteditable="true"]')) return;
        if (event.key === 'Delete' || event.key === 'Backspace') { event.preventDefault(); this.engine.dispatch('removeBlock', { blockId: block.id }, { restoreSelection: false }); return; }
        if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) return;
        event.preventDefault();
        const step = event.shiftKey ? 10 : 1;
        const patch = { layout: { x: Number(block.layout?.x || 0), y: Number(block.layout?.y || 0) } };
        if (event.key === 'ArrowLeft') patch.layout.x -= step;
        if (event.key === 'ArrowRight') patch.layout.x += step;
        if (event.key === 'ArrowUp') patch.layout.y -= step;
        if (event.key === 'ArrowDown') patch.layout.y += step;
        this.engine.dispatch('updateObject', { objectId: block.id, patch, source: 'objectNudge' }, { restoreSelection: false });
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/objects/object-model.js
// ================================================================
import { createStableId } from '../id.js';

function cloneDocumentValue(value) {
    if (value === undefined) return undefined;
    if (typeof structuredClone === 'function') return structuredClone(value);
    return JSON.parse(JSON.stringify(value));
}

const DEFAULT_DISTANCE = Object.freeze({ top: 8, right: 8, bottom: 8, left: 8 });

export const WRAP_TYPES = Object.freeze([
    'inline',
    'square',
    'topBottom',
    'behindText',
    'inFrontOfText',
    'tight',
    'through'
]);

export function defaultObjectLayout(overrides = {}) {
    return {
        mode: 'inline',
        relativeTo: 'paragraph',
        x: 48,
        y: 48,
        width: 240,
        height: 160,
        rotation: 0,
        zIndex: 1,
        allowOverlap: true,
        lockPosition: false,
        ...overrides
    };
}

export function defaultObjectWrap(overrides = {}) {
    const distance = { ...DEFAULT_DISTANCE, ...(overrides.distance || {}) };
    return {
        type: 'inline',
        side: 'both',
        distance,
        contour: Array.isArray(overrides.contour) ? cloneDocumentValue(overrides.contour) : null,
        ...overrides,
        distance
    };
}

export function createImageObject(overrides = {}) {
    const image = overrides.image || {};
    return {
        id: overrides.id || createStableId('obj'),
        type: 'object',
        objectType: 'image',
        anchor: {
            blockId: null,
            offset: 0,
            moveWithText: true,
            lockAnchor: false,
            ...(overrides.anchor || {})
        },
        layout: defaultObjectLayout(overrides.layout || {}),
        wrap: defaultObjectWrap(overrides.wrap || {}),
        image: {
            assetId: null,
            src: '',
            naturalWidth: null,
            naturalHeight: null,
            lockAspectRatio: true,
            crop: { top: 0, right: 0, bottom: 0, left: 0 },
            filters: { brightness: 1, contrast: 1, saturate: 1, grayscale: 0, sepia: 0, opacity: 1 },
            flipX: false,
            flipY: false,
            altText: '',
            decorative: false,
            caption: '',
            hyperlink: null,
            border: { color: 'transparent', width: 0, style: 'solid' },
            shadow: null,
            cornerRadius: 0,
            ...image,
            crop: { top: 0, right: 0, bottom: 0, left: 0, ...(image.crop || {}) },
            filters: { brightness: 1, contrast: 1, saturate: 1, grayscale: 0, sepia: 0, opacity: 1, ...(image.filters || {}) },
            border: { color: 'transparent', width: 0, style: 'solid', ...(image.border || {}) }
        }
    };
}

export function createTextBoxObject(overrides = {}) {
    const textBox = overrides.textBox || {};
    const appearance = overrides.appearance || {};
    const initialContent = overrides.content || textBox.content || 'Text box';
    const blocks = Array.isArray(textBox.blocks) && textBox.blocks.length
        ? cloneDocumentValue(textBox.blocks)
        : [{ id: createStableId('tbblk'), type: 'text', style: 'normal', content: String(initialContent) }];
    return {
        id: overrides.id || createStableId('obj'),
        type: 'object',
        objectType: 'textBox',
        anchor: {
            blockId: null,
            offset: 0,
            moveWithText: true,
            lockAnchor: false,
            ...(overrides.anchor || {})
        },
        layout: defaultObjectLayout({ mode: 'floating', width: 220, height: 110, ...(overrides.layout || {}) }),
        wrap: defaultObjectWrap({ type: 'square', side: 'right', ...(overrides.wrap || {}) }),
        textBox: {
            blocks,
            margins: { top: 8, right: 8, bottom: 8, left: 8, ...(textBox.margins || {}) },
            verticalAlign: textBox.verticalAlign || 'top',
            autoFit: textBox.autoFit || 'resizeShape',
            columns: Math.max(1, Number(textBox.columns || 1)),
            linkedNextId: textBox.linkedNextId || null
        },
        appearance: {
            fill: '#ffffff',
            fillOpacity: 1,
            borderColor: '#64748b',
            borderWidth: 1,
            borderStyle: 'solid',
            cornerRadius: 2,
            shadow: null,
            opacity: 1,
            ...appearance
        }
    };
}

export function isObjectBlock(block) {
    return !!block && block.type === 'object' && ['image', 'textBox', 'shape'].includes(block.objectType);
}

export function isFlowObject(block) {
    if (!isObjectBlock(block)) return false;
    const wrap = block.wrap?.type || (block.layout?.mode === 'inline' ? 'inline' : 'inFrontOfText');
    return wrap === 'inline' || wrap === 'square' || wrap === 'topBottom' || wrap === 'tight' || wrap === 'through';
}

export function normalizeObjectBlock(block, { previousTextBlockId = null } = {}) {
    if (!block || typeof block !== 'object') return { block, changed: false };
    let normalized = block;
    let changed = false;

    if (block.type === 'image') {
        const pct = Math.max(10, Math.min(100, Number(block.width || 100)));
        normalized = createImageObject({
            id: block.id,
            anchor: { blockId: previousTextBlockId, moveWithText: true },
            layout: { mode: 'inline', width: pct, height: null },
            wrap: { type: 'inline', side: block.align === 'right' ? 'left' : block.align === 'left' ? 'right' : 'both' },
            image: {
                src: block.content || '',
                caption: block.caption || '',
                altText: block.altText || '',
                decorative: !!block.decorative,
                lockAspectRatio: block.lockAspectRatio !== false
            }
        });
        normalized.legacy = { align: block.align || 'center', widthPercent: pct };
        changed = true;
    } else if (block.type === 'floating') {
        const common = {
            id: block.id,
            anchor: { blockId: block.anchorBlockId || previousTextBlockId, moveWithText: block.moveWithText !== false },
            layout: {
                mode: 'floating',
                x: Number(block.x || 0),
                y: Number(block.y || 0),
                width: Number(block.w || 180),
                height: Number(block.h || 90),
                rotation: Number(block.rotation || 0),
                zIndex: Number(block.zIndex || 10),
                relativeTo: 'page'
            },
            wrap: { type: block.wrapType || 'inFrontOfText', side: block.wrapSide || 'both' }
        };
        normalized = block.subType === 'image'
            ? createImageObject({ ...common, image: { src: block.content || '', lockAspectRatio: block.lockAspectRatio !== false } })
            : createTextBoxObject({ ...common, content: block.content || 'Floating Text' });
        normalized.legacy = { pageIndex: Number(block.pageIndex || 0) };
        changed = true;
    } else if (isObjectBlock(block)) {
        if (block.objectType === 'image') normalized = createImageObject(block);
        else if (block.objectType === 'textBox') normalized = createTextBoxObject(block);
        else normalized = { ...block, layout: defaultObjectLayout(block.layout), wrap: defaultObjectWrap(block.wrap) };
        changed = JSON.stringify(normalized) !== JSON.stringify(block);
    }

    return { block: normalized, changed };
}

export function normalizeDocumentObjects(document) {
    if (!document || !Array.isArray(document.blocks)) return { document, changed: false };
    let changed = false;
    let previousTextBlockId = null;
    document.blocks = document.blocks.map(block => {
        if (block?.type === 'text') previousTextBlockId = block.id || previousTextBlockId;
        const result = normalizeObjectBlock(block, { previousTextBlockId });
        changed = changed || result.changed;
        return result.block;
    });
    return { document, changed };
}

export function objectTextHtml(block) {
    if (!block || block.objectType !== 'textBox') return '';
    return (block.textBox?.blocks || []).map(item => item.content || '').join('<div><br></div>');
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/position-mapper.js
// ================================================================
import { cloneSelection, createTextPosition } from './selection-model.js';

function htmlTextLength(html) {
    if (typeof document === 'undefined') return String(html || '').replace(/<[^>]*>/g, '').length;
    const el = document.createElement('div');
    el.innerHTML = html || '';
    return (el.textContent || '').length;
}

export class PositionMapper {
    constructor(stateManager) {
        this.state = stateManager;
    }

    mapSelection(selection, operations = [], context = {}) {
        if (!selection) return null;
        const next = cloneSelection(selection);
        if (next.type === 'text') {
            next.anchor = this.mapPosition(next.anchor, operations, context);
            next.focus = this.mapPosition(next.focus, operations, context);
            if (!next.anchor || !next.focus) return null;
        } else if (next.type === 'node') {
            if (this.wasBlockRemoved(next.blockId, operations)) {
                const fallback = this.findFallbackBlockId(next.blockId, operations, context);
                if (!fallback) return null;
                next.blockId = fallback;
                next.nodeId = fallback;
            }
        } else if (next.type === 'table' && this.wasBlockRemoved(next.tableId, operations)) {
            return null;
        }
        return next;
    }

    mapPosition(position, operations = [], context = {}) {
        if (!position?.blockId) return null;
        let current = createTextPosition(position.blockId, position.offset, position.affinity);

        for (const op of operations) {
            const blockId = op.blockId || op.block?.id || null;
            if (op.type === 'REMOVE_BLOCK' && String(blockId) === current.blockId) {
                const fallback = this.findFallbackBlockId(current.blockId, [op], context);
                if (!fallback) return null;
                current = createTextPosition(fallback, 0, current.affinity);
            }

            if (op.type === 'SPLIT_BLOCK' && String(blockId) === current.blockId && Number.isFinite(Number(op.splitOffset))) {
                const splitOffset = Number(op.splitOffset);
                if (current.offset > splitOffset || (current.offset === splitOffset && current.affinity === 'forward')) {
                    current.blockId = String(op.newBlockId || op.newBlock?.id);
                    current.offset = Math.max(0, current.offset - splitOffset);
                }
            }

            if (op.type === 'MERGE_BLOCKS') {
                const removedId = String(op.removedBlockId || op.removedBlock?.id || '');
                const targetId = String(op.targetBlockId || op.blockId || '');
                if (current.blockId === removedId && targetId) {
                    current.blockId = targetId;
                    current.offset += Number.isFinite(Number(op.targetLengthBefore))
                        ? Number(op.targetLengthBefore)
                        : htmlTextLength(op.prevContent);
                }
            }

            if (op.type === 'INSERT_TEXT' && String(blockId) === current.blockId) {
                const at = Number(op.offset) || 0;
                const length = String(op.text || '').length;
                if (current.offset > at || (current.offset === at && current.affinity === 'forward')) current.offset += length;
            }

            if (op.type === 'DELETE_TEXT' && String(blockId) === current.blockId) {
                const from = Math.max(0, Number(op.from) || 0);
                const to = Math.max(from, Number(op.to) || from);
                if (current.offset > to) current.offset -= to - from;
                else if (current.offset > from) current.offset = from;
            }
        }

        return current;
    }

    wasBlockRemoved(blockId, operations) {
        return operations.some(op => op.type === 'REMOVE_BLOCK'
            && String(op.blockId || op.block?.id || '') === String(blockId));
    }

    findFallbackBlockId(blockId, operations, context = {}) {
        for (const op of operations) {
            if (op.type !== 'REMOVE_BLOCK') continue;
            if (String(op.blockId || op.block?.id || '') !== String(blockId)) continue;
            if (op.nextBlockId) return String(op.nextBlockId);
            if (op.previousBlockId) return String(op.previousBlockId);
        }
        const blocks = context.documentAfter?.blocks || this.state?.doc?.blocks || [];
        return blocks[0]?.id ? String(blocks[0].id) : null;
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/review/review-manager.js
// ================================================================
import { createStableId } from '../id.js';
import { cloneDocumentValue } from '../schema.js';

export const DEFAULT_STYLES = {
    normal: { id: 'normal', name: 'Normal', type: 'paragraph', fontFamily: 'Segoe UI', fontSize: 12, lineHeight: 1.15, spacingAfter: 0 },
    h1: { id: 'h1', name: 'Heading 1', type: 'paragraph', basedOn: 'normal', fontSize: 24, bold: true, outlineLevel: 1, keepWithNext: true },
    h2: { id: 'h2', name: 'Heading 2', type: 'paragraph', basedOn: 'normal', fontSize: 20, bold: true, outlineLevel: 2, keepWithNext: true },
    h3: { id: 'h3', name: 'Heading 3', type: 'paragraph', basedOn: 'normal', fontSize: 16, bold: true, outlineLevel: 3, keepWithNext: true },
    quote: { id: 'quote', name: 'Quote', type: 'paragraph', basedOn: 'normal', italic: true, indentLeft: 0.4 }
};

export class ReviewManager {
    constructor(controller) { this.ctrl = controller; this.state = controller.state; this.engine = controller.engine; this.commentHighlightName = 'openword-comments'; }

    setup() {
        this.ensureResources();
        document.getElementById('btn-add-comment')?.addEventListener('click', () => this.addComment());
        document.getElementById('btn-insert-section-break')?.addEventListener('click', () => this.insertSectionBreak());
        document.getElementById('btn-manage-styles')?.addEventListener('click', () => this.manageStyles());
        document.getElementById('sel-block-style')?.addEventListener('focus', () => this.populateStyleSelect());
        const acceptAll = document.getElementById('rp-btn-accept-all');
        const rejectAll = document.getElementById('rp-btn-reject-all');
        if (acceptAll && !acceptAll.dataset.reviewBound) {
            acceptAll.dataset.reviewBound = '1';
            acceptAll.addEventListener('click', () => this.engine.dispatch('acceptAllRevisions'));
        }
        if (rejectAll && !rejectAll.dataset.reviewBound) {
            rejectAll.dataset.reviewBound = '1';
            rejectAll.addEventListener('click', () => this.engine.dispatch('rejectAllRevisions'));
        }
        this.state.subscribeTo('TRANSACTION_APPLIED', ({ transaction }) => this.mapCommentAnchors(transaction));
        this.state.subscribeTo('DOCUMENT_LOADED', () => { this.ensureResources(); this.populateStyleSelect(); this.renderReviewPanel(); });
        this.state.subscribe(() => requestAnimationFrame(() => { this.paintComments(); this.renderReviewPanel(); }));
        this.populateStyleSelect();
    }

    ensureResources() {
        this.state.doc.styles ||= cloneDocumentValue(DEFAULT_STYLES);
        this.state.doc.sections ||= [{ id: createStableId('sec'), startBlockId: this.state.doc.blocks[0]?.id || null, settings: cloneDocumentValue(this.state.doc.settings) }];
        this.state.doc.comments ||= [];
        this.state.doc.settings.editingMode ||= this.state.doc.settings.trackChanges ? 'suggesting' : 'editing';
    }

    populateStyleSelect() {
        this.ensureResources();
        const select = document.getElementById('sel-block-style');
        if (!select) return;
        const value = select.value;
        select.innerHTML = Object.values(this.state.doc.styles).map(style => `<option value="${style.id}">${style.name || style.id}</option>`).join('');
        if ([...select.options].some(option => option.value === value)) select.value = value;
    }

    manageStyles() {
        this.ensureResources();
        const currentId = document.getElementById('sel-block-style')?.value || 'normal';
        const current = this.state.doc.styles[currentId] || this.state.doc.styles.normal;
        const name = window.prompt('Style name', current.name || current.id);
        if (!name) return;
        const size = Number(window.prompt('Font size (pt)', current.fontSize || 12));
        const family = window.prompt('Font family', current.fontFamily || 'Segoe UI') || current.fontFamily;
        this.state.upsertNamedStyle(currentId, { ...current, name, fontSize: Number.isFinite(size) ? size : current.fontSize, fontFamily: family });
        this.populateStyleSelect();
    }

    insertSectionBreak() {
        const afterId = this.engine.captureSelection()?.anchor?.blockId || this.ctrl.activeBlockId;
        const orientation = window.prompt('Section orientation: portrait or landscape', 'portrait');
        this.state.insertSectionBreak(afterId, { orientation: orientation === 'landscape' ? 'landscape' : 'portrait' });
    }

    async addComment() {
        const selection = this.engine.captureSelection();
        if (selection?.type !== 'text') return false;
        const body = window.prompt('Comment');
        if (!body) return false;
        const anchor = { start: cloneDocumentValue(selection.anchor), end: cloneDocumentValue(selection.focus) };
        const saved = await this.requestComment('', 'POST', { anchor, body });
        if (!saved && !navigator.onLine) this.state.addComment({ anchor, body, author: this.state.currentUserName || 'User' });
        this.ctrl.toolbar.openShellPanel('comments');
        return true;
    }

    async requestComment(path, method, payload = {}) {
        const documentId = this.state.doc.id;
        if (!documentId || typeof fetch !== 'function') return false;
        try {
            if (this.state.isDirty && this.state.documentRole !== 'commenter') await this.state.flushSave('before-comment');
            const response = await fetch(`/api/docs/${encodeURIComponent(documentId)}/comments${path}`, {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    'X-OpenWord-Session': this.state.collaborationSessionId || ''
                },
                body: JSON.stringify({ ...payload, baseRevision: Number(this.state.doc.revision) || 0 })
            });
            const result = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(result.error || `Comment update failed (${response.status})`);
            this.state.doc.comments = result.comments || [];
            if (Number.isFinite(Number(result.revision))) this.state.doc.revision = Number(result.revision);
            if (result.updatedAt) this.state.doc.updatedAt = result.updatedAt;
            this.state.isDirty = false;
            this.state.clearRecoveryBackup?.();
            this.state.setSaveStatus('Saved');
            this.state.notify({ type: 'COMMENTS_SYNCED', source: 'server' });
            return true;
        } catch (error) {
            this.ctrl.toolbar?.showShellToast?.(error.message || 'Unable to update comments');
            return false;
        }
    }

    renderComments(body) {
        this.ensureResources();
        const comments = this.state.doc.comments || [];
        body.innerHTML = `<div class="comment-panel-toolbar"><button id="panel-add-comment" class="btn-primary">Add comment</button><button id="panel-show-resolved">Show resolved</button></div><div class="comment-thread-list"></div>`;
        const list = body.querySelector('.comment-thread-list');
        const draw = showResolved => {
            const visible = comments.filter(comment => showResolved || comment.status !== 'resolved');
            list.innerHTML = visible.length ? visible.map(comment => `<article class="comment-thread ${comment.status === 'resolved' ? 'resolved' : ''}" data-comment-id="${comment.id}"><header><strong>${this.escape(comment.author || 'User')}</strong><span>${new Date(comment.createdAt).toLocaleString()}</span></header><p>${this.escape(comment.messages?.[0]?.body || '')}</p>${(comment.messages || []).slice(1).map(message => `<div class="comment-reply"><strong>${this.escape(message.author || 'User')}</strong> ${this.escape(message.body || '')}</div>`).join('')}<footer><button data-action="reply">Reply</button><button data-action="resolve">${comment.status === 'resolved' ? 'Reopen' : 'Resolve'}</button><button data-action="delete">Delete</button></footer></article>`).join('') : '<div class="shell-empty-state"><h3>No comments yet</h3><p>Select text and choose Add comment.</p></div>';
        };
        draw(false);
        body.querySelector('#panel-add-comment')?.addEventListener('click', () => this.addComment());
        body.querySelector('#panel-show-resolved')?.addEventListener('click', event => { event.currentTarget.dataset.show = event.currentTarget.dataset.show === '1' ? '0' : '1'; draw(event.currentTarget.dataset.show === '1'); });
        body.onclick = async event => {
            const thread = event.target.closest('[data-comment-id]'); const action = event.target.dataset.action; if (!thread || !action) return;
            const id = thread.dataset.commentId;
            if (action === 'reply') {
                const text = window.prompt('Reply');
                if (text) await this.requestComment(`/${encodeURIComponent(id)}/replies`, 'POST', { body: text });
            }
            if (action === 'resolve') {
                const comment = this.state.doc.comments?.find(item => item.id === id);
                await this.requestComment(`/${encodeURIComponent(id)}`, 'PATCH', { status: comment?.status === 'resolved' ? 'open' : 'resolved' });
            }
            if (action === 'delete') await this.requestComment(`/${encodeURIComponent(id)}`, 'DELETE');
            this.renderComments(body);
        };
    }

    escape(value) { const div = document.createElement('div'); div.textContent = String(value || ''); return div.innerHTML; }

    mapCommentAnchors(transaction) {
        if (!transaction?.operations?.length || !this.state.doc.comments?.length) return;
        this.state.doc.comments.forEach(comment => {
            const selection = { type: 'text', anchor: comment.anchor.start, focus: comment.anchor.end, direction: 'forward' };
            const mapped = this.engine.positionMapper.mapSelection(selection, transaction.operations);
            if (mapped) comment.anchor = { start: mapped.anchor, end: mapped.focus };
        });
    }

    paintComments() {
        if (!globalThis.CSS?.highlights || typeof Highlight === 'undefined') return;
        const ranges = [];
        (this.state.doc.comments || []).filter(comment => comment.status !== 'resolved').forEach(comment => {
            const start = this.engine.selectionBridge.resolvePosition(comment.anchor.start);
            const end = this.engine.selectionBridge.resolvePosition(comment.anchor.end);
            if (!start || !end) return;
            try { const range = new Range(); range.setStart(start.container, start.offset); range.setEnd(end.container, end.offset); ranges.push(range); } catch (_) { /* stale anchor */ }
        });
        CSS.highlights.set(this.commentHighlightName, new Highlight(...ranges));
    }

    renderReviewPanel() {
        const list = document.getElementById('review-list'); if (!list) return;
        const revisions = this.state.listRunRevisions();
        const canEdit = !this.state.documentRole || ['owner', 'editor'].includes(this.state.documentRole);
        const acceptAll = document.getElementById('rp-btn-accept-all');
        const rejectAll = document.getElementById('rp-btn-reject-all');
        if (acceptAll) acceptAll.disabled = !canEdit || revisions.length === 0;
        if (rejectAll) rejectAll.disabled = !canEdit || revisions.length === 0;
        list.innerHTML = revisions.length ? revisions.map(revision => {
            const label = revision.kind === 'paragraphBreak'
                ? `${revision.type === 'insertion' ? 'Inserted' : 'Deleted'} paragraph break`
                : revision.type === 'insertion' ? 'Inserted' : 'Deleted';
            const preview = revision.text || (revision.kind === 'block' ? 'Document object' : 'Change');
            const when = revision.createdAt || revision.timestamp;
            return `<div class="review-item review-item-${revision.type}" data-revision-id="${this.escape(revision.id)}" data-block-id="${this.escape(revision.blockId)}" tabindex="0"><span class="review-item-type">${this.escape(label)}</span><span class="review-item-text">${this.escape(preview.slice(0, 120))}</span><span class="review-item-meta">${this.escape(revision.author || 'User')}${when ? ` · ${this.escape(new Date(when).toLocaleString())}` : ''}</span><div class="review-item-actions"><button type="button" data-action="accept" title="Accept change" ${canEdit ? '' : 'disabled'}>✓</button><button type="button" data-action="reject" title="Reject change" ${canEdit ? '' : 'disabled'}>×</button></div></div>`;
        }).join('') : '<div class="review-empty">No tracked changes</div>';
        list.querySelectorAll('[data-revision-id]').forEach(item => item.addEventListener('click', event => {
            const actionButton = event.target.closest('[data-action]');
            const action = actionButton?.dataset.action;
            const id = item.dataset.revisionId, blockId = item.dataset.blockId;
            if (!action) {
                this.ctrl.focusBlockById?.(blockId, 'start');
                return;
            }
            event.preventDefault();
            event.stopPropagation();
            if (!canEdit) return;
            if (action === 'accept') this.engine.dispatch('acceptRevision', { revisionId: id, blockId });
            else if (action === 'reject') this.engine.dispatch('rejectRevision', { revisionId: id, blockId });
        }));
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/schema.js
// ================================================================
import { createStableId, ensureDocumentIdentity } from './id.js';
import { normalizeDocumentObjects } from './objects/object-model.js';

export const OPENWORD_SCHEMA_VERSION = 4;

export function createTextBlock(overrides = {}) {
    return {
        id: createStableId('blk'),
        type: 'text',
        style: 'normal',
        content: '',
        ...overrides
    };
}

export function normalizeDocumentSchema(document) {
    if (!document || typeof document !== 'object') {
        return {
            changed: true,
            document: {
                schemaVersion: OPENWORD_SCHEMA_VERSION,
                blocks: [createTextBlock()]
            }
        };
    }

    let changed = false;
    if (document.schemaVersion !== OPENWORD_SCHEMA_VERSION) {
        document.schemaVersion = OPENWORD_SCHEMA_VERSION;
        changed = true;
    }
    if (!Array.isArray(document.blocks)) {
        document.blocks = [createTextBlock()];
        changed = true;
    }
    if (!document.styles || typeof document.styles !== 'object') { document.styles = {}; changed = true; }
    if (!Array.isArray(document.sections)) { document.sections = []; changed = true; }
    if (!Array.isArray(document.comments)) { document.comments = []; changed = true; }
    document.settings ||= {};
    if (!document.settings.editingMode) { document.settings.editingMode = document.settings.trackChanges ? 'suggesting' : 'editing'; changed = true; }

    const identity = ensureDocumentIdentity(document);
    changed = changed || identity.changed;
    const objects = normalizeDocumentObjects(document);
    changed = changed || objects.changed;
    return { changed, document: objects.document };
}

export function cloneDocumentValue(value) {
    if (value === undefined) return undefined;
    if (typeof structuredClone === 'function') return structuredClone(value);
    return JSON.parse(JSON.stringify(value));
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/selection-bridge.js
// ================================================================
import { Formatter } from '../formatter.js';
import {
    createNodeSelection,
    createTableSelection,
    createTextPosition,
    createTextSelection
} from './selection-model.js';

function selectorEscape(value) {
    const text = String(value ?? '');
    if (typeof CSS !== 'undefined' && typeof CSS.escape === 'function') return CSS.escape(text);
    return text.replace(/(["\\])/g, '\\$1');
}

export class SelectionBridge {
    constructor(controller, stateManager) {
        this.controller = controller;
        this.state = stateManager;
        this.current = null;
    }

    get layoutMap() {
        return this.controller?.renderer?.layoutMap || null;
    }

    getBlockElement(node) {
        let element = node;
        if (element?.nodeType === Node.TEXT_NODE) element = element.parentElement;
        if (!element?.closest) return null;
        return element.closest('[data-block-id], [data-index]');
    }

    getBlockId(element) {
        if (!element) return null;
        if (element.dataset?.blockId) return String(element.dataset.blockId);
        const index = Number.parseInt(element.dataset?.index, 10);
        return Number.isInteger(index) ? String(this.state.doc.blocks[index]?.id || '') : null;
    }

    getBlockIndex(element) {
        if (!element) return -1;
        const blockId = this.getBlockId(element);
        if (blockId && typeof this.state.getBlockIndexById === 'function') {
            const index = this.state.getBlockIndexById(blockId);
            if (index >= 0) return index;
        }
        const index = Number.parseInt(element.dataset?.index, 10);
        return Number.isInteger(index) ? index : -1;
    }

    capture() {
        const selection = window.getSelection?.();
        if (!selection || selection.rangeCount === 0 || !selection.anchorNode || !selection.focusNode) return this.current;

        const anchorBlock = this.getBlockElement(selection.anchorNode);
        const focusBlock = this.getBlockElement(selection.focusNode);
        if (!anchorBlock || !focusBlock) return this.current;

        const anchorCell = this.getCell(selection.anchorNode);
        const focusCell = this.getCell(selection.focusNode);
        if (anchorCell && focusCell && this.getBlockId(anchorBlock) === this.getBlockId(focusBlock)) {
            const tableId = this.getBlockId(anchorBlock);
            const model = createTableSelection({
                tableId,
                anchorCellId: anchorCell.dataset.cellId || `${anchorCell.dataset.row}:${anchorCell.dataset.col}`,
                focusCellId: focusCell.dataset.cellId || `${focusCell.dataset.row}:${focusCell.dataset.col}`,
                anchorOffset: Formatter.getTextOffsetFromDomPosition(anchorCell, selection.anchorNode, selection.anchorOffset) || 0,
                focusOffset: Formatter.getTextOffsetFromDomPosition(focusCell, selection.focusNode, selection.focusOffset) || 0
            });
            this.current = model;
            return model;
        }

        const anchorBlockId = this.getBlockId(anchorBlock);
        const focusBlockId = this.getBlockId(focusBlock);
        if (anchorBlockId && anchorBlockId === focusBlockId) {
            const block = this.state.getBlockById?.(anchorBlockId);
            if (block && ['image', 'horizontalRule', 'pageBreak', 'toc'].includes(block.type)) {
                const model = createNodeSelection(block.id);
                this.current = model;
                return model;
            }
        }

        const anchor = this.resolveEndpoint(selection.anchorNode, selection.anchorOffset, anchorBlock);
        const focus = this.resolveEndpoint(selection.focusNode, selection.focusOffset, focusBlock);
        if (!anchor || !focus) {
            const blockId = this.getBlockId(anchorBlock);
            if (blockId) this.current = createNodeSelection(blockId);
            return this.current;
        }

        const direction = this.getDirection(selection);
        this.current = createTextSelection(anchor, focus, direction);
        return this.current;
    }

    getCell(node) {
        let element = node;
        if (element?.nodeType === Node.TEXT_NODE) element = element.parentElement;
        return element?.closest?.('td[data-row][data-col]') || null;
    }

    resolveEndpoint(node, offset, blockElement) {
        const blockId = this.getBlockId(blockElement);
        if (!blockId) return null;
        const parts = this.getTextParts(blockId);
        if (!parts.length) {
            const local = Formatter.getTextOffsetFromDomPosition(blockElement, node, offset);
            return local == null ? null : createTextPosition(blockId, local);
        }

        const host = this.getBlockElement(node);
        let partIndex = parts.indexOf(host);
        if (partIndex < 0) partIndex = parts.findIndex(part => part.contains(node));
        if (partIndex < 0) partIndex = 0;

        const activePart = parts[partIndex];
        const mappedFragment = this.layoutMap?.getFragmentForElement(activePart);
        let base = mappedFragment?.startOffset;
        if (!Number.isFinite(base)) {
            base = 0;
            for (let index = 0; index < partIndex; index += 1) {
                base += Formatter.getTextLengthFromDom(parts[index]);
            }
        }
        const local = Formatter.getTextOffsetFromDomPosition(activePart, node, offset);
        return createTextPosition(blockId, base + Math.max(0, local || 0));
    }

    getDirection(selection) {
        if (selection.isCollapsed) return 'forward';
        try {
            const probe = document.createRange();
            probe.setStart(selection.anchorNode, selection.anchorOffset);
            probe.setEnd(selection.focusNode, selection.focusOffset);
            return probe.collapsed ? 'backward' : 'forward';
        } catch (error) {
            return 'forward';
        }
    }

    getTextParts(blockId) {
        const escaped = selectorEscape(blockId);
        const parts = [...document.querySelectorAll(`[data-block-id="${escaped}"].block-text`)];
        parts.sort((a, b) => Number(a.dataset.splitPart || 0) - Number(b.dataset.splitPart || 0));
        return parts;
    }

    getAnyBlockElements(blockId) {
        const escaped = selectorEscape(blockId);
        return [...document.querySelectorAll(`[data-block-id="${escaped}"]`)];
    }

    restore(model = this.current, options = {}) {
        if (!model) return false;
        this.current = model;

        if (model.type === 'node') {
            const element = this.getAnyBlockElements(model.blockId)[0];
            if (!element) return false;
            element.focus?.({ preventScroll: !!options.preventScroll });
            return true;
        }

        if (model.type === 'table') return this.restoreTableSelection(model, options);
        if (model.type !== 'text') return false;

        const anchor = this.resolveDomPosition(model.anchor);
        const focus = this.resolveDomPosition(model.focus);
        if (!anchor || !focus) return false;

        const selection = window.getSelection?.();
        if (!selection) return false;
        anchor.host?.focus?.({ preventScroll: !!options.preventScroll });
        selection.removeAllRanges();

        if (typeof selection.setBaseAndExtent === 'function') {
            try {
                selection.setBaseAndExtent(anchor.container, anchor.offset, focus.container, focus.offset);
            } catch (error) {
                return this.restoreWithRange(selection, anchor, focus, model.direction);
            }
        } else {
            return this.restoreWithRange(selection, anchor, focus, model.direction);
        }

        if (!options.preventScroll) focus.host?.scrollIntoView?.({ block: 'nearest' });
        return true;
    }

    restoreWithRange(selection, anchor, focus, direction) {
        const range = document.createRange();
        const start = direction === 'backward' ? focus : anchor;
        const end = direction === 'backward' ? anchor : focus;
        try {
            range.setStart(start.container, start.offset);
            range.setEnd(end.container, end.offset);
        } catch (error) {
            return false;
        }
        selection.addRange(range);
        return true;
    }

    resolveDomPosition(position) {
        if (!position?.blockId) return null;
        const parts = this.getTextParts(position.blockId);
        const candidates = parts.length ? parts : this.getAnyBlockElements(position.blockId);
        if (!candidates.length) return null;

        const absoluteOffset = Math.max(0, Number(position.offset) || 0);
        const mappedFragment = this.layoutMap?.findFragment(position.blockId, absoluteOffset);
        let host = mappedFragment?.element || candidates[candidates.length - 1];
        let remaining = mappedFragment
            ? Math.max(0, absoluteOffset - mappedFragment.startOffset)
            : absoluteOffset;
        if (!mappedFragment) {
            for (const candidate of candidates) {
                const length = Formatter.getTextLengthFromDom(candidate);
                if (remaining <= length) {
                    host = candidate;
                    break;
                }
                remaining -= length;
            }
        }
        const dom = Formatter.resolveDomPositionFromTextOffset(host, remaining);
        if (!dom?.container) return { container: host, offset: 0, host };
        return { ...dom, host };
    }

    restoreTableSelection(model, options = {}) {
        const table = this.getAnyBlockElements(model.tableId).find(el => el.tagName === 'TABLE')
            || this.getAnyBlockElements(model.tableId)[0];
        if (!table) return false;
        const anchorCell = table.querySelector(`[data-cell-id="${selectorEscape(model.anchorCellId)}"]`)
            || this.findLegacyCell(table, model.anchorCellId);
        const focusCell = table.querySelector(`[data-cell-id="${selectorEscape(model.focusCellId)}"]`)
            || this.findLegacyCell(table, model.focusCellId);
        if (!anchorCell || !focusCell) return false;
        const anchor = Formatter.resolveDomPositionFromTextOffset(anchorCell, model.anchorOffset || 0);
        const focus = Formatter.resolveDomPositionFromTextOffset(focusCell, model.focusOffset || 0);
        if (!anchor?.container || !focus?.container) return false;
        const selection = window.getSelection();
        anchorCell.focus({ preventScroll: !!options.preventScroll });
        selection.removeAllRanges();
        if (typeof selection.setBaseAndExtent === 'function') {
            selection.setBaseAndExtent(anchor.container, anchor.offset, focus.container, focus.offset);
        } else {
            const range = document.createRange();
            range.setStart(anchor.container, anchor.offset);
            range.setEnd(focus.container, focus.offset);
            selection.addRange(range);
        }
        return true;
    }

    findLegacyCell(table, id) {
        const match = String(id || '').match(/^(\d+):(\d+)$/);
        if (!match) return null;
        return table.querySelector(`td[data-row="${match[1]}"][data-col="${match[2]}"]`);
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/selection-model.js
// ================================================================
import { cloneDocumentValue } from './schema.js';

export function createTextPosition(blockId, offset = 0, affinity = 'forward') {
    return {
        blockId: blockId == null ? null : String(blockId),
        offset: Math.max(0, Number(offset) || 0),
        affinity: affinity === 'backward' ? 'backward' : 'forward'
    };
}

export function createTextSelection(anchor, focus = anchor, direction = 'forward') {
    return {
        type: 'text',
        anchor: createTextPosition(anchor?.blockId, anchor?.offset, anchor?.affinity),
        focus: createTextPosition(focus?.blockId, focus?.offset, focus?.affinity),
        direction: direction === 'backward' ? 'backward' : 'forward'
    };
}

export function createNodeSelection(nodeId, blockId = nodeId) {
    return { type: 'node', nodeId: String(nodeId), blockId: String(blockId) };
}

export function createTableSelection({ tableId, anchorCellId, focusCellId = anchorCellId, anchorOffset = 0, focusOffset = anchorOffset } = {}) {
    return {
        type: 'table',
        tableId: tableId == null ? null : String(tableId),
        anchorCellId: anchorCellId == null ? null : String(anchorCellId),
        focusCellId: focusCellId == null ? null : String(focusCellId),
        anchorOffset: Math.max(0, Number(anchorOffset) || 0),
        focusOffset: Math.max(0, Number(focusOffset) || 0)
    };
}

export function cloneSelection(selection) {
    return cloneDocumentValue(selection);
}

export function isCollapsedSelection(selection) {
    if (!selection) return true;
    if (selection.type === 'text') {
        return selection.anchor?.blockId === selection.focus?.blockId
            && selection.anchor?.offset === selection.focus?.offset;
    }
    if (selection.type === 'table') {
        return selection.anchorCellId === selection.focusCellId
            && selection.anchorOffset === selection.focusOffset;
    }
    return true;
}

export function getSelectionBlockIds(selection) {
    if (!selection) return [];
    if (selection.type === 'text') {
        return [...new Set([selection.anchor?.blockId, selection.focus?.blockId].filter(Boolean))];
    }
    if (selection.type === 'table') return selection.tableId ? [selection.tableId] : [];
    return selection.blockId ? [selection.blockId] : [];
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/table/table-manager.js
// ================================================================
import { createTableSelection } from '../selection-model.js';

export class TableManager {
    constructor(controller) { this.ctrl = controller; this.state = controller.state; this.engine = controller.engine; this.dragging = false; }
    setup() {
        document.addEventListener('mousedown', e => this.down(e));
        document.addEventListener('mouseover', e => this.over(e));
        document.addEventListener('mouseup', () => { this.dragging = false; });
        document.addEventListener('keydown', e => this.key(e), true);
        document.getElementById('ctx-btn-merge-cells')?.addEventListener('click', () => this.merge());
        document.getElementById('ctx-btn-split-cell')?.addEventListener('click', () => this.split());
        document.getElementById('ctx-btn-header-row')?.addEventListener('click', () => this.header());
        this.state.subscribe(() => requestAnimationFrame(() => this.paint()));
    }
    cell(target) { return target?.closest?.('td[data-cell-id],th[data-cell-id]') || null; }
    table(cell) { return cell?.closest?.('table[data-block-id]') || null; }
    down(event) {
        const cell = this.cell(event.target), table = this.table(cell); if (!cell || !table) return;
        const old = this.engine.captureSelection();
        const anchor = event.shiftKey && old?.type === 'table' && old.tableId === table.dataset.blockId ? old.anchorCellId : cell.dataset.cellId;
        this.engine.setSelection(createTableSelection({ tableId: table.dataset.blockId, anchorCellId: anchor, focusCellId: cell.dataset.cellId }));
        this.dragging = true; this.paint();
    }
    over(event) {
        if (!this.dragging || !(event.buttons & 1)) return;
        const cell = this.cell(event.target), table = this.table(cell), old = this.engine.selection;
        if (!cell || !table || old?.type !== 'table' || old.tableId !== table.dataset.blockId) return;
        this.engine.setSelection({ ...old, focusCellId: cell.dataset.cellId }); this.paint();
    }
    cells(tableId) { return [...document.querySelectorAll(`table[data-block-id="${CSS.escape(tableId)}"] [data-cell-id]`)]; }
    key(event) {
        const cell = this.cell(event.target), table = this.table(cell); if (!cell || !table) return;
        const cells = this.cells(table.dataset.blockId), index = cells.indexOf(cell); if (index < 0) return;
        const cols = table.rows[0]?.cells.length || 1;
        let next = null;
        if (event.key === 'Tab') next = index + (event.shiftKey ? -1 : 1);
        else if (event.key === 'ArrowDown') next = index + cols;
        else if (event.key === 'ArrowUp') next = index - cols;
        if (next == null) return;
        event.preventDefault();
        if (next >= cells.length && event.key === 'Tab') {
            const model = this.state.getBlockById(table.dataset.blockId);
            this.state.insertTableRow(model.id, model.rowIds?.[model.rowIds.length - 1]);
            requestAnimationFrame(() => this.focus(this.cells(model.id)[index + 1]));
        } else this.focus(cells[Math.max(0, Math.min(cells.length - 1, next))]);
    }
    focus(cell) {
        if (!cell) return; cell.focus(); const range = document.createRange(); range.selectNodeContents(cell); range.collapse(true); const sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(range);
        const table = this.table(cell); this.engine.setSelection(createTableSelection({ tableId: table.dataset.blockId, anchorCellId: cell.dataset.cellId })); this.paint();
    }
    ids(selection = this.engine.selection) {
        const table = this.state.getBlockById(selection?.tableId), a = this.state.getTableCellPosition(table, selection?.anchorCellId), f = this.state.getTableCellPosition(table, selection?.focusCellId); if (!table || !a || !f) return [];
        const out = []; for (let r = Math.min(a.row, f.row); r <= Math.max(a.row, f.row); r += 1) for (let c = Math.min(a.col, f.col); c <= Math.max(a.col, f.col); c += 1) out.push(table.cellIds[r][c]); return out;
    }
    paint() { document.querySelectorAll('.table-cell-selected').forEach(el => el.classList.remove('table-cell-selected')); this.ids().forEach(id => document.querySelector(`[data-cell-id="${CSS.escape(id)}"]`)?.classList.add('table-cell-selected')); }
    merge() { const s = this.engine.selection; if (s?.type === 'table') this.state.mergeTableCells(s.tableId, s.anchorCellId, s.focusCellId); }
    split() { const s = this.engine.selection; if (s?.type === 'table') this.state.splitTableCell(s.tableId, s.anchorCellId); }
    header() { const s = this.engine.selection; if (s?.type === 'table') this.state.toggleTableHeaderRow(s.tableId); }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/editor/transaction.js
// ================================================================
import { createStableId } from './id.js';
import { cloneDocumentValue } from './schema.js';

export class Transaction {
    constructor({
        id = createStableId('txn'),
        source = 'command',
        operations = [],
        inverseOperations = [],
        renderImpact = null,
        mergeKey = null,
        selectionBefore = null,
        selectionAfter = null,
        meta = {},
        timestamp = Date.now()
    } = {}) {
        this.type = 'TRANSACTION';
        this.id = id;
        this.source = source;
        this.operations = operations.map(op => cloneDocumentValue(op));
        this.inverseOperations = inverseOperations.map(op => cloneDocumentValue(op));
        this.renderImpact = renderImpact ? cloneDocumentValue(renderImpact) : null;
        this.mergeKey = mergeKey || meta?.mergeKey || null;
        this.selectionBefore = cloneDocumentValue(selectionBefore);
        this.selectionAfter = cloneDocumentValue(selectionAfter);
        this.meta = { ...meta };
        this.timestamp = timestamp;
    }

    add(operation) {
        if (operation) this.operations.push(cloneDocumentValue(operation));
        return this;
    }

    setInverseOperations(operations) {
        this.inverseOperations = (operations || []).map(op => cloneDocumentValue(op));
        return this;
    }

    setRenderImpact(impact) {
        this.renderImpact = impact ? cloneDocumentValue(impact) : null;
        return this;
    }

    setSelectionAfter(selection) {
        this.selectionAfter = cloneDocumentValue(selection);
        return this;
    }

    get isEmpty() {
        return this.operations.length === 0;
    }

    toJSON() {
        return {
            type: this.type,
            id: this.id,
            source: this.source,
            operations: cloneDocumentValue(this.operations),
            inverseOperations: cloneDocumentValue(this.inverseOperations),
            renderImpact: cloneDocumentValue(this.renderImpact),
            mergeKey: this.mergeKey,
            selectionBefore: cloneDocumentValue(this.selectionBefore),
            selectionAfter: cloneDocumentValue(this.selectionAfter),
            meta: cloneDocumentValue(this.meta),
            timestamp: this.timestamp
        };
    }

    static from(value) {
        if (value instanceof Transaction) return value;
        return new Transaction(value || {});
    }
}

export function isTransaction(value) {
    return value instanceof Transaction || value?.type === 'TRANSACTION' || Array.isArray(value?.operations);
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/export-import.js
// ================================================================
import { Formatter } from './formatter.js';
import { getBlockRuns } from './editor/inline/block-inline.js';

const TWIPS_PER_INCH = 1440;
const DOCX_PAGE_SIZES = {
    letter: { width: 12240, height: 15840 },
    a4: { width: 11906, height: 16838 }
};

function cleanColor(value, fallback = undefined) {
    if (!value) return fallback;
    const color = String(value).replace('#', '').trim();
    return /^[0-9a-f]{6}$/i.test(color) ? color.toUpperCase() : fallback;
}

function safeNumber(value, fallback) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
}

export class ExportImport {
    constructor(ctrl) {
        this.ctrl = ctrl;
        this.state = ctrl.state;
    }

    printDocument() { return this.exportPDF(); }

    async exportPDF() {
        this.ctrl.toolbar?.showShellToast?.('Generating PDF…');
        const res = await fetch(`/api/docs/${encodeURIComponent(this.state.doc.id)}/export/pdf`, { method: 'POST' });
        if (!res.ok) {
            this.ctrl.toolbar?.showShellToast?.('PDF export failed');
            return false;
        }
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        window.open(url, '_blank', 'noopener');
        setTimeout(() => window.URL.revokeObjectURL(url), 60_000);
        return true;
    }

    htmlToDocxRuns(node, inherited = {}) {
        const { TextRun, ExternalHyperlink } = docx;
        const output = [];
        const walk = (current, options = inherited) => {
            if (current.nodeType === Node.TEXT_NODE) {
                if (current.textContent) output.push(new TextRun({ ...options, text: current.textContent }));
                return;
            }
            if (current.nodeType !== Node.ELEMENT_NODE) return;
            const tag = current.tagName.toLowerCase();
            if (tag === 'br') { output.push(new TextRun({ ...options, break: 1 })); return; }

            const next = { ...options };
            if (['b', 'strong'].includes(tag)) next.bold = true;
            if (['i', 'em'].includes(tag)) next.italics = true;
            if (tag === 'u') next.underline = { type: 'single' };
            if (['s', 'strike'].includes(tag)) next.strike = true;
            if (tag === 'del') { next.strike = true; next.color = next.color || 'C62828'; }
            if (tag === 'ins') { next.underline = { type: 'single' }; next.color = next.color || '2E7D32'; }
            if (tag === 'sub') next.subScript = true;
            if (tag === 'sup') next.superScript = true;
            if (tag === 'code') { next.font = 'Consolas'; next.color = 'C7254E'; next.shading = { type: 'clear', fill: 'F9F2F4' }; }
            if (current.style?.fontSize) next.size = Math.round(parseFloat(current.style.fontSize) * 2);
            if (current.style?.color) next.color = cleanColor(current.style.color, next.color);
            if (current.style?.backgroundColor) next.shading = { type: 'clear', fill: cleanColor(current.style.backgroundColor, 'FFFFFF') };
            if (current.style?.fontFamily) next.font = current.style.fontFamily.replace(/["']/g, '').split(',')[0];

            if (tag === 'a' && current.href && ExternalHyperlink) {
                const children = [];
                current.childNodes.forEach(child => {
                    if (child.nodeType === Node.TEXT_NODE && child.textContent) children.push(new TextRun({ ...next, text: child.textContent, style: 'Hyperlink' }));
                });
                if (children.length) output.push(new ExternalHyperlink({ link: current.href, children }));
                return;
            }
            current.childNodes.forEach(child => walk(child, next));
        };
        node.childNodes.forEach(child => walk(child, inherited));
        return output.length ? output : [new TextRun({ ...inherited, text: '' })];
    }

    blockRunsToDocx(block) {
        const { TextRun, ExternalHyperlink } = docx;
        if (block.contentFormat !== 'runs' || !Array.isArray(block.children)) {
            const container = document.createElement('div');
            container.innerHTML = block.content || '';
            return this.htmlToDocxRuns(container);
        }
        return getBlockRuns(block).map(run => {
            const marks = run.marks || {};
            const revision = marks.revision;
            const options = {
                text: run.text || '',
                bold: !!marks.bold,
                italics: !!marks.italic,
                underline: marks.underline || revision?.type === 'insertion' ? { type: 'single' } : undefined,
                strike: !!marks.strikethrough || revision?.type === 'deletion',
                superScript: !!marks.superscript,
                subScript: !!marks.subscript,
                font: marks.code ? 'Consolas' : marks.fontFamily,
                size: marks.fontSize ? Math.round(Number(marks.fontSize) * 2) : undefined,
                color: cleanColor(revision?.type === 'deletion' ? 'C62828' : revision?.type === 'insertion' ? '2E7D32' : marks.color),
                shading: marks.highlight ? { type: 'clear', fill: cleanColor(marks.highlight, 'FFFFFF') } : undefined
            };
            if (marks.link?.href && ExternalHyperlink) {
                return new ExternalHyperlink({ link: marks.link.href, children: [new TextRun({ ...options, style: 'Hyperlink' })] });
            }
            return new TextRun(options);
        });
    }

    paragraphOptions(block) {
        const { HeadingLevel, AlignmentType } = docx;
        const heading = {
            h1: HeadingLevel.HEADING_1, h2: HeadingLevel.HEADING_2, h3: HeadingLevel.HEADING_3,
            h4: HeadingLevel.HEADING_4, h5: HeadingLevel.HEADING_5, h6: HeadingLevel.HEADING_6
        }[block.style];
        const alignment = {
            left: AlignmentType.LEFT, center: AlignmentType.CENTER,
            right: AlignmentType.RIGHT, justify: AlignmentType.JUSTIFIED
        }[block.align] || AlignmentType.LEFT;
        const customStyle = this.state.doc.styles?.[block.style];
        return {
            heading,
            style: !heading && customStyle ? block.style : undefined,
            alignment,
            indent: block.style === 'quote' ? { left: 720 } : block.indent ? { left: Number(block.indent) * 360 } : undefined,
            spacing: {
                before: Math.round(safeNumber(block.marginTop, 0) * 20),
                after: Math.round(safeNumber(block.marginBottom, customStyle?.spacingAfter || 0) * 20),
                line: block.lineHeight ? Math.round(Number(block.lineHeight) * 240) : customStyle?.lineHeight ? Math.round(Number(customStyle.lineHeight) * 240) : undefined
            },
            keepNext: !!customStyle?.keepWithNext
        };
    }

    async imageToParagraph(block) {
        const { Paragraph, TextRun, ImageRun, AlignmentType } = docx;
        try {
            const response = await fetch(block.content);
            if (!response.ok) throw new Error(`Image response ${response.status}`);
            const buffer = await (await response.blob()).arrayBuffer();
            const pageWidthPx = 624;
            const width = Math.max(24, Math.round(pageWidthPx * (safeNumber(block.width, 100) / 100)));
            let ratio = safeNumber(block.aspectRatio, 0);
            if (!ratio && block.naturalWidth && block.naturalHeight) ratio = Number(block.naturalWidth) / Number(block.naturalHeight);
            if (!ratio) ratio = 4 / 3;
            const height = Math.max(24, Math.round(width / ratio));
            return [new Paragraph({
                children: [new ImageRun({ data: buffer, transformation: { width, height } })],
                alignment: { left: AlignmentType.LEFT, right: AlignmentType.RIGHT, center: AlignmentType.CENTER }[block.align] || AlignmentType.CENTER
            }), ...(block.caption ? [new Paragraph({ children: [new TextRun({ text: block.caption, italics: true, size: 18, color: '666666' })], alignment: AlignmentType.CENTER })] : [])];
        } catch (_) {
            return [new Paragraph({ children: [new TextRun({ text: `[Image: ${block.content || 'unavailable'}]`, italics: true, color: '999999' })] })];
        }
    }

    async objectToDocxElements(block) {
        const { Paragraph, TextRun, ImageRun, AlignmentType, Table, TableRow, TableCell, WidthType, ShadingType } = docx;
        if (block.objectType === 'image') {
            try {
                const response = await fetch(block.image?.src || '');
                if (!response.ok) throw new Error(`Image response ${response.status}`);
                const buffer = await (await response.blob()).arrayBuffer();
                const width = Math.max(24, Math.round(safeNumber(block.layout?.width, 240)));
                let height = safeNumber(block.layout?.height, 0);
                if (!height) {
                    const ratio = block.image?.naturalWidth && block.image?.naturalHeight ? Number(block.image.naturalWidth) / Number(block.image.naturalHeight) : 4 / 3;
                    height = Math.max(24, Math.round(width / ratio));
                }
                const wrapType = block.wrap?.type || 'inline';
                const isFloating = wrapType !== 'inline';
                const floating = isFloating ? {
                    horizontalPosition: { relative: 'page', offset: Math.round(safeNumber(block.layout?.x, 0) * 9525) },
                    verticalPosition: { relative: 'page', offset: Math.round(safeNumber(block.layout?.y, 0) * 9525) },
                    wrap: { type: ({ square: 'square', topBottom: 'topAndBottom', tight: 'tight', through: 'through', behindText: 'none', inFrontOfText: 'none' })[wrapType] || 'square', side: block.wrap?.side || 'bothSides' },
                    behindDocument: wrapType === 'behindText',
                    allowOverlap: block.layout?.allowOverlap !== false,
                    margins: {
                        top: Math.round(safeNumber(block.wrap?.distance?.top, 0) * 9525),
                        right: Math.round(safeNumber(block.wrap?.distance?.right, 0) * 9525),
                        bottom: Math.round(safeNumber(block.wrap?.distance?.bottom, 0) * 9525),
                        left: Math.round(safeNumber(block.wrap?.distance?.left, 0) * 9525)
                    }
                } : undefined;
                const imageRun = new ImageRun({
                    data: buffer,
                    transformation: { width, height, rotation: safeNumber(block.layout?.rotation, 0) },
                    floating,
                    altText: block.image?.decorative ? undefined : { title: block.image?.altText || '', description: block.image?.altText || '', name: block.image?.altText || 'Image' }
                });
                const paragraphs = [new Paragraph({ children: [imageRun], alignment: AlignmentType.CENTER })];
                if (block.image?.caption) paragraphs.push(new Paragraph({ children: [new TextRun({ text: block.image.caption, italics: true, size: 18, color: '666666' })], alignment: AlignmentType.CENTER }));
                return paragraphs;
            } catch (_) {
                return [new Paragraph({ children: [new TextRun({ text: `[Image: ${block.image?.altText || block.image?.src || 'unavailable'}]`, italics: true, color: '999999' })] })];
            }
        }
        if (block.objectType === 'textBox') {
            const appearance = block.appearance || {};
            const content = (block.textBox?.blocks || []).map(item => {
                const container = document.createElement('div'); container.innerHTML = item.content || '';
                return new Paragraph({ children: this.htmlToDocxRuns(container) });
            });
            return [new Table({
                width: { size: Math.max(10, Math.min(100, safeNumber(block.layout?.width, 220) / 6.24)), type: WidthType.PERCENTAGE },
                rows: [new TableRow({ children: [new TableCell({
                    children: content.length ? content : [new Paragraph({ children: [new TextRun({ text: '' })] })],
                    shading: appearance.fill ? { type: ShadingType?.CLEAR || 'clear', fill: cleanColor(appearance.fill, 'FFFFFF') } : undefined,
                    margins: {
                        top: Math.round(safeNumber(block.textBox?.margins?.top, 8) * 15),
                        right: Math.round(safeNumber(block.textBox?.margins?.right, 8) * 15),
                        bottom: Math.round(safeNumber(block.textBox?.margins?.bottom, 8) * 15),
                        left: Math.round(safeNumber(block.textBox?.margins?.left, 8) * 15)
                    }
                })] })]
            })];
        }
        return [];
    }

    tableToDocx(block) {
        const { Table, TableRow, TableCell, Paragraph, WidthType, ShadingType } = docx;
        const rows = [];
        for (let r = 0; r < (block.rows || []).length; r += 1) {
            const cells = [];
            for (let c = 0; c < (block.rows[r] || []).length; c += 1) {
                const cellId = block.cellIds?.[r]?.[c];
                const meta = block.cellMeta?.[cellId] || {};
                if (meta.coveredBy) continue;
                const container = document.createElement('div');
                container.innerHTML = block.rows[r][c] || '';
                cells.push(new TableCell({
                    children: [new Paragraph({ children: this.htmlToDocxRuns(container) })],
                    columnSpan: meta.colspan > 1 ? meta.colspan : undefined,
                    rowSpan: meta.rowspan > 1 ? meta.rowspan : undefined,
                    width: { size: safeNumber(block.colWidths?.[c], 100 / Math.max(1, block.rows[r].length)), type: WidthType.PERCENTAGE },
                    shading: (block.headerRows || 0) > r ? { type: ShadingType?.CLEAR || 'clear', fill: 'EAF2F8' } : undefined
                }));
            }
            rows.push(new TableRow({ children: cells, tableHeader: (block.headerRows || 0) > r }));
        }
        return new Table({ rows, width: { size: 100, type: WidthType.PERCENTAGE } });
    }

    async blockToDocxElements(block) {
        const { Paragraph, TextRun } = docx;
        if (block.type === 'text') return [new Paragraph({ children: this.blockRunsToDocx(block), ...this.paragraphOptions(block) })];
        if (['ul', 'ol', 'checklist'].includes(block.type)) return (block.items || []).map((item) => {
            const container = document.createElement('div'); container.innerHTML = item.text || '';
            const prefix = block.type === 'checklist' ? [new TextRun({ text: item.checked ? '☑ ' : '☐ ' })] : [];
            return new Paragraph({
                children: [...prefix, ...this.htmlToDocxRuns(container)],
                bullet: block.type === 'ul' ? { level: item.level || 0 } : undefined,
                numbering: block.type === 'ol' ? { reference: 'openword-numbering', level: item.level || 0 } : undefined,
                spacing: { after: 60 }
            });
        });
        if (block.type === 'table') return [this.tableToDocx(block)];
        if (block.type === 'image') return this.imageToParagraph(block);
        if (block.type === 'object') return this.objectToDocxElements(block);
        if (block.type === 'horizontalRule') return [new Paragraph({ children: [new TextRun({ text: '' })], border: { bottom: { style: 'single', size: 6, space: 1, color: 'AAAAAA' } } })];
        if (block.type === 'pageBreak') return [new Paragraph({ pageBreakBefore: true, children: [new TextRun({ text: '' })] })];
        if (block.type === 'footnote' || block.type === 'endnote') return [new Paragraph({ children: [new TextRun({ text: `${block.fnNumber || block.enNumber || ''}. ${block.content || ''}`, size: 18, color: '555555' })] })];
        return [];
    }

    makeHeaderFooter(value, kind = 'header') {
        const { Header, Footer, Paragraph, TextRun, PageNumber, AlignmentType } = docx;
        if (!value) return undefined;
        const parts = String(value).split('{n}');
        const children = [];
        parts.forEach((part, index) => {
            if (part) children.push(new TextRun({ text: part, size: 18, color: '777777' }));
            if (index < parts.length - 1) children.push(new TextRun({ children: [PageNumber.CURRENT], size: 18, color: '777777' }));
        });
        const entry = new (kind === 'footer' ? Footer : Header)({ children: [new Paragraph({ children, alignment: AlignmentType.CENTER })] });
        return { default: entry };
    }

    sectionProperties(settings = {}) {
        const { PageOrientation } = docx;
        const base = DOCX_PAGE_SIZES[settings.pageSize] || DOCX_PAGE_SIZES.letter;
        const landscape = settings.orientation === 'landscape';
        return {
            page: {
                size: {
                    width: landscape ? base.height : base.width,
                    height: landscape ? base.width : base.height,
                    orientation: landscape ? PageOrientation.LANDSCAPE : PageOrientation.PORTRAIT
                },
                margin: {
                    top: safeNumber(settings.margins?.top, 1) * TWIPS_PER_INCH,
                    bottom: safeNumber(settings.margins?.bottom, 1) * TWIPS_PER_INCH,
                    left: safeNumber(settings.margins?.left, 1) * TWIPS_PER_INCH,
                    right: safeNumber(settings.margins?.right, 1) * TWIPS_PER_INCH
                },
                pageNumbers: settings.pageNumberStart ? { start: Number(settings.pageNumberStart) } : undefined
            },
            column: settings.columns > 1 ? { count: Number(settings.columns), space: 720 } : undefined
        };
    }

    buildDocxStyles() {
        const paragraphStyles = Object.values(this.state.doc.styles || {}).map(style => ({
            id: style.id,
            name: style.name || style.id,
            basedOn: style.basedOn,
            next: style.next || style.id,
            quickFormat: true,
            run: {
                font: style.fontFamily,
                size: style.fontSize ? Math.round(Number(style.fontSize) * 2) : undefined,
                bold: !!style.bold,
                italics: !!style.italic,
                color: cleanColor(style.color)
            },
            paragraph: {
                spacing: {
                    after: style.spacingAfter ? Math.round(Number(style.spacingAfter) * 20) : undefined,
                    line: style.lineHeight ? Math.round(Number(style.lineHeight) * 240) : undefined
                },
                keepNext: !!style.keepWithNext,
                outlineLevel: style.outlineLevel ? Number(style.outlineLevel) - 1 : undefined
            }
        }));
        return {
            default: { document: { run: { font: this.state.doc.styles?.normal?.fontFamily || 'Segoe UI', size: Math.round(safeNumber(this.state.doc.styles?.normal?.fontSize, 12) * 2) } } },
            paragraphStyles
        };
    }

    async exportDOCX() {
        const { Document, Packer } = docx;
        const source = this.state.doc;
        const groups = [{
            id: source.sections?.[0]?.id || 'default',
            settings: source.sections?.[0]?.settings || source.settings || {},
            header: source.sections?.[0]?.header || source.header,
            footer: source.sections?.[0]?.footer || source.footer,
            children: []
        }];
        for (const block of source.blocks || []) {
            if (block.type === 'toc') continue;
            if (block.type === 'sectionBreak') {
                const section = (source.sections || []).find(item => item.id === block.sectionId) || {};
                groups.push({
                    id: block.sectionId,
                    settings: section.settings || block.settings || source.settings || {},
                    header: section.header || source.header,
                    footer: section.footer || source.footer,
                    children: []
                });
                continue;
            }
            groups[groups.length - 1].children.push(...await this.blockToDocxElements(block));
        }
        groups.forEach(group => { if (!group.children.length) group.children.push(new docx.Paragraph('')); });
        const generated = new Document({
            title: source.title || 'Untitled',
            description: 'Generated by OpenWord',
            creator: source.currentUserName || 'OpenWord',
            styles: this.buildDocxStyles(),
            numbering: { config: [{ reference: 'openword-numbering', levels: Array.from({ length: 9 }, (_, level) => ({ level, format: 'decimal', text: `%${level + 1}.`, alignment: 'left', style: { paragraph: { indent: { left: 720 * (level + 1), hanging: 360 } } } })) }] },
            sections: groups.map(group => ({
                properties: this.sectionProperties(group.settings),
                headers: this.makeHeaderFooter(group.header?.center, 'header'),
                footers: this.makeHeaderFooter(group.footer?.center, 'footer'),
                children: group.children
            }))
        });
        const blob = await Packer.toBlob(generated);
        const url = window.URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url; anchor.download = `${source.title || 'Untitled'}.docx`; anchor.click();
        window.URL.revokeObjectURL(url);
        this.ctrl.toolbar?.showShellToast?.('Word document exported');
        return blob;
    }

    async importDOCX(file) {
        const arrayBuffer = await file.arrayBuffer();
        const styleMap = Object.values(this.state.doc.styles || {}).map(style => `p[style-name='${String(style.name || style.id).replace(/'/g, "\\'")}'] => p.${style.id}:fresh`);
        const result = await mammoth.convertToHtml({ arrayBuffer }, { styleMap, includeDefaultStyleMap: true });
        const parsed = Formatter.parseHTMLToBlocks(result.value);
        if (!parsed.length) { this.ctrl.toolbar?.showShellToast?.('Could not parse Word document'); return false; }
        const insertAt = this.ctrl.getInsertBaseIndex() + 1;
        parsed.forEach((block, offset) => this.state.insertBlockAt(insertAt + offset, this.state.ensureBlockId(block), 'docx-import'));
        this.ctrl.focusInsertedBlock(insertAt, 'text');
        if (result.messages?.length) console.info('DOCX import messages', result.messages);
        return true;
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/find-replace.js
// ================================================================
export class FindReplace {
    constructor(ctrl) {
        this.ctrl = ctrl;
        this.state = ctrl.state;
        this.renderer = ctrl.renderer;
        this.currentMatches = [];
        this.currentMatchIndex = -1;
        this.isCaseSensitive = false;
        this.isRegex = false;
    }

    setup() {
        document.getElementById('btn-find-next').onclick = () => this.find(1);
        document.getElementById('btn-find-prev').onclick = () => this.find(-1);
        document.getElementById('inp-find-text').onkeyup = (e) => {
            if (e.key === 'Enter') this.find(e.shiftKey ? -1 : 1);
            else this.onQueryChange();
        };
        document.getElementById('btn-replace-one').onclick = () => this.replace(false);
        document.getElementById('btn-replace-all').onclick = () => this.replace(true);
        document.getElementById('chk-case-sensitive').onchange = (e) => {
            this.isCaseSensitive = e.target.checked;
            this.onQueryChange();
        };
        document.getElementById('chk-regex').onchange = (e) => {
            this.isRegex = e.target.checked;
            document.getElementById('inp-replace-text').disabled = e.target.checked;
            this.onQueryChange();
        };

        document.addEventListener('keydown', (e) => {
            if (e.key === 'F3') {
                e.preventDefault();
                const modal = document.getElementById('modal-find');
                if (modal.classList.contains('hidden')) return;
                this.find(e.shiftKey ? -1 : 1);
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'g') {
                e.preventDefault();
                this.find(e.shiftKey ? -1 : 1);
            }
        });
    }

    onQueryChange() {
        const query = this.getQuery();
        if (!query) {
            this.clearHighlights();
            return;
        }
        this.currentMatches = this.searchBlocks(query);
        this.currentMatchIndex = this.currentMatches.length > 0 ? 0 : -1;
        this.updateHighlights();
        this.updateStatus();
    }

    getQuery() {
        return document.getElementById('inp-find-text').value;
    }

    getReplaceText() {
        return document.getElementById('inp-replace-text').value;
    }

    searchBlocks(query) {
        if (!query) return [];
        const matches = [];
        const flags = this.isCaseSensitive ? 'g' : 'gi';

        this.state.doc.blocks.forEach((b, i) => {
            if (b.type === 'text' && b.content) {
                let pattern;
                try {
                    pattern = this.isRegex ? new RegExp(query, flags) : new RegExp(this.escapeRegex(query), flags);
                } catch (e) {
                    return;
                }
                let match;
                while ((match = pattern.exec(b.content)) !== null) {
                    matches.push({ blockIndex: i, text: match[0], index: match.index });
                }
            }
        });
        return matches;
    }

    escapeRegex(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    find(direction) {
        const query = this.getQuery();
        if (!query) return;

        if (this.currentMatches.length === 0) {
            this.currentMatches = this.searchBlocks(query);
            if (this.currentMatches.length === 0) {
                document.getElementById('find-status').innerText = 'No matches';
                return;
            }
            this.currentMatchIndex = direction > 0 ? 0 : this.currentMatches.length - 1;
        } else {
            this.currentMatchIndex = (this.currentMatchIndex + direction + this.currentMatches.length) % this.currentMatches.length;
        }

        this.updateHighlights();
        this.updateStatus();
        this.scrollToCurrentMatch();
    }

    updateHighlights() {
        this.renderer.highlightMatches = this.currentMatches;
        this.renderer.currentMatchIndex = this.currentMatchIndex;
        this.renderer.render(this.state.doc, this.state.hfMode);
    }

    updateStatus() {
        const el = document.getElementById('find-status');
        if (this.currentMatches.length === 0) {
            el.innerText = 'No matches';
        } else {
            el.innerText = `Match ${this.currentMatchIndex + 1} of ${this.currentMatches.length}`;
        }
    }

    scrollToCurrentMatch() {
        const match = this.currentMatches[this.currentMatchIndex];
        if (!match) return;
        const el = document.querySelector(`[data-index="${match.blockIndex}"]`);
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    clearHighlights() {
        this.currentMatches = [];
        this.currentMatchIndex = -1;
        this.renderer.highlightMatches = [];
        this.renderer.render(this.state.doc, this.state.hfMode);
        document.getElementById('find-status').innerText = '';
    }

    replace(replaceAll) {
        const query = this.getQuery();
        const replaceText = this.getReplaceText();
        if (!query) return;

        const flags = this.isCaseSensitive ? 'g' : 'gi';
        let count = 0;

        if (replaceAll) {
            for (let i = 0; i < this.state.doc.blocks.length; i++) {
                const b = this.state.doc.blocks[i];
                if (b.type === 'text' && b.content) {
                    let pattern;
                    try {
                        pattern = this.isRegex ? new RegExp(query, flags) : new RegExp(this.escapeRegex(query), flags);
                    } catch (e) {
                        continue;
                    }
                    const newContent = b.content.replace(pattern, replaceText);
                    if (newContent !== b.content) {
                        this.state.updateBlockContent(i, newContent, 'structure');
                        count++;
                    }
                }
            }
        } else {
            const match = this.currentMatches[this.currentMatchIndex];
            if (!match) return;
            const b = this.state.doc.blocks[match.blockIndex];
            if (b && b.type === 'text') {
                let pattern;
                try {
                    pattern = this.isRegex ? new RegExp(query, this.isCaseSensitive ? '' : 'i') : this.escapeRegex(query);
                } catch (e) {
                    return;
                }
                const firstMatch = b.content.slice(match.index).match(pattern);
                if (firstMatch) {
                    const newContent = b.content.slice(0, match.index) + replaceText + b.content.slice(match.index + firstMatch[0].length);
                    this.state.updateBlockContent(match.blockIndex, newContent, 'structure');
                    count++;
                }
            }
        }

        this.currentMatches = [];
        this.currentMatchIndex = -1;
        this.onQueryChange();
        document.getElementById('find-status').innerText = replaceAll
            ? `Replaced ${count} occurrence${count !== 1 ? 's' : ''}`
            : `Replaced 1 occurrence`;
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/formatter.js
// ================================================================
// ===============================
// FILE: public/formatter.js
// ===============================

export class Formatter {
    static applyInlineMark(tag, value = null) {
        document.execCommand('styleWithCSS', false, true);
        if (tag === 'createLink') {
            const url = value || prompt("Enter URL:", "https://");
            if (url) document.execCommand('createLink', false, url);
            return !!url;
        }
        return document.execCommand(tag, false, value);
    }

    static applyInlineStyle(styleMap = {}) {
        const sel = window.getSelection();
        if (!sel || !sel.rangeCount) return false;

        const range = sel.getRangeAt(0);
        if (range.collapsed) return false;

        const wrapper = document.createElement('span');
        Object.entries(styleMap).forEach(([key, value]) => {
            if (value !== undefined && value !== null && value !== '') wrapper.style[key] = value;
        });

        const frag = range.extractContents();
        wrapper.appendChild(frag);
        range.insertNode(wrapper);

        const newRange = document.createRange();
        newRange.selectNodeContents(wrapper);
        sel.removeAllRanges();
        sel.addRange(newRange);
        return true;
    }

    static applyFontFamily(fontFamily) {
        if (!fontFamily) return false;
        const sel = window.getSelection();
        if (!sel || !sel.rangeCount) return false;

        const range = sel.getRangeAt(0);
        if (range.collapsed) {
            document.execCommand('styleWithCSS', false, true);
            return document.execCommand('fontName', false, fontFamily);
        }

        return Formatter.applyInlineStyle({ fontFamily });
    }

    static applyFontSize(size) {
        if (!size) return false;
        const sel = window.getSelection();
        if (!sel || !sel.rangeCount) return false;
        const range = sel.getRangeAt(0);

        if (range.collapsed) {
            document.execCommand('styleWithCSS', false, true);
            const num = parseInt(size);
            if (num >= 1 && num <= 7) {
                return document.execCommand('fontSize', false, size);
            }
            return document.execCommand('fontSize', false, '7');
        }

        return Formatter.applyInlineStyle({ fontSize: `${size}pt` });
    }

    static applyTextColor(color) {
        if (!color) return false;
        document.execCommand('styleWithCSS', false, true);
        return document.execCommand('foreColor', false, color);
    }

    static applyHighlight(color) {
        if (!color) return false;
        document.execCommand('styleWithCSS', false, true);
        return document.execCommand('hiliteColor', false, color);
    }

    static applySuperscript() {
        return document.execCommand('superscript', false, null);
    }

    static applySubscript() {
        return document.execCommand('subscript', false, null);
    }

    static applyInlineCode() {
        const sel = window.getSelection();
        if (!sel || !sel.rangeCount) return false;
        const range = sel.getRangeAt(0);
        if (range.collapsed) return false;

        let node = sel.anchorNode;
        if (node.nodeType === 3) node = node.parentElement;
        const existingCode = node?.closest?.('code');
        if (existingCode && existingCode.parentNode) {
            const parent = existingCode.parentNode;
            const text = document.createTextNode(existingCode.textContent || '');
            parent.replaceChild(text, existingCode);
            const newRange = document.createRange();
            newRange.selectNodeContents(parent);
            newRange.collapse(false);
            sel.removeAllRanges();
            sel.addRange(newRange);
            return true;
        }

        document.execCommand('styleWithCSS', false, true);
        const wrapper = document.createElement('code');
        const frag = range.extractContents();
        wrapper.appendChild(frag);
        range.insertNode(wrapper);
        const newRange = document.createRange();
        newRange.selectNodeContents(wrapper);
        sel.removeAllRanges();
        sel.addRange(newRange);
        return true;
    }

    static applyStrikethrough() {
        return document.execCommand('strikeThrough', false, null);
    }

    static applyBulletList() {
        return document.execCommand('insertUnorderedList', false, null);
    }

    static applyNumberedList() {
        return document.execCommand('insertOrderedList', false, null);
    }

    static applyAlign(align) {
        return document.execCommand(`justify${align.charAt(0).toUpperCase() + align.slice(1)}`, false, null);
    }

    static getActiveMarks() {
        const sel = window.getSelection();
        if (!sel.rangeCount || !sel.anchorNode) return [];
        let node = sel.anchorNode;
        if (node.nodeType === 3) node = node.parentNode;

        const marks = [];
        const styles = window.getComputedStyle(node);
        const fw = styles.fontWeight;
        if (fw === 'bold' || parseInt(fw) > 600) marks.push('bold');
        if (styles.fontStyle === 'italic') marks.push('italic');
        if (styles.textDecoration.includes('underline') || node.tagName === 'U') marks.push('underline');
        if (styles.textDecoration.includes('line-through')) marks.push('strikethrough');
        if (styles.verticalAlign === 'super') marks.push('superscript');
        if (styles.verticalAlign === 'sub') marks.push('subscript');
        if (node.tagName === 'CODE' || node.closest?.('code')) marks.push('code');
        return marks;
    }

    static normalizeText(str) {
        return (str || '')
            .replace(/\u00A0/g, ' ')
            .replace(/[\u200B-\u200D\uFEFF]/g, '')
            .replace(/\s+/g, ' ')
            .trim();
    }

    static escapeHtml(text) {
        return String(text ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    static preservePlainTextSpacing(text) {
        return String(text ?? '')
            .replace(/\t/g, '    ')
            .replace(/^ +/gm, (match) => '&nbsp;'.repeat(match.length))
            .replace(/ {2,}/g, (match) => `${' '.repeat(match.length - 1)}&nbsp;`);
    }

    static plainTextToHtml(text) {
        const escaped = Formatter.escapeHtml(String(text ?? '').replace(/\r\n?/g, '\n'));
        const spaced = Formatter.preservePlainTextSpacing(escaped);
        const html = spaced.replace(/\n/g, '<br>');
        return html === '' ? '<br>' : html;
    }

    static isMeaningfullyEmptyHtml(html) {
        if (!html) return true;

        let clean = html.replace(/<!--[\s\S]*?-->/g, '');
        clean = clean
            .replace(/<br\s*\/?>/gi, '')
            .replace(/&nbsp;/gi, ' ')
            .replace(/<hr\s*\/?>/gi, '');

        const tmp = document.createElement('div');
        tmp.innerHTML = clean;

        if (tmp.querySelector('img, table, iframe, video, blockquote')) {
            return false;
        }

        const text = Formatter.normalizeText(tmp.textContent || '');
        return text.length === 0;
    }

    static isBlockLikeTextContainer(tag) {
        return ['div', 'p', 'section', 'article', 'header', 'footer', 'blockquote', 'pre'].includes((tag || '').toLowerCase());
    }

    static appendBreakIfNeeded(container) {
        const last = container.lastChild;
        if (last && last.nodeType === Node.ELEMENT_NODE && last.tagName.toLowerCase() === 'br') return;
        container.appendChild(document.createElement('br'));
    }

    static normalizeEditableTextChildren(host) {
        if (!host) return;

        const out = document.createElement('div');
        const children = Array.from(host.childNodes);

        children.forEach((child, idx) => {
            if (child.nodeType === Node.COMMENT_NODE) return;

            if (child.nodeType === Node.ELEMENT_NODE && Formatter.isBlockLikeTextContainer(child.tagName)) {
                if (out.childNodes.length) Formatter.appendBreakIfNeeded(out);

                if (child.childNodes.length === 0) {
                    Formatter.appendBreakIfNeeded(out);
                } else {
                    Array.from(child.childNodes).forEach((grand) => out.appendChild(grand.cloneNode(true)));
                }

                const hasMore = children.slice(idx + 1).some((n) => {
                    if (n.nodeType === Node.COMMENT_NODE) return false;
                    if (n.nodeType === Node.TEXT_NODE) return (n.nodeValue || '').length > 0;
                    return true;
                });
                if (hasMore) Formatter.appendBreakIfNeeded(out);
                return;
            }

            out.appendChild(child.cloneNode(true));
        });

        host.innerHTML = out.innerHTML;
    }

    static visibleTextLength(text) {
        return String(text || '').replace(/[\u200B-\u200D\uFEFF]/g, '').length;
    }

    static rawOffsetFromVisibleTextOffset(text, visibleOffset) {
        const value = String(text || '');
        const target = Math.max(0, visibleOffset);
        let visible = 0;

        for (let i = 0; i < value.length; i++) {
            if (/[\u200B-\u200D\uFEFF]/.test(value[i])) continue;
            if (visible >= target) return i;
            visible++;
        }

        return value.length;
    }

    static getTextLengthFromDomNode(node) {
        if (!node) return 0;

        if (node.nodeType === Node.TEXT_NODE) return Formatter.visibleTextLength(node.nodeValue || '');
        if (node.nodeType !== Node.ELEMENT_NODE) return 0;

        if (node.tagName.toLowerCase() === 'br') return 1;

        let len = 0;
        Array.from(node.childNodes).forEach((child) => {
            len += Formatter.getTextLengthFromDomNode(child);
        });
        return len;
    }

    static getTextLengthFromDom(root) {
        if (!root) return 0;
        return Array.from(root.childNodes || []).reduce((sum, child) => sum + Formatter.getTextLengthFromDomNode(child), 0);
    }

    static getTextOffsetFromDomPosition(root, targetContainer, targetOffset) {
        if (!root || !targetContainer) return null;

        let total = 0;
        let found = false;

        const walk = (node) => {
            if (found || !node) return;

            if (node === targetContainer) {
                if (node.nodeType === Node.TEXT_NODE) {
                    total += Formatter.visibleTextLength((node.nodeValue || '').slice(0, targetOffset));
                } else if (node.nodeType === Node.ELEMENT_NODE) {
                    const childNodes = Array.from(node.childNodes || []);
                    const cappedOffset = Math.min(targetOffset, childNodes.length);
                    for (let i = 0; i < cappedOffset; i++) {
                        total += Formatter.getTextLengthFromDomNode(childNodes[i]);
                    }
                }
                found = true;
                return;
            }

            if (node.nodeType === Node.TEXT_NODE) {
                total += Formatter.visibleTextLength(node.nodeValue || '');
                return;
            }

            if (node.nodeType !== Node.ELEMENT_NODE) return;

            if (node.tagName.toLowerCase() === 'br') {
                total += 1;
                return;
            }

            Array.from(node.childNodes).forEach((child) => {
                if (!found) walk(child);
            });
        };

        walk(root);
        return found ? total : null;
    }

    static resolveDomPositionFromTextOffset(root, offset) {
        if (!root) return { container: null, offset: 0 };

        const totalLen = Formatter.getTextLengthFromDom(root);
        let remaining = Math.max(0, Math.min(offset, totalLen));
        let result = null;

        const walk = (node) => {
            if (result || !node) return;

            if (node.nodeType === Node.TEXT_NODE) {
                const len = Formatter.visibleTextLength(node.nodeValue || '');
                if (remaining <= len) {
                    result = {
                        container: node,
                        offset: Formatter.rawOffsetFromVisibleTextOffset(node.nodeValue || '', remaining)
                    };
                    return;
                }
                remaining -= len;
                return;
            }

            if (node.nodeType !== Node.ELEMENT_NODE) return;

            if (node.tagName.toLowerCase() === 'br') {
                const parent = node.parentNode;
                const idx = Array.prototype.indexOf.call(parent.childNodes, node);
                if (remaining === 0) {
                    result = { container: parent, offset: idx };
                    return;
                }
                if (remaining <= 1) {
                    result = { container: parent, offset: idx + 1 };
                    return;
                }
                remaining -= 1;
                return;
            }

            Array.from(node.childNodes).forEach((child) => {
                if (!result) walk(child);
            });
        };

        Array.from(root.childNodes || []).forEach((child) => {
            if (!result) walk(child);
        });

        if (result) return result;
        return { container: root, offset: root.childNodes.length };
    }

    static normalizeTextBlockHtml(html, { emptyAsBr = true } = {}) {
        const host = document.createElement('div');
        host.innerHTML = String(html ?? '')
            .replace(/<!--[\s\S]*?-->/g, '')
            .replace(/[\u200B-\u200D\uFEFF]/g, '');

        Formatter.normalizeEditableTextChildren(host);

        const value = host.innerHTML;

        if (Formatter.isMeaningfullyEmptyHtml(value)) {
            return emptyAsBr ? '<br>' : '';
        }

        return value;
    }

    static fragmentToHtml(fragment) {
        const host = document.createElement('div');
        host.appendChild(fragment);
        return host.innerHTML;
    }

    static rangeToHtml(range) {
        if (!range) return '';
        return Formatter.fragmentToHtml(range.cloneContents());
    }

    static getPlainTextFromHtml(html) {
        const host = document.createElement('div');
        host.innerHTML = html || '';

        let out = '';

        const walk = (node) => {
            if (!node) return;

            if (node.nodeType === Node.TEXT_NODE) {
                out += node.nodeValue || '';
                return;
            }

            if (node.nodeType !== Node.ELEMENT_NODE) return;

            const tag = node.tagName.toLowerCase();

            if (tag === 'br') {
                out += '\n';
                return;
            }

            Array.from(node.childNodes).forEach((child) => walk(child));
        };

        Array.from(host.childNodes).forEach((child) => walk(child));
        return out;
    }

    static getTextLengthFromHtml(html) {
        return Formatter.getPlainTextFromHtml(html).length;
    }

    static findHtmlBoundaryByTextOffset(root, offset) {
        let remaining = offset;
        let result = null;

        const walk = (node) => {
            if (result || !node) return;

            if (node.nodeType === Node.TEXT_NODE) {
                const text = node.nodeValue || '';
                if (remaining <= text.length) {
                    result = { container: node, offset: remaining };
                    return;
                }
                remaining -= text.length;
                return;
            }

            if (node.nodeType !== Node.ELEMENT_NODE) return;

            const tag = node.tagName.toLowerCase();

            if (tag === 'br') {
                if (remaining <= 1) {
                    const parent = node.parentNode;
                    const idx = Array.prototype.indexOf.call(parent.childNodes, node);
                    result = { container: parent, offset: idx + 1 };
                    return;
                }
                remaining -= 1;
                return;
            }

            Array.from(node.childNodes).forEach((child) => walk(child));
        };

        walk(root);
        return result;
    }

    static splitHtmlByTextOffset(html, offset) {
        const src = html || '';
        const host = document.createElement('div');
        host.innerHTML = src;

        const totalLen = Formatter.getTextLengthFromHtml(src);

        if (offset <= 0) return { a: '', b: src };
        if (offset >= totalLen) return { a: src, b: '' };

        const boundary = Formatter.findHtmlBoundaryByTextOffset(host, offset);
        if (!boundary) return { a: src, b: '' };

        const rA = document.createRange();
        rA.selectNodeContents(host);
        rA.setEnd(boundary.container, boundary.offset);

        const rB = document.createRange();
        rB.selectNodeContents(host);
        rB.setStart(boundary.container, boundary.offset);

        return {
            a: Formatter.rangeToHtml(rA),
            b: Formatter.rangeToHtml(rB)
        };
    }

    static parseHTMLToBlocks(html) {
        console.log("--- Formatter: Parsing HTML Start ---");
        html = html.replace(/<!--[\s\S]*?-->/g, '');
        console.log("Input HTML:", html);

        try {
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const body = doc.body;

            console.log("Parsed Body (Before Clean):", body.innerHTML);

            const cleanNode = (n) => {
                if (!n || !n.parentNode) return;

                if (n.nodeType === 8) {
                    n.parentNode.removeChild(n);
                    return;
                }

                if (n.nodeType === 1) {
                    n.removeAttribute('style');

                    const attrs = Array.from(n.attributes || []);
                    attrs.forEach((a) => {
                        if (a.name === 'class' || a.name === 'id' || a.name.startsWith('_ng') || a.name.startsWith('ng-')) {
                            n.removeAttribute(a.name);
                        }
                    });

                    for (let i = n.childNodes.length - 1; i >= 0; i--) {
                        cleanNode(n.childNodes[i]);
                    }
                }
            };

            cleanNode(body);
            console.log("Parsed Body (After Clean):", body.innerHTML);

            const newBlocks = [];
            let inlineAccumulator = [];

            const flushAccumulator = () => {
                if (inlineAccumulator.length === 0) return;

                const div = document.createElement('div');
                inlineAccumulator.forEach((node) => div.appendChild(node.cloneNode(true)));

                const content = Formatter.normalizeTextBlockHtml(div.innerHTML || '', { emptyAsBr: false });
                const isEmpty = Formatter.isMeaningfullyEmptyHtml(content);

                if (!isEmpty) {
                    newBlocks.push({
                        type: 'text',
                        style: 'normal',
                        content,
                        id: Date.now() + Math.random()
                    });
                }

                inlineAccumulator = [];
            };

            const pushPlainTextBlock = (text) => {
                if (text === undefined || text === null) return;
                const normalized = String(text).replace(/\r\n?/g, '\n');

                newBlocks.push({
                    type: 'text',
                    style: 'normal',
                    content: Formatter.plainTextToHtml(normalized),
                    preserveWhitespace: true,
                    id: Date.now() + Math.random()
                });
            };

            const walk = (node) => {
                if (node.nodeType === 3) {
                    const txt = node.textContent || '';
                    const norm = Formatter.normalizeText(txt);
                    if (norm.length > 0 || inlineAccumulator.length > 0) {
                        inlineAccumulator.push(node);
                    }
                    return;
                }

                if (node.nodeType !== 1) return;

                const tag = node.tagName.toLowerCase();
                const isBlock = ['p', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li', 'blockquote', 'tr', 'table', 'ul', 'ol'].includes(tag);
                const isBr = tag === 'br';
                const isImg = tag === 'img';
                const isPre = tag === 'pre';

                if (isPre) {
                    flushAccumulator();
                    pushPlainTextBlock(node.textContent || '');
                    return;
                }

                if (isImg) {
                    flushAccumulator();
                    newBlocks.push({
                        type: 'image',
                        content: node.src,
                        width: 100,
                        align: 'center',
                        caption: '',
                        id: Date.now() + Math.random()
                    });
                    return;
                }

                if (isBr) {
                    if (inlineAccumulator.length > 0) {
                        inlineAccumulator.push(node);
                    }
                    return;
                }

                if (isBlock) {
                    flushAccumulator();

                    let style = 'normal';
                    if (tag === 'h1') style = 'h1';
                    else if (tag === 'h2') style = 'h2';
                    else if (tag === 'h3') style = 'h3';
                    else if (tag === 'h4') style = 'h4';
                    else if (tag === 'h5') style = 'h5';
                    else if (tag === 'h6') style = 'h6';
                    else if (tag === 'blockquote') style = 'quote';

                    const content = Formatter.normalizeTextBlockHtml(node.innerHTML || '', { emptyAsBr: false });

                    if (!Formatter.isMeaningfullyEmptyHtml(content)) {
                        newBlocks.push({
                            type: 'text',
                            style,
                            content,
                            id: Date.now() + Math.random()
                        });
                    }
                    return;
                }

                inlineAccumulator.push(node);
            };

            Array.from(body.childNodes).forEach((node) => walk(node));
            flushAccumulator();

            const finalBlocks = newBlocks.filter((b) => {
                if (b.type !== 'text') return true;
                if (b.preserveWhitespace) return true;
                return !Formatter.isMeaningfullyEmptyHtml(b.content);
            });

            console.log("--- Formatter: End. Total Blocks:", finalBlocks.length);
            return finalBlocks;
        } catch (e) {
            console.error("HTML Parse Error", e);
            return [];
        }
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/history.js
// ================================================================
import { Transaction, isTransaction } from './editor/transaction.js';
import { cloneDocumentValue } from './editor/schema.js';

export class HistoryManager {
    constructor(stateManager) {
        this.undoStack = [];
        this.redoStack = [];
        this.sm = stateManager;
        this.maxSize = 200;
        this.mergeWindowMs = 750;
    }

    push(entry) {
        const value = isTransaction(entry) ? Transaction.from(entry) : cloneDocumentValue(entry);
        const last = this.undoStack[this.undoStack.length - 1];

        if (last && this.tryMerge(last, value)) {
            this.redoStack = [];
            return;
        }

        this.undoStack.push(value);
        if (this.undoStack.length > this.maxSize) this.undoStack.shift();
        this.redoStack = [];
    }

    tryMerge(last, next) {
        const a = Transaction.from(last);
        const b = Transaction.from(next);
        if (a.meta?.mergeable !== true || b.meta?.mergeable !== true) return false;
        if ((b.timestamp - a.timestamp) > this.mergeWindowMs) return false;
        if (a.operations.length !== 1 || b.operations.length !== 1) return false;
        const left = a.operations[0];
        const right = b.operations[0];
        const sameBlock = String(left.blockId || '') === String(right.blockId || '')
            || (left.blockId == null && right.blockId == null && left.index === right.index);
        if (!sameBlock) return false;
        const leftType = a.meta?.inputType || a.source;
        const rightType = b.meta?.inputType || b.source;
        if (leftType !== rightType) return false;
        if (!['insertText', 'delete', 'input'].includes(leftType)) return false;
        if (a.mergeKey && b.mergeKey && a.mergeKey !== b.mergeKey) return false;
        if (left.type !== 'REPLACE_BLOCK_STATE' || right.type !== 'REPLACE_BLOCK_STATE') return false;

        a.operations = cloneDocumentValue(b.operations);
        if (!a.inverseOperations?.length) a.inverseOperations = cloneDocumentValue(b.inverseOperations || []);
        a.selectionAfter = cloneDocumentValue(b.selectionAfter);
        a.renderImpact = cloneDocumentValue(b.renderImpact || a.renderImpact);
        a.timestamp = b.timestamp;
        a.meta = { ...a.meta, ...b.meta };
        return true;
    }

    sameOperationBlock(a, b) {
        if (a.blockId != null || b.blockId != null) return String(a.blockId) === String(b.blockId);
        return a.index === b.index;
    }

    undo() {
        if (this.undoStack.length === 0) return;
        const entry = this.undoStack.pop();
        const inverse = this.getInverse(entry);
        this.redoStack.push(entry);
        if (isTransaction(inverse)) {
            this.sm.applyTransaction(inverse, false);
            this.sm.signal('HISTORY_SELECTION_REQUEST', { selection: inverse.selectionAfter, direction: 'undo' });
        } else {
            this.sm.applyOp(inverse, false);
        }
    }

    redo() {
        if (this.redoStack.length === 0) return;
        const entry = this.redoStack.pop();
        if (isTransaction(entry)) {
            const transaction = Transaction.from(entry);
            this.sm.applyTransaction(transaction, false);
            this.sm.signal('HISTORY_SELECTION_REQUEST', { selection: transaction.selectionAfter, direction: 'redo' });
        } else {
            this.sm.applyOp(entry, false);
        }
        this.undoStack.push(entry);
    }

    getInverse(entry) {
        if (isTransaction(entry)) {
            const transaction = Transaction.from(entry);
            const inverseOperations = transaction.inverseOperations?.length
                ? cloneDocumentValue(transaction.inverseOperations)
                : (() => {
                    const operations = [];
                    [...transaction.operations].reverse().forEach(operation => {
                        operations.push(...this.getInverseOperations(operation));
                    });
                    return operations;
                })();
            return new Transaction({
                source: 'history',
                operations: inverseOperations,
                selectionBefore: transaction.selectionAfter,
                selectionAfter: transaction.selectionBefore,
                meta: { inverseOf: transaction.id, mergeable: false },
                renderImpact: cloneDocumentValue(transaction.renderImpact)
            });
        }
        const operations = this.getInverseOperations(entry);
        return operations.length === 1
            ? operations[0]
            : new Transaction({ source: 'history', operations });
    }

    getInverseOperations(op) {
        switch (op.type) {
            case 'UPDATE_BLOCK':
                return [{
                    type: 'UPDATE_BLOCK',
                    index: op.index,
                    blockId: op.blockId,
                    content: op.prevContent,
                    prevContent: op.content,
                    source: 'history'
                }];
            case 'ADD_BLOCK':
                return [{
                    type: 'REMOVE_BLOCK',
                    index: op.index,
                    blockId: op.blockId || op.block?.id,
                    block: cloneDocumentValue(op.block),
                    previousBlockId: op.previousBlockId,
                    nextBlockId: op.nextBlockId
                }];
            case 'REMOVE_BLOCK':
                return [{
                    type: 'ADD_BLOCK',
                    index: op.index,
                    blockId: op.blockId || op.block?.id,
                    block: cloneDocumentValue(op.block),
                    previousBlockId: op.previousBlockId,
                    nextBlockId: op.nextBlockId
                }];
            case 'REPLACE_BLOCK_STATE':
                return [{
                    type: 'REPLACE_BLOCK_STATE',
                    index: op.index,
                    blockId: op.blockId,
                    block: cloneDocumentValue(op.prevBlock),
                    prevBlock: cloneDocumentValue(op.block),
                    source: 'history'
                }];
            case 'SPLIT_BLOCK':
                return [{
                    type: 'UNSPLIT_BLOCK',
                    index: op.index,
                    blockId: op.blockId,
                    newBlockId: op.newBlockId || op.newBlock?.id,
                    prevBlock: cloneDocumentValue(op.prevBlock),
                    block: cloneDocumentValue(op.block),
                    removedBlock: cloneDocumentValue(op.newBlock)
                }];
            case 'UNSPLIT_BLOCK':
                return [{
                    type: 'SPLIT_BLOCK',
                    index: op.index,
                    blockId: op.blockId,
                    newBlockId: op.newBlockId || op.removedBlock?.id,
                    block: cloneDocumentValue(op.block),
                    newBlock: cloneDocumentValue(op.removedBlock),
                    prevBlock: cloneDocumentValue(op.prevBlock)
                }];
            case 'MERGE_BLOCKS':
                return [
                    {
                        type: 'UPDATE_BLOCK',
                        blockId: op.targetBlockId,
                        content: op.prevContent,
                        prevContent: null,
                        source: 'history'
                    },
                    {
                        type: 'ADD_BLOCK',
                        index: op.index,
                        blockId: op.removedBlockId || op.removedBlock?.id,
                        block: cloneDocumentValue(op.removedBlock)
                    }
                ];
            case 'MOVE_BLOCK':
                return [{
                    type: 'MOVE_BLOCK',
                    blockId: op.blockId,
                    fromIndex: op.toIndex,
                    toIndex: op.fromIndex
                }];
            default:
                return [cloneDocumentValue(op)];
        }
    }

    clear() {
        this.undoStack = [];
        this.redoStack = [];
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/keyboard-manager.js
// ================================================================
export class KeyboardManager {
    constructor(ctrl) {
        this.ctrl = ctrl;
        this.state = ctrl.state;
    }

    setup() {
        const ctrl = this.ctrl;

        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                e.preventDefault();
                this.state.save();
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'z') {
                e.preventDefault();
                this.state.history.undo();
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'y') {
                e.preventDefault();
                this.state.history.redo();
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'b') {
                e.preventDefault();
                ctrl.engine.dispatch('toggleBold');
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'i') {
                e.preventDefault();
                ctrl.engine.dispatch('toggleItalic');
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'u') {
                e.preventDefault();
                ctrl.engine.dispatch('toggleUnderline');
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === '`' || e.key === '~')) {
                e.preventDefault();
                ctrl.engine.dispatch('toggleInlineCode');
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
                e.preventDefault();
                document.getElementById('modal-find').classList.remove('hidden');
                setTimeout(() => document.getElementById('inp-find-text').focus(), 50);
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'h') {
                e.preventDefault();
                document.getElementById('modal-find').classList.remove('hidden');
                setTimeout(() => document.getElementById('inp-replace-text').focus(), 50);
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
                e.preventDefault();
                ctrl.engine.dispatch('updateBlockProps', { blockId: ctrl.activeBlockId, props: { align: 'left' } });
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'e') {
                e.preventDefault();
                ctrl.engine.dispatch('updateBlockProps', { blockId: ctrl.activeBlockId, props: { align: 'center' } });
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
                e.preventDefault();
                ctrl.engine.dispatch('updateBlockProps', { blockId: ctrl.activeBlockId, props: { align: 'right' } });
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'j') {
                e.preventDefault();
                ctrl.engine.dispatch('updateBlockProps', { blockId: ctrl.activeBlockId, props: { align: 'justify' } });
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'L') {
                e.preventDefault();
                ctrl.engine.dispatch('convertBlockToList', { blockId: ctrl.activeBlockId, listType: 'ul' });
                return;
            }
            if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === '>' || e.key === '.')) {
                e.preventDefault();
                ctrl.engine.dispatch('toggleSuperscript');
                return;
            }

            const idx = ctrl.activeBlockIndex;
            if (idx === null || !this.state.doc.blocks[idx]) return;

            const block = this.state.doc.blocks[idx];
            const ctx = ctrl.getActiveBlockContextFromSelection();

            if (e.key === 'Enter') {
                const selection = window.getSelection();
                ctrl.debugEnter('keydown Enter', {
                    supportsBeforeInput: ctrl.supportsBeforeInput,
                    defaultPrevented: e.defaultPrevented,
                    shiftKey: e.shiftKey,
                    activeBlockIndex: ctrl.activeBlockIndex,
                    ctxIndex: ctx?.index ?? null,
                    blockType: block?.type ?? null,
                    blockContent: block?.content ?? null,
                    selectionText: selection?.toString() ?? '',
                    anchorNodeType: selection?.anchorNode?.nodeType ?? null,
                    anchorNodeText: selection?.anchorNode?.textContent ?? null,
                    anchorOffset: selection?.anchorOffset ?? null,
                    focusNodeType: selection?.focusNode?.nodeType ?? null,
                    focusNodeText: selection?.focusNode?.textContent ?? null,
                    focusOffset: selection?.focusOffset ?? null,
                    lastFocusedIndex: ctrl.lastFocusedBlockEl?.dataset?.index ?? null
                });
            }

            if (e.key === 'Escape' && this.state.hfMode) {
                this.state.toggleHFMode(false);
                return;
            }

            if ((e.key === 'Backspace' || e.key === 'Delete') && ['image', 'horizontalRule', 'pageBreak'].includes(block.type)) {
                e.preventDefault();
                this.state.removeBlock(idx);
                const nextIndex = Math.max(0, Math.min(idx, this.state.doc.blocks.length - 1));
                setTimeout(() => ctrl.focusBlock(nextIndex, 'start'), 0);
                return;
            }

            if (['ul', 'ol', 'checklist'].includes(block.type)) {
                if (e.key === 'Tab') {
                    e.preventDefault();
                    const sel = window.getSelection();
                    let n = sel.anchorNode;
                    if (n && n.nodeType === 3) n = n.parentElement;
                    const li = n ? n.closest('li') : null;
                    if (li) {
                        const iIdx = parseInt(li.dataset.idx);
                        this.state.indentListItem(idx, iIdx, e.shiftKey ? 'out' : 'in');
                    }
                    return;
                }

                if (e.key === 'Enter') {
                    e.preventDefault();
                    const sel = window.getSelection();
                    let n = sel.anchorNode;
                    if (n && n.nodeType === 3) n = n.parentElement;
                    const li = n ? n.closest('li') : null;
                    if (li) {
                        const iIdx = parseInt(li.dataset.idx);
                        const item = block.items[iIdx] || { text: '', level: 0 };
                        const rawText = String(item.text || '');
                        const isEmptyItem = rawText.trim() === '' && li.innerText.trim() === '';

                        if (isEmptyItem) {
                            const newItems = [...block.items];
                            newItems.splice(iIdx, 1);
                            if (newItems.length === 0) this.state.removeBlock(idx);
                            else this.state.updateBlockProps(idx, { items: newItems });

                            this.state.insertBlockAt(idx + 1, { type: 'text', style: 'normal', content: '<br>', id: Date.now() });
                            setTimeout(() => ctrl.focusBlock(idx + 1, 'start'), 0);
                        } else {
                            const range = sel.rangeCount ? sel.getRangeAt(0) : null;
                            const start = range ? (Formatter.getTextOffsetFromDomPosition(li, range.startContainer, range.startOffset) ?? rawText.length) : rawText.length;
                            const end = range ? (Formatter.getTextOffsetFromDomPosition(li, range.endContainer, range.endOffset) ?? start) : start;
                            const splitStart = Math.max(0, Math.min(start, rawText.length));
                            const splitEnd = Math.max(splitStart, Math.min(end, rawText.length));

                            const leftText = rawText.slice(0, splitStart);
                            const rightText = rawText.slice(splitEnd);
                            const newItems = [...block.items];
                            newItems[iIdx] = { ...item, text: leftText };
                            newItems.splice(iIdx + 1, 0, { text: rightText, level: item.level || 0, checked: false });
                            this.state.updateBlockProps(idx, { items: newItems });

                            const focusCurrentBlank = range && range.collapsed && splitStart === 0;
                            setTimeout(() => {
                                if (focusCurrentBlank) ctrl.focusListItem(idx, iIdx, 'start');
                                else ctrl.focusListItem(idx, iIdx + 1, 'start');
                            }, 0);
                        }
                    }
                    return;
                }
            }

            if ((['ul', 'ol', 'checklist'].includes(block.type)) && e.key === 'Backspace') {
                const sel = window.getSelection();
                let n = sel.anchorNode;
                if (n && n.nodeType === 3) n = n.parentElement;
                const li = n ? n.closest('li') : null;
                if (li) {
                    const iIdx = parseInt(li.dataset.idx);
                    const item = block.items[iIdx];
                    if (!item) return;

                    const isEmptyItem = Formatter.isMeaningfullyEmptyHtml(li.innerHTML);

                    if (isEmptyItem) {
                        e.preventDefault();
                        const newItems = [...block.items];
                        newItems.splice(iIdx, 1);
                        if (newItems.length === 0) {
                            this.state.removeBlock(idx);
                        } else {
                            this.state.updateBlockProps(idx, { items: newItems });
                            const focusIdx = Math.min(iIdx, newItems.length - 1);
                            setTimeout(() => ctrl.focusListItem(idx, focusIdx, 'start'), 0);
                        }
                        return;
                    }
                }
            }

            if (block.type === 'text') {
                const modelInputActive = !!ctrl.engine?.inputManager?.handlesModelInput(ctx || e.target);
                if (modelInputActive && ['Backspace', 'Delete'].includes(e.key)) return;

                if (!ctrl.supportsBeforeInput && e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    ctrl.debugEnter('keydown fallback splitBlock', {
                        idx,
                        blockContent: block.content
                    });
                    ctrl.splitBlock(idx);
                    return;
                }

                if (e.key === 'Backspace') {
                    if (!ctx || ctx.index !== idx) return;

                    const caretInfo = ctrl.getCaretTextOffsetInElement(ctx.el);
                    if (!caretInfo || !caretInfo.collapsed) return;

                    const currentHtml = ctrl.getCleanBlockHtmlFromElement(ctx.el);
                    const isEmptyPara = Formatter.isMeaningfullyEmptyHtml(currentHtml);

                    if (ctx.isSplit && ctx.partIndex > 0 && ctrl.isCaretAtStart(ctx.el)) {
                        e.preventDefault();
                        const prev = ctx.parts[ctx.partIndex - 1];
                        const prevHtml = ctrl.getCleanBlockHtmlFromElement(prev);
                        const curHtml = ctrl.getCleanBlockHtmlFromElement(ctx.el);

                        const mergedHtml = ctrl.normalizeTextBlockHtml((prevHtml || '') + (curHtml || ''));
                        prev.innerHTML = mergedHtml;

                        ctx.el.parentNode.removeChild(ctx.el);

                        const fullHtml = ctrl.normalizeTextBlockHtml(
                            ctx.parts
                                .filter((p) => p !== ctx.el)
                                .sort((a, b) => parseInt(a.dataset.splitPart || '0') - parseInt(b.dataset.splitPart || '0'))
                                .map((p) => ctrl.getCleanBlockHtmlFromElement(p))
                                .join('')
                        );

                        this.state.updateBlockContent(idx, fullHtml, 'typing');
                        setTimeout(() => ctrl.focusBlock(idx, 'end'), 0);
                        return;
                    }

                    if (isEmptyPara && idx > 0) {
                        e.preventDefault();
                        this.state.removeBlock(idx);
                        setTimeout(() => ctrl.focusBlock(idx - 1, 'end'), 0);
                        return;
                    }

                    if (idx > 0 && ctrl.isCaretAtStart(ctx.el)) {
                        e.preventDefault();
                        const prevBlock = this.state.doc.blocks[idx - 1];
                        if (prevBlock && prevBlock.type === 'text' && Formatter.isMeaningfullyEmptyHtml(prevBlock.content)) {
                            this.state.removeBlock(idx - 1);
                            setTimeout(() => ctrl.focusBlock(idx - 1, 'start'), 0);
                        } else {
                            this.state.mergeBlockWithPrevious(idx);
                            ctrl.focusBlock(idx - 1, 'end');
                        }
                        return;
                    }
                }

                if (e.key === 'Delete') {
                    if (!ctx || ctx.index !== idx) return;

                    const caretInfo = ctrl.getCaretTextOffsetInElement(ctx.el);
                    if (!caretInfo || !caretInfo.collapsed) return;

                    if (ctx.isSplit && ctx.partIndex < ctx.parts.length - 1 && ctrl.isCaretAtEnd(ctx.el)) {
                        e.preventDefault();
                        const next = ctx.parts[ctx.partIndex + 1];
                        const curHtml = ctrl.getCleanBlockHtmlFromElement(ctx.el);
                        const nextHtml = ctrl.getCleanBlockHtmlFromElement(next);

                        const mergedHtml = ctrl.normalizeTextBlockHtml((curHtml || '') + (nextHtml || ''));
                        ctx.el.innerHTML = mergedHtml;

                        next.parentNode.removeChild(next);

                        const partsNow = Array.from(document.querySelectorAll(`[data-index="${idx}"].block-text`));
                        partsNow.sort((a, b) => parseInt(a.dataset.splitPart || '0') - parseInt(b.dataset.splitPart || '0'));
                        const fullHtml = ctrl.normalizeTextBlockHtml(partsNow.map((p) => ctrl.getCleanBlockHtmlFromElement(p)).join(''));
                        this.state.updateBlockContent(idx, fullHtml, 'typing');
                        setTimeout(() => ctrl.focusBlock(idx, 'end'), 0);
                        return;
                    }

                    if (ctrl.isCaretAtEnd(ctx.el) && idx < this.state.doc.blocks.length - 1) {
                        const nextBlock = this.state.doc.blocks[idx + 1];
                        if (nextBlock && nextBlock.type === 'text') {
                            e.preventDefault();
                            if (Formatter.isMeaningfullyEmptyHtml(nextBlock.content)) {
                                this.state.removeBlock(idx + 1);
                                setTimeout(() => ctrl.focusBlock(idx, 'end'), 0);
                            } else {
                                const curContent = ctrl.normalizeTextBlockHtml(this.state.doc.blocks[idx].content || '');
                                const nextContent = ctrl.normalizeTextBlockHtml(nextBlock.content || '');
                                this.state.updateBlockContent(idx, ctrl.normalizeTextBlockHtml(curContent + nextContent), 'structure');
                                this.state.removeBlock(idx + 1);
                                setTimeout(() => ctrl.focusBlock(idx, 'end'), 0);
                            }
                            return;
                        }
                    }
                }

                if (e.key === 'ArrowUp') {
                    if (ctx) {
                        const atStart = ctrl.isCaretAtStart(ctx.el);
                        const isFirstPart = (!ctx.isSplit) || (ctx.partIndex === 0);
                        if (atStart && isFirstPart && idx > 0) {
                            e.preventDefault();
                            ctrl.focusBlock(idx - 1, 'end');
                            return;
                        }
                    }
                }

                if (e.key === 'ArrowDown') {
                    if (ctx) {
                        const atEnd = ctrl.isCaretAtEnd(ctx.el);
                        const isLastPart = (!ctx.isSplit) || (ctx.partIndex === ctx.parts.length - 1);
                        if (atEnd && isLastPart && idx < this.state.doc.blocks.length - 1) {
                            e.preventDefault();
                            ctrl.focusBlock(idx + 1, 'start');
                            return;
                        }
                    }
                }
            }
        });
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/layout/layout-map.js
// ================================================================
import { Formatter } from '../formatter.js';

/**
 * A read-only projection of canonical document blocks onto visual pages.
 * Fragments never become document nodes; they only describe which text offsets
 * are currently displayed by each DOM element.
 */
export class LayoutMap {
    constructor() {
        this.version = 0;
        this.pages = [];
        this.fragmentsByBlock = new Map();
        this.fragmentByElement = new WeakMap();
        this.invalidFromBlockId = null;
    }

    clear() {
        this.pages = [];
        this.fragmentsByBlock = new Map();
        this.fragmentByElement = new WeakMap();
    }

    invalidateFrom(blockId) {
        this.invalidFromBlockId = blockId || null;
    }

    rebuild(root, state, isPageView = true) {
        this.clear();
        if (!root) return this;
        const pageElements = isPageView
            ? [...root.querySelectorAll('.page')]
            : [...root.querySelectorAll('.mode-pageless')];
        const consumedByBlock = new Map();

        pageElements.forEach((pageElement, pageIndex) => {
            const page = {
                number: pageIndex + 1,
                element: pageElement,
                fragments: [],
                objects: []
            };
            const host = isPageView ? pageElement.querySelector('.page-content-area') : pageElement;
            const elements = host
                ? [...host.children].filter(element => element?.dataset?.blockId)
                : [];
            if (isPageView) {
                [...pageElement.querySelectorAll(':scope > .floating-box[data-block-id], :scope > .object-host[data-block-id], :scope > .page-behind-text-objects > .object-host[data-block-id], :scope > .page-front-objects > .object-host[data-block-id]')]
                    .forEach(element => { if (!elements.includes(element)) elements.push(element); });
            }
            elements.forEach(element => {
                const blockId = String(element.dataset.blockId);
                const block = state?.getBlockById?.(blockId);
                const startOffset = consumedByBlock.get(blockId) || 0;
                const length = block?.type === 'text'
                    ? Formatter.getTextLengthFromDom(element)
                    : 0;
                const endOffset = startOffset + length;
                const rect = element.getBoundingClientRect?.() || { top: 0, height: 0 };
                const fragment = {
                    blockId,
                    pageNumber: page.number,
                    startOffset,
                    endOffset,
                    splitPart: Number(element.dataset.splitPart || 0),
                    top: Number(rect.top || 0),
                    height: Number(rect.height || 0),
                    element
                };
                element.dataset.fragmentStart = String(startOffset);
                element.dataset.fragmentEnd = String(endOffset);
                page.fragments.push(fragment);
                if (block?.type === 'object') {
                    const pageRect = pageElement.getBoundingClientRect?.() || { left: 0, top: 0 };
                    page.objects.push({
                        objectId: blockId,
                        anchorBlockId: block.anchor?.blockId || null,
                        wrapType: block.wrap?.type || 'inline',
                        bounds: { x: Number(rect.left || 0) - Number(pageRect.left || 0), y: Number(rect.top || 0) - Number(pageRect.top || 0), width: Number(rect.width || 0), height: Number(rect.height || 0) },
                        exclusionBounds: {
                            x: Number(rect.left || 0) - Number(pageRect.left || 0) - Number(block.wrap?.distance?.left || 0),
                            y: Number(rect.top || 0) - Number(pageRect.top || 0) - Number(block.wrap?.distance?.top || 0),
                            width: Number(rect.width || 0) + Number(block.wrap?.distance?.left || 0) + Number(block.wrap?.distance?.right || 0),
                            height: Number(rect.height || 0) + Number(block.wrap?.distance?.top || 0) + Number(block.wrap?.distance?.bottom || 0)
                        }
                    });
                }
                if (!this.fragmentsByBlock.has(blockId)) this.fragmentsByBlock.set(blockId, []);
                this.fragmentsByBlock.get(blockId).push(fragment);
                this.fragmentByElement.set(element, fragment);
                consumedByBlock.set(blockId, endOffset);
            });
            this.pages.push(page);
        });

        this.version += 1;
        this.invalidFromBlockId = null;
        return this;
    }

    getFragments(blockId) {
        return [...(this.fragmentsByBlock.get(String(blockId)) || [])];
    }

    getFragmentForElement(element) {
        return element ? this.fragmentByElement.get(element) || null : null;
    }

    findFragment(blockId, offset = 0) {
        const fragments = this.getFragments(blockId);
        if (!fragments.length) return null;
        const target = Math.max(0, Number(offset) || 0);
        return fragments.find(fragment => target >= fragment.startOffset && target <= fragment.endOffset)
            || fragments[fragments.length - 1];
    }

    toJSON() {
        return {
            version: this.version,
            pages: this.pages.map(page => ({
                number: page.number,
                fragments: page.fragments.map(({ element, ...fragment }) => ({ ...fragment })),
                objects: page.objects.map(object => ({ ...object }))
            }))
        };
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/layout/pagination-manager.js
// ================================================================
export class PaginationManager {
    constructor(controller) {
        this.ctrl = controller;
        this.state = controller.state;
    }

    setup() {
        this.ensureUi();
        document.getElementById('btn-pagination-options')?.addEventListener('click', () => this.open());
        document.getElementById('pagination-options-panel')?.addEventListener('change', event => this.update(event));
        document.getElementById('pagination-options-panel')?.addEventListener('click', event => {
            if (event.target.dataset.action === 'close') document.getElementById('pagination-options-panel').classList.add('hidden');
        });
    }

    ensureUi() {
        if (!document.getElementById('btn-pagination-options')) {
            const button = document.createElement('button');
            button.id = 'btn-pagination-options'; button.title = 'Paragraph pagination options';
            button.innerHTML = '<span aria-hidden="true">¶</span><span>Pagination</span>';
            const host = document.querySelector('.ribbon-bar-spacer')?.parentElement || document.querySelector('.ribbon-bar');
            host?.appendChild(button);
        }
        if (!document.getElementById('pagination-options-panel')) {
            const panel = document.createElement('div');
            panel.id = 'pagination-options-panel'; panel.className = 'pagination-options-panel hidden';
            panel.innerHTML = `<div class="pagination-panel-header"><strong>Pagination</strong><button data-action="close">×</button></div>
              <label><input type="checkbox" data-field="keepWithNext"> Keep with next paragraph</label>
              <label><input type="checkbox" data-field="keepLinesTogether"> Keep lines together</label>
              <label>Minimum orphan lines <input type="number" min="1" max="10" data-field="orphanLines"></label>
              <label>Minimum widow lines <input type="number" min="1" max="10" data-field="widowLines"></label>
              <p>These rules affect page reflow, DOCX export, and PDF output.</p>`;
            document.body.appendChild(panel);
        }
    }

    activeBlock() {
        const blockId = this.ctrl.activeBlockId || this.ctrl.engine.captureSelection()?.anchor?.blockId;
        return blockId ? this.state.getBlockById(blockId) : null;
    }

    open() {
        const block = this.activeBlock(); if (!block || block.type !== 'text') return this.ctrl.toolbar?.showShellToast?.('Place the cursor in a paragraph first');
        const panel = document.getElementById('pagination-options-panel');
        panel.dataset.blockId = block.id;
        panel.querySelector('[data-field="keepWithNext"]').checked = !!block.keepWithNext;
        panel.querySelector('[data-field="keepLinesTogether"]').checked = !!block.keepLinesTogether;
        panel.querySelector('[data-field="orphanLines"]').value = block.orphanLines || 2;
        panel.querySelector('[data-field="widowLines"]').value = block.widowLines || 2;
        panel.classList.remove('hidden');
    }

    update(event) {
        const input = event.target.closest('[data-field]'); if (!input) return;
        const panel = document.getElementById('pagination-options-panel');
        const block = this.state.getBlockById(panel.dataset.blockId); if (!block) return;
        const value = input.type === 'checkbox' ? input.checked : Math.max(1, Math.min(10, Number(input.value) || 2));
        this.state.updateBlockProps(block.id, { [input.dataset.field]: value });
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/main.js
// ================================================================
import { StateManager } from './state.js';
import { Renderer } from './renderer.js';
import { EditorController } from './controller.js';

// Initialize components in dependency order
// 1. State Manager (Data Layer)
const state = new StateManager();

// 2. Renderer (View Layer) - Depends on State
const renderer = new Renderer('workspace', state);

// 3. Controller (Input/Interaction Layer) - Depends on State and Renderer
const ctrl = new EditorController(state, renderer);

// Kick off the application
ctrl.init();

// ================================================================
// FILE: /home/luanngo/opendoc/public/modal-manager.js
// ================================================================
import { FindReplace } from './find-replace.js';

export class ModalManager {
    constructor(ctrl) {
        this.ctrl = ctrl;
        this.state = ctrl.state;
        this.renderer = ctrl.renderer;
        this.findReplace = new FindReplace(ctrl);
    }

    setup() {
        const modalPage = document.getElementById('modal-page');
        document.querySelector('#modal-page .close-modal').onclick = () => modalPage.classList.add('hidden');
        document.getElementById('btn-apply-page').onclick = () => {
            const mLeft = document.getElementById('inp-margin-left').value;
            const mRight = document.getElementById('inp-margin-right').value;
            const mTop = document.getElementById('inp-margin-top').value;
            const mBot = document.getElementById('inp-margin-bottom').value;
            this.state.updateSettings({
                margins: {
                    left: parseFloat(mLeft) || 1,
                    right: parseFloat(mRight) || 1,
                    top: parseFloat(mTop) || 1,
                    bottom: parseFloat(mBot) || 1
                }
            });
            modalPage.classList.add('hidden');
        };

        const modalFind = document.getElementById('modal-find');
        document.getElementById('btn-find').onclick = () => {
            modalFind.classList.remove('hidden');
            document.getElementById('inp-find-text').focus();
        };
        modalFind.querySelector('.close-modal').onclick = () => {
            modalFind.classList.add('hidden');
            this.renderer.highlightMatches = [];
            this.renderer.render(this.state.doc, this.state.hfMode);
        };
        this.findReplace.setup();
    }

    openFind() {
        const modalFind = document.getElementById('modal-find');
        if (modalFind) {
            modalFind.classList.remove('hidden');
            document.getElementById('inp-find-text')?.focus();
        }
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/outline-manager.js
// ================================================================
export class OutlineManager {
    constructor(ctrl) {
        this.ctrl = ctrl;
        this.state = ctrl.state;
        this._outlineObserver = null;
        this._outlineCollapseState = {};
        this._activeNavTab = 'headings';
        this._pageCount = 0;
    }

    updateOutline(blocks) {
        const container = document.getElementById('outline-content');
        const searchTerm = document.getElementById('inp-outline-search')?.value?.toLowerCase() || '';
        container.innerHTML = '';

        const headings = [];
        blocks.forEach((b, i) => {
            if (b.type === 'text' && ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'].includes(b.style)) {
                headings.push({ index: i, blockId: b.id, style: b.style, text: b.content.replace(/<[^>]*>?/gm, '') || '(Empty Heading)' });
            }
        });

        if (headings.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'outline-empty-state';
            empty.innerHTML = '<div class="empty-icon"><i data-lucide="list"></i></div>No headings yet<div class="empty-hint">Apply Heading 1 or Heading 2 to text to create navigation for this document.</div>';
            container.appendChild(empty);
            if (typeof lucide !== 'undefined') lucide.createIcons();
            return;
        }

        let lastH1Index = -1;
        const groupCollapseState = this._outlineCollapseState || {};

        headings.forEach((h, idx) => {
            if (searchTerm && !h.text.toLowerCase().includes(searchTerm)) return;

            const item = document.createElement('div');
            item.className = `outline-item level-${h.style}`;
            item.dataset.blockIndex = h.index;
            if (h.blockId) item.dataset.blockId = h.blockId;
            item.dataset.outlineIndex = idx;

            const dragHandle = document.createElement('span');
            dragHandle.className = 'outline-item-drag-handle';
            dragHandle.innerHTML = '⠿';
            dragHandle.draggable = true;

            let toggleSpan = null;
            if (['h1', 'h2'].includes(h.style)) {
                lastH1Index = idx;
                toggleSpan = document.createElement('span');
                toggleSpan.className = 'outline-item-toggle';
                const groupKey = `h1-${idx}`;
                const isCollapsed = groupCollapseState[groupKey];
                toggleSpan.innerHTML = isCollapsed ? '▸' : '▾';
                toggleSpan.dataset.groupKey = groupKey;
                toggleSpan.dataset.collapsed = isCollapsed ? 'true' : 'false';
                toggleSpan.onclick = (e) => {
                    e.stopPropagation();
                    const collapsed = toggleSpan.dataset.collapsed === 'true';
                    toggleSpan.dataset.collapsed = collapsed ? 'false' : 'true';
                    toggleSpan.innerHTML = collapsed ? '▾' : '▸';
                    this._outlineCollapseState[groupKey] = !collapsed;
                    this.updateOutline(blocks);
                };
            }

            const textSpan = document.createElement('span');
            textSpan.className = 'outline-item-text';
            textSpan.textContent = h.text;

            if (toggleSpan) item.appendChild(toggleSpan);
            item.appendChild(textSpan);
            item.dataset.headingText = h.text;

            item.onclick = (e) => {
                if (e.target.closest('.outline-item-toggle') || e.target.closest('.outline-item-drag-handle')) return;
                const el = document.querySelector(`[data-index="${h.index}"]`);
                if (el) {
                    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    if (h.blockId) this.ctrl.focusBlockById(h.blockId, 'start');
                    else this.ctrl.focusBlock(h.index, 'start');
                }
            };

            item.oncontextmenu = (e) => {
                e.preventDefault();
                e.stopPropagation();
                const menu = document.getElementById('context-menu-outline');
                if (!menu) return;
                menu.style.left = `${e.clientX}px`;
                menu.style.top = `${e.clientY}px`;
                menu.classList.remove('hidden');
                menu.dataset.blockIndex = h.index;
                menu.dataset.headingStyle = h.style;
                menu.dataset.headingText = h.text;
            };

            container.appendChild(item);
        });

        this.setupOutlineDragAndDrop(container);
        this.trackOutlineScrollPosition(headings);
        if (typeof lucide !== 'undefined') lucide.createIcons();

        // Sync to mobile outline content
        const mobContainer = document.getElementById('mob-outline-content');
        if (mobContainer) {
            mobContainer.innerHTML = container.innerHTML;
            const mobItems = mobContainer.querySelectorAll('.outline-item');
            mobItems.forEach(item => {
                item.addEventListener('click', () => {
                    const blockIndex = parseInt(item.dataset.blockIndex, 10);
                    if (!isNaN(blockIndex)) {
                        const el = document.querySelector(`[data-index="${blockIndex}"]`);
                        if (el) {
                            el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            this.ctrl.focusBlock(blockIndex, 'start');
                            const overlay = document.getElementById('mobile-sheet-overlay');
                            const sheet = document.getElementById('mobile-sheet-outline');
                            if (overlay) overlay.classList.remove('open');
                            if (sheet) sheet.classList.remove('open');
                            document.body.style.overflow = '';
                        }
                    }
                });
            });
        }
    }

    trackOutlineScrollPosition(headings) {
        if (this._outlineObserver) this._outlineObserver.disconnect();

        if (!headings || headings.length === 0) return;

        const wrapper = document.getElementById('workspace-wrapper');

        this._outlineObserver = new IntersectionObserver((entries) => {
            const visible = entries.filter(e => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
            if (visible.length === 0) return;

            const firstEl = visible[0].target;
            const idx = parseInt(firstEl.dataset.index);

            const items = document.querySelectorAll('.outline-item');
            items.forEach(item => item.classList.remove('outline-highlight'));

            const match = document.querySelector(`.outline-item[data-block-index="${idx}"]`);
            if (match) match.classList.add('outline-highlight');
        }, {
            root: wrapper,
            rootMargin: '-80px 0px -60% 0px',
            threshold: 0
        });

        headings.forEach(h => {
            const el = document.querySelector(`[data-index="${h.index}"]`);
            if (el) this._outlineObserver.observe(el);
        });
    }

    setupOutlineDragAndDrop(container) {
        let dragItem = null;

        const onDragStart = (e) => {
            const item = e.target.closest('.outline-item');
            if (!item) return;
            dragItem = item;
            item.classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/plain', item.dataset.blockIndex);
        };

        const onDragEnd = (e) => {
            const items = container.querySelectorAll('.outline-item');
            items.forEach(el => el.classList.remove('dragging', 'drag-over', 'drag-over-bottom'));
            dragItem = null;
        };

        const onDragOver = (e) => {
            e.preventDefault();
            const target = e.target.closest('.outline-item');
            if (!target || target === dragItem) return;

            const rect = target.getBoundingClientRect();
            const midY = rect.top + rect.height / 2;

            container.querySelectorAll('.outline-item').forEach(el => el.classList.remove('drag-over', 'drag-over-bottom'));

            if (e.clientY < midY) target.classList.add('drag-over');
            else target.classList.add('drag-over-bottom');
        };

        const onDrop = (e) => {
            e.preventDefault();
            const fromIdx = parseInt(e.dataTransfer.getData('text/plain'));
            const target = e.target.closest('.outline-item');
            if (!target || dragItem === target) return;

            const toIdx = parseInt(target.dataset.blockIndex);
            if (isNaN(fromIdx) || isNaN(toIdx) || fromIdx === toIdx) return;

            const rect = target.getBoundingClientRect();
            const midY = rect.top + rect.height / 2;
            const insertBefore = e.clientY < midY;

            const allHeadings = Array.from(document.querySelectorAll('.outline-item[data-block-index]'));
            const fromHeadingIdx = allHeadings.indexOf(dragItem);
            const toHeadingIdx = allHeadings.indexOf(target);

            if (fromHeadingIdx === -1 || toHeadingIdx === -1) return;

            let finalToIdx = toIdx;
            const blocks = this.state.doc.blocks;
            const targetBlock = blocks[toIdx];

            if (targetBlock && targetBlock.type === 'text' && ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'].includes(targetBlock.style)) {
                if (!insertBefore && toIdx < blocks.length - 1) {
                    finalToIdx = toIdx + 1;
                }
            }

            this.state.moveBlock(fromIdx, finalToIdx);

            const items = container.querySelectorAll('.outline-item');
            items.forEach(el => el.classList.remove('dragging', 'drag-over', 'drag-over-bottom'));
            dragItem = null;
        };

        container.addEventListener('dragstart', onDragStart);
        container.addEventListener('dragend', onDragEnd);
        container.addEventListener('dragover', onDragOver);
        container.addEventListener('drop', onDrop);
    }

    setupInteractions() {
        const ctrl = this.ctrl;
        const collapseBtn = document.getElementById('btn-outline-collapse');
        const expandBtn = document.getElementById('btn-outline-expand');
        const sidebar = document.getElementById('outline-sidebar');
        const rail = document.getElementById('outline-rail');

        if (collapseBtn && sidebar && rail) {
            collapseBtn.onclick = () => {
                sidebar.classList.add('collapsed');
                rail.classList.remove('hidden');
                ctrl._outlineOpen = false;
                ctrl.savePreference('outlineOpen', false);
            };
        }

        if (expandBtn && sidebar && rail) {
            expandBtn.onclick = () => {
                sidebar.classList.remove('collapsed');
                rail.classList.add('hidden');
                ctrl._outlineOpen = true;
                ctrl.savePreference('outlineOpen', true);
            };
        }

        const outlineSearch = document.getElementById('inp-outline-search');
        if (outlineSearch) {
            outlineSearch.addEventListener('input', () => {
                this.updateOutline(this.state.doc.blocks);
            });
        }

        const outlineCtxMenu = document.getElementById('context-menu-outline');
        if (outlineCtxMenu) {
            document.addEventListener('click', (e) => {
                if (!outlineCtxMenu.contains(e.target)) outlineCtxMenu.classList.add('hidden');
            });

            outlineCtxMenu.addEventListener('click', (e) => {
                const item = e.target.closest('.context-menu-item');
                if (!item) return;
                const action = item.dataset.action;
                const bi = parseInt(outlineCtxMenu.dataset.blockIndex);
                const style = outlineCtxMenu.dataset.headingStyle;
                outlineCtxMenu.classList.add('hidden');

                switch (action) {
                    case 'rename': {
                        const newText = prompt('Enter new heading text:', outlineCtxMenu.dataset.headingText);
                        if (newText && newText.trim()) {
                            const block = this.state.doc.blocks[bi];
                            if (block) this.state.updateBlockContent(bi, newText, 'structure');
                        }
                        break;
                    }
                    case 'delete':
                        if (confirm('Delete this heading?')) this.state.removeBlock(bi);
                        break;
                    case 'promote':
                        this.state.changeBlockStyle(bi, 'h1');
                        break;
                    case 'demote':
                        if (bi >= 0) this.state.changeBlockStyle(bi, 'h2');
                        break;
                }
            });
        }

        this.setupNavTabs();

        const pref = ctrl.loadPreference('outlineOpen');
        if (pref !== null) {
            if (!pref) {
                sidebar.classList.add('collapsed');
                rail.classList.remove('hidden');
            }
            ctrl._outlineOpen = pref;
        } else {
            ctrl._outlineOpen = true;
        }
    }

    setupNavTabs() {
        const bindTabs = (tabSelector, contentMap, searchWrapper) => {
            const tabs = document.querySelectorAll(tabSelector);
            tabs.forEach(tab => {
                tab.addEventListener('click', () => {
                    document.querySelectorAll(tabSelector).forEach(t => t.classList.remove('active'));
                    tab.classList.add('active');
                    this._activeNavTab = tab.dataset.navTab;

                    Object.entries(contentMap).forEach(([key, el]) => {
                        if (el) el.classList.toggle('hidden', key !== this._activeNavTab);
                    });

                    if (searchWrapper) {
                        searchWrapper.style.display = this._activeNavTab === 'headings' ? '' : 'none';
                    }

                    if (this._activeNavTab === 'pages') {
                        this.updatePageThumbnails();
                    }
                });
            });
        };

        bindTabs('.outline-sidebar .nav-pane-tab', {
            headings: document.getElementById('outline-content'),
            pages: document.getElementById('pages-content'),
            results: document.getElementById('results-content')
        }, document.querySelector('.outline-search-wrapper'));

        bindTabs('.mobile-sheet .nav-pane-tab', {
            headings: document.getElementById('mob-outline-content'),
            pages: document.getElementById('mob-pages-content'),
            results: document.getElementById('mob-results-content')
        }, null);
    }

    updatePageThumbnails() {
        const container = document.getElementById('pages-content');
        if (!container) return;

        const pages = document.querySelectorAll('#workspace .page');
        const buildHtml = () => {
            if (pages.length === 0) {
                return '<div class="results-empty">No pages yet</div>';
            }
            let html = '';
            pages.forEach((page, i) => {
                html += `<div class="page-thumbnail" data-page-num="${i + 1}"><div class="page-thumbnail-preview"></div><div class="page-thumbnail-label">Page ${i + 1}</div></div>`;
            });
            return html;
        };

        container.innerHTML = buildHtml();
        const bindEvents = (cont) => {
            cont.querySelectorAll('.page-thumbnail').forEach(thumbnail => {
                thumbnail.addEventListener('click', () => {
                    const pageNum = parseInt(thumbnail.dataset.pageNum, 10);
                    const page = document.querySelectorAll('#workspace .page')[pageNum - 1];
                    if (page) {
                        page.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    }
                    cont.querySelectorAll('.page-thumbnail').forEach(t => t.classList.remove('active'));
                    thumbnail.classList.add('active');
                });
            });
        };
        bindEvents(container);

        const mobPagesContainer = document.getElementById('mob-pages-content');
        if (mobPagesContainer) {
            mobPagesContainer.innerHTML = buildHtml();
            bindEvents(mobPagesContainer);
        }
    }

    updateSearchResults(matches) {
        const container = document.getElementById('results-content');
        if (!container) return;

        container.innerHTML = '';

        if (!matches || matches.length === 0) {
            container.innerHTML = '<div class="results-empty">0 results</div>';
            return;
        }

        matches.forEach((match, i) => {
            const item = document.createElement('div');
            item.className = 'result-item';
            item.innerHTML = `
                <div class="result-item-text">${match.text || 'Match ' + (i + 1)}</div>
                <div class="result-item-context">
                    <span>Block ${match.blockIndex + 1}</span>
                    <span>${match.context || ''}</span>
                </div>
            `;
            item.addEventListener('click', () => {
                const el = document.querySelector(`[data-index="${match.blockIndex}"]`);
                if (el) {
                    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    this.ctrl.focusBlock(match.blockIndex, 'start');
                }
            });
            container.appendChild(item);
        });
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/paste-handler.js
// ================================================================
import { Formatter } from './formatter.js';

export class PasteHandler {
    constructor(ctrl) {
        this.ctrl = ctrl;
        this.state = ctrl.state;
    }

    setup() {
        const ctrl = this.ctrl;
        document.addEventListener('paste', (e) => {
            if (e.defaultPrevented) return;
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

            ctrl._pasteSeq++;
            e.preventDefault();

            const html = e.clipboardData.getData('text/html');
            const text = e.clipboardData.getData('text/plain');

            if (this.tryPasteUrlOverSelection(text)) return;
            if (this.tryPasteIntoTable(html, text)) return;
            if (this.tryPasteIntoList(html, text)) return;
            this.pasteAsBlocks(html, text);
        });
    }

    tryPasteUrlOverSelection(text) {
        const raw = String(text || '').trim();
        if (!raw || /\s/.test(raw)) return false;

        let url;
        try {
            url = new URL(raw.match(/^https?:\/\//i) ? raw : `https://${raw}`);
            if (!['http:', 'https:'].includes(url.protocol)) return false;
        } catch (error) {
            return false;
        }

        const selection = window.getSelection();
        if (!selection || !selection.rangeCount || selection.isCollapsed || !selection.toString().trim()) return false;
        const range = selection.getRangeAt(0);
        const startBlock = this.ctrl.resolveBlockElementFromNode(range.startContainer);
        const endBlock = this.ctrl.resolveBlockElementFromNode(range.endContainer);
        if (!startBlock || startBlock !== endBlock) return false;

        const anchor = document.createElement('a');
        anchor.href = url.href;
        anchor.target = '_blank';
        anchor.rel = 'noopener noreferrer';
        anchor.appendChild(range.extractContents());
        range.insertNode(anchor);
        range.setStartAfter(anchor);
        range.collapse(true);
        selection.removeAllRanges();
        selection.addRange(range);

        const editable = anchor.closest('[contenteditable="true"]') || startBlock;
        const inputEvent = typeof InputEvent === 'function'
            ? new InputEvent('input', { bubbles: true, inputType: 'insertFromPaste' })
            : new Event('input', { bubbles: true });
        editable.dispatchEvent(inputEvent);
        setTimeout(() => this.ctrl.syncCurrentTextBlockFromDom(), 0);
        return true;
    }

    tryPasteIntoTable(html, text) {
        const sel = window.getSelection();
        if (!sel || !sel.rangeCount) return false;
        let n = sel.anchorNode;
        if (n && n.nodeType === 3) n = n.parentElement;
        const td = n?.closest?.('td');
        if (!td) return false;

        const content = html || Formatter.escapeHtml(text);
        document.execCommand('insertHTML', false, content);
        setTimeout(() => this.ctrl.syncCurrentTextBlockFromDom(), 0);
        return true;
    }

    tryPasteIntoList(html, text) {
        const sel = window.getSelection();
        if (!sel || !sel.rangeCount) return false;
        let n = sel.anchorNode;
        if (n && n.nodeType === 3) n = n.parentElement;
        const li = n?.closest?.('li');
        if (!li) return false;

        const listEl = li.closest('ul, ol');
        if (!listEl) return false;
        const blockIndex = parseInt(listEl.dataset.index);
        if (!Number.isInteger(blockIndex)) return false;

        const block = this.state.doc.blocks[blockIndex];
        if (!block || !['ul', 'ol', 'checklist'].includes(block.type)) return false;

        const iIdx = parseInt(li.dataset.idx);
        const rawText = block.items[iIdx]?.text || '';

        const pastedLines = (text || html?.replace(/<[^>]*>/g, '') || '')
            .replace(/\r\n?/g, '\n')
            .split('\n')
            .map(l => l.trim())
            .filter(l => l.length > 0);

        if (pastedLines.length === 0) return false;

        document.execCommand('insertText', false, pastedLines[0]);
        const editable = block.type === 'checklist' ? li.querySelector('.checklist-text') : li;
        const nextHtml = editable ? editable.innerHTML : li.innerHTML;
        this.state.updateListItem(blockIndex, iIdx, nextHtml);
        return true;
    }

    pasteAsBlocks(html, text) {
        const ctrl = this.ctrl;
        let parsedBlocks = [];
        let parsedSource = null;

        if (html) {
            parsedBlocks = Formatter.parseHTMLToBlocks(html);
            if (parsedBlocks.length > 0) parsedSource = 'html';
        }

        if (parsedBlocks.length === 0 && text) {
            const lines = text.replace(/\r\n?/g, '\n').split('\n');
            parsedBlocks = lines.map((line) => ({
                type: 'text',
                style: 'normal',
                content: Formatter.plainTextToHtml(line),
                preserveWhitespace: true,
                id: Date.now() + Math.random()
            }));
            parsedSource = 'text';
        }

        const cleanBlocks = parsedBlocks.filter((b) => {
            if (b.type !== 'text') return true;
            if (b.preserveWhitespace) return true;
            return !Formatter.isMeaningfullyEmptyHtml(b.content);
        });

        if (cleanBlocks.length === 0) return;

        if (cleanBlocks.length === 1 && cleanBlocks[0].type === 'text') {
            const content = parsedSource === 'html' ? cleanBlocks[0].content : text.replace(/\r\n?/g, '\n');
            const sel = window.getSelection();
            if (sel.rangeCount) {
                const range = sel.getRangeAt(0);
                if (!range.collapsed) range.deleteContents();
                const fragment = range.createContextualFragment(content);
                range.insertNode(fragment);
                range.collapse(false);
                sel.removeAllRanges();
                sel.addRange(range);
            } else {
                document.execCommand('insertHTML', false, content);
            }
            setTimeout(() => ctrl.syncCurrentTextBlockFromDom(), 0);
            return;
        }

        const sel = window.getSelection();
        let idx = ctrl.activeBlockIndex;
        if (idx === null || !sel.rangeCount) {
            idx = this.state.doc.blocks.length - 1;
            if (idx < 0) idx = 0;
        }

        cleanBlocks.forEach((b, i) => this.state.insertBlockAt(idx + 1 + i, b));
        this.state.notify();

        setTimeout(() => {
            const focusIdx = idx + cleanBlocks.length;
            ctrl.focusBlock(focusIdx, 'end');
        }, 50);
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/renderer.js
// ================================================================
import { Formatter } from './formatter.js';
import { ensureBlockIdentity } from './editor/id.js';
import { isObjectBlock, isFlowObject, objectTextHtml } from './editor/objects/object-model.js';

/**
 * =========================================================
 * CLASS: Renderer (View Layer)
 * =========================================================
 */
export class Renderer {
    constructor(containerId, stateManager) {
        this.container = document.getElementById(containerId);
        this.sm = stateManager;
        this.rulerBar = document.getElementById('ruler-bar');
        this.isPageView = true;
        this.zoom = 1.0;
        this.highlightMatches = [];
        this.currentMatchIndex = -1;

        if (typeof window.DEBUG_PAGINATION === 'undefined') window.DEBUG_PAGINATION = true;

        this._renderSeq = 0;
        this._lastPaginateSeq = 0;
        this._deferredRenderTimer = null;
        this._dragDropSetup = false;
    }

    dlog(...args) {
        if (!window.DEBUG_PAGINATION) return;
        console.log(...args);
    }

    fmtRect(r) {
        return {
            top: Math.round(r.top),
            bottom: Math.round(r.bottom),
            height: Math.round(r.height)
        };
    }

    getPageMetrics(doc) {
        const pageSize = (doc && doc.settings && doc.settings.pageSize) || 'letter';
        if (pageSize === 'a4') {
            return { widthIn: 8.27, heightIn: 11.69 };
        }
        return { widthIn: 8.5, heightIn: 11 };
    }

    setMode(isPageView) {
        this.isPageView = isPageView;
        this.render(this.sm.doc, this.sm.hfMode);
        try { localStorage.setItem('opendoc_viewMode', JSON.stringify(isPageView ? 'page' : 'pageless')); } catch (e) {}
    }

    setZoom(z) {
        this.zoom = z;
        document.getElementById('zoom-display').innerText = Math.round(z * 100) + '%';
        this.container.style.transform = `scale(${z})`;
        this.container.style.transformOrigin = 'top center';
        const slider = document.getElementById('zoom-slider');
        if (slider) {
            const pct = Math.round(z * 100);
            if (Math.abs(parseInt(slider.value) - pct) > 1) slider.value = pct;
        }
        try { localStorage.setItem('opendoc_zoom', JSON.stringify(z)); } catch (e) {}
    }

    highlightText(html, blockIndex) {
        if (!this.highlightMatches.length) return html;

        let newHtml = html;
        this.highlightMatches.forEach((m, i) => {
            if (m.blockIndex === blockIndex) {
                const safeText = m.text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const regex = new RegExp(`(${safeText})`, 'gi');
                newHtml = newHtml.replace(
                    regex,
                    `<span class="find-highlight ${i === this.currentMatchIndex ? 'active' : ''}">$1</span>`
                );
            }
        });
        return newHtml;
    }

    isBlockCurrentlySplit(index) {
        const els = Array.from(document.querySelectorAll(`[data-index="${index}"]`));
        return els.filter((el) => el.classList && el.classList.contains('block-text')).length > 1;
    }

    canKeepTypingRenderInPlace(index, renderedParts, textParts) {
        if (!renderedParts.length || !textParts.length) return false;

        let activePart = null;
        const active = document.activeElement;
        textParts.forEach((part) => {
            if (active === part || (active && active.closest && active.closest(`[data-index="${index}"]`) === part)) {
                activePart = part;
            }
        });
        if (!activePart) return false;

        const pageAreas = new Set();
        textParts.forEach((part) => {
            const area = part.closest('.page-content-area');
            if (area) pageAreas.add(area);
        });

        if (!pageAreas.size) return false;

        for (const area of pageAreas) {
            if (this.checkOverflow(area)) return false;
        }

        return true;
    }

    scheduleDeferredPagination() {
        if (this._deferredRenderTimer) clearTimeout(this._deferredRenderTimer);
        this._deferredRenderTimer = setTimeout(() => {
            this._deferredRenderTimer = null;
            document.dispatchEvent(new CustomEvent('opendoc:deferred-pagination'));
        }, 450);
    }

    shiftRenderedIndexes(startIndex, delta) {
        const indexed = Array.from(document.querySelectorAll('[data-index]'))
            .map((el) => ({ el, index: parseInt(el.dataset.index) }))
            .filter((item) => Number.isInteger(item.index) && item.index >= startIndex)
            .sort((a, b) => delta > 0 ? b.index - a.index : a.index - b.index);

        indexed.forEach(({ el, index }) => {
            el.dataset.index = String(index + delta);
        });
    }

    getLastRenderedBlockElement(index) {
        const els = Array.from(document.querySelectorAll(`[data-index="${index}"]`));
        return els.length ? els[els.length - 1] : null;
    }

    tryRenderEnterInPlace(op) {
        if (!this.isPageView || !op || op.source !== 'enter' || this.highlightMatches.length) return false;

        if (op.type === 'ADD_BLOCK' && op.block && op.block.type === 'text') {
            const prevEl = this.getLastRenderedBlockElement(op.index - 1);
            const nextEl = document.querySelector(`[data-index="${op.index}"]`);
            const anchor = prevEl || nextEl;
            const pageArea = anchor && anchor.closest ? anchor.closest('.page-content-area') : null;
            if (!pageArea) return false;

            this.shiftRenderedIndexes(op.index, 1);

            const newEl = this.createTextBlockElement(op.block, op.index, op.block.content || '<br>', null);
            if (prevEl && prevEl.parentNode) prevEl.parentNode.insertBefore(newEl, prevEl.nextSibling);
            else if (nextEl && nextEl.parentNode) nextEl.parentNode.insertBefore(newEl, nextEl);
            else pageArea.appendChild(newEl);

            this.scheduleDeferredPagination();
            return false;
        }

        if (op.type === 'SPLIT_BLOCK' && op.splitAtStart && op.block && op.block.type === 'text') {
            const firstOldEl = document.querySelector(`[data-index="${op.index}"]`);
            if (!firstOldEl || !firstOldEl.parentNode) return false;

            this.shiftRenderedIndexes(op.index, 1);

            const newEl = this.createTextBlockElement(op.block, op.index, op.block.content || '<br>', null);
            firstOldEl.parentNode.insertBefore(newEl, firstOldEl);

            this.scheduleDeferredPagination();
            return false;
        }

        if (op.type === 'SPLIT_BLOCK' && op.block && op.newBlock && op.block.type === 'text' && op.newBlock.type === 'text') {
            const textParts = Array.from(document.querySelectorAll(`[data-index="${op.index}"].block-text`));
            if (textParts.length !== 1) return true;

            const currentEl = textParts[0];
            if (!currentEl || !currentEl.parentNode) return true;

            currentEl.innerHTML = this.highlightText(op.block.content || '<br>', op.index) || '<br>';
            this.ensureCaretPlaceholder(currentEl);

            this.shiftRenderedIndexes(op.index + 1, 1);

            const newEl = this.createTextBlockElement(op.newBlock, op.index + 1, op.newBlock.content || '<br>', null);
            currentEl.parentNode.insertBefore(newEl, currentEl.nextSibling);

            this.scheduleDeferredPagination();
            return false;
        }

        return true;
    }

    render(doc, hfMode, op) {
        this._renderSeq++;

        if (op && op.source === 'enter') {
            const enterResult = this.tryRenderEnterInPlace(op);
            if (enterResult === false) return false;
        }

        if (op && op.type === 'UPDATE_BLOCK' && op.source === 'typing' && this.isPageView) {
            const renderedParts = Array.from(document.querySelectorAll(`[data-index="${op.index}"]`));
            const textParts = renderedParts.filter((el) => el.classList && el.classList.contains('block-text'));
            const blockIsSplit = textParts.length > 1;

            if (blockIsSplit && this.canKeepTypingRenderInPlace(op.index, renderedParts, textParts)) {
                return false;
            }

            if (!blockIsSplit && renderedParts.length) {
                let el = null;
                renderedParts.forEach((x) => {
                    if (document.activeElement === x || (document.activeElement && document.activeElement.closest && document.activeElement.closest(`[data-index="${op.index}"]`) === x)) {
                        el = x;
                    }
                });
                if (!el) el = renderedParts[renderedParts.length - 1];

                const pageContent = el.closest('.page-content-area');
                if (pageContent) {
                    const fits = !this.checkOverflow(pageContent);
                    const isActive = (document.activeElement === el || (document.activeElement && document.activeElement.closest && document.activeElement.closest(`[data-index="${op.index}"]`) === el));

                    if (fits && isActive) {
                        return false;
                    }
                }
            }
        }

        const wrapper = document.getElementById('workspace-wrapper');
        const prevScroll = wrapper ? wrapper.scrollTop : 0;

        document.body.className = hfMode ? 'hf-edit-mode' : '';
        document.getElementById('hf-controls').style.display = hfMode ? 'block' : 'none';

        const metrics = this.getPageMetrics(doc);
        const r = document.querySelector(':root');
        r.style.setProperty('--page-width', `${metrics.widthIn}in`);
        r.style.setProperty('--page-height', `${metrics.heightIn}in`);
        r.style.setProperty('--page-margin-left', `${doc.settings.margins.left}in`);
        r.style.setProperty('--page-margin-right', `${doc.settings.margins.right}in`);
        r.style.setProperty('--page-margin-top', `${doc.settings.margins.top}in`);
        r.style.setProperty('--page-margin-bottom', `${doc.settings.margins.bottom}in`);

        this.updateRuler(doc.settings.margins, metrics.widthIn);

        this.container.className = this.isPageView ? 'mode-page' : 'mode-pageless';
        this.container.innerHTML = '';

        if (this.isPageView) this.renderPaginated(doc, hfMode);
        else this.renderContinuous(doc);

        if (wrapper) wrapper.scrollTop = prevScroll;

        if (!this._dragDropSetup) {
            this._dragDropSetup = true;
            this.setupBlockDragDrop();
        }

        if (this.isPageView) {
            const pages = this.container.querySelectorAll('.page');
            pages.forEach((page, pi) => {
                this.renderFootnotesOnPage(page, pi);
            });
            this.renderEndnotesAtEnd();
        } else {
            this.renderEndnotesAtEnd();
        }

        const pageCountEl = document.getElementById('page-count');
        if (pageCountEl && this.isPageView) {
            const pages = this.container.querySelectorAll('.page');
            pageCountEl.innerText = `Page 1 of ${pages.length}`;
        } else if (pageCountEl) {
            pageCountEl.innerText = 'Continuous';
        }

        return true;
    }

    updateRuler(margins, pageWidthInches = 8.5) {
        const leftM = document.getElementById('marker-margin-left');
        const rightM = document.getElementById('marker-margin-right');
        const width = this.rulerBar.clientWidth || (pageWidthInches * 96);
        const pxPerIn = width / pageWidthInches;

        leftM.style.left = `${margins.left * pxPerIn}px`;
        rightM.style.right = `${margins.right * pxPerIn}px`;
        this.pxPerIn = pxPerIn;
    }

    renderContinuous(doc) {
        const page = document.createElement('div');
        page.className = 'mode-pageless';

        doc.blocks.forEach((block, index) => {
            if (block.type === 'pageBreak') {
                page.appendChild(this.createPageBreakVisual());
                return;
            }
            if (block.type === 'floating' || (isObjectBlock(block) && !isFlowObject(block))) {
                page.appendChild(block.type === 'floating' ? this.createFloating(block, index, 0) : this.createObjectBlock(block, index, { floating: true, pageIndex: 0 }));
                return;
            }
            page.appendChild(this.createBlock(block, index));
        });

        const footnotes = this.sm.getFootnotes();
        if (footnotes.length) {
            const fnDiv = document.createElement('div');
            fnDiv.className = 'endnotes-section';
            fnDiv.innerHTML = '<h2 class="endnotes-title">Footnotes</h2>';
            footnotes.forEach(fn => {
                const item = document.createElement('div');
                item.className = 'endnote-item';
                const num = document.createElement('sup');
                num.className = 'endnote-num';
                num.textContent = fn.number;
                const content = document.createElement('span');
                content.className = 'endnote-content';
                content.innerHTML = fn.content || '';
                item.appendChild(num);
                item.appendChild(content);
                fnDiv.appendChild(item);
            });
            page.appendChild(fnDiv);
        }

        const endnotes = this.sm.getEndnotes();
        if (endnotes.length) {
            const enDiv = document.createElement('div');
            enDiv.className = 'endnotes-section';
            enDiv.innerHTML = '<h2 class="endnotes-title">Endnotes</h2>';
            endnotes.forEach(en => {
                const item = document.createElement('div');
                item.className = 'endnote-item';
                const num = document.createElement('sup');
                num.className = 'endnote-num';
                num.textContent = en.number;
                const content = document.createElement('span');
                content.className = 'endnote-content';
                content.innerHTML = en.content || '';
                item.appendChild(num);
                item.appendChild(content);
                enDiv.appendChild(item);
            });
            page.appendChild(enDiv);
        }

        this.container.appendChild(page);
    }

    resolveParagraphRule(block, name, fallback = false) {
        if (!block) return fallback;
        if (block[name] !== undefined) return block[name];
        const style = this.sm.doc.styles?.[block.style || 'normal'];
        return style?.[name] !== undefined ? style[name] : fallback;
    }

    shouldKeepWithNext(block) {
        return block?.type === 'text' && !!this.resolveParagraphRule(block, 'keepWithNext', false);
    }

    shouldKeepLines(block) {
        return block?.type === 'text' && !!this.resolveParagraphRule(block, 'keepLinesTogether', block.keepLinesTogether || false);
    }

    canPairFit(page, block, index, nextBlock, nextIndex) {
        if (!page?.contentArea || !nextBlock || nextBlock.type === 'pageBreak' || nextBlock.type === 'sectionBreak') return true;
        const currentEl = this.createBlock(block, index);
        const nextEl = this.createBlock(nextBlock, nextIndex);
        currentEl.dataset.keepProbe = '1'; nextEl.dataset.keepProbe = '1';
        page.contentArea.appendChild(currentEl); page.contentArea.appendChild(nextEl);
        const fits = !this.checkOverflow(page.contentArea);
        currentEl.remove(); nextEl.remove();
        return fits;
    }

    flowTableAcrossPages(block, index, startPage, addPageFn) {
        let page = startPage;
        const rows = block.rows || [];
        const headerCount = Math.max(0, Number(block.headerRows || 0));
        let cursor = 0;
        while (cursor < rows.length) {
            const includedIndexes = [];
            if (cursor > 0) for (let h = 0; h < Math.min(headerCount, rows.length); h += 1) includedIndexes.push(h);
            const startCursor = cursor;
            let accepted = false;
            while (cursor < rows.length) {
                includedIndexes.push(cursor);
                const partial = {
                    ...block,
                    id: block.id,
                    rows: includedIndexes.map(rowIndex => block.rows[rowIndex]),
                    rowIds: includedIndexes.map(rowIndex => block.rowIds?.[rowIndex]),
                    cellIds: includedIndexes.map(rowIndex => block.cellIds?.[rowIndex]),
                    headerRows: cursor > 0 ? headerCount : Math.min(headerCount, includedIndexes.length)
                };
                const table = this.createTable(partial, index);
                table.dataset.tableFragmentStart = String(startCursor);
                page.contentArea.appendChild(table);
                if (this.checkOverflow(page.contentArea)) {
                    table.remove(); includedIndexes.pop();
                    if (!accepted && page.contentArea.children.length > 0) { page = addPageFn(); continue; }
                    if (!accepted) {
                        const forced = this.createTable({ ...partial, rows: [block.rows[cursor]], rowIds: [block.rowIds?.[cursor]], cellIds: [block.cellIds?.[cursor]], headerRows: 0 }, index);
                        page.contentArea.appendChild(forced); cursor += 1; accepted = true;
                    }
                    break;
                }
                table.remove();
                cursor += 1; accepted = true;
            }
            if (includedIndexes.length) {
                const fragment = {
                    ...block,
                    id: block.id,
                    rows: includedIndexes.map(rowIndex => block.rows[rowIndex]),
                    rowIds: includedIndexes.map(rowIndex => block.rowIds?.[rowIndex]),
                    cellIds: includedIndexes.map(rowIndex => block.cellIds?.[rowIndex]),
                    headerRows: startCursor > 0 ? headerCount : Math.min(headerCount, includedIndexes.length)
                };
                const table = this.createTable(fragment, index);
                table.dataset.tableFragmentStart = String(startCursor);
                page.contentArea.appendChild(table);
            }
            if (cursor < rows.length) page = addPageFn();
        }
        return page;
    }

    resolveObjectCollisions(page) {
        const objects = [...page.querySelectorAll('.page-front-objects > .object-host, .page-behind-text-objects > .object-host')]
            .sort((a, b) => Number(a.style.zIndex || 0) - Number(b.style.zIndex || 0));
        for (let i = 0; i < objects.length; i += 1) {
            const current = objects[i];
            const block = this.sm.getBlockById(current.dataset.blockId);
            if (block?.layout?.allowOverlap !== false) continue;
            for (let j = 0; j < i; j += 1) {
                const other = objects[j];
                const a = current.getBoundingClientRect(), b = other.getBoundingClientRect();
                if (a.right > b.left && a.left < b.right && a.bottom > b.top && a.top < b.bottom) {
                    const shift = b.bottom - a.top + 8;
                    current.style.top = `${Number.parseFloat(current.style.top || 0) + shift}px`;
                }
            }
        }
    }

    renderPaginated(doc, hfMode) {
        this._lastPaginateSeq++;
        let pageNum = 1;
        const pages = [];
        const maxPages = 200;
        const initialBatch = 20;

        const addPage = () => {
            if (pages.length >= maxPages) {
                throw new Error(`Pagination aborted: exceeded ${maxPages} pages.`);
            }
            pageNum++;
            const p = this.createPage(pageNum, doc, hfMode);
            this.container.appendChild(p);
            pages.push(p);
            return p;
        };

        let currentPage = this.createPage(pageNum, doc, hfMode);
        this.container.appendChild(currentPage);
        pages.push(currentPage);

        const flowBlock = (block, index) => {
            if (block.type === 'pageBreak') {
                if (!hfMode) {
                    currentPage.contentArea.appendChild(this.createPageBreakVisual());
                    currentPage = addPage();
                }
                return;
            }

            if (block.type === 'text') {
                currentPage = this.flowTextBlockAcrossPages(block, index, currentPage, addPage);
                return;
            }
            if (block.type === 'table') {
                currentPage = this.flowTableAcrossPages(block, index, currentPage, addPage);
                return;
            }

            const el = this.createBlock(block, index);
            currentPage.contentArea.appendChild(el);

            if (!this.checkOverflow(currentPage.contentArea)) {
                return;
            }

            currentPage.contentArea.removeChild(el);
            currentPage = addPage();
            currentPage.contentArea.appendChild(el);
        };

        const flowFloating = (block, index) => {
            if (block.type !== 'floating' && !(isObjectBlock(block) && !isFlowObject(block))) return;
            let targetPageIdx = Number(block.pageIndex ?? block.legacy?.pageIndex ?? 0);
            const anchorBlockId = block.anchor?.blockId;
            if (anchorBlockId) {
                const anchorElement = this.container.querySelector(`[data-block-id="${CSS.escape(anchorBlockId)}"]`);
                const anchorPage = anchorElement?.closest('.page');
                if (anchorPage) targetPageIdx = Math.max(0, Number(anchorPage.dataset.pageNum || 1) - 1);
            }
            const safeIdx = Math.max(0, Math.min(targetPageIdx, pages.length - 1));
            const targetPage = pages[safeIdx];
            if (targetPage) {
                const element = block.type === 'floating' ? this.createFloating(block, index, safeIdx) : this.createObjectBlock(block, index, { floating: true, pageIndex: safeIdx });
                const wrapType = block.wrap?.type || 'inFrontOfText';
                const layer = wrapType === 'behindText' ? targetPage.behindLayer : targetPage.frontLayer;
                (layer || targetPage).appendChild(element);
            }
        };

        // Synchronous: render initial flow content and page-layer objects.
        const nonFloating = doc.blocks.filter(block => block.type !== 'floating' && !(isObjectBlock(block) && !isFlowObject(block)));
        const floating = doc.blocks.filter(block => block.type === 'floating' || (isObjectBlock(block) && !isFlowObject(block)));

        const flowAt = i => {
            const block = nonFloating[i];
            const docIndex = doc.blocks.indexOf(block);
            const next = nonFloating[i + 1];
            if (this.shouldKeepWithNext(block) && next && currentPage.contentArea.children.length && !this.canPairFit(currentPage, block, docIndex, next, doc.blocks.indexOf(next))) currentPage = addPage();
            flowBlock(block, docIndex);
        };
        for (let i = 0; i < Math.min(nonFloating.length, initialBatch); i++) flowAt(i);
        floating.forEach(block => flowFloating(block, doc.blocks.indexOf(block)));
        pages.forEach(page => this.resolveObjectCollisions(page));

        // Deferred: render remaining blocks in rAF batches.
        if (nonFloating.length > initialBatch) {
            let deferredIdx = initialBatch;
            const renderNextBatch = () => {
                const batchEnd = Math.min(deferredIdx + 10, nonFloating.length);
                for (; deferredIdx < batchEnd; deferredIdx++) flowAt(deferredIdx);
                if (deferredIdx < nonFloating.length) requestAnimationFrame(renderNextBatch);
                else { floating.forEach(block => flowFloating(block, doc.blocks.indexOf(block))); pages.forEach(page => this.resolveObjectCollisions(page)); }
            };
            requestAnimationFrame(renderNextBatch);
        }
    }

    checkOverflow(container) {
        if (!container) return false;

        const ch = container.clientHeight;
        if (!ch || ch < 10) return false;

        const sh = container.scrollHeight;
        if ((sh - ch) > 1) return true;

        const containerRect = container.getBoundingClientRect();
        const children = Array.from(container.children);

        for (const child of children) {
            if (!child || child.classList.contains('floating-box')) continue;
            const rect = child.getBoundingClientRect();
            if ((rect.bottom - containerRect.top) - containerRect.height > 1) {
                return true;
            }
        }

        return false;
    }

    getCleanEditableHtml(el) {
        if (!el) return '';

        const clone = el.cloneNode(true);

        const highlights = clone.querySelectorAll('.find-highlight');
        highlights.forEach((h) => {
            const txt = document.createTextNode(h.textContent || '');
            h.parentNode.replaceChild(txt, h);
        });

        // Footnote/endnote anchors are generated from document metadata and must
        // never be serialized back into the paragraph HTML.
        clone.querySelectorAll('.footnote-anchor, .endnote-anchor').forEach((anchor) => anchor.remove());

        const html = clone.innerHTML || '';

        const normalized = Formatter.normalizeTextBlockHtml(html, { emptyAsBr: false });

        if (Formatter.isMeaningfullyEmptyHtml(normalized)) {
            return '';
        }

        if (/^(\s*<br\s*\/?>\s*)+$/i.test(normalized)) return '';

        return normalized;
    }

    ensureCaretPlaceholder(el) {
        if (!el) return;
        const html = (el.innerHTML || '').trim();
        const isEmpty = (typeof Formatter !== 'undefined' && Formatter.isMeaningfullyEmptyHtml(html)) || /^(\s*<br\s*\/?>\s*)+$/i.test(html) || html === '';
        if (isEmpty) {
            el.innerHTML = '&#8203;';
            return;
        }

        if (!/[\u200B-\u200D\uFEFF]/.test(el.textContent || '')) return;

        const sel = window.getSelection();
        const hasLocalSelection = !!(sel && sel.rangeCount && (el.contains(sel.anchorNode) || sel.anchorNode === el));
        const offset = hasLocalSelection && typeof Formatter !== 'undefined'
            ? Formatter.getTextOffsetFromDomPosition(el, sel.anchorNode, sel.anchorOffset)
            : null;

        const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
        const textNodes = [];
        while (walker.nextNode()) textNodes.push(walker.currentNode);
        textNodes.forEach((node) => {
            node.nodeValue = (node.nodeValue || '').replace(/[\u200B-\u200D\uFEFF]/g, '');
        });

        if (hasLocalSelection && offset !== null && typeof Formatter !== 'undefined') {
            const pos = Formatter.resolveDomPositionFromTextOffset(el, offset);
            if (pos && pos.container) {
                const range = document.createRange();
                range.setStart(pos.container, pos.offset);
                range.collapse(true);
                sel.removeAllRanges();
                sel.addRange(range);
            }
        }
    }

    isMeaningfullyEmptyHtml(html) {
        return Formatter.isMeaningfullyEmptyHtml(html);
    }

    getTextLengthFromHtmlSafe(html) {
        return Formatter.getTextLengthFromHtml(html);
    }

    safeSplitHtmlByTextOffset(html, offset) {
        try {
            return Formatter.splitHtmlByTextOffset(html, offset);
        } catch (err) {
            console.warn('splitHtmlByTextOffset failed:', err);
        }
        return { a: html, b: '' };
    }

    getCandidateSplitOffsetsFromHtml(html) {
        const host = document.createElement('div');
        host.innerHTML = html || '';

        const totalLen = this.getTextLengthFromHtmlSafe(html);
        if (totalLen <= 1) return [];

        const offsets = new Set();
        let count = 0;

        const walk = (node) => {
            if (!node) return;

            if (node.nodeType === Node.TEXT_NODE) {
                const text = node.nodeValue || '';
                for (let i = 0; i < text.length; i++) {
                    const ch = text[i];
                    if (/\s/.test(ch) || /[.,;:!?)}\]]/.test(ch)) {
                        offsets.add(count + i + 1);
                    }
                }
                count += text.length;
                return;
            }

            if (node.nodeType !== Node.ELEMENT_NODE) return;

            const tag = node.tagName.toLowerCase();
            if (tag === 'br') {
                count += 1;
                offsets.add(count);
                return;
            }

            Array.from(node.childNodes).forEach((child) => walk(child));
        };

        Array.from(host.childNodes).forEach((child) => walk(child));

        return Array.from(offsets)
            .filter((v) => v > 0 && v < totalLen)
            .sort((a, b) => a - b);
    }

    getPreferredSplitOffset(html, measuredBest) {
        if (!measuredBest || measuredBest < 1) return measuredBest;

        const totalLen = this.getTextLengthFromHtmlSafe(html);
        if (measuredBest >= totalLen) return measuredBest;

        const minAllowed = Math.max(1, Math.floor(measuredBest * 0.6));
        const candidates = this.getCandidateSplitOffsetsFromHtml(html);

        let chosen = 0;
        for (const candidate of candidates) {
            if (candidate <= measuredBest && candidate >= minAllowed) {
                chosen = candidate;
            }
        }
        if (chosen > 0) return chosen;

        const plainText = Formatter.getPlainTextFromHtml(html);

        for (let i = measuredBest; i >= minAllowed; i--) {
            const prev = plainText[i - 1] || '';
            if (/\s/.test(prev) || /[.,;:!?)}\]]/.test(prev)) {
                return i;
            }
        }

        return measuredBest;
    }

    findBestFittingOffset(tester, remainingHtml, index, totalLen) {
        let low = 1;
        let high = totalLen;
        let best = 0;

        while (low <= high) {
            const mid = Math.floor((low + high) / 2);
            const probe = this.safeSplitHtmlByTextOffset(remainingHtml, mid);

            tester.innerHTML = this.highlightText(probe.a, index) || '';
            this.ensureCaretPlaceholder(tester);

            if (!this.checkOverflow(tester.parentElement)) {
                best = mid;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }

        return best;
    }

    flowTextBlockAcrossPages(block, index, startPage, addPageFn) {
        let currentPage = startPage;
        let remainingHtml = Formatter.normalizeTextBlockHtml(block.content || '', { emptyAsBr: true });
        let partIndex = 0;
        let safety = 0;

        if (this.isMeaningfullyEmptyHtml(remainingHtml)) remainingHtml = '<br>';

        if (this.shouldKeepLines(block)) {
            const whole = this.createTextBlockElement(block, index, remainingHtml, 0);
            currentPage.contentArea.appendChild(whole);
            if (this.checkOverflow(currentPage.contentArea) && currentPage.contentArea.children.length > 1) {
                whole.remove(); currentPage = addPageFn(); currentPage.contentArea.appendChild(whole);
            }
            if (!this.checkOverflow(currentPage.contentArea)) return currentPage;
            whole.remove();
        }

        if (/^(\s*<br\s*\/?>\s*)+$/i.test(remainingHtml)) {
            const emptyEl = this.createTextBlockElement(block, index, '<br>', 0);
            this.ensureCaretPlaceholder(emptyEl);
            currentPage.contentArea.appendChild(emptyEl);

            if (this.checkOverflow(currentPage.contentArea)) {
                currentPage.contentArea.removeChild(emptyEl);
                currentPage = addPageFn();
                currentPage.contentArea.appendChild(emptyEl);
            }

            return currentPage;
        }

        while (!this.isMeaningfullyEmptyHtml(remainingHtml)) {
            safety++;
            if (safety > 500) {
                const fallbackEl = this.createTextBlockElement(block, index, remainingHtml, partIndex);
                this.ensureCaretPlaceholder(fallbackEl);
                currentPage.contentArea.appendChild(fallbackEl);
                return currentPage;
            }

            const tester = this.createTextBlockElement(block, index, '', partIndex);
            tester.dataset.splitTester = '1';
            currentPage.contentArea.appendChild(tester);

            tester.innerHTML = this.highlightText(remainingHtml, index) || '';
            this.ensureCaretPlaceholder(tester);

            if (!this.checkOverflow(currentPage.contentArea)) {
                tester.dataset.splitPart = String(partIndex);
                delete tester.dataset.splitTester;
                return currentPage;
            }

            const hadOtherContent = currentPage.contentArea.children.length > 1;
            const totalLen = this.getTextLengthFromHtmlSafe(remainingHtml);

            if (totalLen < 2) {
                if (hadOtherContent) {
                    currentPage.contentArea.removeChild(tester);
                    currentPage = addPageFn();
                    continue;
                }
                tester.dataset.splitPart = String(partIndex);
                delete tester.dataset.splitTester;
                return currentPage;
            }

            let best = this.findBestFittingOffset(tester, remainingHtml, index, totalLen);

            if (best <= 0) {
                currentPage.contentArea.removeChild(tester);
                if (hadOtherContent) {
                    currentPage = addPageFn();
                    continue;
                }

                const fallbackEl = this.createTextBlockElement(block, index, remainingHtml, partIndex);
                this.ensureCaretPlaceholder(fallbackEl);
                currentPage.contentArea.appendChild(fallbackEl);
                return currentPage;
            }

            let preferred = this.getPreferredSplitOffset(remainingHtml, best);
            const orphanLines = Math.max(1, Number(block.orphanLines || this.sm.doc.styles?.[block.style]?.orphanLines || 2));
            const widowLines = Math.max(1, Number(block.widowLines || this.sm.doc.styles?.[block.style]?.widowLines || 2));
            const approximateCharsPerLine = 55;
            preferred = Math.max(orphanLines * approximateCharsPerLine, preferred);
            if (totalLen - preferred < widowLines * approximateCharsPerLine && totalLen > (orphanLines + widowLines) * approximateCharsPerLine) preferred = totalLen - widowLines * approximateCharsPerLine;
            preferred = Math.max(1, Math.min(best, preferred));
            let finalSplit = this.safeSplitHtmlByTextOffset(remainingHtml, preferred);

            const leftLen = this.getTextLengthFromHtmlSafe(finalSplit.a || '');
            const rightLen = this.getTextLengthFromHtmlSafe(finalSplit.b || '');

            if (leftLen <= 0 || rightLen >= totalLen) {
                finalSplit = this.safeSplitHtmlByTextOffset(remainingHtml, best);
            }

            const finalLeftLen = this.getTextLengthFromHtmlSafe(finalSplit.a || '');
            const finalRightLen = this.getTextLengthFromHtmlSafe(finalSplit.b || '');

            if (finalLeftLen <= 0 || finalRightLen >= totalLen) {
                currentPage.contentArea.removeChild(tester);
                if (hadOtherContent) {
                    currentPage = addPageFn();
                    continue;
                }

                const fallbackEl = this.createTextBlockElement(block, index, remainingHtml, partIndex);
                this.ensureCaretPlaceholder(fallbackEl);
                currentPage.contentArea.appendChild(fallbackEl);
                return currentPage;
            }

            tester.innerHTML = this.highlightText(finalSplit.a, index) || '';
            this.ensureCaretPlaceholder(tester);
            tester.dataset.splitPart = String(partIndex);
            delete tester.dataset.splitTester;

            remainingHtml = Formatter.normalizeTextBlockHtml(finalSplit.b, { emptyAsBr: false });
            partIndex++;

            if (this.isMeaningfullyEmptyHtml(remainingHtml)) {
                return currentPage;
            }

            currentPage = addPageFn();
        }

        return currentPage;
    }

    createPage(pageNum, doc, hfMode) {
        const page = document.createElement('div');
        page.className = 'page';
        page.dataset.pageNum = pageNum;

        const metrics = this.getPageMetrics(doc);
        page.style.width = `${metrics.widthIn}in`;
        page.style.height = `${metrics.heightIn}in`;
        page.style.position = 'relative';

        const h = document.createElement('div');
        h.className = 'page-header';
        h.contentEditable = hfMode;

        if (hfMode) {
            h.innerHTML = `<div style="flex:1; text-align:left">${doc.header.left}</div><div style="flex:1; text-align:center">${doc.header.center}</div><div style="flex:1; text-align:right">${doc.header.right}</div>`;
            h.oninput = () => {
                const divs = h.querySelectorAll('div');
                this.sm.updateHeaderFooter('header', 'left', divs[0].innerText);
                this.sm.updateHeaderFooter('header', 'center', divs[1].innerText);
                this.sm.updateHeaderFooter('header', 'right', divs[2].innerText);
            };
        } else {
            h.innerHTML = `<span>${doc.header.left}</span><span>${doc.header.center}</span><span>${doc.header.right}</span>`;
            h.ondblclick = () => this.sm.toggleHFMode(true);
        }
        page.appendChild(h);

        const behindLayer = document.createElement('div');
        behindLayer.className = 'page-behind-text-objects';
        page.appendChild(behindLayer);
        page.behindLayer = behindLayer;

        const content = document.createElement('div');
        content.className = 'page-content-area';
        content.contentEditable = false;

        content.addEventListener('input', (e) => {
            const blockEl = e.target.closest && e.target.closest('[data-index]');
            if (blockEl) {
                const index = parseInt(blockEl.dataset.index);

                if (blockEl.classList.contains('block-text')) {
                    if (blockEl.dataset.splitPart !== undefined) {
                        const allParts = Array.from(document.querySelectorAll(`[data-index="${index}"].block-text`));
                        allParts.sort((a, b) => parseInt(a.dataset.splitPart || '0') - parseInt(b.dataset.splitPart || '0'));

                        const fullHtml = allParts
                            .map((el) => this.getCleanEditableHtml(el))
                            .join('');

                        this.sm.updateBlockContent(index, fullHtml, 'typing');
                    } else {
                        const html = this.getCleanEditableHtml(blockEl);
                        this.sm.updateBlockContent(index, html, 'typing');
                    }

                    this.ensureCaretPlaceholder(blockEl);
                } else if (e.target.classList?.contains('checklist-text')) {
                    const li = e.target.closest('li[data-idx]');
                    if (li) this.sm.updateListItem(index, parseInt(li.dataset.idx), e.target.innerHTML);
                } else if (e.target.tagName === 'LI') {
                    const iIdx = parseInt(e.target.dataset.idx);
                    this.sm.updateListItem(index, iIdx, e.target.innerHTML);
                } else if (e.target.tagName === 'TD') {
                    const r = parseInt(e.target.dataset.row);
                    const c = parseInt(e.target.dataset.col);
                    this.sm.updateTableCell(index, r, c, e.target.innerText);
                }
            }
        }, true);

        page.appendChild(content);
        page.contentArea = content;

        const fnArea = document.createElement('div');
        fnArea.className = 'page-footnotes-area';
        fnArea.contentEditable = false;
        page.appendChild(fnArea);
        page.footnotesArea = fnArea;

        const frontLayer = document.createElement('div');
        frontLayer.className = 'page-front-objects';
        page.appendChild(frontLayer);
        page.frontLayer = frontLayer;

        const f = document.createElement('div');
        f.className = 'page-footer';
        f.contentEditable = hfMode;

        if (hfMode) {
            f.innerHTML = `<div style="flex:1; text-align:left">${doc.footer.left}</div><div style="flex:1; text-align:center">${doc.footer.center}</div><div style="flex:1; text-align:right">${doc.footer.right}</div>`;
            f.oninput = () => {
                const divs = f.querySelectorAll('div');
                this.sm.updateHeaderFooter('footer', 'left', divs[0].innerText);
                this.sm.updateHeaderFooter('footer', 'center', divs[1].innerText);
                this.sm.updateHeaderFooter('footer', 'right', divs[2].innerText);
            };
        } else {
            f.innerHTML = `<span>${doc.footer.left}</span><span>${(doc.footer.center || '').replace('{n}', pageNum)}</span><span>${doc.footer.right}</span>`;
            f.ondblclick = () => this.sm.toggleHFMode(true);
        }
        page.appendChild(f);

        return page;
    }

    makeBlockDraggable(el, index) {
        el.draggable = true;
        el.dataset.dragIndex = index;

        el.addEventListener('dragstart', (e) => {
            const selection = window.getSelection();
            const selectionInside = selection && !selection.isCollapsed
                && el.contains(selection.anchorNode) && el.contains(selection.focusNode);

            if (selectionInside) {
                e.dataTransfer.effectAllowed = 'copyMove';
                e.dataTransfer.setData('text/plain', selection.toString());
                return;
            }

            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('application/x-openword-block-index', String(index));
            el.classList.add('dragging');
        });

        el.addEventListener('dragend', () => {
            el.classList.remove('dragging');
            document.querySelectorAll('.block-drop-indicator, .drag-over').forEach(x => x.classList.remove('block-drop-indicator', 'drag-over'));
        });
    }

    applyBlockIdentity(el, block) {
        if (!el || !block) return;
        const bid = block.id;
        if (bid) {
            el.dataset.blockId = bid;
        }
        if (block.revision?.id) {
            el.dataset.revisionId = block.revision.id;
            el.classList.add('revision-block', `revision-block-${block.revision.type || 'change'}`);
        }
        if (block.breakRevision?.id) {
            el.dataset.breakRevisionId = block.breakRevision.id;
            el.classList.add('revision-paragraph-break', `revision-paragraph-break-${block.breakRevision.type || 'change'}`);
        }
    }

    createTextBlockElement(block, index, html, splitPart = null) {
        const tag = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'].includes(block.style) ? block.style : 'div';
        const el = document.createElement(tag);

        el.className = `block-text style-${block.style}`;
        if (block.preserveWhitespace) {
            el.classList.add('preserve-whitespace');
        }

        el.dataset.index = index;
        this.applyBlockIdentity(el, block);
        if (this.resolveParagraphRule(block, 'keepLinesTogether', block.keepLinesTogether || false)) el.style.breakInside = 'avoid';
        if (this.resolveParagraphRule(block, 'keepWithNext', false)) el.style.breakAfter = 'avoid';
        el.style.orphans = String(Math.max(1, Number(block.orphanLines || this.sm.doc.styles?.[block.style]?.orphanLines || 2)));
        el.style.widows = String(Math.max(1, Number(block.widowLines || this.sm.doc.styles?.[block.style]?.widowLines || 2)));

        if (splitPart !== null) el.dataset.splitPart = String(splitPart);

        el.contentEditable = true;
        el.spellcheck = true;

        const rendered = this.highlightText(html || '', index);
        el.innerHTML = rendered;

        if (block.align) el.style.textAlign = block.align;
        if (block.lineHeight) el.style.lineHeight = block.lineHeight;
        if (block.indent) el.style.paddingLeft = `${block.indent * 20}px`;
        if (block.marginTop !== undefined && block.marginTop !== null) el.style.marginTop = `${block.marginTop}pt`;
        if (block.marginBottom !== undefined && block.marginBottom !== null) el.style.marginBottom = `${block.marginBottom}pt`;

        this.ensureCaretPlaceholder(el);
        this.makeBlockDraggable(el, index);

        this.insertFootnoteAnchorInText(el, index);
        this.insertEndnoteAnchorInText(el, index);

        return el;
    }

    createToc(block, index) {
        const div = document.createElement('div');
        div.className = 'block-toc';
        div.dataset.index = index;
        this.applyBlockIdentity(div, block);
        div.contentEditable = false;

        const title = document.createElement('div');
        title.className = 'toc-title';
        title.innerText = 'Table of Contents';
        div.appendChild(title);

        const headings = this.sm.generateToc();
        if (headings.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'toc-empty';
            empty.innerText = '(No headings found)';
            div.appendChild(empty);
            return div;
        }

        const pageMap = this.sm.getHeadingPageMap(headings);

        const list = document.createElement('div');
        list.className = 'toc-list';
        headings.forEach((h) => {
            const item = document.createElement('div');
            item.className = `toc-item toc-item-${h.style}`;
            item.dataset.targetIndex = h.index;

            const row = document.createElement('div');
            row.className = 'toc-row';

            const link = document.createElement('span');
            link.className = 'toc-link';
            link.textContent = h.text;
            link.title = `Navigate to "${h.text}"`;
            link.onclick = (e) => {
                e.stopPropagation();
                const target = document.querySelector(`[data-index="${h.index}"]`);
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    target.focus();
                }
            };
            row.appendChild(link);

            if (pageMap[h.index]) {
                const pageNum = document.createElement('span');
                pageNum.className = 'toc-page-num';
                pageNum.textContent = pageMap[h.index];
                row.appendChild(pageNum);
            }

            item.appendChild(row);
            list.appendChild(item);
        });

        const updateBtn = document.createElement('button');
        updateBtn.className = 'toc-update-btn';
        updateBtn.innerText = 'Update Table of Contents';
        updateBtn.onclick = (e) => {
            e.stopPropagation();
            this.render(this.sm.doc, this.sm.hfMode);
        };
        div.appendChild(list);
        div.appendChild(updateBtn);
        return div;
    }

    applyTrackedChangesStyling(el, block) {
        if (!block.revisions || !block.revisions.length) return;
        const html = el.innerHTML;
        const tmp = document.createElement('div');
        tmp.innerHTML = html;

        block.revisions.forEach(rev => {
            const spans = tmp.querySelectorAll('[data-rev-id]');
            if (spans.length) return;
        });

        if (!this.sm.doc.settings.trackChanges || !block.revisions) return;
        let styledHtml = html;
        block.revisions.forEach(rev => {
            if (rev.type === 'deletion' && rev.text) {
                const esc = rev.text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                styledHtml = styledHtml.replace(
                    new RegExp(`(${esc})`, 'g'),
                    `<span class="rev-deletion" data-rev-id="${rev.id}" title="Deleted: ${rev.author}, ${new Date(rev.timestamp).toLocaleString()}">$1</span>`
                );
            }
            if (rev.type === 'insertion' && rev.text) {
                const esc = rev.text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                styledHtml = styledHtml.replace(
                    new RegExp(`(${esc})`, 'g'),
                    `<span class="rev-insertion" data-rev-id="${rev.id}" title="Inserted: ${rev.author}, ${new Date(rev.timestamp).toLocaleString()}">$1</span>`
                );
            }
        });
        el.innerHTML = styledHtml;
    }

    renderFootnotesOnPage(page, pageIndex) {
        const footnotes = this.sm.getFootnotes();
        const fnArea = page.footnotesArea;
        if (!fnArea) return;
        fnArea.innerHTML = '';

        const relevantFootnotes = footnotes.filter(fn => {
            const el = document.querySelector(`[data-index="${fn.blockIndex}"]`);
            if (!el) return false;
            const pageEl = el.closest('.page');
            return pageEl === page;
        });

        if (!relevantFootnotes.length) return;

        const sep = document.createElement('div');
        sep.className = 'footnote-separator';
        fnArea.appendChild(sep);

        relevantFootnotes.forEach(fn => {
            const noteDiv = document.createElement('div');
            noteDiv.className = 'footnote-item';
            noteDiv.dataset.fnId = fn.id;
            noteDiv.id = `fn-content-${fn.id}`;

            const numSpan = document.createElement('sup');
            numSpan.className = 'footnote-num';
            numSpan.textContent = fn.number;
            numSpan.onclick = () => {
                const anchor = document.querySelector(`[data-fn-anchor="${fn.id}"]`);
                if (anchor) anchor.scrollIntoView({ behavior: 'smooth', block: 'center' });
            };
            noteDiv.appendChild(numSpan);

            const contentSpan = document.createElement('span');
            contentSpan.className = 'footnote-content';
            contentSpan.contentEditable = true;
            contentSpan.spellcheck = true;
            contentSpan.innerHTML = fn.content || '';
            contentSpan.oninput = () => {
                this.sm.updateFootnoteContent(fn.id, contentSpan.innerHTML);
            };
            contentSpan.onblur = () => {
                this.sm.updateFootnoteContent(fn.id, contentSpan.innerHTML);
            };
            noteDiv.appendChild(contentSpan);

            const removeBtn = document.createElement('button');
            removeBtn.className = 'footnote-remove-btn';
            removeBtn.innerHTML = '&times;';
            removeBtn.title = 'Remove footnote';
            removeBtn.onclick = (e) => {
                e.stopPropagation();
                this.sm.removeFootnote(fn.id);
            };
            noteDiv.appendChild(removeBtn);

            fnArea.appendChild(noteDiv);
        });
    }

    renderEndnotesAtEnd() {
        const endnotes = this.sm.getEndnotes();
        if (!endnotes.length) return;

        const container = this.container;
        const endDiv = document.createElement('div');
        endDiv.className = 'endnotes-section';
        endDiv.contentEditable = false;

        const title = document.createElement('h2');
        title.className = 'endnotes-title';
        title.textContent = 'Notes';
        endDiv.appendChild(title);

        endnotes.forEach(en => {
            const noteDiv = document.createElement('div');
            noteDiv.className = 'endnote-item';
            noteDiv.id = `en-content-${en.id}`;

            const numSpan = document.createElement('sup');
            numSpan.className = 'endnote-num';
            numSpan.textContent = en.number;
            numSpan.onclick = () => {
                const anchor = document.querySelector(`[data-en-anchor="${en.id}"]`);
                if (anchor) anchor.scrollIntoView({ behavior: 'smooth', block: 'center' });
            };
            noteDiv.appendChild(numSpan);

            const contentSpan = document.createElement('span');
            contentSpan.className = 'endnote-content';
            contentSpan.contentEditable = true;
            contentSpan.spellcheck = true;
            contentSpan.innerHTML = en.content || '';
            contentSpan.oninput = () => {
                this.sm.updateEndnoteContent(en.id, contentSpan.innerHTML);
            };
            contentSpan.onblur = () => {
                this.sm.updateEndnoteContent(en.id, contentSpan.innerHTML);
            };
            noteDiv.appendChild(contentSpan);

            const removeBtn = document.createElement('button');
            removeBtn.className = 'endnote-remove-btn';
            removeBtn.innerHTML = '&times;';
            removeBtn.title = 'Remove endnote';
            removeBtn.onclick = (e) => {
                e.stopPropagation();
                this.sm.removeEndnote(en.id);
            };
            noteDiv.appendChild(removeBtn);

            endDiv.appendChild(noteDiv);
        });

        container.appendChild(endDiv);
    }

    insertNoteAnchors(el, notes, kind) {
        if (!notes.length) return;
        const isFootnote = kind === 'footnote';
        const sorted = [...notes].sort((a, b) => {
            const ao = Number.isFinite(Number(a.offset)) ? Number(a.offset) : Number.MAX_SAFE_INTEGER;
            const bo = Number.isFinite(Number(b.offset)) ? Number(b.offset) : Number.MAX_SAFE_INTEGER;
            return bo - ao;
        });

        sorted.forEach(note => {
            const sup = document.createElement('sup');
            sup.className = isFootnote ? 'footnote-anchor' : 'endnote-anchor';
            sup.dataset[isFootnote ? 'fnAnchor' : 'enAnchor'] = note.id;
            sup.dataset[isFootnote ? 'fnNum' : 'enNum'] = note.number;
            sup.contentEditable = 'false';
            sup.title = `${isFootnote ? 'Footnote' : 'Endnote'} ${note.number}`;
            sup.textContent = note.number;
            sup.addEventListener('click', (event) => {
                event.stopPropagation();
                const target = document.getElementById(`${isFootnote ? 'fn' : 'en'}-content-${note.id}`);
                target?.scrollIntoView({ behavior: 'smooth', block: 'center' });
            });

            const textLength = Formatter.getTextLengthFromDom(el);
            const offset = Number.isFinite(Number(note.offset)) ? Math.min(Number(note.offset), textLength) : textLength;
            const position = Formatter.resolveDomPositionFromTextOffset(el, Math.max(0, offset));
            const range = document.createRange();
            if (position?.container) range.setStart(position.container, position.offset);
            else {
                range.selectNodeContents(el);
                range.collapse(false);
            }
            range.collapse(true);
            range.insertNode(sup);
        });
    }

    insertFootnoteAnchorInText(el, blockIndex) {
        this.insertNoteAnchors(el, this.sm.getFootnotes().filter(note => note.blockIndex === blockIndex), 'footnote');
    }

    insertEndnoteAnchorInText(el, blockIndex) {
        this.insertNoteAnchors(el, this.sm.getEndnotes().filter(note => note.blockIndex === blockIndex), 'endnote');
    }

    createBlock(block, index) {
        if (block.type === 'text') {
            const el = this.createTextBlockElement(block, index, block.content, null);
            this.applyTrackedChangesStyling(el, block);
            return el;
        } else if (block.type === 'ul' || block.type === 'ol' || block.type === 'checklist') {
            return this.createList(block, index);
        } else if (block.type === 'table') {
            return this.createTable(block, index);
        } else if (block.type === 'image') {
            return this.createImageBlock(block, index);
        } else if (isObjectBlock(block)) {
            return this.createObjectBlock(block, index);
        } else if (block.type === 'horizontalRule') {
            return this.createHorizontalRule(block, index);
        } else if (block.type === 'toc') {
            return this.createToc(block, index);
        } else if (block.type === 'footnote') {
            return this.createFootnoteBlock(block, index);
        } else if (block.type === 'endnote') {
            return this.createEndnoteBlock(block, index);
        }
        return document.createElement('div');
    }

    createFootnoteBlock(block, index) {
        const div = document.createElement('div');
        div.className = 'block-footnote';
        div.dataset.index = index;
        this.applyBlockIdentity(div, block);
        div.contentEditable = false;
        div.innerHTML = `<sup class="block-footnote-num">${block.fnNumber || ''}</sup> <span class="block-footnote-content" contenteditable="true">${block.content || ''}</span>`;
        return div;
    }

    createEndnoteBlock(block, index) {
        const div = document.createElement('div');
        div.className = 'block-endnote';
        div.dataset.index = index;
        this.applyBlockIdentity(div, block);
        div.contentEditable = false;
        div.innerHTML = `<sup class="block-endnote-num">${block.enNumber || ''}</sup> <span class="block-endnote-content" contenteditable="true">${block.content || ''}</span>`;
        return div;
    }

    createObjectBlock(block, index, options = {}) {
        const floating = options.floating || !isFlowObject(block);
        const host = document.createElement(block.wrap?.type === 'inline' ? 'figure' : 'div');
        host.dataset.index = index;
        this.applyBlockIdentity(host, block);
        host.dataset.objectId = block.id;
        host.contentEditable = false;
        host.className = `object-host object-${block.objectType} object-wrap-${block.wrap?.type || 'inline'} ${floating ? 'object-floating' : 'object-flow'}`;
        const layout = block.layout || {};
        const distance = block.wrap?.distance || {};
        const widthPercent = block.legacy?.widthPercent;
        if (widthPercent && block.wrap?.type === 'inline') host.style.width = `${Math.max(10, Math.min(100, Number(widthPercent)))}%`;
        else host.style.width = `${Math.max(24, Number(layout.width || 240))}px`;
        if (layout.height) host.style.height = `${Math.max(24, Number(layout.height))}px`;
        else host.classList.add('object-auto-height');
        host.style.setProperty('--object-rotation', `${Number(layout.rotation || 0)}deg`);
        host.style.zIndex = String(Number(layout.zIndex || 1));
        host.style.marginTop = `${Number(distance.top || 0)}px`;
        host.style.marginRight = `${Number(distance.right || 0)}px`;
        host.style.marginBottom = `${Number(distance.bottom || 0)}px`;
        host.style.marginLeft = `${Number(distance.left || 0)}px`;
        if (floating) {
            host.style.left = `${Number(layout.x || 0)}px`;
            host.style.top = `${Number(layout.y || 0)}px`;
        } else if (['square', 'tight', 'through'].includes(block.wrap?.type)) {
            const side = block.wrap?.side === 'left' ? 'right' : 'left';
            host.style.float = side;
            if (block.wrap?.side === 'both' || block.wrap?.side === 'largest') host.style.float = 'right';
            if (Array.isArray(block.wrap?.contour) && block.wrap.contour.length >= 3) {
                host.style.shapeOutside = `polygon(${block.wrap.contour.map(point => `${Number(point.x) * 100}% ${Number(point.y) * 100}%`).join(',')})`;
            } else if ((block.wrap?.type === 'tight' || block.wrap?.type === 'through') && block.image?.src) {
                host.style.shapeOutside = `url("${block.image.src}")`;
                host.style.shapeImageThreshold = '0.1';
                host.style.shapeMargin = `${Math.max(...Object.values(distance).map(Number).filter(Number.isFinite), 0)}px`;
            } else if (block.wrap?.type === 'tight' || block.wrap?.type === 'through') host.style.shapeOutside = 'margin-box';
        } else if (block.wrap?.type === 'topBottom') {
            host.style.clear = 'both'; host.style.display = 'block';
        }

        const frame = document.createElement('div');
        frame.className = 'object-frame';
        frame.style.transform = this.objectTransformCss(block);
        frame.style.borderRadius = `${Number(block.image?.cornerRadius ?? block.appearance?.cornerRadius ?? 0)}px`;
        host.appendChild(frame);

        if (block.objectType === 'image') this.renderObjectImage(frame, block);
        else if (block.objectType === 'textBox') this.renderTextBox(frame, block, index);

        if (block.objectType === 'image' && block.image?.caption) {
            const caption = document.createElement('figcaption');
            caption.className = 'object-caption';
            caption.contentEditable = true;
            caption.textContent = block.image.caption;
            caption.addEventListener('input', event => this.sm.updateBlockProps(block.id, { image: { ...block.image, caption: event.target.innerText } }));
            host.appendChild(caption);
        }

        // Renderer receives the object manager through StateManager after controller setup.
        this.sm._objectManager?.decorateElement?.(host, block);

        if (floating && !layout.lockPosition) this.attachObjectDrag(host, block, options.pageIndex || 0);
        return host;
    }

    objectTransformCss(block) {
        const flipX = block.image?.flipX ? -1 : 1;
        const flipY = block.image?.flipY ? -1 : 1;
        return `rotate(${Number(block.layout?.rotation || 0)}deg) scale(${flipX},${flipY})`;
    }

    renderObjectImage(frame, block) {
        const viewport = document.createElement('div');
        viewport.className = 'object-image-viewport';
        const image = document.createElement('img');
        image.src = block.image?.src || '';
        image.alt = block.image?.decorative ? '' : (block.image?.altText || '');
        image.loading = 'lazy'; image.decoding = 'async';
        const crop = block.image?.crop || {};
        const left = Math.max(0, Math.min(.95, Number(crop.left || 0)));
        const right = Math.max(0, Math.min(.95, Number(crop.right || 0)));
        const top = Math.max(0, Math.min(.95, Number(crop.top || 0)));
        const bottom = Math.max(0, Math.min(.95, Number(crop.bottom || 0)));
        const visibleWidth = Math.max(.05, 1 - left - right), visibleHeight = Math.max(.05, 1 - top - bottom);
        const hasCrop = left > 0 || right > 0 || top > 0 || bottom > 0;
        if (!block.layout?.height && !hasCrop) {
            image.style.position = 'relative'; image.style.width = '100%'; image.style.height = 'auto'; image.style.left = '0'; image.style.top = '0';
            viewport.style.height = 'auto';
        } else {
            image.style.width = `${100 / visibleWidth}%`; image.style.height = `${100 / visibleHeight}%`;
            image.style.left = `${-left / visibleWidth * 100}%`; image.style.top = `${-top / visibleHeight * 100}%`;
        }
        const filters = block.image?.filters || {};
        image.style.filter = `brightness(${filters.brightness ?? 1}) contrast(${filters.contrast ?? 1}) saturate(${filters.saturate ?? 1}) grayscale(${filters.grayscale ?? 0}) sepia(${filters.sepia ?? 0})`;
        image.style.opacity = String(filters.opacity ?? 1);
        viewport.appendChild(image);
        const border = block.image?.border || {};
        viewport.style.border = `${Number(border.width || 0)}px ${border.style || 'solid'} ${border.color || 'transparent'}`;
        if (block.image?.shadow) viewport.style.boxShadow = block.image.shadow;
        frame.appendChild(viewport);
    }

    renderTextBox(frame, block, index) {
        const textBox = block.textBox || {};
        const appearance = block.appearance || {};
        frame.classList.add('text-box-frame');
        frame.style.background = appearance.fill || 'transparent';
        frame.style.opacity = String(appearance.opacity ?? 1);
        frame.style.border = `${Number(appearance.borderWidth || 0)}px ${appearance.borderStyle || 'solid'} ${appearance.borderColor || 'transparent'}`;
        if (appearance.shadow) frame.style.boxShadow = appearance.shadow;
        const editor = document.createElement('div');
        editor.className = `text-box-editor vertical-${textBox.verticalAlign || 'top'}`;
        editor.contentEditable = true; editor.spellcheck = true;
        const margins = textBox.margins || {};
        editor.style.padding = `${Number(margins.top || 0)}px ${Number(margins.right || 0)}px ${Number(margins.bottom || 0)}px ${Number(margins.left || 0)}px`;
        editor.style.columnCount = String(Math.max(1, Number(textBox.columns || 1)));
        editor.innerHTML = objectTextHtml(block) || '<div><br></div>';
        editor.addEventListener('input', event => {
            const next = JSON.parse(JSON.stringify(block));
            next.textBox ||= {}; next.textBox.blocks ||= [{ id: `tbblk_${Date.now()}`, type: 'text', style: 'normal', content: '' }];
            next.textBox.blocks[0].content = event.target.innerHTML;
            this.sm.replaceBlockById(block.id, next, 'textBoxInput');
        });
        if (textBox.autoFit === 'resizeShape') {
            const resize = () => {
                if (editor.scrollHeight > frame.clientHeight) {
                    const nextHeight = Math.min(1200, editor.scrollHeight + 4);
                    frame.parentElement.style.height = `${nextHeight}px`;
                }
            };
            editor.addEventListener('input', resize);
        } else if (textBox.autoFit === 'scroll') editor.style.overflow = 'auto';
        frame.appendChild(editor);
    }

    attachObjectDrag(element, block, pageIndex) {
        element.addEventListener('pointerdown', event => {
            if (event.target.closest('[contenteditable="true"],.object-handle,.object-rotate-handle,.object-wrap-button')) return;
            event.preventDefault();
            const page = element.closest('.page, .mode-pageless');
            const pageRect = page?.getBoundingClientRect();
            const start = { x: event.clientX, y: event.clientY, left: Number(block.layout?.x || 0), top: Number(block.layout?.y || 0) };
            const move = moveEvent => {
                const left = Math.max(0, start.left + moveEvent.clientX - start.x);
                const top = Math.max(0, start.top + moveEvent.clientY - start.y);
                element.style.left = `${left}px`; element.style.top = `${top}px`;
                element.dataset.previewPosition = JSON.stringify({ left, top });
            };
            const up = upEvent => {
                document.removeEventListener('pointermove', move); document.removeEventListener('pointerup', up);
                let pos = {}; try { pos = JSON.parse(element.dataset.previewPosition || '{}'); } catch (_) {}
                delete element.dataset.previewPosition;
                const manager = this.sm._objectManager;
                const pageHost = element.closest('.page, .mode-pageless');
                const objectTop = element.getBoundingClientRect().top;
                const candidates = [...(pageHost?.querySelectorAll('.page-content-area [data-block-id], :scope > [data-block-id]') || [])]
                    .filter(candidate => candidate.dataset.blockId !== block.id && this.sm.getBlockById(candidate.dataset.blockId)?.type === 'text');
                const anchorElement = candidates.sort((a, b) => Math.abs(a.getBoundingClientRect().top - objectTop) - Math.abs(b.getBoundingClientRect().top - objectTop))[0];
                const anchorBlockId = block.anchor?.lockAnchor ? block.anchor?.blockId : (anchorElement?.dataset.blockId || block.anchor?.blockId || null);
                manager?.engine.dispatch('updateObject', { objectId: block.id, patch: { layout: { x: pos.left ?? block.layout.x, y: pos.top ?? block.layout.y }, anchor: { blockId: anchorBlockId }, legacy: { pageIndex } }, source: 'objectMove' }, { restoreSelection: false });
            };
            document.addEventListener('pointermove', move); document.addEventListener('pointerup', up, { once: true });
        });
    }

    createImageBlock(block, index) {
        const div = document.createElement('div');
        div.className = `block-image align-${block.align || 'center'}`;
        div.dataset.index = index;
        this.applyBlockIdentity(div, block);
        div.contentEditable = false;
        div.tabIndex = 0;

        const wrapper = document.createElement('div');
        wrapper.className = 'image-wrapper';
        wrapper.style.width = (block.width || 100) + '%';

        const img = document.createElement('img');
        img.src = block.content;
        img.loading = 'lazy';
        img.decoding = 'async';
        wrapper.appendChild(img);

        const hSE = document.createElement('div');
        hSE.className = 'img-handle se';
        const hSW = document.createElement('div');
        hSW.className = 'img-handle sw';
        wrapper.appendChild(hSE);
        wrapper.appendChild(hSW);

        div.appendChild(wrapper);

        const cap = document.createElement('div');
        cap.className = 'caption';
        cap.contentEditable = true;
        cap.spellcheck = true;
        cap.innerText = block.caption || 'Add a caption...';
        cap.oninput = (e) => {
            e.stopPropagation();
            this.sm.updateImageProps(index, { caption: e.target.innerText });
        };
        div.appendChild(cap);

        div.onfocus = () => div.classList.add('selected');
        div.onblur = (e) => {
            if (!div.contains(e.relatedTarget)) div.classList.remove('selected');
        };

        this.attachImageResize(hSE, index, wrapper, 'se');
        this.attachImageResize(hSW, index, wrapper, 'sw');
        this.makeBlockDraggable(div, index);

        return div;
    }

    createHorizontalRule(block, index) {
        const div = document.createElement('div');
        div.className = 'block-horizontal-rule';
        div.dataset.index = index;
        this.applyBlockIdentity(div, block);
        div.contentEditable = false;
        div.tabIndex = 0;
        div.innerHTML = '<hr>';
        this.makeBlockDraggable(div, index);
        return div;
    }

    attachImageResize(handle, index, wrapper, dir) {
        const startResize = (startX) => {
            const startWidth = wrapper.offsetWidth;
            const parentWidth = wrapper.parentElement.offsetWidth;

            const onMove = (ev) => {
                const cx = ev.clientX ?? ev.touches?.[0]?.clientX;
                if (cx == null) return;
                const diff = (dir === 'se') ? (cx - startX) : (startX - cx);
                const newPx = startWidth + diff;
                let newPct = (newPx / parentWidth) * 100;
                if (newPct > 100) newPct = 100;
                if (newPct < 10) newPct = 10;
                wrapper.style.width = newPct + '%';
            };
            const onUp = () => {
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
                document.removeEventListener('touchmove', onMove);
                document.removeEventListener('touchend', onUp);
                const pct = (wrapper.offsetWidth / parentWidth) * 100;
                this.sm.updateImageProps(index, { width: pct });
            };
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
            document.addEventListener('touchmove', onMove, { passive: false });
            document.addEventListener('touchend', onUp);
        };

        handle.onmousedown = (e) => {
            e.preventDefault();
            e.stopPropagation();
            startResize(e.clientX);
        };
        handle.addEventListener('touchstart', (e) => {
            e.preventDefault();
            e.stopPropagation();
            startResize(e.touches[0].clientX);
        }, { passive: false });
    }

    createList(block, index) {
        const list = document.createElement(block.type === 'ol' ? 'ol' : 'ul');
        list.dataset.index = index;
        this.applyBlockIdentity(list, block);
        if (block.type === 'checklist') list.classList.add('block-checklist');

        (block.items || []).forEach((item, i) => {
            const li = document.createElement('li');
            li.dataset.idx = i;
            li.dataset.level = item.level || 0;
            li.style.marginLeft = `${(item.level || 0) * 20}px`;
            li.spellcheck = true;

            if (block.type === 'checklist') {
                li.className = 'checklist-item';
                li.classList.toggle('is-checked', !!item.checked);
                li.contentEditable = false;

                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.checked = !!item.checked;
                checkbox.tabIndex = -1;
                checkbox.contentEditable = false;
                checkbox.setAttribute('aria-label', 'Mark task complete');
                checkbox.addEventListener('change', () => this.sm.updateListItemChecked(index, i, checkbox.checked));

                const text = document.createElement('span');
                text.className = 'checklist-text';
                text.contentEditable = true;
                text.spellcheck = true;
                text.innerHTML = this.highlightText(item.text || '', index) || '<br>';

                li.appendChild(checkbox);
                li.appendChild(text);
            } else {
                li.innerHTML = this.highlightText(item.text || '', index);
                li.contentEditable = true;
                if (!li.innerText || li.innerText.trim() === '') li.innerHTML = '<br>';
            }

            list.appendChild(li);
        });

        this.makeBlockDraggable(list, index);
        return list;
    }

    createTable(block, index) {
        const table = document.createElement('table');
        table.dataset.index = index;
        this.applyBlockIdentity(table, block);

        if (block.colWidths) {
            const cg = document.createElement('colgroup');
            block.colWidths.forEach((w) => {
                const col = document.createElement('col');
                col.style.width = w + '%';
                cg.appendChild(col);
            });
            table.appendChild(cg);
        }

        const tbody = document.createElement('tbody');
        table.appendChild(tbody);

        block.rows.forEach((row, r) => {
            const tr = document.createElement('tr');
            tr.dataset.rowId = block.rowIds?.[r] || '';
            row.forEach((cell, c) => {
                const cellId = block.cellIds?.[r]?.[c] || '';
                const cellMeta = block.cellMeta?.[cellId] || {};
                if (cellMeta.coveredBy) return;
                const td = document.createElement((block.headerRows || 0) > r ? 'th' : 'td');
                td.innerHTML = this.highlightText(cell || '', index);
                td.dataset.row = r;
                td.dataset.col = c;
                td.dataset.cellId = cellId;
                td.contentEditable = true;
                td.spellcheck = true;
                if (cellMeta.rowspan > 1) td.rowSpan = cellMeta.rowspan;
                if (cellMeta.colspan > 1) td.colSpan = cellMeta.colspan;

                if (r === 0) {
                    const handle = document.createElement('div');
                    handle.className = 'tbl-col-resizer';
                    handle.contentEditable = false;
                    this.attachTableResize(handle, index, c, table);
                    td.appendChild(handle);
                }

                if (!td.innerText || td.innerText.trim() === '') {
                    td.innerHTML = (td.innerHTML.includes('tbl-col-resizer') ? td.innerHTML : '<br>');
                }

                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });

        this.makeBlockDraggable(table, index);
        return table;
    }

    createFloating(block, index, pageIndex) {
        const box = document.createElement('div');
        box.className = 'floating-box';
        box.style.left = `${block.x}px`;
        box.style.top = `${block.y}px`;
        box.style.width = `${block.w}px`;
        box.style.height = `${block.h}px`;
        box.dataset.index = index;

        const content = block.subType === 'text'
            ? `<div class="box-text-content" contenteditable="true">${block.content}</div>`
            : `<img src="${block.content}" class="box-img-content">`;
        box.innerHTML = content + '<div class="resize-handle"></div>';

        if (block.subType === 'text') {
            const txt = box.querySelector('.box-text-content');
            if (txt) txt.oninput = (e) => this.sm.updateBlockContent(index, e.target.innerHTML, 'typing');
        }

        this.attachDragLogic(box, index, pageIndex);

        const handle = box.querySelector('.resize-handle');
        if (handle) {
            const startResize = (sX, sY) => {
                const sW = box.offsetWidth;
                const sH = box.offsetHeight;
                const move = (ev) => {
                    const cx = ev.clientX ?? ev.touches?.[0]?.clientX;
                    const cy = ev.clientY ?? ev.touches?.[0]?.clientY;
                    if (cx == null || cy == null) return;
                    box.style.width = `${sW + (cx - sX)}px`;
                    box.style.height = `${sH + (cy - sY)}px`;
                };
                const up = () => {
                    document.removeEventListener('mousemove', move);
                    document.removeEventListener('mouseup', up);
                    document.removeEventListener('touchmove', move);
                    document.removeEventListener('touchend', up);
                    this.sm.updateFloatingSize(index, box.offsetWidth, box.offsetHeight);
                };
                document.addEventListener('mousemove', move);
                document.addEventListener('mouseup', up);
                document.addEventListener('touchmove', move, { passive: false });
                document.addEventListener('touchend', up);
            };

            handle.onmousedown = (e) => {
                e.stopPropagation();
                e.preventDefault();
                startResize(e.clientX, e.clientY);
            };
            handle.addEventListener('touchstart', (e) => {
                e.stopPropagation();
                e.preventDefault();
                startResize(e.touches[0].clientX, e.touches[0].clientY);
            }, { passive: false });
        }

        return box;
    }

    attachDragLogic(el, index, initialPageIndex) {
        const startDrag = (clientX, clientY) => {
            const rect = el.getBoundingClientRect();
            const offsetX = clientX - rect.left;
            const offsetY = clientY - rect.top;

            const move = (ev) => {
                const cx = ev.clientX ?? ev.touches?.[0]?.clientX;
                const cy = ev.clientY ?? ev.touches?.[0]?.clientY;
                if (cx == null || cy == null) return;
                const pageRect = el.closest('.page').getBoundingClientRect();
                el.style.left = `${cx - pageRect.left - offsetX}px`;
                el.style.top = `${cy - pageRect.top - offsetY}px`;
            };

            const up = (ev) => {
                document.removeEventListener('mousemove', move);
                document.removeEventListener('mouseup', up);
                document.removeEventListener('touchmove', move);
                document.removeEventListener('touchend', up);

                const dropX = ev.clientX ?? ev.changedTouches?.[0]?.clientX;
                const dropY = ev.clientY ?? ev.changedTouches?.[0]?.clientY;
                if (dropX == null || dropY == null) return;

                el.style.display = 'none';
                const elements = document.elementsFromPoint(dropX, dropY);
                el.style.display = 'block';

                const targetPage = elements.find((x) => x.classList.contains('page'));
                let newPageIndex = initialPageIndex;
                let finalX = parseFloat(el.style.left);
                let finalY = parseFloat(el.style.top);

                if (targetPage) {
                    newPageIndex = parseInt(targetPage.dataset.pageNum) - 1;
                    const pageRect = targetPage.getBoundingClientRect();
                    finalX = dropX - pageRect.left - offsetX;
                    finalY = dropY - pageRect.top - offsetY;
                }
                this.sm.updateFloatingPos(index, finalX, finalY, newPageIndex);
            };

            document.addEventListener('mousemove', move);
            document.addEventListener('mouseup', up);
            document.addEventListener('touchmove', move, { passive: false });
            document.addEventListener('touchend', up);
        };

        el.onmousedown = (e) => {
            if (e.target.closest('.box-text-content') || e.target.closest('.resize-handle')) return;
            e.preventDefault();
            startDrag(e.clientX, e.clientY);
        };
        el.addEventListener('touchstart', (e) => {
            if (e.target.closest('.box-text-content') || e.target.closest('.resize-handle')) return;
            e.preventDefault();
            startDrag(e.touches[0].clientX, e.touches[0].clientY);
        }, { passive: false });
    }

    setupBlockDragDrop() {
        this.container.addEventListener('dragenter', (e) => {
            if (!Array.from(e.dataTransfer.types || []).includes('application/x-openword-block-index')) return;
            if (!e.target.closest('[data-index]') && !e.target.closest('.page-content-area')) return;
            e.preventDefault();
        });

        this.container.addEventListener('dragover', (e) => {
            if (!Array.from(e.dataTransfer.types || []).includes('application/x-openword-block-index')) return;
            const blockEl = e.target.closest('[data-index]');
            if (!blockEl) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';

            document.querySelectorAll('.drag-over').forEach(x => x.classList.remove('drag-over'));
            blockEl.classList.add('drag-over');
        });

        this.container.addEventListener('dragleave', (e) => {
            const blockEl = e.target.closest('[data-index]');
            if (blockEl) blockEl.classList.remove('drag-over');
        });

        this.container.addEventListener('drop', (e) => {
            e.preventDefault();
            if (!Array.from(e.dataTransfer.types || []).includes('application/x-openword-block-index')) return;
            const fromIndex = parseInt(e.dataTransfer.getData('application/x-openword-block-index'));
            if (!Number.isInteger(fromIndex)) return;

            const targetBlock = e.target.closest('[data-index]');
            if (!targetBlock) return;
            const toIndex = parseInt(targetBlock.dataset.index);
            if (!Number.isInteger(toIndex) || fromIndex === toIndex) return;

            document.querySelectorAll('.drag-over').forEach(x => x.classList.remove('drag-over'));
            this.sm.moveBlock(fromIndex, toIndex);
        });
    }

    createPageBreakVisual() {
        const div = document.createElement('div');
        div.className = 'block-page-break';
        return div;
    }

    attachTableResize(handle, blockIdx, colIdx, tableEl) {
        const startResize = (startX) => {
            const startWidth = tableEl.rows[0].cells[colIdx].offsetWidth;
            const tableWidth = tableEl.offsetWidth;

            const onMove = (ev) => {
                const cx = ev.clientX ?? ev.touches?.[0]?.clientX;
                if (cx == null) return;
                const diff = cx - startX;
                const newWidthPct = ((startWidth + diff) / tableWidth) * 100;
                this.sm.resizeTableCol(blockIdx, colIdx, newWidthPct);
            };

            const onUp = () => {
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
                document.removeEventListener('touchmove', onMove);
                document.removeEventListener('touchend', onUp);
            };

            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
            document.addEventListener('touchmove', onMove, { passive: false });
            document.addEventListener('touchend', onUp);
        };

        handle.onmousedown = (e) => {
            e.preventDefault();
            e.stopPropagation();
            startResize(e.clientX);
        };
        handle.addEventListener('touchstart', (e) => {
            e.preventDefault();
            e.stopPropagation();
            startResize(e.touches[0].clientX);
        }, { passive: false });
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/rendering/render-impact.js
// ================================================================
export function normalizeRenderImpact(impact = {}) {
    return {
        dirtyBlockIds: [...new Set((impact.dirtyBlockIds || []).filter(Boolean).map(String))],
        insertedBlockIds: [...new Set((impact.insertedBlockIds || []).filter(Boolean).map(String))],
        removedBlockIds: [...new Set((impact.removedBlockIds || []).filter(Boolean).map(String))],
        layoutInvalidFromBlockId: impact.layoutInvalidFromBlockId ? String(impact.layoutInvalidFromBlockId) : null
    };
}

export function canPatchRenderImpact(impact) {
    const normalized = normalizeRenderImpact(impact);
    return normalized.dirtyBlockIds.length > 0
        && normalized.insertedBlockIds.length === 0
        && normalized.removedBlockIds.length === 0;
}

export function earliestAffectedBlockIndex(state, impact) {
    const normalized = normalizeRenderImpact(impact);
    const ids = [
        normalized.layoutInvalidFromBlockId,
        ...normalized.dirtyBlockIds,
        ...normalized.insertedBlockIds,
        ...normalized.removedBlockIds
    ].filter(Boolean);
    let earliest = Infinity;
    ids.forEach(id => {
        const index = state.getBlockIndexById(id);
        if (index >= 0) earliest = Math.min(earliest, index);
    });
    return Number.isFinite(earliest) ? earliest : -1;
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/ruler-manager.js
// ================================================================
export class RulerManager {
    constructor(ctrl) {
        this.ctrl = ctrl;
        this.state = ctrl.state;
        this.renderer = ctrl.renderer;
    }

    setup() {
        const ctrl = this.ctrl;
        const attach = (id, side) => {
            const el = document.getElementById(id);
            el.onmousedown = (e) => {
                e.preventDefault();
                const startX = e.clientX;
                const startVal = this.state.doc.settings.margins[side];
                const onMove = (ev) => {
                    const diffIn = (side === 'right' ? (startX - ev.clientX) : (ev.clientX - startX)) / this.renderer.pxPerIn;
                    let newVal = startVal + diffIn;
                    if (newVal < 0.25) newVal = 0.25;
                    this.state.updateMargins(side, newVal);
                };
                const onUp = () => {
                    document.removeEventListener('mousemove', onMove);
                    document.removeEventListener('mouseup', onUp);
                };
                document.addEventListener('mousemove', onMove);
                document.addEventListener('mouseup', onUp);
            };
        };
        attach('marker-margin-left', 'left');
        attach('marker-margin-right', 'right');
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/sharing-manager.js
// ================================================================
export class SharingManager {
    constructor(controller) {
        this.ctrl = controller;
        this.state = controller.state;
        this.user = null;
        this.authenticated = false;
        this.documentRole = 'owner';
        this.permissionObserver = null;
    }

    async setup() {
        this.ensureUi();
        await this.refreshUser();
        this.state.subscribeTo('DOCUMENT_LOADED', ({ documentId }) => this.loadAccess(documentId));
        this.installPermissionGuards();
        document.getElementById('btn-share')?.addEventListener('click', event => {
            event.preventDefault(); event.stopImmediatePropagation(); this.openShareDialog();
        }, true);
        document.getElementById('btn-user-menu')?.addEventListener('click', event => {
            event.preventDefault(); event.stopImmediatePropagation(); this.openAccountDialog();
        }, true);
    }

    ensureUi() {
        if (!document.getElementById('account-dialog')) {
            const account = document.createElement('div');
            account.id = 'account-dialog'; account.className = 'share-dialog-backdrop hidden';
            account.innerHTML = `<div class="share-dialog-card account-dialog-card">
              <div class="share-dialog-header"><h2>Account</h2><button data-action="close">×</button></div>
              <div class="account-current hidden" data-view="current"><p>Signed in as <strong data-user-name></strong></p><p data-user-email></p><button data-action="logout">Sign out</button></div>
              <div data-view="auth">
                <div class="auth-tabs"><button data-tab="login" class="active">Sign in</button><button data-tab="register">Create account</button></div>
                <form data-form="login"><label>Email<input name="email" type="email" required></label><label>Password<input name="password" type="password" required minlength="8"></label><button class="btn-primary">Sign in</button></form>
                <form data-form="register" class="hidden"><label>Name<input name="name" required></label><label>Email<input name="email" type="email" required></label><label>Password<input name="password" type="password" required minlength="8"></label><button class="btn-primary">Create account</button></form>
                <p class="auth-error" data-auth-error></p>
              </div>
            </div>`;
            document.body.appendChild(account);
            account.addEventListener('click', event => this.handleAccountClick(event));
            account.querySelectorAll('form').forEach(form => form.addEventListener('submit', event => this.submitAuth(event)));
        }
        if (!document.getElementById('share-dialog')) {
            const share = document.createElement('div');
            share.id = 'share-dialog'; share.className = 'share-dialog-backdrop hidden';
            share.innerHTML = `<div class="share-dialog-card">
              <div class="share-dialog-header"><h2>Share document</h2><button id="btn-close-share" data-action="close">×</button></div>
              <div class="share-dialog-section"><h3>Invite people</h3><div class="share-invite-row"><input data-invite-email type="email" placeholder="name@example.com"><select data-invite-role><option value="viewer">Viewer</option><option value="commenter">Commenter</option><option value="editor">Editor</option></select><button data-action="invite">Invite</button></div><div data-members-list class="share-members-list"></div></div>
              <div class="share-dialog-section"><h3>Share link</h3><div class="share-link-role"><select data-link-role><option value="viewer">Anyone with link can view</option><option value="commenter">Anyone with link can comment</option><option value="editor">Anyone with link can edit</option></select><button data-action="create-link">Create link</button></div><div data-links-list class="share-links-list"></div></div>
              <p class="share-dialog-note" data-share-status></p>
            </div>`;
            document.body.appendChild(share);
            share.addEventListener('click', event => this.handleShareClick(event));
        }
    }

    async refreshUser() {
        try {
            const response = await fetch('/api/auth/me', { cache: 'no-store' });
            const result = await response.json();
            this.user = result.user; this.authenticated = !!result.authenticated;
            if (this.user?.name) { this.state.currentUserName = this.user.name; if (this.ctrl.collaboration) this.ctrl.collaboration.userName = this.user.name; }
            const button = document.getElementById('btn-user-menu');
            if (button) { button.title = this.user?.name || 'Account'; button.textContent = this.initials(this.user?.name || 'Local User'); }
            this.renderAccount();
        } catch (_) { /* local editor remains usable */ }
    }

    renderAccount() {
        const dialog = document.getElementById('account-dialog'); if (!dialog) return;
        const current = dialog.querySelector('[data-view="current"]'), auth = dialog.querySelector('[data-view="auth"]');
        current.classList.toggle('hidden', !this.authenticated); auth.classList.toggle('hidden', this.authenticated);
        current.querySelector('[data-user-name]').textContent = this.user?.name || '';
        current.querySelector('[data-user-email]').textContent = this.user?.email || '';
    }

    openAccountDialog() { this.renderAccount(); document.getElementById('account-dialog')?.classList.remove('hidden'); }
    closeAccountDialog() { document.getElementById('account-dialog')?.classList.add('hidden'); }


    async loadAccess(documentId = this.state.doc.id) {
        if (!documentId) return;
        try {
            const response = await fetch(`/api/docs/${encodeURIComponent(documentId)}/access`, { cache: 'no-store' });
            if (!response.ok) return;
            const access = await response.json();
            this.applyDocumentRole(access.role || 'viewer', access.permissions || {});
        } catch (_) { /* retain local editing while offline */ }
    }

    applyDocumentRole(role, permissions = {}) {
        this.documentRole = role;
        this.state.documentRole = role;
        this.state.documentPermissions = permissions;
        document.body.dataset.documentRole = role;
        this.enforceReadOnlyDom();
        const shareButton = document.getElementById('btn-share');
        if (shareButton) shareButton.title = permissions.share ? 'Share' : `Shared with you as ${role}`;
        this.ctrl.toolbar?.showShellToast?.(role === 'owner' ? 'Owner access' : `${role[0].toUpperCase()}${role.slice(1)} access`);
    }

    installPermissionGuards() {
        const canEdit = () => ['owner', 'editor'].includes(this.documentRole);
        document.addEventListener('beforeinput', event => {
            if (!canEdit() && event.target?.closest?.('#workspace')) event.preventDefault();
        }, true);
        document.addEventListener('keydown', event => {
            if (canEdit() || !event.target?.closest?.('#workspace')) return;
            if (event.key.length === 1 || ['Backspace', 'Delete', 'Enter', 'Tab'].includes(event.key)) {
                event.preventDefault(); event.stopImmediatePropagation();
            }
        }, true);
        document.addEventListener('pointerdown', event => {
            if (canEdit()) return;
            if (event.target?.closest?.('.object-transform-handle, .object-rotation-handle, .floating-object, .block-image')) {
                event.preventDefault(); event.stopImmediatePropagation();
            }
        }, true);
        const safeIds = new Set(['btn-comments', 'btn-add-comment', 'panel-add-comment', 'btn-version-history', 'btn-print', 'btn-export-pdf', 'btn-export-docx', 'btn-docs', 'btn-outline', 'btn-find', 'btn-view-page', 'btn-view-web', 'btn-view-page-sb', 'btn-view-web-sb', 'btn-zoom-in', 'btn-zoom-out']);
        document.addEventListener('click', event => {
            if (canEdit()) return;
            const control = event.target.closest?.('button,select,input');
            if (!control || !control.closest('.ribbon, .compact-toolbar, #context-menu, .contextual-toolbar')) return;
            const id = control.id || '';
            const action = control.dataset?.action || '';
            if (safeIds.has(id) || ['copy'].includes(action) || id.includes('comment') || id.includes('view') || id.includes('zoom') || id.includes('export')) return;
            event.preventDefault(); event.stopImmediatePropagation();
            this.ctrl.toolbar?.showShellToast?.(`${this.documentRole} access is read-only for document content`);
        }, true);
        if (typeof MutationObserver !== 'undefined') {
            this.permissionObserver = new MutationObserver(() => this.enforceReadOnlyDom());
            const workspace = document.getElementById('workspace');
            if (workspace) this.permissionObserver.observe(workspace, { childList: true, subtree: true, attributes: true, attributeFilter: ['contenteditable'] });
        }
        this.state.subscribe(() => requestAnimationFrame(() => this.enforceReadOnlyDom()));
    }

    enforceReadOnlyDom() {
        const canEdit = ['owner', 'editor'].includes(this.documentRole);
        document.querySelectorAll('#workspace [contenteditable]').forEach(element => {
            if (!canEdit && element.getAttribute('contenteditable') === 'true') {
                element.dataset.readonlyByRole = '1';
                element.setAttribute('contenteditable', 'false');
            } else if (canEdit && element.dataset.readonlyByRole === '1') {
                element.setAttribute('contenteditable', 'true');
                delete element.dataset.readonlyByRole;
            }
        });
        document.getElementById('workspace')?.classList.toggle('document-read-only', !canEdit);
    }

    handleAccountClick(event) {
        const dialog = event.currentTarget;
        if (event.target === dialog || event.target.dataset.action === 'close') return this.closeAccountDialog();
        const tab = event.target.dataset.tab;
        if (tab) {
            dialog.querySelectorAll('[data-tab]').forEach(button => button.classList.toggle('active', button.dataset.tab === tab));
            dialog.querySelectorAll('[data-form]').forEach(form => form.classList.toggle('hidden', form.dataset.form !== tab));
        }
        if (event.target.dataset.action === 'logout') this.logout();
    }

    async submitAuth(event) {
        event.preventDefault();
        const form = event.currentTarget, mode = form.dataset.form;
        const payload = Object.fromEntries(new FormData(form).entries());
        const error = document.querySelector('[data-auth-error]'); error.textContent = '';
        try {
            const response = await fetch(`/api/auth/${mode}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            const result = response.status === 204 ? {} : await response.json();
            if (!response.ok) throw new Error(result.error || 'Authentication failed');
            await this.refreshUser(); this.closeAccountDialog(); this.ctrl.toolbar?.showShellToast?.(mode === 'register' ? 'Account created' : 'Signed in');
        } catch (authError) { error.textContent = authError.message; }
    }

    async logout() {
        await fetch('/api/auth/logout', { method: 'POST' });
        await this.refreshUser(); this.closeAccountDialog(); this.ctrl.toolbar?.showShellToast?.('Signed out');
    }

    async openShareDialog() {
        const dialog = document.getElementById('share-dialog'); if (!dialog) return;
        dialog.classList.remove('hidden');
        await this.loadSharing();
    }
    closeShareDialog() { document.getElementById('share-dialog')?.classList.add('hidden'); }

    async handleShareClick(event) {
        const dialog = event.currentTarget;
        if (event.target === dialog || event.target.dataset.action === 'close') return this.closeShareDialog();
        const action = event.target.dataset.action;
        if (action === 'invite') await this.inviteMember();
        if (action === 'create-link') await this.createShareLink();
        if (action === 'copy-link') await navigator.clipboard.writeText(event.target.dataset.url || '');
        if (action === 'revoke-link') await this.revokeShareLink(event.target.dataset.id);
        if (action === 'remove-member') await this.removeMember(event.target.dataset.id);
    }

    async loadSharing() {
        const id = this.state.doc.id; if (!id) return;
        const status = document.querySelector('[data-share-status]'); if (status) status.textContent = '';
        const [membersResponse, linksResponse] = await Promise.all([fetch(`/api/docs/${encodeURIComponent(id)}/members`), fetch(`/api/docs/${encodeURIComponent(id)}/share-links`)]);
        if (membersResponse.status === 403 || linksResponse.status === 403) { if (status) status.textContent = 'Only the document owner can manage sharing.'; return; }
        if (membersResponse.ok) this.renderMembers((await membersResponse.json()).members || []);
        if (linksResponse.ok) this.renderLinks((await linksResponse.json()).links || []);
    }

    renderMembers(members) {
        const host = document.querySelector('[data-members-list]');
        host.innerHTML = members.length ? members.map(member => `<div class="share-entry"><span><strong>${this.escape(member.name || member.email)}</strong><small>${this.escape(member.email || '')} · ${this.escape(member.role)}</small></span><button data-action="remove-member" data-id="${this.escape(member.userId || member.email)}">Remove</button></div>`).join('') : '<p class="share-empty">No invited members.</p>';
    }
    renderLinks(links) {
        const host = document.querySelector('[data-links-list]');
        host.innerHTML = links.length ? links.map(link => { const url = new URL(link.url, location.origin).href; return `<div class="share-entry"><span><strong>${this.escape(link.role)}</strong><small>${this.escape(url)}</small></span><button data-action="copy-link" data-url="${this.escape(url)}">Copy</button><button data-action="revoke-link" data-id="${this.escape(link.id)}">Revoke</button></div>`; }).join('') : '<p class="share-empty">No active share links.</p>';
    }

    async inviteMember() {
        const email = document.querySelector('[data-invite-email]').value.trim(); const role = document.querySelector('[data-invite-role]').value;
        const response = await fetch(`/api/docs/${encodeURIComponent(this.state.doc.id)}/members`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, role }) });
        const result = await response.json(); if (!response.ok) return this.setShareStatus(result.error || 'Unable to invite member');
        document.querySelector('[data-invite-email]').value = ''; this.setShareStatus('Member invited'); await this.loadSharing();
    }
    async createShareLink() {
        const role = document.querySelector('[data-link-role]').value;
        const response = await fetch(`/api/docs/${encodeURIComponent(this.state.doc.id)}/share-links`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ role }) });
        const result = await response.json(); if (!response.ok) return this.setShareStatus(result.error || 'Unable to create link');
        const url = new URL(result.url, location.origin).href; await navigator.clipboard.writeText(url).catch(() => undefined); this.setShareStatus('Share link created and copied'); await this.loadSharing();
    }
    async revokeShareLink(id) { await fetch(`/api/docs/${encodeURIComponent(this.state.doc.id)}/share-links/${encodeURIComponent(id)}`, { method: 'DELETE' }); await this.loadSharing(); }
    async removeMember(id) { await fetch(`/api/docs/${encodeURIComponent(this.state.doc.id)}/members/${encodeURIComponent(id)}`, { method: 'DELETE' }); await this.loadSharing(); }
    setShareStatus(message) { const status = document.querySelector('[data-share-status]'); if (status) status.textContent = message; }
    initials(name) { return String(name || '?').split(/\s+/).filter(Boolean).slice(0, 2).map(part => part[0]).join('').toUpperCase(); }
    escape(value) { const div = document.createElement('div'); div.textContent = String(value || ''); return div.innerHTML; }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/sidebar-manager.js
// ================================================================
export class SidebarManager {
    constructor(ctrl) {
        this.ctrl = ctrl;
        this.state = ctrl.state;
    }

    setup() {
        const ctrl = this.ctrl;
        const sb = document.getElementById('doc-sidebar');
        document.getElementById('btn-docs').onclick = async () => {
            const list = await this.state.loadDocsList();
            const con = document.getElementById('doc-list');
            con.innerHTML = '';
            list.forEach((d) => {
                const item = document.createElement('div');
                item.className = `doc-item ${this.state.doc.id === d.id ? 'active' : ''}`;
                item.innerHTML = `<div><b>${d.title}</b></div><div style="font-size:10px; color:#888;">${new Date(d.updatedAt).toLocaleDateString()}</div>`;
                item.onclick = () => {
                    this.state.loadDoc(d.id);
                    sb.classList.add('hidden');
                };

                const controls = document.createElement('div');
                controls.style.marginTop = '5px';

                const del = document.createElement('button');
                del.innerText = 'Del';
                del.style.fontSize = '10px';
                del.style.marginRight = '5px';
                del.onclick = (e) => {
                    e.stopPropagation();
                    if (confirm('Delete?')) this.state.deleteDoc(d.id).then(() => this.ctrl.init());
                };

                const dup = document.createElement('button');
                dup.innerText = 'Copy';
                dup.style.fontSize = '10px';
                dup.onclick = (e) => {
                    e.stopPropagation();
                    this.state.duplicateDoc(d.id).then(() => {
                        alert('Copied');
                        this.ctrl.init();
                    });
                };

                controls.append(del, dup);
                item.appendChild(controls);
                con.appendChild(item);
            });
            sb.classList.remove('hidden');
        };

        document.getElementById('btn-sidebar-close').onclick = () => sb.classList.add('hidden');
        document.getElementById('btn-new-doc').onclick = async () => {
            await this.state.createNewDoc();
            sb.classList.add('hidden');
        };
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/smart-input-manager.js
// ================================================================
import { Formatter } from './formatter.js';

/**
 * Native-feeling input rules and inline command menus.
 *
 * This layer intentionally talks to OpenWord's StateManager instead of
 * embedding document logic in the menu. That keeps the behaviour replaceable
 * when the editing engine changes later.
 */
export class SmartInputManager {
    constructor(ctrl) {
        this.ctrl = ctrl;
        this.state = ctrl.state;
        this.menu = null;
        this.menuKind = null;
        this.context = null;
        this.filteredItems = [];
        this.activeIndex = 0;

        this.slashItems = [
            { id: 'paragraph', label: 'Normal text', hint: 'Paragraph', keywords: 'text paragraph normal' },
            { id: 'heading1', label: 'Heading 1', hint: 'Large section heading', keywords: 'h1 title heading' },
            { id: 'heading2', label: 'Heading 2', hint: 'Medium section heading', keywords: 'h2 subtitle heading' },
            { id: 'heading3', label: 'Heading 3', hint: 'Small section heading', keywords: 'h3 heading' },
            { id: 'quote', label: 'Quote', hint: 'Highlighted quotation', keywords: 'blockquote quote' },
            { id: 'bulleted-list', label: 'Bulleted list', hint: 'Create a bullet list', keywords: 'ul bullet list' },
            { id: 'numbered-list', label: 'Numbered list', hint: 'Create a numbered list', keywords: 'ol ordered list number' },
            { id: 'checklist', label: 'Checklist', hint: 'Track completed items', keywords: 'todo task checkbox list' },
            { id: 'table', label: 'Table', hint: 'Insert a 2 × 2 table', keywords: 'grid rows columns' },
            { id: 'image', label: 'Image', hint: 'Upload an inline image', keywords: 'photo picture upload' },
            { id: 'horizontal-rule', label: 'Divider', hint: 'Insert a horizontal line', keywords: 'separator rule line hr' },
            { id: 'page-break', label: 'Page break', hint: 'Start on a new page', keywords: 'new page break' },
            { id: 'footnote', label: 'Footnote', hint: 'Add a note at the bottom of the page', keywords: 'reference note' },
            { id: 'endnote', label: 'Endnote', hint: 'Add a note at the end of the document', keywords: 'reference note' },
            { id: 'today', label: 'Today\'s date', hint: 'Insert the current date', keywords: 'date today calendar' }
        ];
    }

    setup() {
        this.menu = document.getElementById('quick-insert-menu');
        if (!this.menu) return;

        document.addEventListener('input', (event) => this.handleInput(event));
        document.addEventListener('keydown', (event) => this.handleKeydown(event), true);
        document.addEventListener('selectionchange', () => {
            if (!this.menu.classList.contains('hidden') && !this.getActiveTextContext()) this.closeMenu();
        });
        document.addEventListener('mousedown', (event) => {
            if (!event.target.closest('#quick-insert-menu')) this.closeMenu();
        });
        this.menu.addEventListener('mousedown', (event) => event.preventDefault());
        this.menu.addEventListener('click', (event) => {
            const item = event.target.closest('[data-smart-menu-index]');
            if (!item) return;
            const selected = this.filteredItems[parseInt(item.dataset.smartMenuIndex, 10)];
            if (selected) this.executeItem(selected);
        });
        window.addEventListener('resize', () => this.closeMenu());
        document.addEventListener('scroll', () => this.closeMenu(), true);
    }

    getActiveTextContext(target = null) {
        const selection = window.getSelection();
        if (!selection || !selection.rangeCount || !selection.isCollapsed) return null;

        let element = target || selection.anchorNode;
        if (element && element.nodeType === Node.TEXT_NODE) element = element.parentElement;
        const blockEl = element?.closest?.('.block-text[data-block-id], .block-text[data-index]');
        if (!blockEl) return null;

        const blockId = blockEl.dataset.blockId || null;
        const index = blockId ? this.state.getBlockIndexById(blockId) : parseInt(blockEl.dataset.index, 10);
        const block = this.state.doc.blocks[index];
        if (!block || block.type !== 'text') return null;

        const range = selection.getRangeAt(0);
        if (!blockEl.contains(range.startContainer) && range.startContainer !== blockEl) return null;
        const caretOffset = Formatter.getTextOffsetFromDomPosition(blockEl, range.startContainer, range.startOffset);
        if (caretOffset === null || caretOffset === undefined) return null;

        const prefixRange = document.createRange();
        prefixRange.selectNodeContents(blockEl);
        prefixRange.setEnd(range.startContainer, range.startOffset);

        return {
            blockEl,
            blockId: block.id,
            index,
            block,
            range,
            caretOffset,
            textBeforeCaret: prefixRange.toString()
        };
    }

    handleInput(event) {
        const target = event.target?.closest?.('.block-text[data-block-id], .block-text[data-index]');
        if (!target) return;

        const context = this.getActiveTextContext(target);
        if (!context) return;

        if (this.applyMarkdownInputRule(context)) {
            this.closeMenu();
            return;
        }

        const slashMatch = context.textBeforeCaret.match(/(?:^|\s)\/([\w -]*)$/);
        if (slashMatch) {
            const query = slashMatch[1] || '';
            const triggerLength = query.length + 1;
            this.openMenu('slash', query, {
                ...context,
                triggerStart: Math.max(0, context.caretOffset - triggerLength),
                triggerEnd: context.caretOffset
            });
            return;
        }

        const mentionMatch = context.textBeforeCaret.match(/(?:^|\s)@([\w -]*)$/);
        if (mentionMatch) {
            const query = mentionMatch[1] || '';
            const triggerLength = query.length + 1;
            this.openMenu('mention', query, {
                ...context,
                triggerStart: Math.max(0, context.caretOffset - triggerLength),
                triggerEnd: context.caretOffset
            });
            return;
        }

        this.closeMenu();
    }

    applyMarkdownInputRule(context) {
        const text = (context.blockEl.innerText || '').replace(/\u00a0/g, ' ');
        const trimmedRight = text.replace(/\r?\n/g, '').trimEnd();
        const id = context.block.id || (Date.now() + Math.random());

        const heading = text.match(/^(#{1,3})\s$/);
        if (heading) {
            this.state.updateBlockContent(context.index, '', 'input-rule');
            this.state.changeBlockStyle(context.index, `h${heading[1].length}`);
            setTimeout(() => this.ctrl.focusBlock(context.index, 'start'), 0);
            return true;
        }

        if (/^>\s$/.test(text)) {
            this.state.updateBlockContent(context.index, '', 'input-rule');
            this.state.changeBlockStyle(context.index, 'quote');
            setTimeout(() => this.ctrl.focusBlock(context.index, 'start'), 0);
            return true;
        }

        if (/^(?:-|\*)\s$/.test(text)) {
            this.state.replaceBlockAt(context.index, {
                id, type: 'ul', items: [{ text: '', level: 0 }]
            }, 'input-rule');
            setTimeout(() => this.ctrl.focusListItem(context.index, 0, 'start'), 0);
            return true;
        }

        if (/^1\.\s$/.test(text)) {
            this.state.replaceBlockAt(context.index, {
                id, type: 'ol', items: [{ text: '', level: 0 }]
            }, 'input-rule');
            setTimeout(() => this.ctrl.focusListItem(context.index, 0, 'start'), 0);
            return true;
        }

        if (/^\[\s?\]\s$/.test(text)) {
            this.state.replaceBlockAt(context.index, {
                id, type: 'checklist', items: [{ text: '', level: 0, checked: false }]
            }, 'input-rule');
            setTimeout(() => this.ctrl.focusListItem(context.index, 0, 'start'), 0);
            return true;
        }

        if (trimmedRight === '---' || trimmedRight === '___') {
            this.state.replaceBlockAt(context.index, { id, type: 'horizontalRule' }, 'input-rule');
            this.state.insertBlockAt(context.index + 1, {
                id: Date.now() + Math.random(), type: 'text', style: 'normal', content: '<br>'
            }, 'input-rule');
            setTimeout(() => this.ctrl.focusBlock(context.index + 1, 'start'), 0);
            return true;
        }

        return false;
    }

    getMentionItems() {
        const now = new Date();
        const pageNumber = this.ctrl.getCurrentPageIndex() + 1;
        return [
            { id: 'mention-today', label: now.toLocaleDateString(), hint: 'Today\'s date', keywords: 'today date calendar' },
            { id: 'mention-time', label: now.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }), hint: 'Current time', keywords: 'time now clock' },
            { id: 'mention-document', label: this.state.doc.title || 'Untitled', hint: 'Current document', keywords: 'document file title' },
            { id: 'mention-page', label: `Page ${pageNumber}`, hint: 'Current page reference', keywords: 'page reference' },
            { id: 'mention-user', label: 'You', hint: 'Current editor', keywords: 'person user me' }
        ];
    }

    openMenu(kind, query, context) {
        this.menuKind = kind;
        this.context = context;
        const items = kind === 'slash' ? this.slashItems : this.getMentionItems();
        const normalized = query.trim().toLowerCase();
        this.filteredItems = items.filter((item) => {
            if (!normalized) return true;
            return `${item.label} ${item.hint || ''} ${item.keywords || ''}`.toLowerCase().includes(normalized);
        }).slice(0, 10);
        this.activeIndex = Math.min(this.activeIndex, Math.max(0, this.filteredItems.length - 1));

        this.menu.innerHTML = this.filteredItems.length
            ? this.filteredItems.map((item, index) => `
                <button type="button" class="quick-insert-item ${index === this.activeIndex ? 'active' : ''}" data-smart-menu-index="${index}">
                    <span class="quick-insert-item-label">${Formatter.escapeHtml(item.label)}</span>
                    <span class="quick-insert-item-hint">${Formatter.escapeHtml(item.hint || '')}</span>
                </button>`).join('')
            : '<div class="quick-insert-empty">No matching commands</div>';

        const rect = context.range.getBoundingClientRect();
        const fallback = context.blockEl.getBoundingClientRect();
        const left = rect.left || fallback.left;
        const top = (rect.bottom || fallback.bottom) + 8;
        this.menu.style.left = `${Math.min(Math.max(8, left), Math.max(8, window.innerWidth - 340))}px`;
        this.menu.style.top = `${Math.min(Math.max(8, top), Math.max(8, window.innerHeight - 360))}px`;
        this.menu.classList.remove('hidden');
        this.menu.dataset.kind = kind;
        if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    handleKeydown(event) {
        if (!this.menu || this.menu.classList.contains('hidden')) return;

        if (event.key === 'ArrowDown') {
            event.preventDefault();
            event.stopImmediatePropagation();
            this.activeIndex = Math.min(this.filteredItems.length - 1, this.activeIndex + 1);
            this.renderActiveItem();
        } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            event.stopImmediatePropagation();
            this.activeIndex = Math.max(0, this.activeIndex - 1);
            this.renderActiveItem();
        } else if (event.key === 'Enter' || event.key === 'Tab') {
            const item = this.filteredItems[this.activeIndex];
            if (!item) return;
            event.preventDefault();
            event.stopImmediatePropagation();
            this.executeItem(item);
        } else if (event.key === 'Escape') {
            event.preventDefault();
            event.stopImmediatePropagation();
            this.closeMenu();
        }
    }

    renderActiveItem() {
        this.menu.querySelectorAll('[data-smart-menu-index]').forEach((item, index) => {
            item.classList.toggle('active', index === this.activeIndex);
            if (index === this.activeIndex) item.scrollIntoView({ block: 'nearest' });
        });
    }

    deleteTrigger({ blockEl, triggerStart, triggerEnd }) {
        const start = Formatter.resolveDomPositionFromTextOffset(blockEl, triggerStart);
        const end = Formatter.resolveDomPositionFromTextOffset(blockEl, triggerEnd);
        if (!start?.container || !end?.container) return null;

        const range = document.createRange();
        range.setStart(start.container, start.offset);
        range.setEnd(end.container, end.offset);
        range.deleteContents();
        range.collapse(true);

        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        return range;
    }

    replaceCurrentBlock(block, focusKind = 'text') {
        const context = this.context;
        if (!context) return;
        const current = this.state.doc.blocks[context.index];
        this.state.replaceBlockAt(context.index, {
            ...block,
            id: current?.id || block.id || (Date.now() + Math.random())
        }, 'quick-insert');
        this.ctrl.focusInsertedBlock(context.index, focusKind);
    }

    insertSmartChip(item) {
        const range = this.deleteTrigger(this.context);
        if (!range) return;

        const chip = document.createElement('span');
        chip.className = 'smart-chip';
        chip.contentEditable = 'false';
        chip.dataset.smartType = item.id.replace('mention-', '');
        chip.textContent = item.label;
        range.insertNode(chip);

        const spacer = document.createTextNode('\u00a0');
        chip.parentNode.insertBefore(spacer, chip.nextSibling);
        range.setStartAfter(spacer);
        range.collapse(true);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        this.ctrl.syncCurrentTextBlockFromDom();
    }

    executeItem(item) {
        if (!this.context) return;
        const context = this.context;
        this.closeMenu(false);

        if (item.id.startsWith('mention-')) {
            this.insertSmartChip(item);
            this.closeMenu();
            return;
        }

        this.deleteTrigger(context);
        this.ctrl.syncCurrentTextBlockFromDom();

        const id = context.block.id || (Date.now() + Math.random());
        switch (item.id) {
            case 'paragraph':
                this.state.changeBlockStyle(context.index, 'normal');
                this.ctrl.focusBlock(context.index, 'start');
                break;
            case 'heading1':
            case 'heading2':
            case 'heading3':
                this.state.changeBlockStyle(context.index, item.id.replace('heading', 'h'));
                this.ctrl.focusBlock(context.index, 'start');
                break;
            case 'quote':
                this.state.changeBlockStyle(context.index, 'quote');
                this.ctrl.focusBlock(context.index, 'start');
                break;
            case 'bulleted-list':
                this.replaceCurrentBlock({ id, type: 'ul', items: [{ text: '', level: 0 }] }, 'list');
                break;
            case 'numbered-list':
                this.replaceCurrentBlock({ id, type: 'ol', items: [{ text: '', level: 0 }] }, 'list');
                break;
            case 'checklist':
                this.replaceCurrentBlock({ id, type: 'checklist', items: [{ text: '', level: 0, checked: false }] }, 'list');
                break;
            case 'table':
                this.replaceCurrentBlock({ id, type: 'table', rows: [['', ''], ['', '']], colWidths: [50, 50] }, 'table');
                break;
            case 'horizontal-rule':
                this.replaceCurrentBlock({ id, type: 'horizontalRule' }, 'text');
                this.state.insertBlockAt(context.index + 1, { id: Date.now() + Math.random(), type: 'text', style: 'normal', content: '<br>' }, 'quick-insert');
                setTimeout(() => this.ctrl.focusBlock(context.index + 1, 'start'), 0);
                break;
            case 'page-break':
                this.replaceCurrentBlock({ id, type: 'pageBreak' }, 'text');
                this.state.insertBlockAt(context.index + 1, { id: Date.now() + Math.random(), type: 'text', style: 'normal', content: '<br>' }, 'quick-insert');
                setTimeout(() => this.ctrl.focusBlock(context.index + 1, 'start'), 0);
                break;
            case 'image':
                document.getElementById('btn-img-inline')?.click();
                break;
            case 'footnote':
                this.ctrl.insertNoteAtSelection('footnote');
                break;
            case 'endnote':
                this.ctrl.insertNoteAtSelection('endnote');
                break;
            case 'today': {
                const date = new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
                this.ctrl.engine.dispatch('replaceSelection', { text: date, source: 'smart-input' });
                break;
            }
        }
        this.closeMenu();
    }

    closeMenu(clearContext = true) {
        if (!this.menu) return;
        this.menu.classList.add('hidden');
        this.menu.innerHTML = '';
        this.menuKind = null;
        this.filteredItems = [];
        this.activeIndex = 0;
        if (clearContext) this.context = null;
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/state.js
// ================================================================
import { HistoryManager } from './history.js';
import { Formatter } from './formatter.js';
import { createStableId, ensureBlockIdentity } from './editor/id.js';
import { normalizeDocumentSchema, cloneDocumentValue } from './editor/schema.js';
import { Transaction } from './editor/transaction.js';
import { getBlockRuns, withBlockRuns } from './editor/inline/block-inline.js';
import { normalizeRuns } from './editor/inline/inline-model.js';
 
/**
 * =========================================================
 * CLASS: StateManager
 * =========================================================
 */
export class StateManager {
    constructor() {
        this.doc = {
            id: null,
            title: 'Loading...',
            blocks: [],
            settings: { pageSize: 'letter', margins: { top: 1, bottom: 1, left: 1, right: 1 }, trackChanges: false, schemaVersion: 4 },
            header: { left: 'OpenWord Doc', center: '', right: '' },
            footer: { left: '', center: 'Page {n}', right: '' },
            footnotes: [],
            endnotes: []
        };
        this.listeners = [];
        this._typedListeners = {};
        this.history = new HistoryManager(this);
        this.isDirty = false;
        this.hfMode = false;
        this._changeSeq = 0;
        this._saveTimer = null;
        this._recoveryTimer = null;
        this._retryTimer = null;
        this._saveChain = Promise.resolve();
        this._lastSaveError = null;
        this.pendingConflict = null;
        this.pendingRecovery = null;
        this.autosaveDelay = 1000;
        this.retryDelay = 4000;
        this._transactionDepth = 0;
        this.collaborationOwnsPersistence = false;
        this.setupAutosave();
    }

    subscribe(fn) { this.listeners.push(fn); }

    subscribeTo(eventType, fn) {
        if (!this._typedListeners[eventType]) this._typedListeners[eventType] = [];
        this._typedListeners[eventType].push(fn);
        return () => {
            const arr = this._typedListeners[eventType];
            if (arr) {
                const idx = arr.indexOf(fn);
                if (idx >= 0) arr.splice(idx, 1);
            }
        };
    }

    signal(eventType, data = {}) {
        const handlers = this._typedListeners[eventType];
        if (handlers) handlers.forEach(fn => fn(data));
    }

    // CHANGED: notify now passes the operation that caused the change
    notify(op = null) {
        this.listeners.forEach(fn => fn(this.doc, this.hfMode, op));
        if (op && op.type && this._typedListeners[op.type]) {
            this._typedListeners[op.type].forEach(fn => fn(op, this.doc, this.hfMode));
        }
        if (this._typedListeners['*']) {
            this._typedListeners['*'].forEach(fn => fn(op, this.doc, this.hfMode));
        }
    }

    setSaveStatus(status, detail = '') {
        const statusBar = document.getElementById('save-status');
        if (statusBar) statusBar.innerText = status;

        const indicator = document.getElementById('save-indicator');
        const indicatorText = document.getElementById('save-indicator-text');
        if (indicatorText) indicatorText.innerText = status;
        else if (indicator) indicator.innerText = status;

        if (indicator) {
            indicator.dataset.status = status.toLowerCase().replace(/[^a-z]+/g, '-').replace(/^-+|-+$/g, '');
            indicator.title = detail || (status === 'Saved' ? 'All changes saved' : status);
            indicator.setAttribute('aria-label', indicator.title);
        }
        this.signal('SAVE_STATUS_CHANGED', { status, detail });
    }

    markDirty(options = {}) {
        this.isDirty = true;
        this._changeSeq += 1;
        this.setSaveStatus(this.isOnline() ? 'Unsaved changes' : 'Offline');
        this.scheduleRecoveryBackup();
        if (!(this.collaborationOwnsPersistence && options.collaborativeTransaction)) this.scheduleSave('edit');
    }

    isOnline() {
        return typeof navigator === 'undefined' || navigator.onLine !== false;
    }

    setupAutosave() {
        if (typeof document !== 'undefined') {
            document.addEventListener('visibilitychange', () => {
                if (document.visibilityState === 'hidden') {
                    this.writeRecoveryBackup();
                    this.flushSave('visibility-change');
                }
            });
        }

        if (typeof window !== 'undefined') {
            window.addEventListener('online', () => {
                if (this.isDirty) this.flushSave('back-online');
                else this.setSaveStatus('Saved');
            });
            window.addEventListener('offline', () => {
                this.writeRecoveryBackup();
                this.setSaveStatus('Offline', 'Changes are stored in this browser until the connection returns.');
            });
            window.addEventListener('pagehide', () => this.writeRecoveryBackup());
            window.addEventListener('beforeunload', (event) => {
                if (!this.isDirty) return;
                this.writeRecoveryBackup();
                event.preventDefault();
                event.returnValue = '';
            });
        }
    }

    scheduleSave(reason = 'edit', delay = this.autosaveDelay) {
        if (!this.doc.id) return;
        clearTimeout(this._saveTimer);
        this._saveTimer = setTimeout(() => {
            this._saveTimer = null;
            this.flushSave(reason);
        }, delay);
    }

    flushSave(reason = 'manual', options = {}) {
        clearTimeout(this._saveTimer);
        this._saveTimer = null;
        const shouldSave = this.doc.id && (this.isDirty || options.allowClean || options.force);
        if (!shouldSave) return this._saveChain;

        this._saveChain = this._saveChain
            .catch(() => undefined)
            .then(() => this.performSave(reason, options));
        return this._saveChain;
    }

    async performSave(reason = 'manual', { force = false } = {}) {
        if (!this.doc.id) return null;
        if (!this.isOnline()) {
            this.writeRecoveryBackup();
            this.setSaveStatus('Offline', 'Changes are stored in this browser until the connection returns.');
            return null;
        }

        const saveSeq = this._changeSeq;
        const snapshot = JSON.parse(JSON.stringify(this.doc));
        const baseRevision = Number.isFinite(Number(snapshot.revision)) ? Number(snapshot.revision) : 0;
        this.setSaveStatus('Saving…');

        try {
            const response = await fetch(`/api/docs/${encodeURIComponent(snapshot.id)}${force ? '?force=1' : ''}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'If-Match': `W/"${snapshot.id}:${baseRevision}"`,
                    'X-OpenWord-Save-Reason': reason,
                    'X-OpenWord-Session': this.collaborationSessionId || ''
                },
                body: JSON.stringify({ document: snapshot, baseRevision })
            });

            if (response.status === 409) {
                const conflict = await response.json();
                this.pendingConflict = conflict;
                this.writeRecoveryBackup();
                this.setSaveStatus('Conflict', 'This document changed somewhere else. Choose which version to keep.');
                this.signal('SAVE_CONFLICT', conflict);
                return null;
            }

            if (!response.ok) {
                throw new Error(`Save failed with status ${response.status}`);
            }

            const result = await response.json();
            const saved = result.document || result;
            if (saved && Number.isFinite(Number(saved.revision))) this.doc.revision = Number(saved.revision);
            if (saved?.updatedAt) this.doc.updatedAt = saved.updatedAt;
            if (saved?.storageVersion) this.doc.storageVersion = saved.storageVersion;

            this.pendingConflict = null;
            this._lastSaveError = null;
            if (saveSeq === this._changeSeq) {
                this.isDirty = false;
                this.clearRecoveryBackup();
                this.setSaveStatus('Saved');
            } else {
                this.isDirty = true;
                this.setSaveStatus('Unsaved changes');
                this.scheduleSave('edit-during-save', 150);
            }
            this.signal('SAVE_SUCCEEDED', { document: saved, reason });
            return saved;
        } catch (error) {
            this._lastSaveError = error;
            this.writeRecoveryBackup();
            this.setSaveStatus(this.isOnline() ? 'Save failed' : 'Offline', error.message);
            this.signal('SAVE_FAILED', { error, reason });
            clearTimeout(this._retryTimer);
            if (this.isDirty && this.isOnline()) {
                this._retryTimer = setTimeout(() => this.flushSave('automatic-retry'), this.retryDelay);
            }
            return null;
        }
    }

    recoveryKey(docId = this.doc.id) {
        return docId ? `openword_recovery_${docId}` : null;
    }

    scheduleRecoveryBackup() {
        clearTimeout(this._recoveryTimer);
        this._recoveryTimer = setTimeout(() => this.writeRecoveryBackup(), 200);
    }

    writeRecoveryBackup() {
        const key = this.recoveryKey();
        if (!key || typeof localStorage === 'undefined' || !this.doc.id) return;
        try {
            localStorage.setItem(key, JSON.stringify({
                savedAt: new Date().toISOString(),
                baseRevision: Number(this.doc.revision) || 0,
                changeSeq: this._changeSeq,
                document: this.doc
            }));
        } catch (error) {
            // Storage may be unavailable in private browsing or the draft may
            // exceed quota. The server save path remains the primary store.
        }
    }

    readRecoveryBackup(docId = this.doc.id) {
        const key = this.recoveryKey(docId);
        if (!key || typeof localStorage === 'undefined') return null;
        try {
            const value = localStorage.getItem(key);
            return value ? JSON.parse(value) : null;
        } catch (error) {
            return null;
        }
    }

    clearRecoveryBackup(docId = this.doc.id) {
        const key = this.recoveryKey(docId);
        if (!key || typeof localStorage === 'undefined') return;
        try { localStorage.removeItem(key); } catch (error) { /* ignore */ }
    }

    getPageMetrics(pageSize = this.doc.settings?.pageSize || 'letter') {
        if (pageSize === 'a4') return { width: 8.27, height: 11.69 };
        return { width: 8.5, height: 11 };
    }

    clamp(value, min, max) {
        return Math.min(max, Math.max(min, value));
    }

    sanitizeMargins(margins, pageSize = this.doc.settings?.pageSize || 'letter') {
        const metrics = this.getPageMetrics(pageSize);
        const minMargin = 0.25;
        const minContentWidth = 2;
        const minContentHeight = 2;

        const next = {
            top: Number.isFinite(parseFloat(margins?.top)) ? parseFloat(margins.top) : 1,
            bottom: Number.isFinite(parseFloat(margins?.bottom)) ? parseFloat(margins.bottom) : 1,
            left: Number.isFinite(parseFloat(margins?.left)) ? parseFloat(margins.left) : 1,
            right: Number.isFinite(parseFloat(margins?.right)) ? parseFloat(margins.right) : 1
        };

        const maxSingleHorizontal = Math.max(minMargin, metrics.width - minContentWidth - minMargin);
        const maxSingleVertical = Math.max(minMargin, metrics.height - minContentHeight - minMargin);

        next.left = this.clamp(next.left, minMargin, maxSingleHorizontal);
        next.right = this.clamp(next.right, minMargin, maxSingleHorizontal);
        next.top = this.clamp(next.top, minMargin, maxSingleVertical);
        next.bottom = this.clamp(next.bottom, minMargin, maxSingleVertical);

        const maxHorizontalSum = Math.max(minMargin * 2, metrics.width - minContentWidth);
        const maxVerticalSum = Math.max(minMargin * 2, metrics.height - minContentHeight);

        if (next.left + next.right > maxHorizontalSum) {
            const scale = maxHorizontalSum / (next.left + next.right);
            next.left = Math.max(minMargin, next.left * scale);
            next.right = Math.max(minMargin, next.right * scale);
        }

        if (next.top + next.bottom > maxVerticalSum) {
            const scale = maxVerticalSum / (next.top + next.bottom);
            next.top = Math.max(minMargin, next.top * scale);
            next.bottom = Math.max(minMargin, next.bottom * scale);
        }

        return {
            top: Number(next.top.toFixed(2)),
            bottom: Number(next.bottom.toFixed(2)),
            left: Number(next.left.toFixed(2)),
            right: Number(next.right.toFixed(2))
        };
    }

    // ---------
    // FIX: On-load sanitization to prevent "blank page explosions"
    // caused by trailing/duplicate page breaks and meaningless empty text blocks.
    // ---------
    normalizeText(str) {
        return (str || '')
            .replace(/\u00A0/g, ' ')
            .replace(/[\u200B-\u200D\uFEFF]/g, '')
            .replace(/\s+/g, ' ')
            .trim();
    }

    isMeaningfullyEmptyTextBlock(block, tmpEl) {
        if (!block || block.type !== 'text') return false;

        const content = (typeof block.content === 'string') ? block.content : '';
        const raw = content.trim();

        if (!raw) return true;

        // Only <br> tags => empty
        if (/^(\s*<br\s*\/?>\s*)+$/i.test(raw)) return true;

        tmpEl.innerHTML = raw;
        const hasRich = !!tmpEl.querySelector('img, table, hr');
        const text = this.normalizeText(tmpEl.textContent || '');

        return !hasRich && text.length === 0;
    }

    sanitizeBlocks(blocks) {
        const tmp = document.createElement('div');
        let changed = false;

        if (!Array.isArray(blocks)) {
            return { blocks: [{ type: 'text', style: 'normal', content: '', id: createStableId('blk') }], changed: true };
        }

        // 1) Drop invalid blocks, ensure IDs
        const cleaned = [];
        for (const b of blocks) {
            if (!b || typeof b !== 'object') {
                changed = true;
                continue;
            }
            const result = ensureBlockIdentity(b);
            if (result.changed) changed = true;
            cleaned.push(result.block);
        }

        // 2) Collapse meaningless empty text blocks (keep at most N in a row)
        const out = [];
        const maxConsecutiveEmptyText = 2;
        let emptyTextRun = 0;

        for (const b of cleaned) {
            if (b.type === 'text') {
                const isEmpty = this.isMeaningfullyEmptyTextBlock(b, tmp);

                if (isEmpty) {
                    emptyTextRun++;

                    // Normalize stored empty to '' (remove &nbsp;/<br>/zero-width junk)
                    if (typeof b.content === 'string' && b.content !== '') {
                        b.content = '';
                        changed = true;
                    }

                    if (emptyTextRun <= maxConsecutiveEmptyText) {
                        out.push(b);
                    } else {
                        changed = true;
                    }
                } else {
                    emptyTextRun = 0;
                    out.push(b);
                }
            } else {
                emptyTextRun = 0;
                out.push(b);
            }
        }

        // 3) Collapse consecutive pageBreaks to one
        const collapsedBreaks = [];
        let lastWasBreak = false;
        for (const b of out) {
            if (b.type === 'pageBreak') {
                if (lastWasBreak) {
                    changed = true;
                    continue;
                }
                lastWasBreak = true;
                collapsedBreaks.push(b);
            } else {
                lastWasBreak = false;
                collapsedBreaks.push(b);
            }
        }

        // 4) Remove leading pageBreaks
        while (collapsedBreaks.length > 0 && collapsedBreaks[0].type === 'pageBreak') {
            collapsedBreaks.shift();
            changed = true;
        }

        // 5) Remove trailing pageBreaks (THIS is what creates blank pages on load)
        while (collapsedBreaks.length > 0 && collapsedBreaks[collapsedBreaks.length - 1].type === 'pageBreak') {
            collapsedBreaks.pop();
            changed = true;
        }

        // 6) If everything got nuked, keep one empty text block
        if (collapsedBreaks.length === 0) {
            changed = true;
            collapsedBreaks.push({ type: 'text', style: 'normal', content: '', id: createStableId('blk') });
        }

        return { blocks: collapsedBreaks, changed };
    }

    sanitizeTextContentHtml(html, { emptyAsBr = false } = {}) {
        return Formatter.normalizeTextBlockHtml(html, { emptyAsBr });
    }

    resolveBlockIndex(ref) {
        if (Number.isInteger(ref)) return ref;
        if (typeof ref === 'string') return this.getBlockIndexById(ref);
        if (ref && typeof ref === 'object') {
            if (ref.blockId) return this.getBlockIndexById(ref.blockId);
            if (Number.isInteger(ref.index)) return ref.index;
        }
        return -1;
    }

    resolveBlockId(ref) {
        if (typeof ref === 'string') return ref;
        const index = this.resolveBlockIndex(ref);
        return index >= 0 ? this.doc.blocks[index]?.id || null : null;
    }

    resolveInsertIndex(op) {
        if (Number.isInteger(op.index)) return op.index;
        if (op.previousBlockId) {
            const previous = this.getBlockIndexById(op.previousBlockId);
            if (previous >= 0) return previous + 1;
        }
        if (op.nextBlockId) {
            const next = this.getBlockIndexById(op.nextBlockId);
            if (next >= 0) return next;
        }
        return this.doc.blocks.length;
    }

    applyOp(op, recordHistory = true, { notify = true, dirty = true } = {}) {
        if (recordHistory) this.history.push(op);

        if (op.type === 'ADD_BLOCK') op.index = this.resolveInsertIndex(op);
        else if (op.blockId) {
            const resolved = this.getBlockIndexById(op.blockId);
            if (resolved >= 0) op.index = resolved;
        }

        switch (op.type) {
            case 'UPDATE_BLOCK':
                if (this.doc.blocks[op.index]) this.doc.blocks[op.index].content = op.content;
                break;
            case 'ADD_BLOCK': {
                const normalized = ensureBlockIdentity(op.block);
                op.block = normalized.block;
                op.blockId = op.block.id;
                this.doc.blocks.splice(op.index, 0, op.block);
                break;
            }
            case 'REMOVE_BLOCK':
                this.doc.blocks.splice(op.index, 1);
                break;
            case 'REPLACE_BLOCK_STATE':
                this.doc.blocks[op.index] = op.block;
                break;
            case 'SPLIT_BLOCK':
                this.doc.blocks[op.index] = op.block;
                this.doc.blocks.splice(op.index + 1, 0, op.newBlock);
                break;
            case 'UNSPLIT_BLOCK':
                this.doc.blocks[op.index] = op.prevBlock;
                this.doc.blocks.splice(op.index + 1, 1);
                break;
            case 'MOVE_BLOCK': {
                const fromIndex = Number.isInteger(op.fromIndex) ? op.fromIndex : this.resolveBlockIndex(op.blockId);
                if (fromIndex < 0) break;
                const [block] = this.doc.blocks.splice(fromIndex, 1);
                const toIndex = Math.max(0, Math.min(this.doc.blocks.length, Number(op.toIndex) || 0));
                this.doc.blocks.splice(toIndex, 0, block);
                op.fromIndex = fromIndex;
                op.toIndex = toIndex;
                break;
            }
            case 'MERGE_BLOCKS': {
                const target = this.doc.blocks[op.index];
                const prev = this.doc.blocks[op.index - 1];
                prev.content = this.sanitizeTextContentHtml(`${prev.content || ''}${target.content || ''}`, { emptyAsBr: false });
                this.doc.blocks.splice(op.index, 1);
                break;
            }
        }
        if (notify) this.notify(op);
        if (dirty) this.markDirty();
    }

    updateBlockContent(ref, newContent, source = 'typing') {
        const index = this.resolveBlockIndex(ref);
        const block = this.doc.blocks[index];
        if (!block) return false;
        const prev = block.content;
        const preserveEmptyPlaceholder = source !== 'typing';
        const normalized = this.sanitizeTextContentHtml(newContent, { emptyAsBr: preserveEmptyPlaceholder });
        if (prev === normalized) return false;
        this.applyOp({
            type: 'UPDATE_BLOCK',
            index,
            blockId: block.id,
            prevContent: prev,
            content: normalized,
            source
        });
        return true;
    }

    updateBlockContentById(blockId, newContent, source = 'typing') {
        return this.updateBlockContent(blockId, newContent, source);
    }

    generateToc() {
        const headings = [];
        this.doc.blocks.forEach((b, i) => {
            if (b.type === 'text' && ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'].includes(b.style)) {
                const tmp = document.createElement('div');
                tmp.innerHTML = b.content || '';
                headings.push({ index: i, style: b.style, text: tmp.textContent || '(Empty)', level: parseInt(b.style.slice(1)) });
            }
        });
        return headings;
    }

    getHeadingPageMap(headings) {
        const map = {};
        const pages = document.querySelectorAll('#workspace .page');
        headings.forEach(h => {
            const el = document.querySelector(`[data-index="${h.index}"]`);
            if (el) {
                for (let i = 0; i < pages.length; i++) {
                    if (pages[i].contains(el)) { map[h.index] = i + 1; break; }
                }
            }
        });
        return map;
    }

    addBlock(type, style = 'normal') {
        const id = createStableId('blk');
        let block = { type: 'text', style, content: '', id };
        if (type === 'ul' || type === 'ol') block = { type, items: [{ text: 'List Item', level: 0 }], id };
        else if (type === 'checklist') block = { type, items: [{ text: 'Task', level: 0, checked: false }], id };
        else if (type === 'table') block = { type, rows: [['H1', 'H2'], ['Cell 1', 'Cell 2']], colWidths: [50, 50], id };
        else if (type === 'pageBreak') block = { type: 'pageBreak', id };
        else if (type === 'horizontalRule') block = { type: 'horizontalRule', id };
        else if (type === 'floating') block = { type: 'object', objectType: 'textBox', id, anchor: { blockId: this.doc.blocks.at(-1)?.id || null, offset: 0, moveWithText: true, lockAnchor: false }, layout: { mode: 'floating', relativeTo: 'paragraph', x: 50, y: 50, width: 180, height: 80, rotation: 0, zIndex: 10, allowOverlap: true }, wrap: { type: 'square', side: 'right', distance: { top: 8, right: 8, bottom: 8, left: 8 } }, textBox: { blocks: [{ id: createStableId('tbblk'), type: 'text', style: 'normal', content: 'Floating Text' }], margins: { top: 8, right: 8, bottom: 8, left: 8 }, verticalAlign: 'top', autoFit: 'resizeShape', columns: 1 }, appearance: { fill: '#ffffff', fillOpacity: 1, borderColor: '#64748b', borderWidth: 1, borderStyle: 'solid', cornerRadius: 2, opacity: 1 } };
        else if (type === 'toc') block = { type: 'toc', id };

        const index = this.doc.blocks.length;
        this.applyOp({ type: 'ADD_BLOCK', index, block });
    }

    insertBlockAt(index, block, source = 'structure') {
        const result = ensureBlockIdentity(block);
        this.applyOp({
            type: 'ADD_BLOCK',
            index,
            blockId: result.block.id,
            block: result.block,
            previousBlockId: this.doc.blocks[index - 1]?.id || null,
            nextBlockId: this.doc.blocks[index]?.id || null,
            source
        });
        return result.block;
    }

    insertBlockAfter(blockId, block, source = 'structure') {
        const index = this.getBlockIndexById(blockId);
        return this.insertBlockAt(index >= 0 ? index + 1 : this.doc.blocks.length, block, source);
    }

    insertBlockBefore(blockId, block, source = 'structure') {
        const index = this.getBlockIndexById(blockId);
        return this.insertBlockAt(index >= 0 ? index : 0, block, source);
    }

    removeBlock(ref) {
        const index = this.resolveBlockIndex(ref);
        const block = this.doc.blocks[index];
        if (!block) return false;
        this.applyOp({
            type: 'REMOVE_BLOCK',
            index,
            blockId: block.id,
            block: JSON.parse(JSON.stringify(block)),
            previousBlockId: this.doc.blocks[index - 1]?.id || null,
            nextBlockId: this.doc.blocks[index + 1]?.id || null
        });
        return true;
    }

    removeBlockById(blockId) { return this.removeBlock(blockId); }
    replaceBlockAt(ref, block, source = 'structure') {
        const index = this.resolveBlockIndex(ref);
        const prevBlock = this.doc.blocks[index];
        if (!prevBlock || !block) return false;
        const result = ensureBlockIdentity({ ...block, id: block.id || prevBlock.id });
        this.applyOp({
            type: 'REPLACE_BLOCK_STATE',
            index,
            blockId: prevBlock.id,
            block: result.block,
            prevBlock: JSON.parse(JSON.stringify(prevBlock)),
            source
        });
        return true;
    }

    replaceBlockById(blockId, block, source = 'structure') { return this.replaceBlockAt(blockId, block, source); }
    splitTextBlock(ref, block, newBlock, source = 'enter', meta = {}) {
        const index = this.resolveBlockIndex(ref);
        const existing = this.doc.blocks[index];
        if (!existing) return false;
        const prevBlock = JSON.parse(JSON.stringify(existing));
        const blockResult = ensureBlockIdentity({ ...block, id: existing.id });
        const newBlockResult = ensureBlockIdentity(newBlock);
        this.applyOp({
            type: 'SPLIT_BLOCK',
            index,
            blockId: existing.id,
            newBlockId: newBlockResult.block.id,
            block: blockResult.block,
            newBlock: newBlockResult.block,
            prevBlock,
            source,
            ...meta
        });
        return true;
    }
    moveBlock(fromRef, toIndex) {
        const fromIndex = this.resolveBlockIndex(fromRef);
        const block = this.doc.blocks[fromIndex];
        if (!block || !Number.isInteger(toIndex)) return false;
        this.applyOp({ type: 'MOVE_BLOCK', blockId: block.id, fromIndex, toIndex });
        return true;
    }

    moveBlockById(blockId, toIndex) { return this.moveBlock(blockId, toIndex); }

    getBlockIndexById(blockId) {
        if (!blockId) return -1;
        for (let i = 0; i < this.doc.blocks.length; i++) {
            if (this.doc.blocks[i].id === blockId) return i;
        }
        return -1;
    }

    getBlockById(blockId) {
        const idx = this.getBlockIndexById(blockId);
        return idx >= 0 ? this.doc.blocks[idx] : null;
    }

    ensureBlockId(block) {
        if (!block) return block;
        const result = ensureBlockIdentity(block);
        return result.block;
    }

    applyTransaction(transaction, recordHistory = true, options = {}) {
        const tx = Transaction.from(transaction);
        if (recordHistory) this.history.push(tx);
        this._transactionDepth += 1;
        try {
            for (const op of tx.operations) this.applyOp(op, false, { notify: false, dirty: false });
        } finally {
            this._transactionDepth = Math.max(0, this._transactionDepth - 1);
        }
        this.notify(tx);
        if (options.dirty !== false) this.markDirty({ collaborativeTransaction: !options.remote });
        this.signal('TRANSACTION_APPLIED', { transaction: tx, remote: !!options.remote });
        return tx;
    }

    acknowledgeCollaborativeRevision(revision, updatedAt = null) {
        if (Number.isFinite(Number(revision))) this.doc.revision = Number(revision);
        if (updatedAt) this.doc.updatedAt = updatedAt;
        this.isDirty = false;
        clearTimeout(this._saveTimer); this._saveTimer = null;
        this.clearRecoveryBackup();
        this.setSaveStatus('Saved');
        this.signal('COLLABORATIVE_REVISION_ACKNOWLEDGED', { revision: this.doc.revision, updatedAt });
    }

    applyRemoteTransaction(transaction, revision, updatedAt = null) {
        const tx = Transaction.from(transaction);
        tx.meta = { ...(tx.meta || {}), remote: true };
        this.applyTransaction(tx, false, { dirty: false, remote: true });
        this.acknowledgeCollaborativeRevision(revision, updatedAt);
        return tx;
    }

    normalizeOperationIdentity(op) {
        if (op.blockId && op.index === undefined) {
            op.index = this.getBlockIndexById(op.blockId);
            if (op.index < 0) return false;
        }
        return true;
    }

    resolveOperationIndex(op) {
        if (op.blockId && op.index === undefined) {
            op.index = this.getBlockIndexById(op.blockId);
        }
        return op.index;
    }

    mergeBlockWithPrevious(index) {
        if (index <= 0) return false;
        const current = this.doc.blocks[index];
        const prev = this.doc.blocks[index - 1];
        if (current.type === 'text' && prev.type === 'text') {
            const removedBlock = JSON.parse(JSON.stringify(current));
            this.applyOp({ type: 'MERGE_BLOCKS', index: index, removedBlock: removedBlock, prevContent: prev.content });
            return true;
        }
        return false;
    }

    updateBlockProps(ref, props) {
        const index = this.resolveBlockIndex(ref);
        const prevBlock = this.doc.blocks[index];
        const newBlock = { ...prevBlock, ...props };
        this.applyOp({
            type: 'REPLACE_BLOCK_STATE',
            index,
            block: JSON.parse(JSON.stringify(newBlock)),
            prevBlock: JSON.parse(JSON.stringify(prevBlock))
        });
    }

    convertBlockToList(ref, listType = 'ul') {
        const index = this.resolveBlockIndex(ref);
        const block = this.doc.blocks[index];
        if (!block || block.type !== 'text') return false;
        const tmp = document.createElement('div');
        tmp.innerHTML = block.content || '';
        const lines = (tmp.textContent || '').split('\n').filter(l => l.trim().length > 0);
        if (lines.length === 0) lines.push('');
        const items = lines.map(text => ({ text, level: 0 }));
        const prevBlock = JSON.parse(JSON.stringify(block));
        const newBlock = { type: listType, items, id: block.id || createStableId('blk') };
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index, block: newBlock, prevBlock });
        return true;
    }

    convertBlockToText(ref) {
        const index = this.resolveBlockIndex(ref);
        const block = this.doc.blocks[index];
        if (!block || !['ul', 'ol', 'checklist'].includes(block.type)) return false;
        const lines = (block.items || []).map(i => i.text).filter(l => l.length > 0);
        const content = lines.length > 0 ? lines.join('<br>') : '<br>';
        const prevBlock = JSON.parse(JSON.stringify(block));
        const newBlock = { type: 'text', style: 'normal', content, id: block.id || createStableId('blk') };
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index, block: newBlock, prevBlock });
        return true;
    }

    toggleListType(ref) {
        const index = this.resolveBlockIndex(ref);
        const block = this.doc.blocks[index];
        if (!block || !['ul', 'ol', 'checklist'].includes(block.type)) return false;
        const newType = block.type === 'ul' ? 'ol' : 'ul';
        const prevBlock = JSON.parse(JSON.stringify(block));
        const newBlock = { ...block, type: newType };
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index, block: newBlock, prevBlock });
        return true;
    }

    getListItemIndex(block, itemRef) {
        if (Number.isInteger(itemRef)) return itemRef;
        return (block?.items || []).findIndex(item => item?.id === itemRef);
    }

    updateListItem(blockRef, itemRef, text) {
        const bIdx = this.resolveBlockIndex(blockRef);
        const block = this.doc.blocks[bIdx];
        const iIdx = this.getListItemIndex(block, itemRef);
        if (!block?.items?.[iIdx]) return false;
        block.items[iIdx].text = text;
        this.markDirty();
        this.notify({ type: 'LIST_ITEM_UPDATED', blockId: block.id, itemId: block.items[iIdx].id, blockIndex: bIdx, itemIndex: iIdx });
        return true;
    }
    updateListItemChecked(blockRef, itemRef, checked) {
        const bIdx = this.resolveBlockIndex(blockRef);
        const block = this.doc.blocks[bIdx];
        const iIdx = this.getListItemIndex(block, itemRef);
        if (!block?.items?.[iIdx]) return false;
        block.items[iIdx].checked = !!checked;
        this.markDirty();
        this.notify({ type: 'CHECKLIST_ITEM_TOGGLED', blockId: block.id, itemId: block.items[iIdx].id, blockIndex: bIdx, itemIndex: iIdx, checked: !!checked });
        return true;
    }
    indentListItem(blockRef, itemRef, direction) {
        const bIdx = this.resolveBlockIndex(blockRef);
        const prevBlock = this.doc.blocks[bIdx];
        const iIdx = this.getListItemIndex(prevBlock, itemRef);
        if (!prevBlock || iIdx < 0) return false;
        const newBlock = JSON.parse(JSON.stringify(prevBlock));
        const item = newBlock.items[iIdx];
        if (direction === 'in') item.level = Math.min((item.level || 0) + 1, 3);
        else item.level = Math.max((item.level || 0) - 1, 0);
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index: bIdx, blockId: prevBlock.id, block: newBlock, prevBlock });
        return true;
    }

    getTableCellPosition(block, cellRef, rowRef = null, colRef = null) {
        if (!block || block.type !== 'table') return null;
        if (typeof cellRef === 'string') {
            for (let r = 0; r < (block.cellIds || []).length; r += 1) {
                const c = block.cellIds[r]?.indexOf(cellRef) ?? -1;
                if (c >= 0) return { row: r, col: c };
            }
        }
        const row = Number.isInteger(rowRef) ? rowRef : Number.isInteger(cellRef) ? cellRef : -1;
        const col = Number.isInteger(colRef) ? colRef : -1;
        return row >= 0 && col >= 0 ? { row, col } : null;
    }

    updateTableCell(blockRef, rowOrCellRef, colOrText, maybeText) {
        const bIdx = this.resolveBlockIndex(blockRef);
        const block = this.doc.blocks[bIdx];
        const byCellId = typeof rowOrCellRef === 'string';
        const position = byCellId
            ? this.getTableCellPosition(block, rowOrCellRef)
            : this.getTableCellPosition(block, rowOrCellRef, rowOrCellRef, colOrText);
        const text = byCellId ? colOrText : maybeText;
        if (!position || !block?.rows?.[position.row]) return false;
        block.rows[position.row][position.col] = text;
        this.markDirty();
        this.notify({ type: 'TABLE_CELL_UPDATED', blockId: block.id, cellId: block.cellIds?.[position.row]?.[position.col], row: position.row, col: position.col });
        return true;
    }

    insertTableRow(blockRef, rowRef) {
        const bIdx = this.resolveBlockIndex(blockRef);
        const block = this.doc.blocks[bIdx];
        if (!block || block.type !== 'table' || !block.rows) return false;
        const cols = block.rows[0]?.length || 2;
        const prev = JSON.parse(JSON.stringify(block));
        const byId = typeof rowRef === 'string' ? block.rowIds?.indexOf(rowRef) : -1;
        const insertAt = byId >= 0 ? byId + 1 : (Number.isInteger(rowRef) && rowRef >= 0 ? rowRef : block.rows.length);
        block.rows.splice(insertAt, 0, new Array(cols).fill(''));
        ensureBlockIdentity(block);
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index: bIdx, blockId: block.id, block: JSON.parse(JSON.stringify(block)), prevBlock: prev });
        return true;
    }

    removeTableRow(blockRef, rowRef) {
        const bIdx = this.resolveBlockIndex(blockRef);
        const block = this.doc.blocks[bIdx];
        if (!block || block.type !== 'table' || !block.rows || block.rows.length <= 1) return false;
        const prev = JSON.parse(JSON.stringify(block));
        const byId = typeof rowRef === 'string' ? block.rowIds?.indexOf(rowRef) : -1;
        const removeAt = byId >= 0 ? byId : (Number.isInteger(rowRef) && rowRef >= 0 && rowRef < block.rows.length ? rowRef : block.rows.length - 1);
        block.rows.splice(removeAt, 1);
        block.rowIds?.splice(removeAt, 1);
        block.cellIds?.splice(removeAt, 1);
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index: bIdx, blockId: block.id, block: JSON.parse(JSON.stringify(block)), prevBlock: prev });
        return true;
    }

    insertTableCol(blockRef, colRef) {
        const bIdx = this.resolveBlockIndex(blockRef);
        const block = this.doc.blocks[bIdx];
        if (!block || block.type !== 'table' || !block.rows) return false;
        const prev = JSON.parse(JSON.stringify(block));
        let insertAt = Number.isInteger(colRef) && colRef >= 0 ? colRef : (block.rows[0]?.length || 0);
        if (typeof colRef === 'string') {
            const pos = this.getTableCellPosition(block, colRef);
            if (pos) insertAt = pos.col + 1;
        }
        block.rows.forEach(row => row.splice(insertAt, 0, ''));
        if (block.colWidths) block.colWidths.splice(insertAt, 0, 10);
        ensureBlockIdentity(block);
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index: bIdx, blockId: block.id, block: JSON.parse(JSON.stringify(block)), prevBlock: prev });
        return true;
    }

    removeTableCol(blockRef, colRef) {
        const bIdx = this.resolveBlockIndex(blockRef);
        const block = this.doc.blocks[bIdx];
        if (!block || block.type !== 'table' || !block.rows || block.rows[0]?.length <= 1) return false;
        const prev = JSON.parse(JSON.stringify(block));
        let removeAt = Number.isInteger(colRef) && colRef >= 0 ? colRef : block.rows[0].length - 1;
        if (typeof colRef === 'string') {
            const pos = this.getTableCellPosition(block, colRef);
            if (pos) removeAt = pos.col;
        }
        block.rows.forEach(row => row.splice(removeAt, 1));
        block.cellIds?.forEach(row => row.splice(removeAt, 1));
        if (block.colWidths) block.colWidths.splice(removeAt, 1);
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index: bIdx, blockId: block.id, block: JSON.parse(JSON.stringify(block)), prevBlock: prev });
        return true;
    }

    resizeTableCol(blockRef, colIdx, widthPercent) {
        const bIdx = this.resolveBlockIndex(blockRef);
        const prev = this.doc.blocks[bIdx];
        const next = JSON.parse(JSON.stringify(prev));
        if (!next.colWidths) next.colWidths = next.rows[0].map(() => 100 / next.rows[0].length);
        next.colWidths[colIdx] = widthPercent;
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index: bIdx, blockId: prev.id, block: next, prevBlock: prev });
    }

    updateFloatingPos(ref, x, y, pageIndex) {
        const index = this.resolveBlockIndex(ref);
        const prev = this.doc.blocks[index];
        if (!prev) return;
        const next = cloneDocumentValue(prev);
        if (next.type === 'object') {
            next.layout ||= {}; next.layout.x = x; next.layout.y = y;
            next.legacy ||= {}; if (pageIndex !== undefined) next.legacy.pageIndex = pageIndex;
        } else { next.x = x; next.y = y; next.pageIndex = pageIndex !== undefined ? pageIndex : (prev.pageIndex || 0); }
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index, blockId: prev.id, block: next, prevBlock: cloneDocumentValue(prev), source: 'objectMove' });
    }
    updateFloatingSize(ref, w, h) {
        const index = this.resolveBlockIndex(ref);
        const prev = this.doc.blocks[index];
        if (!prev) return;
        const next = cloneDocumentValue(prev);
        if (next.type === 'object') { next.layout ||= {}; next.layout.width = w; next.layout.height = h; }
        else { next.w = w; next.h = h; }
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index, blockId: prev.id, block: next, prevBlock: cloneDocumentValue(prev), source: 'objectResize' });
    }

    mergeTableCells(blockRef, anchorCellId, focusCellId = anchorCellId) {
        const index = this.resolveBlockIndex(blockRef), previous = this.doc.blocks[index];
        if (!previous || previous.type !== 'table') return false;
        const a = this.getTableCellPosition(previous, anchorCellId), f = this.getTableCellPosition(previous, focusCellId);
        if (!a || !f) return false;
        const top = Math.min(a.row, f.row), bottom = Math.max(a.row, f.row), left = Math.min(a.col, f.col), right = Math.max(a.col, f.col);
        if (top === bottom && left === right) return false;
        const next = cloneDocumentValue(previous); next.cellMeta ||= {}; const masterId = next.cellIds[top][left], content = [];
        for (let r = top; r <= bottom; r += 1) for (let c = left; c <= right; c += 1) { const id = next.cellIds[r][c]; if (next.rows[r][c]) content.push(next.rows[r][c]); if (id !== masterId) next.cellMeta[id] = { coveredBy: masterId }; }
        next.rows[top][left] = content.join('<br>'); next.cellMeta[masterId] = { rowspan: bottom - top + 1, colspan: right - left + 1 };
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index, blockId: previous.id, block: next, prevBlock: cloneDocumentValue(previous), source: 'tableMerge' }); return true;
    }

    splitTableCell(blockRef, cellId) {
        const index = this.resolveBlockIndex(blockRef), previous = this.doc.blocks[index]; if (!previous || previous.type !== 'table') return false;
        const next = cloneDocumentValue(previous); next.cellMeta ||= {}; const masterId = next.cellMeta[cellId]?.coveredBy || cellId; const master = next.cellMeta[masterId];
        if (!master) return false; Object.keys(next.cellMeta).forEach(id => { if (id === masterId || next.cellMeta[id]?.coveredBy === masterId) delete next.cellMeta[id]; });
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index, blockId: previous.id, block: next, prevBlock: cloneDocumentValue(previous), source: 'tableSplit' }); return true;
    }

    toggleTableHeaderRow(blockRef) {
        const index = this.resolveBlockIndex(blockRef), previous = this.doc.blocks[index]; if (!previous || previous.type !== 'table') return false;
        const next = cloneDocumentValue(previous); next.headerRows = next.headerRows === 1 ? 0 : 1;
        this.applyOp({ type: 'REPLACE_BLOCK_STATE', index, blockId: previous.id, block: next, prevBlock: cloneDocumentValue(previous), source: 'tableHeader' }); return true;
    }

    updateImageProps(ref, props) {
        this.updateBlockProps(ref, props);
    }
    renameDoc(newTitle) {
        this.doc.title = newTitle;
        this.markDirty();
        this.signal('RENAME_DOC', { title: newTitle });
        this.notify();
    }

    updateSettings(settings) {
        const nextSettings = {
            ...this.doc.settings,
            ...settings
        };
        nextSettings.margins = this.sanitizeMargins(nextSettings.margins, nextSettings.pageSize);
        this.doc.settings = nextSettings;
        this.signal('SETTINGS_CHANGED', { settings: nextSettings });
        this.notify();
        this.markDirty();
    }

    updateMargins(side, valueInches) {
        const nextMargins = {
            ...this.doc.settings.margins,
            [side]: parseFloat(valueInches)
        };
        this.doc.settings.margins = this.sanitizeMargins(nextMargins, this.doc.settings.pageSize);
        this.notify();
        this.markDirty();
    }

    toggleHFMode(isActive) { this.hfMode = isActive; this.notify(); }
    updateHeaderFooter(section, align, val) { this.doc[section][align] = val; this.markDirty(); }
    changeBlockStyle(index, style) { this.updateBlockProps(index, { style }); }

    async loadDocsList() {
        const res = await fetch('/api/docs', { cache: 'no-store' });
        if (!res.ok) throw new Error(`Unable to load documents (${res.status})`);
        return await res.json();
    }

    async loadDoc(id, { skipFlush = false } = {}) {
        const previousId = this.doc.id;
        if (!skipFlush && previousId && previousId !== id && this.isDirty) {
            await this.flushSave('switch-document');
        }

        this.setSaveStatus('Loading…');
        const res = await fetch(`/api/docs/${encodeURIComponent(id)}`, { cache: 'no-store' });
        if (!res.ok) {
            if (res.status === 404) { await this.createNewDoc(); return; }
            this.setSaveStatus('Load failed');
            throw new Error(`Unable to load document (${res.status})`);
        }
        let data = await res.json();

        if (!data) { await this.createNewDoc(); return; }

        if (data.blocks) data.blocks.forEach(b => {
            if (b.type === 'table' && !b.colWidths) b.colWidths = [50, 50];
            if (['ul', 'ol', 'checklist'].includes(b.type) && Array.isArray(b.items) && typeof b.items[0] === 'string') {
                b.items = b.items.map(t => ({ text: t, level: 0, checked: false }));
            }
            if (b.type === 'checklist') {
                b.items = (b.items || []).map(item => ({ text: '', level: 0, checked: false, ...item }));
            }
            if (b.type === 'image' && typeof b.width === 'string') b.width = 100;
            if (b.type === 'floating' && b.pageIndex === undefined) b.pageIndex = 0;
        });

        if (!data.settings) data.settings = { pageSize: 'letter', margins: { top: 1, bottom: 1, left: 1, right: 1 }, trackChanges: false };
        if (!data.settings.margins) data.settings.margins = { top: 1, bottom: 1, left: 1, right: 1 };
        if (data.settings.trackChanges === undefined) data.settings.trackChanges = false;
        if (!data.footnotes) data.footnotes = [];
        if (!data.endnotes) data.endnotes = [];
        if (!Number.isFinite(Number(data.revision))) data.revision = 0;
        data.settings.margins = this.sanitizeMargins(data.settings.margins, data.settings.pageSize);

        // Apply current schema migrations, including stable object records.
        {
            const migration = normalizeDocumentSchema(data);
            data = migration.document;
            data.settings.schemaVersion = data.schemaVersion;
        }

        const beforeSig = JSON.stringify((data.blocks || []).map(b => ({ t: b.type, c: b.content, id: b.id })));
        const sanitized = this.sanitizeBlocks(data.blocks || []);
        data.blocks = sanitized.blocks;
        const afterSig = JSON.stringify((data.blocks || []).map(b => ({ t: b.type, c: b.content, id: b.id })));

        this.doc = data;
        this.hfMode = false;
        this.isDirty = false;
        this._changeSeq = 0;
        this.pendingConflict = null;
        this.history.undoStack = [];
        this.history.redoStack = [];
        this.notify({ type: 'DOCUMENT_LOADED', documentId: data.id });
        this.setSaveStatus('Saved');

        const recovery = this.readRecoveryBackup(data.id);
        if (recovery?.document) {
            const recoveryTime = Date.parse(recovery.savedAt || 0);
            const serverTime = Date.parse(data.updatedAt || 0);
            if (recoveryTime > serverTime) {
                this.pendingRecovery = recovery;
                this.signal('RECOVERY_AVAILABLE', recovery);
            } else {
                this.clearRecoveryBackup(data.id);
            }
        }

        if (sanitized.changed || beforeSig !== afterSig) {
            this.markDirty();
            await this.flushSave('document-cleanup');
        }
    }

    async createNewDoc(template = null) {
        if (this.doc.id && this.isDirty) await this.flushSave('new-document');
        const res = await fetch('/api/docs', {
            method: 'POST',
            body: JSON.stringify({ title: template?.title || 'Untitled' }),
            headers: { 'Content-Type': 'application/json' }
        });
        if (!res.ok) throw new Error(`Unable to create document (${res.status})`);
        let created = await res.json();

        if (template?.blocks) {
            const templateDoc = {
                ...created,
                title: template.title || created.title,
                blocks: template.blocks
            };
            const saveRes = await fetch(`/api/docs/${encodeURIComponent(created.id)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ document: templateDoc, baseRevision: created.revision || 0 })
            });
            if (saveRes.ok) {
                const result = await saveRes.json();
                created = result.document || result;
            }
        }

        await this.loadDoc(created.id, { skipFlush: true });
        return created;
    }

    save(options = {}) {
        return this.flushSave('manual', { allowClean: true, ...options });
    }

    async loadRevisions() {
        if (!this.doc.id) return [];
        const response = await fetch(`/api/docs/${encodeURIComponent(this.doc.id)}/revisions`, { cache: 'no-store' });
        if (!response.ok) throw new Error(`Unable to load version history (${response.status})`);
        const result = await response.json();
        return result.revisions || [];
    }

    async restoreRevision(revision) {
        if (!this.doc.id) return null;
        const response = await fetch(`/api/docs/${encodeURIComponent(this.doc.id)}/revisions/${encodeURIComponent(revision)}/restore`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ baseRevision: Number(this.doc.revision) || 0 })
        });
        if (response.status === 409) {
            const conflict = await response.json();
            this.pendingConflict = conflict;
            this.signal('SAVE_CONFLICT', conflict);
            this.setSaveStatus('Conflict');
            return null;
        }
        if (!response.ok) throw new Error(`Unable to restore version (${response.status})`);
        const result = await response.json();
        const restored = result.document || result;
        await this.loadDoc(restored.id, { skipFlush: true });
        this.signal('REVISION_RESTORED', { revision, document: restored });
        return restored;
    }

    recoverLocalDraft() {
        const recovery = this.pendingRecovery || this.readRecoveryBackup();
        if (!recovery?.document) return false;
        const serverRevision = Number(this.doc.revision) || 0;
        let recovered = {
            ...recovery.document,
            id: this.doc.id,
            revision: serverRevision,
            updatedAt: this.doc.updatedAt
        };
        // Apply schema migration for recovered documents
        if (!recovered.settings?.schemaVersion || recovered.settings.schemaVersion < 2) {
            const migration = normalizeDocumentSchema(recovered);
            recovered = migration.document;
            recovered.settings = recovered.settings || {};
            recovered.settings.schemaVersion = 2;
        }
        this.doc = recovered;
        this.pendingRecovery = null;
        this.isDirty = true;
        this._changeSeq += 1;
        this.notify({ type: 'LOCAL_DRAFT_RECOVERED' });
        this.scheduleSave('recovered-local-draft', 50);
        this.setSaveStatus('Unsaved changes');
        return true;
    }

    discardLocalRecovery() {
        this.pendingRecovery = null;
        this.clearRecoveryBackup();
        this.signal('RECOVERY_DISCARDED');
    }

    async resolveSaveConflict(strategy) {
        const conflict = this.pendingConflict;
        if (!conflict || !this.doc.id) return null;

        if (strategy === 'reload') {
            const id = this.doc.id;
            this.pendingConflict = null;
            this.clearRecoveryBackup(id);
            await this.loadDoc(id, { skipFlush: true });
            return this.doc;
        }

        if (strategy === 'overwrite') {
            this.pendingConflict = null;
            this.isDirty = true;
            return await this.flushSave('conflict-overwrite', { force: true });
        }

        if (strategy === 'copy') {
            const localCopy = JSON.parse(JSON.stringify(this.doc));
            const createResponse = await fetch('/api/docs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title: `${localCopy.title || 'Untitled'} (Recovered copy)` })
            });
            if (!createResponse.ok) throw new Error(`Unable to create recovered copy (${createResponse.status})`);
            const created = await createResponse.json();
            localCopy.id = created.id;
            localCopy.title = created.title;
            localCopy.revision = created.revision || 0;
            localCopy.createdAt = created.createdAt;
            const saveResponse = await fetch(`/api/docs/${encodeURIComponent(created.id)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ document: localCopy, baseRevision: created.revision || 0 })
            });
            if (!saveResponse.ok) throw new Error(`Unable to save recovered copy (${saveResponse.status})`);
            this.pendingConflict = null;
            this.clearRecoveryBackup(this.doc.id);
            await this.loadDoc(created.id, { skipFlush: true });
            return this.doc;
        }

        return null;
    }

    async duplicateDoc(id) {
        const response = await fetch(`/api/docs/${encodeURIComponent(id)}/duplicate`, { method: 'POST' });
        if (!response.ok) throw new Error(`Unable to duplicate document (${response.status})`);
        return await response.json();
    }

    async deleteDoc(id) {
        const response = await fetch(`/api/docs/${encodeURIComponent(id)}`, { method: 'DELETE' });
        if (!response.ok) throw new Error(`Unable to delete document (${response.status})`);
        this.clearRecoveryBackup(id);
        return await response.json();
    }
    async uploadImage(file) {
        const fd = new FormData();
        fd.append('image', file);
        const res = await fetch('/api/upload/image', { method: 'POST', body: fd });
        if (!res.ok) {
            const error = await res.json().catch(() => ({}));
            throw new Error(error.error || `Image upload failed (${res.status})`);
        }
        return await res.json();
    }

    // ---- Footnotes & Endnotes ----
    addFootnote(blockIndex, noteContent = '', offset = null, blockId = null) {
        if (!this.doc.footnotes) this.doc.footnotes = [];
        const fnNum = this.doc.footnotes.length + 1;
        const fn = { id: createStableId('fn'), number: fnNum, content: noteContent || '', blockIndex, blockId, offset, type: 'footnote' };
        this.doc.footnotes.push(fn);
        this.markDirty();
        this.notify({ type: 'ADD_FOOTNOTE', footnote: fn });
        return fn;
    }

    addEndnote(blockIndex, noteContent = '', offset = null, blockId = null) {
        if (!this.doc.endnotes) this.doc.endnotes = [];
        const enNum = this.doc.endnotes.length + 1;
        const en = { id: createStableId('en'), number: enNum, content: noteContent || '', blockIndex, blockId, offset, type: 'endnote' };
        this.doc.endnotes.push(en);
        this.markDirty();
        this.notify({ type: 'ADD_ENDNOTE', endnote: en });
        return en;
    }

    getFootnotes() { return this.doc.footnotes || []; }
    getEndnotes() { return this.doc.endnotes || []; }

    updateFootnoteContent(fnId, content) {
        const fn = (this.doc.footnotes || []).find(f => f.id === fnId);
        if (fn) { fn.content = content; this.markDirty(); this.notify(); }
    }

    updateEndnoteContent(enId, content) {
        const en = (this.doc.endnotes || []).find(e => e.id === enId);
        if (en) { en.content = content; this.markDirty(); this.notify(); }
    }

    removeFootnote(fnId) {
        const idx = (this.doc.footnotes || []).findIndex(f => f.id === fnId);
        if (idx >= 0) {
            this.doc.footnotes.splice(idx, 1);
            this.doc.footnotes.forEach((f, i) => { f.number = i + 1; });
            this.markDirty(); this.notify();
        }
    }

    removeEndnote(enId) {
        const idx = (this.doc.endnotes || []).findIndex(e => e.id === enId);
        if (idx >= 0) {
            this.doc.endnotes.splice(idx, 1);
            this.doc.endnotes.forEach((e, i) => { e.number = i + 1; });
            this.markDirty(); this.notify();
        }
    }

    upsertNamedStyle(styleId, definition) {
        this.doc.styles ||= {};
        this.doc.styles[styleId] = { id: styleId, ...(this.doc.styles[styleId] || {}), ...cloneDocumentValue(definition) };
        this.markDirty(); this.notify({ type: 'STYLE_UPDATED', styleId }); return this.doc.styles[styleId];
    }

    deleteNamedStyle(styleId) {
        if (!this.doc.styles?.[styleId] || ['normal', 'h1', 'h2', 'h3', 'quote'].includes(styleId)) return false;
        delete this.doc.styles[styleId]; this.doc.blocks.forEach(block => { if (block.style === styleId) block.style = 'normal'; });
        this.markDirty(); this.notify({ type: 'STYLE_DELETED', styleId }); return true;
    }

    insertSectionBreak(afterBlockId, settings = {}) {
        const afterIndex = this.resolveBlockIndex(afterBlockId);
        const sectionId = createStableId('sec');
        const block = { id: createStableId('blk'), type: 'sectionBreak', sectionId, settings: { ...cloneDocumentValue(this.doc.settings), ...settings } };
        this.insertBlockAt(afterIndex >= 0 ? afterIndex + 1 : this.doc.blocks.length, block, 'section');
        const nextBlock = this.doc.blocks[afterIndex + 2];
        this.doc.sections ||= [];
        this.doc.sections.push({ id: sectionId, startBlockId: nextBlock?.id || null, settings: cloneDocumentValue(block.settings), header: cloneDocumentValue(this.doc.header), footer: cloneDocumentValue(this.doc.footer) });
        this.markDirty(); this.notify({ type: 'SECTION_ADDED', sectionId }); return block;
    }

    addComment({ anchor, body, author = 'User' }) {
        this.doc.comments ||= [];
        const comment = { id: createStableId('comment'), threadId: createStableId('thread'), author, anchor: cloneDocumentValue(anchor), status: 'open', createdAt: new Date().toISOString(), messages: [{ id: createStableId('message'), author, body: String(body), createdAt: new Date().toISOString() }] };
        this.doc.comments.push(comment); this.markDirty(); this.notify({ type: 'COMMENT_ADDED', comment }); return comment;
    }
    replyToComment(commentId, body, author = 'User') { const comment = this.doc.comments?.find(item => item.id === commentId); if (!comment) return false; comment.messages.push({ id: createStableId('message'), author, body: String(body), createdAt: new Date().toISOString() }); this.markDirty(); this.notify({ type: 'COMMENT_REPLIED', commentId }); return true; }
    toggleCommentResolved(commentId) { const comment = this.doc.comments?.find(item => item.id === commentId); if (!comment) return false; comment.status = comment.status === 'resolved' ? 'open' : 'resolved'; this.markDirty(); this.notify({ type: 'COMMENT_STATUS', commentId, status: comment.status }); return true; }
    deleteComment(commentId) { const index = this.doc.comments?.findIndex(item => item.id === commentId) ?? -1; if (index < 0) return false; this.doc.comments.splice(index, 1); this.markDirty(); this.notify({ type: 'COMMENT_DELETED', commentId }); return true; }

    listRunRevisions() {
        const grouped = new Map();
        const add = (revision, block, text = '', kind = 'text') => {
            if (!revision?.id || !block?.id) return;
            const existing = grouped.get(revision.id) || {
                ...revision,
                id: revision.id,
                type: revision.type || 'insertion',
                kind: revision.kind || kind,
                blockId: block.id,
                blockIds: [],
                text: ''
            };
            if (!existing.blockIds.includes(block.id)) existing.blockIds.push(block.id);
            if (text) existing.text += text;
            grouped.set(revision.id, existing);
        };

        this.doc.blocks.forEach(block => {
            if (block.type === 'text') {
                getBlockRuns(block).forEach(run => add(run.marks?.revision, block, run.text, 'text'));
            }
            add(block.revision, block, block.type === 'object' ? (block.objectType === 'image' ? 'Image' : 'Text box') : ` ${block.type || 'block'} `, 'block');
            add(block.breakRevision, block, 'Paragraph break', 'paragraphBreak');
            (block.revisions || []).forEach(revision => add(revision, block, revision.text || '', 'legacy'));
        });

        return [...grouped.values()].sort((a, b) => {
            const left = Date.parse(a.createdAt || a.timestamp || 0) || 0;
            const right = Date.parse(b.createdAt || b.timestamp || 0) || 0;
            return left - right;
        });
    }

    resolveRunRevision(blockRef, revisionId, accept) {
        const index = this.resolveBlockIndex(blockRef), block = this.doc.blocks[index]; if (!block || block.type !== 'text') return false;
        const runs = [];
        getBlockRuns(block).forEach(run => { const revision = run.marks?.revision; if (!revision || revision.id !== revisionId) { runs.push(run); return; } const keep = revision.type === 'insertion' ? accept : !accept; if (keep) { const marks = { ...run.marks }; delete marks.revision; runs.push({ ...run, marks }); } });
        this.replaceBlockById(block.id, withBlockRuns(block, normalizeRuns(runs)), accept ? 'acceptRevision' : 'rejectRevision'); return true;
    }
    acceptRunRevision(blockRef, revisionId) { return this.resolveRunRevision(blockRef, revisionId, true); }
    rejectRunRevision(blockRef, revisionId) { return this.resolveRunRevision(blockRef, revisionId, false); }
    acceptAllRunRevisions() { this.listRunRevisions().forEach(revision => this.acceptRunRevision(revision.blockId, revision.id)); }
    rejectAllRunRevisions() { this.listRunRevisions().forEach(revision => this.rejectRunRevision(revision.blockId, revision.id)); }

    // ---- Tracked Changes ----
    toggleTrackChanges() {
        this.doc.settings.trackChanges = !this.doc.settings.trackChanges;
        this.doc.settings.editingMode = this.doc.settings.trackChanges ? 'suggesting' : 'editing';
        this.markDirty();
        this.notify({ type: 'TRACK_CHANGES_TOGGLED', active: this.doc.settings.trackChanges, editingMode: this.doc.settings.editingMode });
        return this.doc.settings.trackChanges;
    }

    addRevision(blockIndex, revision) {
        const block = this.doc.blocks[blockIndex];
        if (!block) return;
        if (!block.revisions) block.revisions = [];
        block.revisions.push({
            id: createStableId('rev'),
            author: 'User',
            timestamp: new Date().toISOString(),
            ...revision
        });
        this.markDirty();
        this.notify({ type: 'ADD_REVISION', blockIndex, revision: block.revisions[block.revisions.length - 1] });
    }

    acceptRevision(blockIndex, revisionId) {
        const block = this.doc.blocks[blockIndex];
        if (!block || !block.revisions) return false;
        const idx = block.revisions.findIndex(r => r.id === revisionId);
        if (idx < 0) return false;
        const rev = block.revisions[idx];
        if (rev.type === 'deletion') {
            block.content = rev.oldContent || block.content;
        }
        block.revisions.splice(idx, 1);
        this.markDirty();
        this.notify({ type: 'ACCEPT_REVISION', blockIndex, revisionId });
        return true;
    }

    rejectRevision(blockIndex, revisionId) {
        const block = this.doc.blocks[blockIndex];
        if (!block || !block.revisions) return false;
        const idx = block.revisions.findIndex(r => r.id === revisionId);
        if (idx < 0) return false;
        const rev = block.revisions[idx];
        if (rev.type === 'insertion') {
            block.content = rev.oldContent || block.content;
        }
        block.revisions.splice(idx, 1);
        this.markDirty();
        this.notify({ type: 'REJECT_REVISION', blockIndex, revisionId });
        return true;
    }

    acceptAllRevisions() {
        this.doc.blocks.forEach((block, i) => {
            if (!block.revisions) return;
            block.revisions = block.revisions.filter(r => {
                if (r.type === 'deletion') {
                    block.content = r.oldContent || block.content;
                }
                return false;
            });
        });
        this.markDirty();
        this.notify({ type: 'ACCEPT_ALL' });
    }

    rejectAllRevisions() {
        this.doc.blocks.forEach((block, i) => {
            if (!block.revisions) return;
            block.revisions = block.revisions.filter(r => {
                if (r.type === 'insertion') {
                    block.content = r.oldContent || block.content;
                }
                return false;
            });
        });
        this.markDirty();
        this.notify({ type: 'REJECT_ALL' });
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/sw.js
// ================================================================
const CACHE_NAME = 'opendoc-v3-custom-engine';
const ASSETS = [
  '/',
  '/index.html',
  '/css/variables.css',
  '/css/reset.css',
  '/css/layout.css',
  '/css/typography.css',
  '/css/components.css',
  '/css/shell.css',
  '/css/mobile.css',
  '/main.js',
  '/smart-input-manager.js',
  '/editor/editor-engine.js',
  '/editor/selection-bridge.js',
  '/editor/selection-model.js',
  '/editor/position-mapper.js',
  '/editor/transaction.js',
  '/editor/command-registry.js',
  '/editor/schema.js',
  '/editor/id.js',
  '/manifest.json',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS).catch(() => {});
    })
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  if (event.request.url.includes('/api/')) return;
  if (event.request.url.includes('/uploads/')) return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      return cached || fetch(event.request).then((response) => {
        if (response.ok && response.type === 'basic') {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, clone);
          });
        }
        return response;
      });
    })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      );
    })
  );
});


// ================================================================
// FILE: /home/luanngo/opendoc/public/toolbar-manager.js
// ================================================================
export class ToolbarManager {
    constructor(ctrl) {
        this.ctrl = ctrl;
        this.state = ctrl.state;
        this.renderer = ctrl.renderer;
        this.toolbarSelectionSnapshot = null;
        this.formatPainterStyle = null;
        this.formatPainterActive = false;
        this._floatingTimer = null;
    }

    captureToolbarSelection() {
        const sel = window.getSelection();
        if (!sel || !sel.rangeCount) return;

        const range = sel.getRangeAt(0).cloneRange();
        const blockEl = this.ctrl.resolveBlockElementFromNode(sel.anchorNode) || this.ctrl.getFallbackBlockElement();
        const blockIndex = blockEl ? parseInt(blockEl.dataset.index) : this.ctrl.activeBlockIndex;

        this.toolbarSelectionSnapshot = {
            range,
            blockIndex,
            pageIndex: this.ctrl.getCurrentPageIndex()
        };

        if (blockEl) {
            this.ctrl.lastFocusedBlockEl = blockEl;
            this.ctrl.activeBlockIndex = blockIndex;
        }
    }

    restoreToolbarSelection() {
        if (!this.toolbarSelectionSnapshot) return false;

        const snap = this.toolbarSelectionSnapshot;
        if (Number.isInteger(snap.blockIndex)) {
            const blockEl = document.querySelector(`[data-index="${snap.blockIndex}"]`);
            if (blockEl) {
                this.ctrl.lastFocusedBlockEl = blockEl;
                this.ctrl.activeBlockIndex = snap.blockIndex;
            }
        }

        try {
            const sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(snap.range.cloneRange());
            return true;
        } catch (err) {
            return false;
        }
    }

    bindToolbarButton(id, handler, { preserveSelection = false } = {}) {
        const el = document.getElementById(id);
        if (!el) return;

        el.addEventListener('mousedown', (e) => {
            if (preserveSelection) this.captureToolbarSelection();
            e.preventDefault();
        });

        el.addEventListener('click', (e) => {
            if (preserveSelection) this.restoreToolbarSelection();
            handler(e);
        });
    }

    modifyIndent(delta) {
        if (this.ctrl.activeBlockIndex === null) return;
        const b = this.state.doc.blocks[this.ctrl.activeBlockIndex];
        if (b.type === 'text') {
            let val = (b.indent || 0) + delta;
            if (val < 0) val = 0;
            this.state.updateBlockProps(this.ctrl.activeBlockIndex, { indent: val });
        }
    }

    insertBlocksAfterActive(blocks, focusKind = 'text', focusIndexOffset = 0) {
        const baseIndex = this.ctrl.pendingInsertIndex ?? this.ctrl.getInsertBaseIndex();
        this.ctrl.pendingInsertIndex = null;
        const insertAt = Math.max(0, baseIndex + 1);

        blocks.forEach((block, i) => this.state.insertBlockAt(insertAt + i, block));
        this.ctrl.focusInsertedBlock(insertAt + focusIndexOffset, focusKind);
        return insertAt;
    }

    updateToolbarState() {
        const marks = this.ctrl.engine.captureSelection()?.marks || [];
        ['bold', 'italic', 'underline', 'strikethrough', 'code', 'superscript', 'subscript'].forEach((m) => {
            const active = marks.includes(m);
            const b = document.getElementById(`btn-${m}`);
            if (b) b.classList.toggle('active', active);
            document.querySelectorAll(`[data-command-target="btn-${m}"]`).forEach((proxy) => {
                proxy.classList.toggle('active', active);
            });
        });
    }

    updateContextualToolbar() {
        const ctx = this.ctrl.getActiveBlockContextFromSelection();
        const sel = window.getSelection();

        const hasSelection = sel && !sel.isCollapsed && sel.toString().trim().length > 0;
        let activeBlockType = 'text';
        let activeBlock = null;

        if (ctx && ctx.index !== null) {
            activeBlock = this.state.doc.blocks[ctx.index];
            if (activeBlock) activeBlockType = activeBlock.type;
        }

        document.querySelectorAll('.contextual').forEach(el => el.classList.remove('active'));

        if (activeBlockType === 'image' || activeBlockType === 'object') {
            document.querySelector('.contextual-image')?.classList.add('active');
        } else if (activeBlockType === 'table') {
            document.querySelector('.contextual-table')?.classList.add('active');
        } else if (activeBlockType === 'ul' || activeBlockType === 'ol' || activeBlockType === 'checklist') {
            document.querySelector('.contextual-list')?.classList.add('active');
        } else if (hasSelection) {
            document.querySelector('.contextual-text-selection')?.classList.add('active');
        }
    }

    setupContextualToolbar() {
        document.addEventListener('selectionchange', () => {
            this.updateContextualToolbar();
            this.updateFloatingToolbar();
        });
        document.addEventListener('focusin', () => this.updateContextualToolbar());
    }

    updateFloatingToolbar() {
        if (this.formatPainterActive) return;

        const sel = window.getSelection();
        const flt = document.getElementById('floating-toolbar');
        if (!flt) return;

        if (!sel || sel.isCollapsed || !sel.toString().trim()) {
            flt.classList.remove('visible');
            flt.classList.add('hidden');
            return;
        }

        const range = sel.getRangeAt(0);
        const rect = range.getBoundingClientRect();
        if (!rect || rect.width === 0) {
            flt.classList.remove('visible');
            flt.classList.add('hidden');
            return;
        }

        const left = Math.min(Math.max(10, rect.left + rect.width / 2 - flt.offsetWidth / 2), window.innerWidth - flt.offsetWidth - 10);
        const top = Math.max(5, rect.top - flt.offsetHeight - 8);

        flt.style.left = left + 'px';
        flt.style.top = top + 'px';
        flt.classList.remove('hidden');

        clearTimeout(this._floatingTimer);
        this._floatingTimer = setTimeout(() => {
            flt.classList.add('visible');
        }, 10);

        this.updateFloatingToolbarState();
    }

    updateFloatingToolbarState() {
        const marks = this.ctrl.engine.captureSelection()?.marks || [];
        ['bold', 'italic', 'underline', 'strikethrough', 'code'].forEach((m) => {
            const b = document.getElementById(`flt-btn-${m}`);
            if (b) b.classList.toggle('active', marks.includes(m));
        });
    }

    hideFloatingToolbar() {
        const flt = document.getElementById('floating-toolbar');
        if (!flt) return;
        flt.classList.remove('visible');
        clearTimeout(this._floatingTimer);
        this._floatingTimer = setTimeout(() => {
            if (!flt.classList.contains('visible')) {
                flt.classList.add('hidden');
            }
        }, 150);
    }

    setupFloatingToolbar() {
        const flt = document.getElementById('floating-toolbar');
        if (!flt) return;

        const bindFltBtn = (id, handler) => {
            const el = document.getElementById(id);
            if (!el) return;
            el.addEventListener('mousedown', (e) => {
                this.captureToolbarSelection();
                e.preventDefault();
            });
            el.addEventListener('click', (e) => {
                this.restoreToolbarSelection();
                handler(e);
                this.hideFloatingToolbar();
            });
        };

        bindFltBtn('flt-btn-bold', () => this.ctrl.engine.dispatch('toggleBold'));
        bindFltBtn('flt-btn-italic', () => this.ctrl.engine.dispatch('toggleItalic'));
        bindFltBtn('flt-btn-underline', () => this.ctrl.engine.dispatch('toggleUnderline'));
        bindFltBtn('flt-btn-strikethrough', () => this.ctrl.engine.dispatch('toggleStrikethrough'));
        bindFltBtn('flt-btn-code', () => this.ctrl.engine.dispatch('toggleInlineCode'));

        const fltFontSize = document.getElementById('flt-sel-font-size');
        if (fltFontSize) {
            fltFontSize.addEventListener('mousedown', () => this.captureToolbarSelection());
            fltFontSize.addEventListener('change', (e) => {
                this.restoreToolbarSelection();
                ctrl.engine.dispatch('setFontSize', { fontSize: e.target.value });
                this.hideFloatingToolbar();
            });
        }

        const fltStyle = document.getElementById('flt-sel-style');
        if (fltStyle) {
            fltStyle.addEventListener('mousedown', () => this.captureToolbarSelection());
            fltStyle.addEventListener('change', (e) => {
                const blockIndex = this.ctrl.getInsertBaseIndex();
                if (blockIndex !== null && blockIndex >= 0) {
                    this.ctrl.engine.dispatch('setBlockStyle', { blockId: this.state.doc.blocks[blockIndex]?.id, style: e.target.value });
                }
                this.hideFloatingToolbar();
            });
        }

        flt.addEventListener('mouseenter', () => {
            clearTimeout(this._floatingTimer);
            flt.classList.add('visible');
        });

        flt.addEventListener('mouseleave', () => {
            this.hideFloatingToolbar();
        });
    }

    toggleFormatPainter() {
        if (this.formatPainterActive) {
            this.formatPainterActive = false;
            this.formatPainterStyle = null;
            document.getElementById('btn-format-painter').classList.remove('active-format-painter');
            document.body.style.cursor = '';
            return;
        }

        const sel = window.getSelection();
        if (!sel || sel.isCollapsed || !sel.toString().trim()) {
            return;
        }

        const range = sel.getRangeAt(0);
        const container = range.commonAncestorContainer;
        let el = container.nodeType === 3 ? container.parentElement : container;
        if (!el) return;

        const computed = window.getComputedStyle(el);
        this.formatPainterStyle = {
            fontFamily: computed.fontFamily,
            fontSize: computed.fontSize,
            fontWeight: computed.fontWeight,
            fontStyle: computed.fontStyle,
            textDecoration: computed.textDecoration,
            verticalAlign: computed.verticalAlign,
            color: computed.color,
            backgroundColor: computed.backgroundColor !== 'rgba(0, 0, 0, 0)' ? computed.backgroundColor : null
        };

        this.formatPainterActive = true;
        const btn = document.getElementById('btn-format-painter');
        if (btn) btn.classList.add('active-format-painter');
        document.body.style.cursor = 'crosshair';
    }

    paintFormat() {
        if (!this.formatPainterActive || !this.formatPainterStyle) return;

        const sel = window.getSelection();
        if (!sel || sel.isCollapsed || !sel.toString().trim()) return;

        const style = this.formatPainterStyle;
        const map = {};
        if (style.fontFamily && style.fontFamily !== 'normal') map.fontFamily = style.fontFamily.split(',')[0].replace(/"/g, '').trim();
        if (style.fontSize) map.fontSize = style.fontSize;
        if (style.fontWeight && style.fontWeight !== '400') map.fontWeight = style.fontWeight;
        if (style.fontStyle && style.fontStyle !== 'normal') map.fontStyle = style.fontStyle;
        if (style.verticalAlign && style.verticalAlign !== 'baseline') map.verticalAlign = style.verticalAlign;
        if (style.color && style.color !== 'rgb(0, 0, 0)') map.color = style.color;
        if (style.backgroundColor) map.backgroundColor = style.backgroundColor;
        if (style.textDecoration && style.textDecoration.includes('line-through')) map.textDecoration = 'line-through';
        if (style.textDecoration && style.textDecoration.includes('underline')) map.textDecoration = 'underline';

        this.ctrl.engine.dispatch('applyInlineStyle', map);

        this.formatPainterActive = false;
        this.formatPainterStyle = null;
        const btn = document.getElementById('btn-format-painter');
        if (btn) btn.classList.remove('active-format-painter');
        document.body.style.cursor = '';
    }

    showShellToast(message, timeout = 2400) {
        const toast = document.getElementById('shell-toast');
        if (!toast) return;
        toast.textContent = message;
        toast.classList.remove('hidden');
        clearTimeout(this._shellToastTimer);
        this._shellToastTimer = setTimeout(() => toast.classList.add('hidden'), timeout);
    }

    escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    setupToolbarMode() {
        const toolbar = document.querySelector('.toolbar.ribbon');
        const toggle = document.getElementById('btn-toolbar-mode');
        const label = document.getElementById('toolbar-mode-label');
        if (!toolbar || !toggle) return;

        const applyMode = (mode, persist = true) => {
            const expanded = mode === 'expanded';
            toolbar.classList.toggle('toolbar-mode-expanded', expanded);
            toolbar.classList.toggle('toolbar-mode-compact', !expanded);
            toolbar.classList.remove('pinned');
            toggle.setAttribute('aria-pressed', String(expanded));
            toggle.title = expanded ? 'Use compact toolbar' : 'Use expanded ribbon';
            if (label) label.textContent = expanded ? 'Compact' : 'Ribbon';
            if (persist) this.ctrl.savePreference('toolbarMode', mode);
        };

        const savedMode = this.ctrl.loadPreference('toolbarMode');
        applyMode(savedMode === 'expanded' ? 'expanded' : 'compact', false);

        toggle.addEventListener('click', () => {
            const expanded = toolbar.classList.contains('toolbar-mode-expanded');
            applyMode(expanded ? 'compact' : 'expanded');
        });
    }

    setupCompactToolbar() {
        const compact = document.getElementById('compact-toolbar');
        if (!compact) return;

        compact.querySelectorAll('[data-command-target]').forEach((proxy) => {
            proxy.addEventListener('mousedown', (e) => {
                this.captureToolbarSelection();
                e.preventDefault();
            });
            proxy.addEventListener('click', () => {
                this.restoreToolbarSelection();
                const target = document.getElementById(proxy.dataset.commandTarget);
                if (target) target.click();
            });
        });

        compact.querySelectorAll('[data-select-target]').forEach((proxy) => {
            const target = document.getElementById(proxy.dataset.selectTarget);
            if (!target) return;

            proxy.value = target.value;
            proxy.addEventListener('mousedown', () => this.captureToolbarSelection());
            proxy.addEventListener('change', () => {
                this.restoreToolbarSelection();
                target.value = proxy.value;
                target.dispatchEvent(new Event('change', { bubbles: true }));
            });
            target.addEventListener('change', () => { proxy.value = target.value; });
        });

        compact.querySelectorAll('[data-color-target]').forEach((proxy) => {
            const target = document.getElementById(proxy.dataset.colorTarget);
            if (!target) return;

            proxy.value = target.value;
            proxy.addEventListener('mousedown', () => this.captureToolbarSelection());
            proxy.addEventListener('input', () => {
                this.restoreToolbarSelection();
                target.value = proxy.value;
                target.dispatchEvent(new Event('input', { bubbles: true }));
            });
            target.addEventListener('input', () => { proxy.value = target.value; });
        });
    }

    async runFileAction(action) {
        const ctrl = this.ctrl;
        const state = this.state;
        const docId = state.doc?.id;

        switch (action) {
            case 'new':
                await state.createNewDoc();
                break;
            case 'open':
                document.getElementById('btn-docs')?.click();
                break;
            case 'copy': {
                if (!docId) return;
                await state.duplicateDoc(docId);
                const docs = await state.loadDocsList();
                if (docs?.length) await state.loadDoc(docs[0].id);
                this.showShellToast('Document copy created');
                break;
            }
            case 'rename': {
                const title = document.getElementById('doc-title-display');
                if (!title) return;
                title.focus();
                const range = document.createRange();
                range.selectNodeContents(title);
                const selection = window.getSelection();
                selection.removeAllRanges();
                selection.addRange(range);
                break;
            }
            case 'save':
                try {
                    state.setSaveStatus?.('Saving...');
                    await state.flushSave?.() || await state.save();
                    state.isDirty = false;
                    state.setSaveStatus?.('Saved');
                    this.showShellToast('All changes saved');
                } catch (err) {
                    state.setSaveStatus?.('Save failed');
                    this.showShellToast('Save failed: ' + (err.message || 'Unknown error'));
                }
                break;
            case 'import-docx':
                document.getElementById('inp-docx-import')?.click();
                break;
            case 'export-docx':
                ctrl.exportDOCX();
                break;
            case 'export-pdf':
                ctrl.exportPDF();
                break;
            case 'print':
                ctrl.printDocument();
                break;
            case 'page-setup':
                document.getElementById('modal-page')?.classList.remove('hidden');
                break;
            case 'details':
                this.openShellPanel('details');
                break;
            case 'trash': {
                if (!docId || !window.confirm(`Move "${state.doc.title || 'Untitled'}" to trash?`)) return;
                await state.deleteDoc(docId);
                const docs = await state.loadDocsList();
                if (docs?.length) await state.loadDoc(docs[0].id);
                else await state.createNewDoc();
                this.showShellToast('Document moved to trash');
                break;
            }
        }
    }

    setupFileMenu() {
        const trigger = document.getElementById('btn-file-menu');
        const menu = document.getElementById('file-menu');
        if (!trigger || !menu) return;

        const close = () => {
            menu.classList.add('hidden');
            trigger.setAttribute('aria-expanded', 'false');
        };
        const open = () => {
            menu.classList.remove('hidden');
            trigger.setAttribute('aria-expanded', 'true');
            menu.querySelector('button')?.focus();
        };

        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            if (menu.classList.contains('hidden')) open();
            else close();
        });

        menu.addEventListener('click', async (e) => {
            const item = e.target.closest('[data-shell-action]');
            if (!item) return;
            close();
            await this.runFileAction(item.dataset.shellAction);
        });

        document.addEventListener('click', (e) => {
            if (!menu.classList.contains('hidden') && !menu.contains(e.target) && !trigger.contains(e.target)) close();
        });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') close();
        });
    }

    setupCommandSearch() {
        const input = document.getElementById('app-command-search');
        const results = document.getElementById('command-search-results');
        if (!input || !results) return;

        const commands = [
            { label: 'New document', category: 'File', action: 'new', keywords: 'blank create' },
            { label: 'Open documents', category: 'File', action: 'open', keywords: 'folder recent' },
            { label: 'Save document', category: 'File', action: 'save', keywords: 'save changes' },
            { label: 'Make a copy', category: 'File', action: 'copy', keywords: 'duplicate' },
            { label: 'Rename document', category: 'File', action: 'rename', keywords: 'title' },
            { label: 'Import Word document', category: 'File', action: 'import-docx', keywords: 'docx upload' },
            { label: 'Download as Word', category: 'File', action: 'export-docx', keywords: 'docx export' },
            { label: 'Download as PDF', category: 'File', action: 'export-pdf', keywords: 'pdf export' },
            { label: 'Print document', category: 'File', target: 'btn-print', keywords: 'printer' },
            { label: 'Undo', category: 'Edit', target: 'btn-undo', keywords: 'revert' },
            { label: 'Redo', category: 'Edit', target: 'btn-redo', keywords: 'repeat' },
            { label: 'Find and replace', category: 'Edit', target: 'btn-find', keywords: 'search replace' },
            { label: 'Bold', category: 'Format', target: 'btn-bold', keywords: 'strong' },
            { label: 'Italic', category: 'Format', target: 'btn-italic', keywords: 'emphasis' },
            { label: 'Underline', category: 'Format', target: 'btn-underline', keywords: 'format' },
            { label: 'Clear formatting', category: 'Format', target: 'btn-clear-fmt', keywords: 'remove style' },
            { label: 'Insert link', category: 'Insert', target: 'btn-link', keywords: 'url hyperlink' },
            { label: 'Insert image', category: 'Insert', target: 'btn-img-inline', keywords: 'picture photo' },
            { label: 'Insert table', category: 'Insert', target: 'btn-table', keywords: 'grid rows columns' },
            { label: 'Insert page break', category: 'Insert', target: 'btn-page-break', keywords: 'new page' },
            { label: 'Page setup', category: 'Layout', action: 'page-setup', keywords: 'margins paper' },
            { label: 'Show navigation outline', category: 'View', target: 'btn-toggle-outline', keywords: 'headings sidebar' },
            { label: 'Toggle ruler', category: 'View', target: 'btn-toggle-ruler', keywords: 'margins' },
            { label: 'Comments', category: 'Review', shellPanel: 'comments', keywords: 'discussion notes' },
            { label: 'Version history', category: 'Review', shellPanel: 'history', keywords: 'versions revisions' }
        ];

        let visible = [];
        let activeIndex = 0;

        const close = () => {
            results.classList.add('hidden');
            input.setAttribute('aria-expanded', 'false');
            activeIndex = 0;
        };

        const run = async (command) => {
            close();
            input.value = '';
            if (command.target) {
                this.restoreToolbarSelection();
                document.getElementById(command.target)?.click();
            } else if (command.action) {
                await this.runFileAction(command.action);
            } else if (command.shellPanel) {
                this.openShellPanel(command.shellPanel);
            }
        };

        const render = () => {
            const query = input.value.trim().toLowerCase();
            visible = commands.filter((command) => {
                const haystack = `${command.label} ${command.category} ${command.keywords || ''}`.toLowerCase();
                return !query || haystack.includes(query);
            }).slice(0, 10);
            activeIndex = Math.min(activeIndex, Math.max(0, visible.length - 1));

            if (!visible.length) {
                results.innerHTML = '<div class="command-search-empty">No matching commands</div>';
            } else {
                results.innerHTML = visible.map((command, index) => `
                    <button class="command-search-result ${index === activeIndex ? 'active' : ''}" data-command-index="${index}" role="option" aria-selected="${index === activeIndex}">
                        <span>${this.escapeHtml(command.label)}</span><small>${this.escapeHtml(command.category)}</small>
                    </button>
                `).join('');
            }
            results.classList.remove('hidden');
            input.setAttribute('aria-expanded', 'true');
        };

        input.addEventListener('mousedown', () => this.captureToolbarSelection());
        input.addEventListener('focus', render);
        input.addEventListener('input', render);
        input.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                activeIndex = Math.min(visible.length - 1, activeIndex + 1);
                render();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                activeIndex = Math.max(0, activeIndex - 1);
                render();
            } else if (e.key === 'Enter' && visible[activeIndex]) {
                e.preventDefault();
                run(visible[activeIndex]);
            } else if (e.key === 'Escape') {
                close();
                input.blur();
            }
        });

        results.addEventListener('mousedown', (e) => e.preventDefault());
        results.addEventListener('click', (e) => {
            const item = e.target.closest('[data-command-index]');
            if (item) run(visible[parseInt(item.dataset.commandIndex)]);
        });

        document.addEventListener('keydown', (e) => {
            if (e.altKey && e.key === '/') {
                e.preventDefault();
                this.captureToolbarSelection();
                input.focus();
                input.select();
            }
        });
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.command-search')) close();
        });
    }

    async openShellPanel(type) {
        const panel = document.getElementById('shell-side-panel');
        const backdrop = document.getElementById('shell-panel-backdrop');
        const title = document.getElementById('shell-side-panel-title');
        const body = document.getElementById('shell-side-panel-body');
        if (!panel || !backdrop || !title || !body) return;

        const doc = this.state.doc || {};
        const updated = doc.updatedAt ? new Date(doc.updatedAt) : new Date();

        if (type === 'history') {
            title.textContent = 'Version history';
            body.innerHTML = `<div class="shell-empty-state"><div class="save-spinner"></div><p>Loading version history...</p></div>`;
            panel.classList.remove('hidden');
            backdrop.classList.remove('hidden');

            try {
                const revisions = await this.state.loadRevisions();
                let html = `
                    <div class="version-entry">
                        <span class="version-entry-icon"><i data-lucide="check"></i></span>
                        <div><strong>Current version</strong><span>${this.escapeHtml(updated.toLocaleString())}</span></div>
                    </div>`;

                if (revisions && revisions.length > 0) {
                    revisions.forEach((rev, i) => {
                        const revDate = new Date(rev.createdAt || rev.updatedAt || Date.now());
                        const revisionNumber = Number(rev.revision) || (revisions.length - i);
                        html += `
                            <div class="version-entry">
                                <span class="version-entry-icon"><i data-lucide="history"></i></span>
                                <div>
                                    <strong>Revision ${revisionNumber}</strong>
                                    <span>${this.escapeHtml(revDate.toLocaleString())}</span>
                                    ${rev.reason ? `<span>${this.escapeHtml(rev.reason)}</span>` : ''}
                                    <div class="version-entry-actions">
                                        <button class="btn-primary" data-revision-id="${this.escapeHtml(revisionNumber)}">Restore</button>
                                    </div>
                                </div>
                            </div>`;
                    });
                } else {
                    html += `
                        <div class="shell-empty-state">
                            <i data-lucide="history"></i>
                            <h3>No saved revisions yet</h3>
                            <p>Revisions are created automatically when you save.</p>
                        </div>`;
                }
                body.innerHTML = html;
                if (typeof lucide !== 'undefined') lucide.createIcons();

                body.querySelectorAll('[data-revision-id]').forEach(btn => {
                    btn.addEventListener('click', async () => {
                        const revId = btn.dataset.revisionId;
                        if (!window.confirm('Restore this version? Current changes will be replaced.')) return;
                        await this.state.restoreRevision(revId);
                        this.showShellToast('Version restored');
                        closePanel();
                    });
                });
            } catch (err) {
                body.innerHTML = `
                    <div class="shell-empty-state">
                        <i data-lucide="history"></i>
                        <h3>Could not load version history</h3>
                        <p>${this.escapeHtml(err.message || 'Unknown error')}</p>
                    </div>`;
                if (typeof lucide !== 'undefined') lucide.createIcons();
            }
        } else if (type === 'comments') {
            title.textContent = 'Comments';
            this.ctrl.reviewManager?.renderComments(body);
        } else {
            title.textContent = 'Document details';
            body.innerHTML = `
                <div class="version-entry">
                    <span class="version-entry-icon"><i data-lucide="file-text"></i></span>
                    <div><strong>${this.escapeHtml(doc.title || 'Untitled')}</strong><span>Document ID: ${this.escapeHtml(doc.id || 'Not saved')}</span></div>
                </div>
                <div class="version-entry">
                    <span class="version-entry-icon"><i data-lucide="calendar-clock"></i></span>
                    <div><strong>Last updated</strong><span>${this.escapeHtml(updated.toLocaleString())}</span></div>
                </div>`;
        }

        panel.classList.remove('hidden');
        backdrop.classList.remove('hidden');
        if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    setupShellPanels() {
        const panel = document.getElementById('shell-side-panel');
        const backdrop = document.getElementById('shell-panel-backdrop');
        const share = document.getElementById('share-dialog');
        const closePanel = () => {
            panel?.classList.add('hidden');
            backdrop?.classList.add('hidden');
        };
        const closeShare = () => share?.classList.add('hidden');

        document.getElementById('btn-version-history')?.addEventListener('click', () => this.openShellPanel('history'));
        document.getElementById('btn-comments')?.addEventListener('click', () => this.openShellPanel('comments'));
        document.getElementById('btn-close-shell-panel')?.addEventListener('click', closePanel);
        backdrop?.addEventListener('click', closePanel);

        document.getElementById('btn-share')?.addEventListener('click', () => {
            const link = document.getElementById('share-link-input');
            if (link) link.value = window.location.href;
            share?.classList.remove('hidden');
        });
        document.getElementById('btn-close-share')?.addEventListener('click', closeShare);
        share?.addEventListener('click', (e) => { if (e.target === share) closeShare(); });
        document.getElementById('btn-copy-share-link')?.addEventListener('click', async () => {
            const link = document.getElementById('share-link-input');
            if (!link) return;
            try {
                await navigator.clipboard.writeText(link.value);
            } catch (err) {
                link.select();
                document.execCommand('copy');
            }
            this.showShellToast('Document link copied');
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closePanel();
                closeShare();
            }
        });
    }

    setupApplicationShell() {
        this.setupToolbarMode();
        this.setupCompactToolbar();
        this.setupFileMenu();
        this.setupCommandSearch();
        this.setupShellPanels();

        document.getElementById('save-indicator')?.addEventListener('click', () => this.runFileAction('save'));
        document.getElementById('btn-app-home')?.addEventListener('click', () => {
            document.getElementById('welcome-page')?.classList.remove('hidden');
        });
        document.getElementById('btn-star-document')?.addEventListener('click', (e) => {
            const button = e.currentTarget;
            const active = !button.classList.contains('active');
            button.classList.toggle('active', active);
            button.title = active ? 'Unstar document' : 'Star document';
            this.ctrl.savePreference(`starred_${this.state.doc?.id || 'current'}`, active);
            this.showShellToast(active ? 'Document starred' : 'Document unstarred');
        });
    }

    setupRibbon() {
        const tabs = document.querySelectorAll('.ribbon-tab');
        const panels = document.querySelectorAll('.ribbon-panel');
        const toggleBtn = document.getElementById('ribbon-toggle');
        const toolbar = document.querySelector('.toolbar.ribbon');
        let ribbonCollapsed = false;
        let pinnedTab = 'home';

        const activateTab = (tabName, temporary = false) => {
            tabs.forEach(t => {
                t.classList.toggle('active', t.dataset.tab === tabName);
            });
            panels.forEach(p => {
                p.classList.toggle('active', p.dataset.panel === tabName);
            });
            if (!temporary) pinnedTab = tabName;
        };

        tabs.forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.stopPropagation();
                if (ribbonCollapsed) {
                    if (toolbar.classList.contains('pinned')) {
                        toolbar.classList.remove('pinned');
                        activateTab(pinnedTab);
                        document.removeEventListener('click', this._ribbonDocClickHandler);
                    } else {
                        toolbar.classList.add('pinned');
                        activateTab(tab.dataset.tab, true);
                        this._ribbonDocClickHandler = () => {
                            toolbar.classList.remove('pinned');
                            activateTab(pinnedTab);
                            document.removeEventListener('click', this._ribbonDocClickHandler);
                        };
                        document.addEventListener('click', this._ribbonDocClickHandler);
                    }
                } else {
                    activateTab(tab.dataset.tab);
                }
            });
        });

        if (toggleBtn) {
            toggleBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                ribbonCollapsed = !ribbonCollapsed;
                toolbar.classList.toggle('collapsed', ribbonCollapsed);
                toolbar.classList.remove('pinned');
                document.removeEventListener('click', this._ribbonDocClickHandler);
            });
        }

        activateTab('home');
    }

    setup() {
        const ctrl = this.ctrl;
        this.setupApplicationShell();
        this.setupRibbon();
        this.setupFloatingToolbar();

        document.addEventListener('mousedown', (e) => {
            if (this.formatPainterActive) {
                const isToolbar = e.target.closest('.toolbar') || e.target.closest('.floating-toolbar') ||
                    e.target.closest('.status-bar') || e.target.closest('.sidebar') ||
                    e.target.closest('.outline-sidebar') || e.target.closest('.modal');
                if (!isToolbar) {
                    e.preventDefault();
                }
            }
        });

        document.addEventListener('mouseup', (e) => {
            if (this.formatPainterActive) {
                const isToolbar = e.target.closest('.toolbar') || e.target.closest('.floating-toolbar') ||
                    e.target.closest('.status-bar') || e.target.closest('.sidebar') ||
                    e.target.closest('.outline-sidebar') || e.target.closest('.modal');
                if (!isToolbar) {
                    this.paintFormat();
                }
            }
        });

        this.bindToolbarButton('btn-bold', () => {
            ctrl.engine.dispatch('toggleBold');
        }, { preserveSelection: true });
        this.bindToolbarButton('btn-italic', () => {
            ctrl.engine.dispatch('toggleItalic');
        }, { preserveSelection: true });
        this.bindToolbarButton('btn-underline', () => {
            ctrl.engine.dispatch('toggleUnderline');
        }, { preserveSelection: true });
        this.bindToolbarButton('btn-strikethrough', () => {
            ctrl.engine.dispatch('toggleStrikethrough');
        }, { preserveSelection: true });
        this.bindToolbarButton('btn-superscript', () => {
            ctrl.engine.dispatch('toggleSuperscript');
        }, { preserveSelection: true });
        this.bindToolbarButton('btn-subscript', () => {
            ctrl.engine.dispatch('toggleSubscript');
        }, { preserveSelection: true });
        this.bindToolbarButton('btn-link', () => {
            ctrl.engine.dispatch('createLink');
        }, { preserveSelection: true });
        this.bindToolbarButton('btn-code', () => {
            ctrl.engine.dispatch('toggleInlineCode');
        }, { preserveSelection: true });
        this.bindToolbarButton('btn-clear-fmt', () => {
            ctrl.engine.dispatch('clearFormatting');
        }, { preserveSelection: true });

        this.bindToolbarButton('btn-format-painter', () => {
            if (this.formatPainterActive) {
                this.paintFormat();
            } else {
                this.toggleFormatPainter();
            }
        }, { preserveSelection: true });

        this.bindToolbarButton('btn-save', async () => {
            const saveBtn = document.getElementById('btn-save');
            if (saveBtn) {
                saveBtn.disabled = true;
                saveBtn.innerHTML = '<span class="save-spinner"></span>';
            }
            try {
                await this.state.flushSave?.() || await this.state.save();
                this.showShellToast('All changes saved');
            } catch (err) {
                this.showShellToast('Save failed: ' + (err.message || 'Unknown error'));
            } finally {
                if (saveBtn) {
                    saveBtn.disabled = false;
                    saveBtn.innerHTML = '<i data-lucide="save"></i>';
                    if (typeof lucide !== 'undefined') lucide.createIcons();
                }
            }
        });
        this.bindToolbarButton('btn-undo', () => this.state.history.undo());
        this.bindToolbarButton('btn-redo', () => this.state.history.redo());
        this.bindToolbarButton('btn-page-setup', () => document.getElementById('modal-page').classList.remove('hidden'));
        this.bindToolbarButton('btn-view-page', () => this.renderer.setMode(true));
        this.bindToolbarButton('btn-view-web', () => this.renderer.setMode(false));

        ['left', 'center', 'right', 'justify'].forEach((a) => {
            this.bindToolbarButton(`btn-align-${a}`, () => {
                if (ctrl.activeBlockIndex !== null) {
                    const b = this.state.doc.blocks[ctrl.activeBlockIndex];
                    if (b.type === 'image') ctrl.engine.dispatch('updateImageProps', { blockId: b.id, props: { align: a } });
                    else if (b.type === 'object') {
                        const side = a === 'left' ? 'right' : a === 'right' ? 'left' : 'both';
                        ctrl.engine.dispatch('updateObject', { objectId: b.id, patch: { wrap: { side }, legacy: { align: a } }, source: 'objectAlign' }, { restoreSelection: false });
                    } else ctrl.engine.dispatch('updateBlockProps', { blockId: b.id, props: { align: a } });
                }
            });
        });

        const fontSel = document.getElementById('sel-font');
        if (fontSel) {
            fontSel.addEventListener('mousedown', () => this.captureToolbarSelection());
            fontSel.addEventListener('change', (e) => {
                this.restoreToolbarSelection();
                ctrl.engine.dispatch('setFontFamily', { fontFamily: e.target.value });
            });
        }

        const fontSizeSel = document.getElementById('sel-font-size');
        if (fontSizeSel) {
            fontSizeSel.addEventListener('mousedown', () => this.captureToolbarSelection());
            fontSizeSel.addEventListener('change', (e) => {
                this.restoreToolbarSelection();
                ctrl.engine.dispatch('setFontSize', { fontSize: e.target.value });
            });
        }

        const textColor = document.getElementById('inp-text-color');
        if (textColor) {
            textColor.addEventListener('mousedown', () => this.captureToolbarSelection());
            textColor.addEventListener('input', (e) => {
                this.restoreToolbarSelection();
                ctrl.engine.dispatch('setTextColor', { color: e.target.value });
            });
        }

        const hlColor = document.getElementById('inp-highlight-color');
        if (hlColor) {
            hlColor.addEventListener('mousedown', () => this.captureToolbarSelection());
            hlColor.addEventListener('input', (e) => {
                this.restoreToolbarSelection();
                ctrl.engine.dispatch('setHighlight', { color: e.target.value });
            });
        }

        document.getElementById('sel-line-height').onchange = (e) => {
            const blockIndex = ctrl.getInsertBaseIndex();
            if (blockIndex !== null && blockIndex >= 0) this.state.updateBlockProps(blockIndex, { lineHeight: e.target.value });
        };

        const setupSpacingSelect = (id, prop) => {
            const sel = document.getElementById(id);
            if (!sel) return;
            sel.addEventListener('mousedown', () => this.captureToolbarSelection());
            sel.onchange = (e) => {
                const blockIndex = ctrl.getInsertBaseIndex();
                if (blockIndex !== null && blockIndex >= 0) {
                    this.state.updateBlockProps(blockIndex, { [prop]: parseInt(e.target.value) });
                }
            };
        };
        setupSpacingSelect('sel-space-before', 'marginTop');
        setupSpacingSelect('sel-space-after', 'marginBottom');
        document.getElementById('sel-block-style').addEventListener('mousedown', () => this.captureToolbarSelection());
        document.getElementById('sel-block-style').onchange = (e) => {
            const blockIndex = ctrl.getInsertBaseIndex();
            if (blockIndex !== null && blockIndex >= 0) this.state.changeBlockStyle(blockIndex, e.target.value);
        };

        let z = 1.0;
        this.bindToolbarButton('btn-zoom-in', () => {
            z = Math.min(2.0, z + 0.1);
            this.renderer.setZoom(z);
            ctrl.savePreference('zoom', z);
            const slider = document.getElementById('zoom-slider');
            if (slider) slider.value = Math.round(z * 100);
        });
        this.bindToolbarButton('btn-zoom-out', () => {
            z = Math.max(0.5, z - 0.1);
            this.renderer.setZoom(z);
            ctrl.savePreference('zoom', z);
            const slider = document.getElementById('zoom-slider');
            if (slider) slider.value = Math.round(z * 100);
        });

        const zoomSlider = document.getElementById('zoom-slider');
        if (zoomSlider) {
            zoomSlider.addEventListener('input', (e) => {
                z = parseInt(e.target.value) / 100;
                this.renderer.setZoom(z);
                ctrl.savePreference('zoom', z);
            });
        }

        this.bindToolbarButton('btn-indent-inc', () => this.modifyIndent(1));
        this.bindToolbarButton('btn-indent-dec', () => this.modifyIndent(-1));

        this.bindToolbarButton('ctx-btn-link', () => {
            ctrl.engine.dispatch('createLink');
        }, { preserveSelection: true });
        this.bindToolbarButton('ctx-btn-indent-inc', () => this.modifyIndent(1));
        this.bindToolbarButton('ctx-btn-indent-dec', () => this.modifyIndent(-1));
        this.bindToolbarButton('ctx-btn-ul', () => {
            ctrl.engine.dispatch('insertBlock', {
                block: { type: 'ul', items: [{ text: '', level: 0 }] },
                source: 'list'
            });
        }, { preserveSelection: true });
        this.bindToolbarButton('ctx-btn-ol', () => {
            ctrl.engine.dispatch('insertBlock', {
                block: { type: 'ol', items: [{ text: '', level: 0 }] },
                source: 'list'
            });
        }, { preserveSelection: true });
        this.bindToolbarButton('ctx-btn-toggle-list-type', () => {
            if (ctrl.activeBlockIndex !== null) {
                ctrl.engine.dispatch('toggleListType', { index: ctrl.activeBlockIndex });
            }
        });
        this.bindToolbarButton('ctx-btn-list-to-text', () => {
            if (ctrl.activeBlockIndex !== null) {
                ctrl.engine.dispatch('convertBlockToText', { index: ctrl.activeBlockIndex });
            }
        });
        ['left', 'center', 'right'].forEach((a) => {
            this.bindToolbarButton(`ctx-btn-align-${a}`, () => {
                if (ctrl.activeBlockIndex !== null) {
                    const b = this.state.doc.blocks[ctrl.activeBlockIndex];
                    if (b.type === 'image') ctrl.engine.dispatch('updateImageProps', { index: ctrl.activeBlockIndex, props: { align: a } });
                    else if (b.type === 'object') ctrl.engine.dispatch('updateObject', { objectId: b.id, patch: { wrap: { side: a === 'left' ? 'right' : a === 'right' ? 'left' : 'both' }, legacy: { align: a } }, source: 'objectAlign' }, { restoreSelection: false });
                }
            });
        });
        this.bindToolbarButton('ctx-btn-del-image', () => {
            if (ctrl.activeBlockIndex !== null) {
                const b = this.state.doc.blocks[ctrl.activeBlockIndex];
                if (b.type === 'image' || b.type === 'object') ctrl.engine.dispatch('removeBlock', { blockId: b.id, index: ctrl.activeBlockIndex });
            }
        });
        const getFocusedTableCell = () => {
            const sel = window.getSelection();
            if (!sel || !sel.rangeCount) return null;
            let n = sel.anchorNode;
            if (n && n.nodeType === 3) n = n.parentElement;
            const td = n?.closest?.('td');
            if (!td) return null;
            return { row: parseInt(td.dataset.row), col: parseInt(td.dataset.col), td };
        };

        this.bindToolbarButton('ctx-btn-insert-row', () => {
            const idx = ctrl.activeBlockIndex;
            if (idx === null) return;
            const cell = getFocusedTableCell();
            const rowIdx = cell !== null ? cell.row + 1 : undefined;
            ctrl.engine.dispatch('insertTableRow', { index: idx, rowIdx });
        });
        this.bindToolbarButton('ctx-btn-insert-col', () => {
            const idx = ctrl.activeBlockIndex;
            if (idx === null) return;
            const cell = getFocusedTableCell();
            const colIdx = cell !== null ? cell.col + 1 : undefined;
            ctrl.engine.dispatch('insertTableCol', { index: idx, colIdx });
        });
        this.bindToolbarButton('ctx-btn-del-row', () => {
            const idx = ctrl.activeBlockIndex;
            if (idx === null) return;
            const cell = getFocusedTableCell();
            const rowIdx = cell !== null ? cell.row : undefined;
            ctrl.engine.dispatch('removeTableRow', { index: idx, rowIdx });
        });
        this.bindToolbarButton('ctx-btn-del-col', () => {
            const idx = ctrl.activeBlockIndex;
            if (idx === null) return;
            const cell = getFocusedTableCell();
            const colIdx = cell !== null ? cell.col : undefined;
            ctrl.engine.dispatch('removeTableCol', { index: idx, colIdx });
        });
        this.bindToolbarButton('ctx-btn-del-table', () => {
            if (ctrl.activeBlockIndex !== null) {
                const b = this.state.doc.blocks[ctrl.activeBlockIndex];
                if (b.type === 'table') ctrl.engine.dispatch('removeBlock', { index: ctrl.activeBlockIndex });
            }
        });

        this.bindToolbarButton('btn-page-break', () => {
            ctrl.engine.dispatch('insertBlock', {
                block: { type: 'pageBreak' },
                source: 'page-break',
                focusOffset: 1,
                focusBlock: { type: 'text', style: 'normal', content: '<br>' }
            });
        }, { preserveSelection: true });

        const insertOrConvertList = (listType) => {
            const idx = ctrl.activeBlockIndex;
            if (idx !== null) {
                const block = this.state.doc.blocks[idx];
                if (block && block.type === 'text') {
                    ctrl.engine.dispatch('convertBlockToList', { index: idx, listType });
                    return;
                }
            }
            ctrl.engine.dispatch('insertBlock', {
                block: { type: listType, items: [{ text: '', level: 0 }] },
                source: 'list'
            });
        };

        this.bindToolbarButton('btn-ul', () => insertOrConvertList('ul'), { preserveSelection: true });
        this.bindToolbarButton('btn-ol', () => insertOrConvertList('ol'), { preserveSelection: true });

        this.bindToolbarButton('btn-toc', () => {
            ctrl.engine.dispatch('insertBlock', {
                block: { type: 'toc' },
                source: 'toc'
            });
        }, { preserveSelection: true });

        this.bindToolbarButton('btn-toc-ref', () => {
            ctrl.engine.dispatch('insertBlock', {
                block: { type: 'toc' },
                source: 'toc'
            });
        }, { preserveSelection: true });

        this.bindToolbarButton('btn-footnote', () => {
            const noteContent = prompt('Enter footnote content:', '');
            if (noteContent !== null && noteContent !== '') {
                ctrl.insertNoteAtSelection('footnote', noteContent);
            }
        }, { preserveSelection: true });

        this.bindToolbarButton('btn-endnote', () => {
            const noteContent = prompt('Enter endnote content:', '');
            if (noteContent !== null && noteContent !== '') {
                ctrl.insertNoteAtSelection('endnote', noteContent);
            }
        }, { preserveSelection: true });

        this.bindToolbarButton('btn-track-changes', () => {
            const active = this.state.toggleTrackChanges();
            const btn = document.getElementById('btn-track-changes');
            if (btn) btn.classList.toggle('active', active);
            const panel = document.getElementById('review-panel');
            if (panel) panel.classList.toggle('hidden', !active && this.state.listRunRevisions().length === 0);
            ctrl.updateReviewPanel();
        });

        this.bindToolbarButton('btn-accept-all', () => {
            ctrl.engine.dispatch('acceptAllRevisions');
            ctrl.updateReviewPanel();
        });

        this.bindToolbarButton('btn-reject-all', () => {
            ctrl.engine.dispatch('rejectAllRevisions');
            ctrl.updateReviewPanel();
        });

        this.bindToolbarButton('btn-table', () => {
            ctrl.engine.dispatch('insertBlock', {
                block: { type: 'table', rows: [['', ''], ['', '']], colWidths: [50, 50] },
                source: 'table'
            });
        }, { preserveSelection: true });

        this.bindToolbarButton('btn-box-text', () => {
            ctrl.engine.dispatch('insertTextBoxObject', {
                content: 'Text box',
                anchorBlockId: ctrl.activeBlockId || ctrl.engine.captureSelection()?.anchor?.blockId || null,
                x: 50, y: 50, width: 220, height: 110
            });
        }, { preserveSelection: true });

        this.bindToolbarButton('btn-img-inline', () => {
            ctrl.pendingInsertIndex = ctrl.getInsertBaseIndex();
            document.getElementById('inp-image-upload').click();
        }, { preserveSelection: true });

        document.getElementById('inp-image-upload').onchange = async (e) => {
            const file = e.target.files && e.target.files[0];
            if (!file) return;

            const replaceObjectId = e.target.dataset.replaceObjectId || null;
            delete e.target.dataset.replaceObjectId;
            const res = await this.state.uploadImage(file);
            if (res.url) {
                if (replaceObjectId) {
                    ctrl.engine.dispatch('updateObject', {
                        objectId: replaceObjectId,
                        patch: { image: { src: res.url, assetId: res.asset?.id || null, naturalWidth: null, naturalHeight: null } },
                        source: 'replaceImage'
                    }, { restoreSelection: false });
                } else {
                    ctrl.engine.dispatch('insertImageObject', {
                        src: res.url,
                        assetId: res.asset?.id || null,
                        anchorBlockId: ctrl.activeBlockId || ctrl.engine.captureSelection()?.anchor?.blockId || null,
                        mode: 'inline',
                        wrapType: 'inline'
                    });
                }
            }

            e.target.value = '';
        };

        this.bindToolbarButton('btn-close-hf', () => this.state.toggleHFMode(false));
        this.bindToolbarButton('btn-print', () => ctrl.printDocument());
        this.bindToolbarButton('btn-exp-pdf', () => ctrl.exportPDF());
        this.bindToolbarButton('btn-export-docx', () => ctrl.exportDOCX());

        this.bindToolbarButton('btn-toggle-outline', () => {
            const sidebar = document.getElementById('outline-sidebar');
            const rail = document.getElementById('outline-rail');
            if (!sidebar || !rail) return;
            if (sidebar.classList.contains('collapsed')) {
                sidebar.classList.remove('collapsed');
                rail.classList.add('hidden');
                ctrl._outlineOpen = true;
            } else {
                sidebar.classList.add('collapsed');
                rail.classList.remove('hidden');
                ctrl._outlineOpen = false;
            }
            ctrl.savePreference('outlineOpen', ctrl._outlineOpen);
        });

        this.bindToolbarButton('btn-toggle-ruler', () => {
            const ruler = document.querySelector('.ruler-container');
            if (!ruler) return;
            const isHidden = ruler.style.display === 'none';
            ruler.style.display = isHidden ? '' : 'none';
            ctrl.savePreference('rulerVisible', !isHidden);
        });

        this.bindToolbarButton('btn-split-view', () => {
            ctrl.toggleSplitView();
        });

        document.getElementById('btn-import-docx').onclick = () => {
            document.getElementById('inp-docx-import').click();
        };
        document.getElementById('inp-docx-import').onchange = async (e) => {
            const file = e.target.files && e.target.files[0];
            if (!file) return;
            await ctrl.importDOCX(file);
            e.target.value = '';
        };

        const btnReviewClose = document.getElementById('btn-review-close');
        if (btnReviewClose) {
            btnReviewClose.addEventListener('click', () => {
                document.getElementById('review-panel').classList.add('hidden');
            });
        }

        const toggleBtn = document.getElementById('btn-toolbar-toggle');
        const drawer = document.getElementById('mobile-toolbar-drawer');
        if (toggleBtn && drawer) {
            const menuIcon = '<i data-lucide="menu"></i>';
            const closeIcon = '<i data-lucide="x"></i>';

            const addToDrawer = (container, label) => {
                const groupDiv = document.createElement('div');
                groupDiv.className = 'toolbar-group';
                if (label) {
                    const labelEl = document.createElement('span');
                    labelEl.className = 'toolbar-label';
                    labelEl.textContent = label;
                    groupDiv.appendChild(labelEl);
                }
                const els = container.querySelectorAll('button, select, input[type="color"]');
                let hasContent = false;
                els.forEach(el => {
                    const origId = el.id;
                    const commandTarget = el.dataset.commandTarget;
                    const selectTarget = el.dataset.selectTarget;
                    const colorTarget = el.dataset.colorTarget;
                    if (!origId && !commandTarget && !selectTarget && !colorTarget && el.tagName !== 'INPUT') return;
                    if (el.type === 'file') return;
                    if (el.classList.contains('ribbon-toggle')) return;

                    const clone = el.cloneNode(true);
                    clone.id = `mob-${origId || commandTarget || selectTarget || colorTarget || Math.random().toString(36).slice(2)}`;

                    if (commandTarget) {
                        clone.addEventListener('click', () => {
                            document.getElementById(commandTarget)?.click();
                            drawer.classList.remove('open');
                        });
                    } else if (selectTarget) {
                        clone.addEventListener('change', (e) => {
                            const target = document.getElementById(selectTarget);
                            if (!target) return;
                            target.value = e.target.value;
                            target.dispatchEvent(new Event('change', { bubbles: true }));
                        });
                    } else if (colorTarget) {
                        clone.addEventListener('input', (e) => {
                            const target = document.getElementById(colorTarget);
                            if (!target) return;
                            target.value = e.target.value;
                            target.dispatchEvent(new Event('input', { bubbles: true }));
                        });
                    } else if (origId) {
                        const orig = document.getElementById(origId);
                        if (orig && el.tagName !== 'SELECT' && el.tagName !== 'INPUT') {
                            clone.addEventListener('click', () => {
                                orig.click();
                                drawer.classList.remove('open');
                            });
                        }
                        if (orig && el.tagName === 'INPUT' && el.type === 'color') {
                            clone.addEventListener('input', (e) => {
                                orig.value = e.target.value;
                                orig.dispatchEvent(new Event('input', { bubbles: true }));
                            });
                        }
                        if (orig && el.tagName === 'SELECT') {
                            clone.addEventListener('change', (e) => {
                                orig.value = e.target.value;
                                orig.dispatchEvent(new Event('change', { bubbles: true }));
                            });
                        }
                    }
                    groupDiv.appendChild(clone);
                    hasContent = true;
                });
                if (hasContent) drawer.appendChild(groupDiv);
            };

            const compactToolbar = document.getElementById('compact-toolbar');
            if (compactToolbar) addToDrawer(compactToolbar, 'Quick tools');

            const quickActions = ['btn-undo', 'btn-redo', 'btn-save'];
            quickActions.forEach((id) => {
                const original = document.getElementById(id);
                if (!original) return;
                const clone = original.cloneNode(true);
                clone.id = `mob-${id}`;
                clone.addEventListener('click', () => {
                    original.click();
                    drawer.classList.remove('open');
                });
                const groupDiv = document.createElement('div');
                groupDiv.className = 'toolbar-group';
                groupDiv.appendChild(clone);
                drawer.appendChild(groupDiv);
            });

            const ribbonGroups = document.querySelectorAll('.ribbon-body .ribbon-group');
            ribbonGroups.forEach(group => {
                const label = group.querySelector('.ribbon-group-label')?.textContent?.trim() || '';
                const buttonsEl = group.querySelector('.ribbon-group-buttons');
                if (buttonsEl) addToDrawer(buttonsEl, label);
            });

            // Add ribbon tabs as pill buttons in mobile drawer
            const tabsContainer = document.createElement('div');
            tabsContainer.className = 'mobile-ribbon-tabs';
            const tabs = document.querySelectorAll('.ribbon-tab-row .ribbon-tab');
            tabs.forEach(tab => {
                const tabBtn = document.createElement('button');
                tabBtn.className = 'mobile-ribbon-tab';
                tabBtn.textContent = tab.textContent.trim();
                tabBtn.dataset.tab = tab.dataset.tab;
                if (tab.classList.contains('active')) {
                    tabBtn.classList.add('active');
                }
                tabBtn.addEventListener('click', () => {
                    const originalTab = document.querySelector(`.ribbon-tab-row .ribbon-tab[data-tab="${tab.dataset.tab}"]`);
                    if (originalTab) originalTab.click();
                    document.querySelectorAll('.mobile-ribbon-tab').forEach(t => t.classList.remove('active'));
                    tabBtn.classList.add('active');
                });
                tabsContainer.appendChild(tabBtn);
            });
            drawer.insertBefore(tabsContainer, drawer.firstChild);

            toggleBtn.addEventListener('click', () => {
                drawer.classList.toggle('open');
                toggleBtn.innerHTML = drawer.classList.contains('open') ? closeIcon : menuIcon;
                if (typeof lucide !== 'undefined') {
                    lucide.createIcons();
                }
            });

            document.addEventListener('click', (e) => {
                if (drawer.classList.contains('open') &&
                    !drawer.contains(e.target) &&
                    !toggleBtn.contains(e.target)) {
                    drawer.classList.remove('open');
                    toggleBtn.innerHTML = menuIcon;
                    if (typeof lucide !== 'undefined') lucide.createIcons();
                }
            });
        }
    }
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/page-layout.mjs
// ================================================================
export function getPageMetrics(pageSize = 'letter', orientation = 'portrait') {
  const base = pageSize === 'a4' ? { widthIn: 8.27, heightIn: 11.69 } : { widthIn: 8.5, heightIn: 11 };
  return orientation === 'landscape' ? { widthIn: base.heightIn, heightIn: base.widthIn } : base;
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

function resolveStyle(block, styles = {}) {
  const visited = new Set();
  const merge = styleId => {
    if (!styleId || visited.has(styleId)) return {};
    visited.add(styleId);
    const style = styles[styleId] || {};
    return { ...merge(style.basedOn), ...style };
  };
  return merge(block.style || 'normal');
}

function objectTransform(block) {
  const sx = block.image?.flipX ? -1 : 1;
  const sy = block.image?.flipY ? -1 : 1;
  return `rotate(${Number(block.layout?.rotation || 0)}deg) scale(${sx},${sy})`;
}

function objectImageHtml(block) {
  const image = block.image || {};
  const crop = image.crop || {};
  const left = Math.max(0, Math.min(.95, Number(crop.left || 0)));
  const right = Math.max(0, Math.min(.95, Number(crop.right || 0)));
  const top = Math.max(0, Math.min(.95, Number(crop.top || 0)));
  const bottom = Math.max(0, Math.min(.95, Number(crop.bottom || 0)));
  const visibleWidth = Math.max(.05, 1 - left - right);
  const visibleHeight = Math.max(.05, 1 - top - bottom);
  const filters = image.filters || {};
  const imgStyle = `width:${100 / visibleWidth}%;height:${100 / visibleHeight}%;left:${-left / visibleWidth * 100}%;top:${-top / visibleHeight * 100}%;filter:brightness(${filters.brightness ?? 1}) contrast(${filters.contrast ?? 1}) saturate(${filters.saturate ?? 1}) grayscale(${filters.grayscale ?? 0}) sepia(${filters.sepia ?? 0});opacity:${filters.opacity ?? 1};`;
  const border = image.border || {};
  const viewportStyle = `border:${Number(border.width || 0)}px ${esc(border.style || 'solid')} ${esc(border.color || 'transparent')};border-radius:${Number(image.cornerRadius || 0)}px;${image.shadow ? `box-shadow:${esc(image.shadow)};` : ''}`;
  return `<div class="print-object-image" style="${viewportStyle}"><img src="${esc(image.src || '')}" alt="${image.decorative ? '' : esc(image.altText || '')}" style="${imgStyle}"></div>${image.caption ? `<figcaption>${esc(image.caption)}</figcaption>` : ''}`;
}

function objectTextBoxHtml(block) {
  const textBox = block.textBox || {};
  const margins = textBox.margins || {};
  const appearance = block.appearance || {};
  const content = (textBox.blocks || []).map(item => item.content || '').join('<div><br></div>');
  const style = `padding:${Number(margins.top || 0)}px ${Number(margins.right || 0)}px ${Number(margins.bottom || 0)}px ${Number(margins.left || 0)}px;column-count:${Math.max(1, Number(textBox.columns || 1))};background:${esc(appearance.fill || 'transparent')};border:${Number(appearance.borderWidth || 0)}px ${esc(appearance.borderStyle || 'solid')} ${esc(appearance.borderColor || 'transparent')};border-radius:${Number(appearance.cornerRadius || 0)}px;opacity:${appearance.opacity ?? 1};${appearance.shadow ? `box-shadow:${esc(appearance.shadow)};` : ''}`;
  return `<div class="print-text-box vertical-${esc(textBox.verticalAlign || 'top')}" style="${style}">${content}</div>`;
}

function objectToHtml(block) {
  const layout = block.layout || {};
  const wrap = block.wrap || {};
  const distance = wrap.distance || {};
  const flow = ['inline', 'square', 'topBottom', 'tight', 'through'].includes(wrap.type || 'inline');
  const classes = `print-object object-${esc(block.objectType)} wrap-${esc(wrap.type || 'inline')} ${flow ? 'flow-object' : 'positioned-object'}`;
  let style = `width:${Number(layout.width || 240)}px;${layout.height ? `height:${Number(layout.height)}px;` : ''}transform:${objectTransform(block)};z-index:${Number(layout.zIndex || 1)};margin:${Number(distance.top || 0)}px ${Number(distance.right || 0)}px ${Number(distance.bottom || 0)}px ${Number(distance.left || 0)}px;`;
  if (!flow) style += `left:${Number(layout.x || 0)}px;top:${Number(layout.y || 0)}px;`;
  if (['square', 'tight', 'through'].includes(wrap.type)) {
    const floatSide = wrap.side === 'left' ? 'right' : 'left';
    style += `float:${floatSide};`;
    if (Array.isArray(wrap.contour) && wrap.contour.length >= 3) style += `shape-outside:polygon(${wrap.contour.map(point => `${Number(point.x) * 100}% ${Number(point.y) * 100}%`).join(',')});`;
    else if ((wrap.type === 'tight' || wrap.type === 'through') && block.image?.src) style += `shape-outside:url("${esc(block.image.src)}");shape-image-threshold:.1;`;
  }
  if (wrap.type === 'topBottom') style += 'clear:both;';
  const content = block.objectType === 'image' ? objectImageHtml(block) : objectTextBoxHtml(block);
  return `<div data-block-id="${esc(block.id)}" class="${classes}" style="${style}"><div class="print-object-frame">${content}</div></div>`;
}

export function blockToHtml(block, context = {}) {
  const styles = context.styles || {};
  if (block.type === 'text') {
    const named = resolveStyle(block, styles);
    const fontFamily = block.fontFamily || named.fontFamily || 'Segoe UI';
    const fontSize = block.fontSize || named.fontSize || 12;
    const lineHeight = block.lineHeight || named.lineHeight || 1.5;
    const spacingAfter = block.marginBottom ?? named.spacingAfter ?? 6;
    let css = `font-family:"${esc(fontFamily)}",Arial,sans-serif;font-size:${fontSize}pt;line-height:${lineHeight};margin:0 0 ${spacingAfter}pt;position:relative;`;
    if (named.bold) css += 'font-weight:700;';
    if (named.italic) css += 'font-style:italic;';
    if (named.color) css += `color:${esc(named.color)};`;
    if (block.style === 'h1') css += 'font-size:24pt;font-weight:700;color:#2b579a;margin-top:20px;';
    else if (block.style === 'h2') css += 'font-size:18pt;font-weight:700;color:#444;margin-top:15px;';
    else if (block.style === 'h3') css += 'font-size:14pt;font-weight:700;color:#444;margin-top:12px;';
    else if (block.style === 'quote') css += 'font-style:italic;border-left:4px solid #ccc;padding-left:10px;color:#555;';
    if (block.align) css += `text-align:${block.align};`;
    if (block.indent) css += `padding-left:${Number(block.indent) * 20}px;`;
    if (block.marginTop) css += `margin-top:${Number(block.marginTop)}pt;`;
    if (block.keepLinesTogether || named.keepLinesTogether) css += 'break-inside:avoid;';
    if (block.keepWithNext || named.keepWithNext) css += 'break-after:avoid;';
    css += `orphans:${Math.max(1, Number(block.orphanLines || named.orphanLines || 2))};widows:${Math.max(1, Number(block.widowLines || named.widowLines || 2))};`;
    return `<div data-block-id="${esc(block.id)}" style="${css}">${block.content || ''}</div>`;
  }
  if (block.type === 'pageBreak') return '<div class="explicit-page-break"></div>';
  if (block.type === 'sectionBreak') return '';
  if (['ul', 'ol', 'checklist'].includes(block.type)) {
    if (block.type === 'checklist') {
      const items = (block.items || []).map(item => `<li style="list-style:none">${item.checked ? '&#9745;' : '&#9744;'} ${item.text || ''}</li>`).join('');
      return `<ul data-block-id="${esc(block.id)}" class="checklist">${items}</ul>`;
    }
    const items = (block.items || []).map(item => `<li>${item.text || ''}</li>`).join('');
    return `<${block.type} data-block-id="${esc(block.id)}">${items}</${block.type}>`;
  }
  if (block.type === 'horizontalRule') return `<hr data-block-id="${esc(block.id)}">`;
  if (block.type === 'table') {
    const renderedRows = (block.rows || []).map((row, rowIndex) => {
      const cells = [];
      row.forEach((content, colIndex) => {
        const cellId = block.cellIds?.[rowIndex]?.[colIndex];
        const meta = block.cellMeta?.[cellId] || {};
        if (meta.coveredBy) return;
        const tag = (block.headerRows || 0) > rowIndex ? 'th' : 'td';
        const spans = `${meta.rowspan > 1 ? ` rowspan="${meta.rowspan}"` : ''}${meta.colspan > 1 ? ` colspan="${meta.colspan}"` : ''}`;
        cells.push(`<${tag}${spans}>${content || ''}</${tag}>`);
      });
      return `<tr>${cells.join('')}</tr>`;
    });
    const headerCount = Math.max(0, Math.min(renderedRows.length, Number(block.headerRows || 0)));
    return `<table data-block-id="${esc(block.id)}">${headerCount ? `<thead>${renderedRows.slice(0, headerCount).join('')}</thead>` : ''}<tbody>${renderedRows.slice(headerCount).join('')}</tbody></table>`;
  }
  if (block.type === 'object') return objectToHtml(block);
  if (block.type === 'image') {
    const align = block.align || 'center';
    const margin = align === 'center' ? '0 auto' : align === 'right' ? '0 0 0 auto' : '0';
    return `<figure data-block-id="${esc(block.id)}" style="width:${Number(block.width || 100)}%;margin:${margin}"><img src="${esc(block.content)}">${block.caption ? `<figcaption>${esc(block.caption)}</figcaption>` : ''}</figure>`;
  }
  if (block.type === 'toc') return '<section class="toc"><strong>Table of Contents</strong></section>';
  if (block.type === 'footnote' || block.type === 'endnote') return `<div class="document-note"><sup>${esc(block.fnNumber || block.enNumber || '')}</sup> ${block.content || ''}</div>`;
  if (block.type === 'floating') {
    const content = block.subType === 'image' ? `<img src="${esc(block.content)}">` : `<div>${block.content || ''}</div>`;
    return `<div class="floating" style="left:${Number(block.x || 0)}px;top:${Number(block.y || 0)}px;width:${Number(block.w || 100)}px;height:${Number(block.h || 100)}px">${content}</div>`;
  }
  return '';
}

function splitIntoSections(blocks, settings, doc) {
  const declared = doc?.sections || [];
  const initial = declared[0] || {};
  const groups = [{ id: initial.id || 'section-default', settings: initial.settings || settings || {}, header: initial.header || doc?.header, footer: initial.footer || doc?.footer, blocks: [] }];
  (blocks || []).forEach(block => {
    if (block.type === 'sectionBreak') {
      const declaredSection = declared.find(section => section.id === block.sectionId) || {};
      groups.push({ id: block.sectionId || `section-${groups.length + 1}`, settings: declaredSection.settings || block.settings || settings || {}, header: declaredSection.header || doc?.header, footer: declaredSection.footer || doc?.footer, blocks: [] });
    } else groups[groups.length - 1].blocks.push(block);
  });
  return groups;
}

function footerHtml(value) {
  if (!value) return '';
  return String(value).split('{n}').map((part, index, values) => `${esc(part)}${index < values.length - 1 ? '<span class="page-number-field"></span>' : ''}`).join('');
}

export function generatePageHtml(blocks, settings, doc) {
  const sections = splitIntoSections(blocks, settings, doc);
  const pageRules = sections.map((section, index) => {
    const current = section.settings || {};
    const metrics = getPageMetrics(current.pageSize || settings?.pageSize || 'letter', current.orientation || 'portrait');
    return `@page section-${index} { size:${metrics.widthIn}in ${metrics.heightIn}in; margin:0; }`;
  }).join('\n');
  const sectionHtml = sections.map((section, index) => {
    const current = section.settings || {};
    const metrics = getPageMetrics(current.pageSize || settings?.pageSize || 'letter', current.orientation || 'portrait');
    const margins = current.margins || settings?.margins || { top: 1, right: 1, bottom: 1, left: 1 };
    const columns = Math.max(1, Number(current.columns || 1));
    return `<section class="document-section" style="--page-width:${metrics.widthIn}in;--page-height:${metrics.heightIn}in;--margin-top:${margins.top}in;--margin-right:${margins.right}in;--margin-bottom:${margins.bottom}in;--margin-left:${margins.left}in;page:section-${index}">
      ${section.header?.center ? `<header class="section-header">${esc(section.header.center)}</header>` : ''}
      <main class="section-content" style="column-count:${columns}">${section.blocks.map(block => blockToHtml(block, { styles: doc?.styles || {} })).join('\n')}</main>
      ${section.footer?.center ? `<footer class="section-footer">${footerHtml(section.footer.center)}</footer>` : ''}
    </section>`;
  }).join('\n');

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><style>
    ${pageRules}
    html,body{margin:0;padding:0;background:white;font-family:"Segoe UI",Arial,sans-serif;counter-reset:page}
    *{box-sizing:border-box}.document-section{width:var(--page-width);min-height:var(--page-height);padding:var(--margin-top) var(--margin-right) var(--margin-bottom) var(--margin-left);position:relative;break-after:page;counter-increment:page}.document-section:last-child{break-after:auto}
    .section-header{font-size:9pt;color:#777;text-align:center;margin-bottom:18px}.section-footer{font-size:9pt;color:#777;text-align:center;position:absolute;left:var(--margin-left);right:var(--margin-right);bottom:.3in}.page-number-field::after{content:counter(page)}
    .explicit-page-break{break-before:page;height:0}.section-content{column-gap:.35in}img{max-width:100%;height:auto}figure{margin-top:8px;margin-bottom:8px}figcaption{text-align:center;font-size:10pt;color:#666}
    table{width:100%;border-collapse:collapse;break-inside:auto}tr{break-inside:avoid}thead{display:table-header-group}th,td{border:1px solid #999;padding:5px;vertical-align:top}th{background:#eaf2f8;font-weight:700}ul,ol{font-size:12pt;margin:0 0 10px 0}.checklist{padding-left:0}hr{border:0;border-top:1px solid #777;margin:12px 0}.document-note{font-size:10pt;color:#555;margin-bottom:4px}.floating,.positioned-object{position:absolute;overflow:visible}.floating img{width:100%;height:100%;object-fit:contain}.print-object{position:relative;max-width:100%;transform-origin:center}.print-object-frame{width:100%;height:100%;position:relative}.print-object-image{width:100%;height:100%;position:relative;overflow:hidden}.print-object-image img{position:absolute;max-width:none;object-fit:cover}.print-text-box{width:100%;height:100%;overflow:hidden}.vertical-middle{display:flex;flex-direction:column;justify-content:center}.vertical-bottom{display:flex;flex-direction:column;justify-content:flex-end}.wrap-behindText{z-index:0}.wrap-inFrontOfText{z-index:30}.wrap-topBottom{display:block;clear:both}code{font-family:Consolas,monospace;background:#f0f0f0;color:#c7254e;padding:1px 4px;border-radius:3px}ins{color:#2e7d32;text-decoration:underline}del{color:#c62828;text-decoration:line-through}
  </style></head><body>${sectionHtml}</body></html>`;
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/css/components.css
// ================================================================
button,
select,
input[type="text"],
input[type="number"] {
  padding: var(--space-1) var(--space-2);
  cursor: pointer;
  border: 1px solid transparent;
  background: transparent;
  border-radius: var(--radius-md);
  font-size: var(--text-base);
  font-family: var(--font-sans);
  color: var(--text-primary);
  line-height: 1;
  transition:
    background var(--transition-fast),
    border-color var(--transition-fast),
    box-shadow var(--transition-fast),
    color var(--transition-fast),
    transform var(--transition-fast);
}

button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-1);
}

button:active {
  transform: scale(0.97);
}

button:focus-visible,
select:focus-visible,
input:focus-visible {
  outline: none;
  box-shadow: 0 0 0 2px var(--color-primary-200);
  border-color: var(--color-primary-400);
}

button.active {
  background: var(--color-primary-100);
  border-color: var(--color-primary-200);
  color: var(--color-primary-500);
}

button:hover,
select:hover {
  background: var(--color-gray-50);
  border-color: var(--color-primary-200);
}

button:has(> svg:only-child),
button#btn-superscript,
button#btn-subscript {
  min-width: 30px;
  min-height: 30px;
}

.btn-label {
  font-size: var(--text-sm);
  line-height: 1;
}

.btn-danger {
  background: #fee2e2;
  color: var(--color-danger);
  font-weight: 600;
  border-color: transparent;
}

.btn-danger:hover {
  background: #fecaca;
  border-color: var(--color-danger);
}

.btn-primary {
  background: var(--color-primary-500);
  color: var(--text-inverse);
  border: none;
  width: 100%;
  padding: var(--space-2);
  border-radius: var(--radius-md);
  font-weight: 500;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-1);
}

.btn-primary:hover {
  background: var(--color-primary-600);
  border-color: transparent;
}

select,
input[type="text"],
input[type="number"] {
  background: white;
  border-color: var(--border-color);
  cursor: default;
}

select {
  appearance: none;
  padding-right: 20px;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 4px center;
}

select:hover {
  border-color: var(--color-primary-300);
}

.toolbar-label {
  font-size: var(--text-sm);
  color: var(--text-secondary);
  white-space: nowrap;
}

.page {
  background: white;
  box-shadow: var(--shadow-page);
  position: relative;
  box-sizing: border-box;
  width: var(--page-width);
  height: var(--page-height);
  overflow: hidden;
  display: block;
  margin-bottom: var(--space-5);
  border-radius: 1px;
}

.page-content-area {
  position: absolute;
  left: var(--page-margin-left);
  right: var(--page-margin-right);
  top: var(--page-margin-top);
  bottom: var(--page-margin-bottom);
  outline: none;
  cursor: text;
  overflow: hidden;
  display: block;
}

.page-content-area > * {
  box-sizing: border-box;
}

.page-header,
.page-footer {
  position: absolute;
  left: var(--page-margin-left);
  right: var(--page-margin-right);
  height: 0.5in;
  display: flex;
  justify-content: space-between;
  font-size: var(--text-xs);
  color: var(--text-tertiary);
  border: 1px dashed transparent;
  cursor: default;
  overflow: hidden;
  z-index: 2;
}

.page-header {
  top: 0.25in;
  border-bottom-color: var(--color-gray-200);
  align-items: flex-end;
}

.page-footer {
  bottom: 0.25in;
  border-top: 1px dashed var(--color-gray-200);
  align-items: flex-start;
}

body.hf-edit-mode .page-header,
body.hf-edit-mode .page-footer {
  border: 1px dashed var(--color-primary-500);
  background: rgba(43, 87, 154, 0.05);
  pointer-events: auto;
  cursor: text;
}

body.hf-edit-mode .page-content-area {
  opacity: 0.5;
  pointer-events: none;
}

body:not(.hf-edit-mode) .page-header,
body:not(.hf-edit-mode) .page-footer {
  pointer-events: none;
}

.block-image {
  position: relative;
  margin: var(--space-3) 0;
  outline: none;
}

.block-image.align-center { text-align: center; }
.block-image.align-left { text-align: left; }
.block-image.align-right { text-align: right; }

.image-wrapper {
  display: inline-block;
  position: relative;
  max-width: 100%;
  border: 2px solid transparent;
  border-radius: var(--radius-sm);
  transition: border-color var(--transition-fast);
}

.image-wrapper img {
  width: 100%;
  display: block;
  border-radius: inherit;
}

.block-image.selected .image-wrapper {
  border-color: var(--color-primary-500);
}

.block-image .caption {
  margin-top: var(--space-1);
  text-align: center;
  color: var(--text-secondary);
  font-style: italic;
  font-size: var(--text-sm);
  outline: none;
  border: 1px dashed transparent;
  min-height: 1.2em;
  display: block;
}

.block-image .caption:focus,
.block-image .caption:hover {
  border-color: var(--color-gray-300);
}

.img-handle {
  position: absolute;
  width: 12px;
  height: 12px;
  background: white;
  border: 1px solid var(--color-primary-500);
  display: none;
  z-index: 20;
  border-radius: 2px;
}

.block-image.selected .img-handle { display: block; }
.img-handle.se { bottom: -6px; right: -6px; cursor: se-resize; }
.img-handle.sw { bottom: -6px; left: -6px; cursor: sw-resize; }

ul, ol {
  margin: 0 0 10px 0;
  padding-left: 20px;
}

li {
  margin-bottom: var(--space-1);
  outline: none;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 1em;
  table-layout: fixed;
}

td {
  border: 1px solid var(--color-gray-300);
  padding: var(--space-2);
  vertical-align: top;
  outline: none;
  position: relative;
}

td:focus-within {
  border: 2px solid var(--color-primary-500);
  background: rgba(43, 87, 154, 0.05);
}

.tbl-col-resizer {
  position: absolute;
  top: 0;
  right: -2px;
  width: 5px;
  height: 100%;
  cursor: col-resize;
  z-index: 10;
  background: transparent;
}

.tbl-col-resizer:hover {
  background: var(--color-primary-500);
}

.floating-box {
  position: absolute;
  border: 1px dashed var(--color-gray-300);
  cursor: move;
  z-index: 10;
  overflow: hidden;
  background: white;
  border-radius: var(--radius-sm);
  transition: border-color var(--transition-fast);
}

.floating-box:hover {
  border: 1px dashed var(--color-primary-500);
}

.box-text-content {
  width: 100%;
  height: 100%;
  padding: var(--space-1);
  box-sizing: border-box;
  overflow: hidden;
  cursor: text;
  outline: none;
}

.box-img-content {
  width: 100%;
  height: 100%;
  pointer-events: none;
  object-fit: fill;
}

.resize-handle {
  width: 10px;
  height: 10px;
  background: white;
  border: 1px solid var(--color-primary-500);
  position: absolute;
  bottom: 0;
  right: 0;
  cursor: nwse-resize;
  display: none;
  border-radius: 1px;
}

.floating-box:hover .resize-handle {
  display: block;
}

.modal {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: var(--bg-modal-overlay);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: var(--z-modal);
  backdrop-filter: blur(2px);
}

.modal.hidden {
  display: none;
}

.modal-content {
  background: white;
  padding: var(--space-5);
  border-radius: var(--radius-lg);
  width: 320px;
  box-shadow: var(--shadow-modal);
}

.modal-content:not(.hidden) {
  animation: modal-enter 200ms ease-out;
}

@keyframes modal-enter {
  from {
    opacity: 0;
    transform: scale(0.95) translateY(-10px);
  }
  to {
    opacity: 1;
    transform: scale(1) translateY(0);
  }
}

.modal-header {
  font-weight: 600;
  margin-bottom: var(--space-4);
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: var(--text-lg);
  color: var(--text-primary);
}

.close-modal {
  cursor: pointer;
  color: var(--text-tertiary);
  display: flex;
  align-items: center;
  transition: color var(--transition-fast);
}

.close-modal:hover {
  color: var(--text-primary);
}

.modal-body label {
  font-size: var(--text-sm);
  color: var(--text-secondary);
  display: block;
  margin-bottom: var(--space-1);
}

.modal-body input[type="text"],
.modal-body input[type="number"] {
  width: 100%;
  padding: var(--space-2);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  margin-bottom: var(--space-2);
}

.sidebar {
  position: fixed;
  top: 0;
  left: 0;
  bottom: 0;
  width: 300px;
  background: var(--bg-sidebar);
  border-right: 1px solid var(--color-gray-300);
  z-index: var(--z-sidebar);
  display: flex;
  flex-direction: column;
  transform: translateX(-100%);
  transition:
    transform var(--transition-slow),
    box-shadow var(--transition-slow);
  box-shadow: none;
}

.sidebar:not(.hidden) {
  transform: translateX(0);
  box-shadow: 4px 0 15px rgba(0, 0, 0, 0.1);
}

.sidebar-header {
  background: var(--color-primary-500);
  color: var(--text-inverse);
  padding: var(--space-4);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.sidebar-header h3 {
  margin: 0;
  font-size: var(--text-lg);
  font-weight: 600;
}

.sidebar-header button {
  color: var(--text-inverse);
}

.sidebar-actions {
  padding: var(--space-3);
}

.doc-list {
  flex: 1;
  overflow-y: auto;
  padding: var(--space-3);
}

.doc-item {
  background: white;
  border: 1px solid var(--border-color);
  padding: var(--space-3);
  margin-bottom: var(--space-2);
  cursor: pointer;
  border-radius: var(--radius-md);
  transition:
    border-color var(--transition-fast),
    background var(--transition-fast),
    box-shadow var(--transition-fast);
}

.doc-item:hover {
  border-color: var(--color-primary-300);
  box-shadow: var(--shadow-sm);
}

.doc-item.active {
  border-left: 4px solid var(--color-primary-500);
  background: var(--color-primary-50);
  border-color: var(--color-primary-200);
}

.outline-sidebar {
  width: 220px;
  background: white;
  border-right: 1px solid var(--color-gray-300);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  overflow: hidden;
  transition: width 250ms ease, min-width 250ms ease;
}

.outline-sidebar.collapsed {
  width: 0;
  min-width: 0;
  border: none;
  overflow: hidden;
}

#outline-content {
  flex: 1;
  overflow-y: auto;
}

.outline-header {
  padding: var(--space-3);
  font-weight: 600;
  background: var(--bg-sidebar);
  border-bottom: 1px solid var(--color-gray-200);
  font-size: var(--text-sm);
  text-transform: uppercase;
  color: var(--text-secondary);
  letter-spacing: 0.03em;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-shrink: 0;
}

.outline-header button {
  width: 22px;
  height: 22px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: none;
  background: transparent;
  border-radius: var(--radius-sm);
  color: var(--text-tertiary);
  cursor: pointer;
  transition: background var(--transition-fast), color var(--transition-fast);
}

.outline-header button:hover {
  background: var(--color-gray-100);
  color: var(--text-primary);
}

.outline-empty-state {
  padding: var(--space-6) var(--space-4);
  text-align: center;
  color: var(--text-tertiary);
  font-size: var(--text-sm);
  line-height: 1.5;
}

.outline-empty-state .empty-icon {
  font-size: 28px;
  margin-bottom: var(--space-3);
  opacity: 0.4;
}

.outline-empty-state .empty-hint {
  margin-top: var(--space-2);
  font-size: var(--text-xs);
  color: var(--color-gray-400);
}

.outline-item {
  padding: var(--space-2) var(--space-3);
  cursor: pointer;
  font-size: var(--text-base);
  color: var(--text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  border-bottom: 1px solid var(--color-gray-100);
  transition: background var(--transition-fast), color var(--transition-fast);
  user-select: none;
}

.outline-item:hover {
  background: var(--color-primary-50);
  color: var(--color-primary-500);
}

.outline-item.level-h1 {
  padding-left: var(--space-3);
  font-weight: 600;
}

.outline-item.level-h2 {
  padding-left: 25px;
  font-size: var(--text-sm);
  color: var(--text-secondary);
}

.outline-item.level-h3 {
  padding-left: 40px;
  font-size: var(--text-sm);
  color: var(--color-gray-500);
}

.outline-item.level-h4 {
  padding-left: 55px;
  font-size: var(--text-xs);
  color: var(--color-gray-500);
}

.outline-item.level-h5 {
  padding-left: 70px;
  font-size: var(--text-xs);
  color: var(--color-gray-400);
}

.outline-item.level-h6 {
  padding-left: 85px;
  font-size: var(--text-xs);
  color: var(--color-gray-400);
}

span.find-highlight {
  background-color: #fef08a;
  color: black;
  border-radius: 2px;
  padding: 1px 0;
}

span.find-highlight.active {
  background-color: #f97316;
  color: white;
  outline: 1px solid #ea580c;
  border-radius: 2px;
}

.block-page-break {
  border-top: 1px dashed var(--color-gray-400);
  color: var(--text-tertiary);
  font-size: var(--text-xs);
  text-align: center;
  margin: var(--space-3) 0;
  display: block;
  width: 100%;
  pointer-events: none;
}

.block-page-break::after {
  content: "Page Break";
  background: var(--color-gray-100);
  padding: 2px var(--space-1);
  border-radius: var(--radius-sm);
}

.doc-title {
  margin-left: var(--space-3);
  font-weight: 600;
  font-size: var(--text-lg);
  color: var(--text-primary);
  padding: var(--space-1);
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  outline: none;
  min-width: 100px;
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  transition: border-color var(--transition-fast);
}

.doc-title:focus {
  border-color: var(--color-primary-300);
  background: var(--color-primary-50);
}

.toolbar button svg {
  width: 18px;
  height: 18px;
  stroke-width: 2;
  vertical-align: middle;
  pointer-events: none;
}

.status-bar button svg {
  width: 14px;
  height: 14px;
  stroke-width: 2;
  vertical-align: middle;
  pointer-events: none;
}

.sidebar button svg {
  width: 18px;
  height: 18px;
  stroke-width: 2;
  vertical-align: middle;
  pointer-events: none;
}

.context-menu {
  position: fixed;
  z-index: 8000;
  background: white;
  border: 1px solid var(--color-gray-300);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-lg);
  padding: var(--space-1) 0;
  min-width: 180px;
  font-family: var(--font-sans);
  font-size: var(--text-base);
}

.context-menu-item {
  padding: var(--space-1) var(--space-4);
  cursor: pointer;
  display: flex;
  align-items: center;
  color: var(--text-primary);
  transition: background var(--transition-fast);
}

.context-menu-item:hover {
  background: var(--color-primary-50);
  color: var(--color-primary-500);
}

.context-menu-separator {
  height: 1px;
  background: var(--color-gray-200);
  margin: var(--space-1) var(--space-2);
}

/* ─── Dropdown menus ─── */
.dropdown-trigger {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-primary);
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--radius-md);
  cursor: pointer;
  white-space: nowrap;
  transition: background var(--transition-fast), border-color var(--transition-fast);
}

.dropdown-trigger:hover {
  background: var(--color-gray-50);
  border-color: var(--color-primary-200);
}

.dropdown-trigger.active {
  background: var(--color-primary-50);
  border-color: var(--color-primary-300);
}

.dropdown-trigger::after {
  content: '';
  display: inline-block;
  width: 0;
  height: 0;
  border-left: 4px solid transparent;
  border-right: 4px solid transparent;
  border-top: 4px solid currentColor;
  margin-left: 4px;
  vertical-align: middle;
  transition: transform var(--transition-fast);
}

.dropdown-trigger.active::after {
  transform: rotate(180deg);
}

.dropdown-menu {
  background: white;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.12);
  padding: 4px;
}

.dropdown-menu button {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 6px 10px;
  font-size: 13px;
  text-align: left;
  background: transparent;
  border: none;
  border-radius: var(--radius-sm);
  cursor: pointer;
  color: var(--text-primary);
  transition: background var(--transition-fast);
  min-height: 30px;
}

.dropdown-menu button:hover {
  background: var(--color-primary-50);
}

.dropdown-menu button svg {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.dropdown-menu .dropdown-row button {
  width: auto;
  justify-content: center;
  min-width: 30px;
  min-height: 30px;
}

.dropdown-divider {
  height: 1px;
  background: var(--border-color);
  margin: 4px 8px;
}

.dropdown-label {
  font-size: 12px;
  color: var(--text-secondary);
  white-space: nowrap;
  flex-shrink: 0;
}

.dropdown-item select {
  font-size: 13px;
  min-height: 28px;
}

.dropdown-menu .color-picker {
  width: 28px;
  height: 28px;
  padding: 0;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  cursor: pointer;
  background: none;
}

/* ─── Contextual toolbar groups (see also ribbon variants below) ─── */

.btn-danger-outline {
  color: var(--color-danger);
  border-color: transparent;
}
.btn-danger-outline:hover {
  background: #fee2e2;
  border-color: var(--color-danger);
}

/* ─── Outline search ─── */
.outline-search-wrapper {
  padding: var(--space-2) var(--space-3);
  border-bottom: 1px solid var(--color-gray-200);
}

.outline-search-input {
  width: 100%;
  padding: var(--space-1) var(--space-2);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  font-size: var(--text-sm);
  font-family: var(--font-sans);
  outline: none;
  background: var(--color-gray-50);
  transition: border-color var(--transition-fast);
}

.outline-search-input:focus {
  border-color: var(--color-primary-400);
  background: white;
}

.outline-item.dragging {
  opacity: 0.5;
  background: var(--color-primary-50);
}

.outline-item.drag-over {
  border-top: 2px solid var(--color-primary-500);
}

.outline-item.drag-over-bottom {
  border-bottom: 2px solid var(--color-primary-500);
}

.outline-item .outline-item-drag-handle {
  display: inline-block;
  width: 12px;
  cursor: grab;
  color: var(--color-gray-400);
  font-size: 10px;
  margin-right: var(--space-1);
  vertical-align: middle;
}

.outline-item .outline-item-drag-handle:active {
  cursor: grabbing;
}

.outline-item .outline-item-toggle {
  display: inline-block;
  width: 14px;
  cursor: pointer;
  color: var(--color-gray-400);
  font-size: 10px;
  margin-right: 2px;
  vertical-align: middle;
  text-align: center;
  transition: transform var(--transition-fast);
}

.outline-item .outline-item-toggle.collapsed {
  transform: rotate(-90deg);
}

.outline-item .outline-item-text {
  vertical-align: middle;
}

.outline-highlight {
  background: var(--color-primary-100) !important;
  border-left: 3px solid var(--color-primary-500) !important;
}

/* ─── Outline collapsed rail ─── */
.outline-rail {
  width: 40px;
  background: white;
  border-right: 1px solid var(--color-gray-300);
  display: flex;
  flex-direction: column;
  align-items: center;
  padding-top: var(--space-3);
  flex-shrink: 0;
}

.outline-rail button {
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius-md);
  color: var(--text-secondary);
  transition: background var(--transition-fast), color var(--transition-fast);
}

.outline-rail button:hover {
  background: var(--color-primary-50);
  color: var(--color-primary-500);
}

.hidden {
  display: none !important;
}

[data-index].dragging {
  opacity: 0.4;
  outline: 2px dashed var(--color-primary-500);
  outline-offset: 2px;
}

[data-index].drag-over {
  border-top: 3px solid var(--color-primary-500) !important;
  margin-top: -1px;
}

.block-toc {
  border: 1px solid var(--color-gray-200);
  border-radius: 6px;
  padding: 12px 16px;
  margin-bottom: 12px;
  background: var(--color-gray-50);
  user-select: none;
}

.block-toc .toc-title {
  font-size: 14pt;
  font-weight: 700;
  color: var(--color-gray-800);
  border-bottom: 2px solid var(--color-primary-500);
  padding-bottom: 6px;
  margin-bottom: 10px;
}

.block-toc .toc-empty {
  color: var(--color-gray-400);
  font-style: italic;
  font-size: 11pt;
  padding: 8px 0;
}

.block-toc .toc-list {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.block-toc .toc-item {
  padding: 3px 0;
}

.block-toc .toc-item-h1 {
  padding-left: 0;
}

.block-toc .toc-item-h2 {
  padding-left: 24px;
}

.block-toc .toc-item-h3 {
  padding-left: 48px;
}

.block-toc .toc-item-h4 {
  padding-left: 72px;
}

.block-toc .toc-item-h5 {
  padding-left: 96px;
}

.block-toc .toc-item-h6 {
  padding-left: 120px;
}

.block-toc .toc-link {
  cursor: pointer;
  color: var(--color-primary-600);
  font-size: 11pt;
  line-height: 1.5;
  text-decoration: none;
}

.block-toc .toc-link:hover {
  text-decoration: underline;
  color: var(--color-primary-800);
}

/* ─── Ribbon button styles ─── */
.ribbon-group-buttons button {
  display: inline-flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 1px;
  padding: 3px 6px;
  min-width: 36px;
  min-height: 42px;
  font-size: 10px;
  color: var(--text-primary);
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--radius-md);
  cursor: pointer;
  line-height: 1.1;
  transition: background var(--transition-fast), border-color var(--transition-fast);
  position: relative;
}

.ribbon-group-buttons button:hover {
  background: var(--color-primary-50);
  border-color: var(--color-primary-200);
}

.ribbon-group-buttons button:active {
  background: var(--color-primary-100);
  transform: scale(0.96);
}

.ribbon-group-buttons button.active {
  background: var(--color-primary-100);
  border-color: var(--color-primary-300);
  color: var(--color-primary-600);
}

.ribbon-group-buttons button svg {
  width: 18px;
  height: 18px;
  stroke-width: 2;
  pointer-events: none;
  flex-shrink: 0;
}

.ribbon-group-buttons button code {
  font-size: 11px;
  font-family: var(--font-mono);
  font-weight: 700;
}

.ribbon-group-buttons button sup,
.ribbon-group-buttons button sub {
  font-size: 9px;
}

/* Ribbon color picker buttons */
.ribbon-color-btn {
  position: relative !important;
  min-width: 34px !important;
  padding: 4px 6px !important;
}

.ribbon-color-label {
  font-weight: 700;
  font-size: 15px;
  line-height: 1;
}

.ribbon-color-input {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  opacity: 0;
  cursor: pointer;
  padding: 0;
  border: none;
}

/* Ribbon select inputs */
.ribbon-group-buttons select {
  padding: 3px 6px;
  font-size: 11px;
  font-family: var(--font-sans);
  color: var(--text-primary);
  background: var(--color-gray-50);
  border: 1px solid var(--color-gray-200);
  border-radius: var(--radius-md);
  cursor: pointer;
  min-width: 78px;
  max-width: 130px;
  height: 28px;
  outline: none;
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
}

.ribbon-group-buttons select:hover {
  border-color: var(--color-primary-200);
  background: white;
}

.ribbon-group-buttons select:focus {
  border-color: var(--color-primary-300);
  box-shadow: 0 0 0 1px var(--color-primary-200);
}

/* Ribbon contextual groups */
.ribbon-group.contextual { display: none; }
.ribbon-group.contextual.active { display: flex !important; }
.ribbon-group.contextual.hidden { display: none !important; }

/* Ribbon group danger styles */
.ribbon-group-buttons .btn-danger-outline {
  color: var(--color-danger);
  border-color: transparent;
}
.ribbon-group-buttons .btn-danger-outline:hover {
  background: #fee2e2;
  border-color: var(--color-danger);
}
.ribbon-group-buttons .btn-danger {
  color: #fff;
  background: var(--color-danger);
  border-color: var(--color-danger);
}
.ribbon-group-buttons .btn-danger:hover {
  background: #b91c1c;
  border-color: #b91c1c;
}

/* ─── Floating formatting toolbar ─── */
.floating-toolbar {
  position: fixed;
  z-index: 7500;
  background: white;
  border: 1px solid var(--color-gray-200);
  border-radius: var(--radius-lg);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
  padding: 4px;
  opacity: 0;
  transform: translateY(4px);
  transition: opacity 120ms ease, transform 120ms ease;
  pointer-events: none;
}

.floating-toolbar.visible {
  opacity: 1;
  transform: translateY(0);
  pointer-events: auto;
}

.floating-toolbar.hidden {
  display: none;
}

.floating-toolbar-buttons {
  display: flex;
  gap: 1px;
  align-items: center;
}

.floating-toolbar-buttons button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 30px;
  height: 30px;
  padding: 0;
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  cursor: pointer;
  color: var(--text-primary);
  transition: background var(--transition-fast);
}

.floating-toolbar-buttons button:hover {
  background: var(--color-primary-50);
  border-color: var(--color-primary-200);
}

.floating-toolbar-buttons button:active {
  background: var(--color-primary-100);
}

.floating-toolbar-buttons button.active {
  background: var(--color-primary-100);
  border-color: var(--color-primary-200);
  color: var(--color-primary-500);
}

.floating-toolbar-buttons button svg {
  width: 14px;
  height: 14px;
  stroke-width: 2;
}

.floating-toolbar-buttons button code {
  font-size: 10px;
  font-family: var(--font-mono);
  font-weight: 700;
}

.flt-sep {
  width: 1px;
  height: 18px;
  background: var(--color-gray-200);
  margin: 0 3px;
  flex-shrink: 0;
}

.flt-font-size,
.flt-style {
  font-size: 11px;
  padding: 2px 4px;
  border: 1px solid var(--color-gray-200);
  border-radius: var(--radius-sm);
  background: white;
  cursor: pointer;
  font-family: var(--font-sans);
  height: 24px;
  outline: none;
}

.flt-font-size:hover,
.flt-style:hover {
  border-color: var(--color-primary-200);
}

/* ─── Format Painter button styling ─── */
#btn-format-painter.active-format-painter {
  background: var(--color-primary-500) !important;
  color: white !important;
  border-color: var(--color-primary-500) !important;
}

#btn-format-painter.active-format-painter svg {
  color: white;
}

/* ─── Navigation pane tabs ─── */
.nav-pane-tabs {
  display: flex;
  border-bottom: 1px solid var(--color-gray-200);
  flex-shrink: 0;
}

.nav-pane-tab {
  flex: 1;
  text-align: center;
  padding: 6px 4px;
  font-size: 11px;
  font-weight: 500;
  color: var(--text-secondary);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  transition: color var(--transition-fast), border-color var(--transition-fast);
  user-select: none;
}

.nav-pane-tab:hover {
  color: var(--text-primary);
}

.nav-pane-tab.active {
  color: var(--color-primary-500);
  border-bottom-color: var(--color-primary-500);
}

.nav-pane-content {
  flex: 1;
  overflow-y: auto;
}

.nav-pane-content.hidden {
  display: none;
}

/* ─── Page thumbnails in nav pane ─── */
#pages-content {
  padding: var(--space-2);
}

.page-thumbnail {
  background: white;
  border: 1px solid var(--color-gray-200);
  border-radius: var(--radius-md);
  margin-bottom: var(--space-2);
  overflow: hidden;
  cursor: pointer;
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
}

.page-thumbnail:hover {
  border-color: var(--color-primary-300);
  box-shadow: var(--shadow-sm);
}

.page-thumbnail.active {
  border-color: var(--color-primary-500);
  box-shadow: 0 0 0 1px var(--color-primary-300);
}

.page-thumbnail-preview {
  height: 60px;
  background: var(--color-gray-50);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  color: var(--text-tertiary);
  overflow: hidden;
  border-bottom: 1px solid var(--color-gray-100);
}

.page-thumbnail-label {
  padding: 4px 8px;
  font-size: 10px;
  color: var(--text-secondary);
  text-align: center;
}

/* ─── Results tab in nav pane ─── */
#results-content {
  padding: var(--space-2);
}

.results-empty {
  text-align: center;
  padding: var(--space-6) var(--space-4);
  color: var(--text-tertiary);
  font-size: var(--text-sm);
}

.result-item {
  padding: var(--space-2) var(--space-3);
  font-size: var(--text-sm);
  color: var(--text-primary);
  cursor: pointer;
  border-radius: var(--radius-md);
  margin-bottom: 2px;
  transition: background var(--transition-fast);
  border: 1px solid transparent;
}

.result-item:hover {
  background: var(--color-primary-50);
  border-color: var(--color-primary-100);
}

.result-item-text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  margin-bottom: 2px;
}

.result-item-context {
  font-size: var(--text-xs);
  color: var(--text-tertiary);
  display: flex;
  justify-content: space-between;
}

/* ─── Welcome / Landing page ─── */
.welcome-page {
  position: absolute;
  inset: 0;
  background: var(--bg-page-view);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1;
  overflow-y: auto;
  padding: var(--space-10);
}

.welcome-page.hidden {
  display: none;
}

.welcome-container {
  max-width: 560px;
  width: 100%;
  text-align: center;
}

.welcome-logo {
  margin-bottom: var(--space-4);
}

.welcome-icon {
  width: 48px;
  height: 48px;
  stroke-width: 1.5;
  color: var(--color-primary-500);
}

.welcome-title {
  font-size: 28px;
  font-weight: 700;
  color: var(--text-primary);
  margin: 0 0 var(--space-6) 0;
  letter-spacing: -0.5px;
}

.welcome-actions {
  display: flex;
  gap: var(--space-3);
  justify-content: center;
  margin-bottom: var(--space-8);
}

.welcome-btn {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-3) var(--space-5);
  border-radius: var(--radius-lg);
  font-size: var(--text-base);
  font-weight: 500;
  cursor: pointer;
  border: 1px solid transparent;
  transition: background var(--transition-fast), border-color var(--transition-fast), box-shadow var(--transition-fast);
}

.welcome-btn svg {
  width: 18px;
  height: 18px;
}

.welcome-btn-primary {
  background: var(--color-primary-500);
  color: white;
}

.welcome-btn-primary:hover {
  background: var(--color-primary-600);
  box-shadow: var(--shadow-md);
}

.welcome-btn-secondary {
  background: white;
  color: var(--text-primary);
  border-color: var(--color-gray-200);
}

.welcome-btn-secondary:hover {
  background: var(--color-gray-50);
  border-color: var(--color-gray-300);
  box-shadow: var(--shadow-sm);
}

.welcome-section-title {
  font-size: var(--text-sm);
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin: 0 0 var(--space-3) 0;
  text-align: left;
}

.welcome-recent {
  margin-bottom: var(--space-6);
}

.welcome-recent-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.welcome-recent-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--space-2) var(--space-3);
  background: white;
  border-radius: var(--radius-md);
  border: 1px solid var(--color-gray-200);
  cursor: pointer;
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
  text-align: left;
}

.welcome-recent-item:hover {
  border-color: var(--color-primary-300);
  box-shadow: var(--shadow-sm);
}

.welcome-recent-item-name {
  font-size: var(--text-sm);
  font-weight: 500;
  color: var(--text-primary);
}

.welcome-recent-item-date {
  font-size: var(--text-xs);
  color: var(--text-tertiary);
}

.welcome-template-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--space-3);
}

.welcome-template-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-3);
  background: white;
  border: 1px solid var(--color-gray-200);
  border-radius: var(--radius-lg);
  cursor: pointer;
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
}

.welcome-template-card:hover {
  border-color: var(--color-primary-300);
  box-shadow: var(--shadow-md);
}

.welcome-template-card span {
  font-size: var(--text-xs);
  color: var(--text-secondary);
  text-align: center;
}

.template-preview {
  width: 64px;
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius-md);
  border: 1px solid var(--color-gray-150);
  background: white;
}

.template-preview svg {
  width: 28px;
  height: 28px;
  color: var(--color-primary-500);
}

.template-preview.blank-preview {
  background: white;
}

.template-preview.report-preview {
  background: var(--color-primary-50);
}

.template-preview.letter-preview {
  background: #fef3c7;
}

.template-preview.notes-preview {
  background: #ecfdf5;
}

/* ─── Ribbon font select sizing ─── */
.ribbon-font-sel {
  min-width: 90px;
  max-width: 120px;
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}

/* ---- Enhanced TOC ---- */
.block-toc .toc-row {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  width: 100%;
}

.block-toc .toc-link {
  flex: 1;
  position: relative;
  overflow: hidden;
  white-space: nowrap;
}

.block-toc .toc-link::after {
  content: '';
  display: inline;
}

.block-toc .toc-page-num {
  font-size: 10pt;
  color: var(--text-secondary);
  margin-left: 4px;
  flex-shrink: 0;
}

.block-toc .toc-update-btn {
  display: block;
  margin-top: 10px;
  padding: 4px 12px;
  font-size: 11px;
  background: var(--color-primary-50);
  border: 1px solid var(--color-primary-200);
  border-radius: var(--radius-md);
  color: var(--color-primary-600);
  cursor: pointer;
  width: 100%;
}

.block-toc .toc-update-btn:hover {
  background: var(--color-primary-100);
  border-color: var(--color-primary-300);
}

/* ---- Footnotes ---- */
.footnote-anchor {
  color: var(--color-primary-600);
  font-size: 0.7em;
  cursor: pointer;
  vertical-align: super;
  font-weight: 600;
}

.footnote-anchor:hover {
  color: var(--color-primary-800);
  text-decoration: underline;
}

.endnote-anchor {
  color: var(--color-accent-600);
  font-size: 0.7em;
  cursor: pointer;
  vertical-align: super;
  font-weight: 600;
}

.endnote-anchor:hover {
  color: var(--color-accent-800);
  text-decoration: underline;
}

.page-footnotes-area {
  position: absolute;
  left: var(--page-margin-left);
  right: var(--page-margin-right);
  bottom: 1.2in;
  font-size: 9pt;
  border-top: 1px solid var(--color-gray-300);
  padding-top: 6px;
  max-height: 1.2in;
  overflow-y: auto;
}

.footnote-separator {
  width: 30%;
  border-top: 1px solid var(--color-gray-400);
  margin-bottom: 4px;
}

.footnote-item {
  padding: 2px 0;
  display: flex;
  align-items: flex-start;
  gap: 4px;
  font-size: 9pt;
  color: var(--text-secondary);
  position: relative;
}

.footnote-num {
  color: var(--color-primary-600);
  font-size: 8pt;
  cursor: pointer;
  flex-shrink: 0;
}

.footnote-content {
  flex: 1;
  cursor: text;
  outline: none;
  min-height: 1em;
}

.footnote-content:focus {
  background: rgba(43, 87, 154, 0.05);
}

.footnote-remove-btn {
  opacity: 0;
  font-size: 12px;
  color: var(--color-danger);
  background: none;
  border: none;
  cursor: pointer;
  line-height: 1;
  padding: 0 2px;
  flex-shrink: 0;
}

.footnote-item:hover .footnote-remove-btn {
  opacity: 1;
}

/* ---- Endnotes ---- */
.endnotes-section {
  background: white;
  box-shadow: var(--shadow-page);
  padding: 20px var(--page-margin-right) 20px var(--page-margin-left);
  margin-top: 16px;
  border-radius: 1px;
}

.endnotes-title {
  font-size: 16pt;
  font-weight: 700;
  color: var(--text-primary);
  border-bottom: 2px solid var(--color-primary-500);
  padding-bottom: 6px;
  margin-bottom: 12px;
}

.endnote-item {
  padding: 4px 0;
  display: flex;
  align-items: flex-start;
  gap: 6px;
  font-size: 10pt;
  color: var(--text-secondary);
  position: relative;
}

.endnote-num {
  color: var(--color-accent-600);
  font-size: 9pt;
  cursor: pointer;
  flex-shrink: 0;
}

.endnote-content {
  flex: 1;
  cursor: text;
  outline: none;
  min-height: 1em;
}

.endnote-content:focus {
  background: rgba(43, 87, 154, 0.05);
}

.endnote-remove-btn {
  opacity: 0;
  font-size: 12px;
  color: var(--color-danger);
  background: none;
  border: none;
  cursor: pointer;
  line-height: 1;
  padding: 0 2px;
  flex-shrink: 0;
}

.endnote-item:hover .endnote-remove-btn {
  opacity: 1;
}

/* ---- Tracked Changes ---- */
.rev-insertion {
  color: #166534;
  text-decoration: underline;
  text-decoration-color: #16a34a;
  background-color: rgba(22, 163, 74, 0.1);
  cursor: pointer;
}

.rev-deletion {
  color: #991b1b;
  text-decoration: line-through;
  text-decoration-color: #dc2626;
  background-color: rgba(220, 38, 38, 0.08);
  cursor: pointer;
}

/* ---- Review Panel (sidebar) ---- */
.review-panel {
  position: fixed;
  top: 0;
  right: 0;
  bottom: 0;
  width: 300px;
  background: white;
  border-left: 1px solid var(--color-gray-300);
  z-index: var(--z-sidebar);
  display: flex;
  flex-direction: column;
  box-shadow: -4px 0 15px rgba(0, 0, 0, 0.1);
}

.review-panel.hidden {
  display: none;
}

.review-panel-header {
  background: var(--color-primary-500);
  color: white;
  padding: 12px 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
  font-size: 14px;
}

.review-panel-header button {
  color: white;
  background: none;
  border: none;
  cursor: pointer;
  padding: 2px;
  border-radius: var(--radius-sm);
}

.review-panel-header button:hover {
  background: rgba(255, 255, 255, 0.2);
}

.review-panel-actions {
  display: flex;
  gap: 8px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--color-gray-200);
}

.review-btn {
  flex: 1;
  padding: 5px 8px;
  border-radius: var(--radius-md);
  font-size: 11px;
  font-weight: 500;
  cursor: pointer;
  border: 1px solid transparent;
  text-align: center;
}

.review-btn-accept {
  background: var(--color-primary-500);
  color: white;
}

.review-btn-accept:hover {
  background: var(--color-primary-600);
}

.review-btn-reject {
  background: white;
  color: var(--color-danger);
  border-color: var(--color-danger);
}

.review-btn-reject:hover {
  background: #fee2e2;
}

.review-list {
  flex: 1;
  overflow-y: auto;
  padding: 8px;
}

.review-empty {
  text-align: center;
  padding: 40px 20px;
  color: var(--text-tertiary);
  font-size: 13px;
}

.review-item {
  background: white;
  border: 1px solid var(--color-gray-200);
  border-radius: var(--radius-md);
  padding: 8px 10px;
  margin-bottom: 6px;
  cursor: pointer;
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
}

.review-item:hover {
  border-color: var(--color-primary-300);
  box-shadow: var(--shadow-sm);
}

.review-item-type {
  display: inline-block;
  font-size: 10px;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 10px;
  margin-bottom: 4px;
}

.review-item-insertion .review-item-type {
  background: rgba(22, 163, 74, 0.15);
  color: #166534;
}

.review-item-deletion .review-item-type {
  background: rgba(220, 38, 38, 0.1);
  color: #991b1b;
}

.review-item-text {
  font-size: 12px;
  color: var(--text-primary);
  display: block;
  margin-bottom: 4px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.review-item-meta {
  font-size: 10px;
  color: var(--text-tertiary);
  display: block;
}

.review-item-actions {
  display: flex;
  gap: 4px;
  margin-top: 6px;
  justify-content: flex-end;
}

.review-item-actions button {
  width: 24px;
  height: 24px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius-sm);
  border: 1px solid var(--color-gray-200);
  background: white;
  cursor: pointer;
  transition: background var(--transition-fast);
}

.review-item-actions button svg {
  width: 12px;
  height: 12px;
}

.review-item-accept {
  color: #166534;
}

.review-item-accept:hover {
  background: rgba(22, 163, 74, 0.1);
  border-color: #16a34a;
}

.review-item-reject {
  color: #991b1b;
}

.review-item-reject:hover {
  background: rgba(220, 38, 38, 0.1);
  border-color: #dc2626;
}

/* ---- Footnote/Endnote block types ---- */
.block-footnote {
  font-size: 10pt;
  color: var(--text-secondary);
  padding: 4px 0;
}

.block-footnote-num {
  color: var(--color-primary-600);
}

.block-endnote {
  font-size: 10pt;
  color: var(--text-secondary);
  padding: 4px 0;
}

.block-endnote-num {
  color: var(--color-accent-600);
}

.block-footnote-content,
.block-endnote-content {
  cursor: text;
  outline: none;
}

.table-cell-selected { outline: 2px solid #2b579a; outline-offset: -2px; background: #dbeafe !important; }
table th[data-cell-id] { font-weight: 600; background: #f3f4f6; }

::highlight(openword-comments) { background: rgba(255, 218, 76, .45); text-decoration: underline dotted #9a6700; }
.rev-insertion { text-decoration: underline; background: rgba(34,197,94,.12); }
.rev-deletion { text-decoration: line-through; background: rgba(239,68,68,.12); color: #991b1b; }
.comment-thread { padding: 12px; border-bottom: 1px solid #e5e7eb; }
.comment-thread header, .comment-thread footer { display: flex; gap: 8px; align-items: center; justify-content: space-between; }
.comment-thread header span { font-size: 11px; color: #6b7280; }
.comment-thread.resolved { opacity: .65; }
.comment-reply { margin: 8px 0 0 12px; padding-left: 8px; border-left: 2px solid #d1d5db; }
.comment-panel-toolbar { display: flex; gap: 8px; padding-bottom: 12px; }

/* Collaboration presence and remote change awareness */
.collaboration-presence { display:flex; align-items:center; padding:0 6px; min-width:34px; }
.presence-avatar { width:28px; height:28px; border-radius:50%; padding:0; margin-left:-5px; border:2px solid white; background:var(--presence-color); color:white; font-size:10px; font-weight:700; box-shadow:0 1px 3px rgba(0,0,0,.2); }
.presence-avatar:first-child { margin-left:0; }
.presence-avatar.self { outline:1px solid color-mix(in srgb, var(--presence-color) 55%, white); }
.presence-more { font-size:11px; color:var(--text-secondary); margin-left:4px; }
.remote-caret { position:fixed; z-index:10050; width:2px; pointer-events:none; background:var(--presence-color); }
.remote-caret span { position:absolute; left:0; top:-17px; white-space:nowrap; background:var(--presence-color); color:white; font-size:10px; line-height:16px; padding:0 4px; border-radius:3px 3px 3px 0; }
.remote-update-banner { position:fixed; z-index:10060; left:50%; bottom:42px; transform:translateX(-50%); min-width:min(560px,calc(100vw - 24px)); display:flex; align-items:center; justify-content:space-between; gap:18px; padding:12px 14px; border:1px solid #93c5fd; border-radius:10px; background:#eff6ff; color:#1e3a8a; box-shadow:0 8px 30px rgba(15,23,42,.2); }
.remote-update-banner.hidden { display:none; }
.remote-update-banner > div { display:flex; gap:8px; }
@media (max-width:700px) { .collaboration-presence .presence-avatar:not(.self):nth-of-type(n+3){display:none}.remote-update-banner{align-items:flex-start;flex-direction:column}.remote-update-banner>div{align-self:flex-end} }

/* Unified anchored objects */
.object-host {
  position: relative;
  display: block;
  max-width: 100%;
  min-width: 24px;
  min-height: 24px;
  outline: none;
  isolation: isolate;
}

.object-host.object-flow { margin-block: 8px; }
.object-host.object-wrap-inline { display: inline-block; vertical-align: baseline; }
.object-host.object-wrap-square,
.object-host.object-wrap-tight,
.object-host.object-wrap-through { display: block; }
.object-host.object-wrap-topBottom { clear: both; }
.object-host.object-floating { position: absolute; margin: 0; }
.object-host.object-wrap-behindText { z-index: 0 !important; pointer-events: auto; }
.object-host.object-wrap-inFrontOfText { z-index: 30; }
.object-frame {
  position: relative;
  width: 100%;
  height: 100%;
  min-height: 24px;
  transform: rotate(var(--object-rotation, 0deg));
  transform-origin: center;
}
.object-image-viewport { position: relative; width: 100%; height: 100%; overflow: hidden; background: transparent; }
.object-image-viewport img { position: absolute; max-width: none; object-fit: cover; display: block; }
.object-caption { margin-top: 6px; text-align: center; font-size: 12px; color: var(--text-secondary); font-style: italic; }
.text-box-frame { display: flex; overflow: hidden; }
.text-box-editor { width: 100%; min-height: 100%; outline: none; overflow: hidden; column-gap: 18px; cursor: text; }
.text-box-editor.vertical-top { display: block; }
.text-box-editor.vertical-middle { display: flex; flex-direction: column; justify-content: center; }
.text-box-editor.vertical-bottom { display: flex; flex-direction: column; justify-content: flex-end; }
.object-transform-handles { position: absolute; inset: 0; pointer-events: none; display: none; z-index: 60; }
.object-selected > .object-transform-handles,
.object-selected .object-transform-handles { display: block; }
.object-selected { outline: 2px solid var(--color-primary-500); outline-offset: 2px; }
.object-handle, .object-rotate-handle {
  position: absolute; width: 10px; height: 10px; border: 1px solid var(--color-primary-600);
  background: white; border-radius: 2px; pointer-events: auto;
}
.object-handle.nw { left:-6px;top:-6px;cursor:nwse-resize}.object-handle.n{left:50%;top:-6px;transform:translateX(-50%);cursor:ns-resize}
.object-handle.ne{right:-6px;top:-6px;cursor:nesw-resize}.object-handle.e{right:-6px;top:50%;transform:translateY(-50%);cursor:ew-resize}
.object-handle.se{right:-6px;bottom:-6px;cursor:nwse-resize}.object-handle.s{left:50%;bottom:-6px;transform:translateX(-50%);cursor:ns-resize}
.object-handle.sw{left:-6px;bottom:-6px;cursor:nesw-resize}.object-handle.w{left:-6px;top:50%;transform:translateY(-50%);cursor:ew-resize}
.object-rotate-handle { left:50%;top:-30px;transform:translateX(-50%);border-radius:50%;cursor:grab; }
.object-rotate-handle::after { content:""; position:absolute; left:4px; top:9px; height:18px; border-left:1px solid var(--color-primary-500); }
.object-wrap-button { position:absolute; right:-34px; top:0; width:26px; height:26px; display:grid; place-items:center; background:white; border:1px solid var(--color-gray-300); border-radius:4px; pointer-events:auto; cursor:pointer; }
.object-anchor-indicator { position:absolute; left:-26px; top:0; font-size:15px; opacity:.7; }
.object-crop-mode .object-image-viewport { outline: 2px dashed #f59e0b; box-shadow: 0 0 0 9999px rgba(15,23,42,.2); }
.object-format-panel { position:fixed; right:18px; top:112px; width:292px; max-height:calc(100vh - 140px); overflow:auto; z-index:var(--z-modal,1000); background:var(--bg-primary,#fff); border:1px solid var(--color-gray-300); border-radius:10px; padding:12px; box-shadow:0 12px 30px rgba(15,23,42,.18); display:grid; gap:9px; }
.object-format-panel.hidden { display:none; }
.object-format-panel label { display:grid; gap:4px; font-size:12px; color:var(--text-secondary); }
.object-format-panel input, .object-format-panel select { width:100%; min-height:30px; border-color:var(--color-gray-300); background:var(--bg-primary,#fff); }
.object-panel-row { display:flex; gap:6px; align-items:center; }
.object-panel-row button { flex:1; min-height:30px; }
.object-panel-title { justify-content:space-between; }
.object-panel-title button { flex:0 0 28px; }
.object-panel-grid { display:grid; grid-template-columns:1fr 1fr; gap:7px; }
.object-guide-layer { position:fixed; inset:0; pointer-events:none; z-index:9999; }
.object-guide-layer i { position:absolute; display:block; background:#ef4444; opacity:.75; }
.object-guide-layer .guide-v { top:0; bottom:0; width:1px; }
.object-guide-layer .guide-h { left:0; right:0; height:1px; }
.page-behind-text-objects,.page-front-objects { position:absolute; inset:0; pointer-events:none; }
.page-behind-text-objects { z-index:0; }
.page-front-objects { z-index:25; }
.page-content-area { position:relative; z-index:5; }
.page-behind-text-objects .object-host,.page-front-objects .object-host { pointer-events:auto; }
.object-host.object-auto-height,.object-host.object-auto-height .object-frame,.object-host.object-auto-height .object-image-viewport { height:auto; }
.object-host.object-auto-height .object-image-viewport img { position:relative; width:100%; height:auto; left:auto; top:auto; }
.pagination-options-panel { position:fixed; right:20px; top:118px; width:270px; z-index:var(--z-modal,1000); background:var(--bg-primary,#fff); border:1px solid var(--color-gray-300); border-radius:9px; box-shadow:0 12px 30px rgba(15,23,42,.18); padding:12px; display:grid; gap:10px; }
.pagination-options-panel.hidden { display:none; }
.pagination-options-panel label { display:flex; justify-content:space-between; align-items:center; gap:12px; font-size:13px; }
.pagination-options-panel input[type="number"] { width:70px; border:1px solid var(--color-gray-300); }
.pagination-options-panel p { margin:0; color:var(--text-secondary); font-size:12px; }
.pagination-panel-header { display:flex; justify-content:space-between; align-items:center; }



/* Model-backed structural tracked changes */
.revision-block-insertion {
  outline: 2px solid rgba(34, 197, 94, 0.45);
  outline-offset: 2px;
}

.revision-block-deletion {
  outline: 2px dashed rgba(239, 68, 68, 0.55);
  outline-offset: 2px;
  opacity: 0.72;
}

.block-text.revision-paragraph-break::after {
  content: "¶";
  display: inline-block;
  margin-left: 0.25em;
  font-size: 0.85em;
  font-weight: 700;
  user-select: none;
}

.block-text.revision-paragraph-break-insertion::after {
  color: #15803d;
  text-decoration: underline;
}

.block-text.revision-paragraph-break-deletion::after {
  color: #b91c1c;
  text-decoration: line-through;
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/css/layout.css
// ================================================================
.toolbar {
  background: var(--bg-toolbar);
  border-bottom: 1px solid var(--border-color);
  box-shadow: var(--shadow-sm);
  z-index: var(--z-toolbar);
  flex-shrink: 0;
  position: relative;
  display: flex;
  flex-direction: column;
}

/* ─── Layer 1: App/Document bar ─── */
.ribbon-bar {
  display: flex;
  align-items: center;
  padding: 0 var(--space-3);
  height: 40px;
  gap: var(--space-1);
  flex-shrink: 0;
  background: var(--bg-toolbar);
  border-bottom: 1px solid var(--color-gray-200);
}

.ribbon-docs-btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  font-size: var(--text-sm);
  font-weight: 500;
  color: var(--text-primary);
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--radius-md);
  cursor: pointer;
  white-space: nowrap;
  transition: background var(--transition-fast), border-color var(--transition-fast);
  min-height: 32px;
}

.ribbon-docs-btn:hover {
  background: var(--color-gray-50);
  border-color: var(--color-gray-200);
}

.ribbon-docs-btn svg {
  width: 18px;
  height: 18px;
  stroke-width: 2;
}

.docs-chevron {
  width: 12px !important;
  height: 12px !important;
}

.doc-title {
  margin-left: var(--space-2);
  font-weight: 600;
  font-size: var(--text-lg);
  color: var(--text-primary);
  padding: 3px 6px;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  outline: none;
  min-width: 80px;
  max-width: 240px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  line-height: 1.3;
  transition: border-color var(--transition-fast);
}

.doc-title:focus {
  border-color: var(--color-primary-300);
  background: var(--color-primary-50);
}

.save-indicator {
  font-size: var(--text-xs);
  color: var(--color-primary-500);
  font-weight: 500;
  margin-left: var(--space-2);
  white-space: nowrap;
  flex-shrink: 0;
}

.ribbon-bar-sep {
  width: 1px;
  height: 22px;
  background: var(--color-gray-200);
  margin: 0 var(--space-1);
  flex-shrink: 0;
}

.ribbon-bar-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  padding: 0;
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--radius-md);
  cursor: pointer;
  color: var(--text-secondary);
  transition: background var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
  flex-shrink: 0;
}

.ribbon-bar-btn:hover {
  background: var(--color-gray-50);
  border-color: var(--color-gray-200);
  color: var(--text-primary);
}

.ribbon-bar-btn svg {
  width: 18px;
  height: 18px;
  stroke-width: 2;
}

.ribbon-bar-spacer {
  flex: 1;
  min-width: 0;
}

.ribbon-toggle {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 34px;
  padding: 0;
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--radius-md);
  cursor: pointer;
  color: var(--text-secondary);
  flex-shrink: 0;
  transition: background var(--transition-fast), color var(--transition-fast);
}

.ribbon-toggle:hover {
  background: var(--color-gray-50);
  border-color: var(--color-gray-200);
  color: var(--text-primary);
}

.ribbon-toggle svg {
  width: 18px;
  height: 18px;
  stroke-width: 2;
  transition: transform var(--transition-fast);
}

.ribbon.collapsed .ribbon-toggle svg {
  transform: rotate(180deg);
}

/* ─── Layer 2: Ribbon tabs ─── */
.ribbon-tab-row {
  display: flex;
  align-items: flex-end;
  gap: 0;
  padding: 0 var(--space-3);
  padding-top: 0;
  background: var(--color-gray-50);
  border-bottom: 1px solid var(--color-gray-200);
  flex-shrink: 0;
  min-height: 32px;
}

.ribbon-tab {
  padding: 6px 18px 5px;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
  cursor: pointer;
  white-space: nowrap;
  user-select: none;
  border: 1px solid transparent;
  border-bottom: none;
  border-radius: var(--radius-md) var(--radius-md) 0 0;
  margin-bottom: -1px;
  transition: background var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
}

.ribbon-tab:hover {
  color: var(--text-primary);
  background: var(--color-gray-100);
}

.ribbon-tab.active {
  color: var(--color-primary-600);
  background: white;
  border-color: var(--color-gray-200) var(--color-gray-200) white;
  font-weight: 600;
}

/* ─── Layer 3: Ribbon body / commands ─── */
.ribbon-body {
  display: flex;
  align-items: flex-start;
  gap: 0;
  padding: 6px var(--space-3) 6px;
  background: white;
  border-bottom: 1px solid var(--color-gray-200);
  overflow-x: auto;
  overflow-y: hidden;
  flex-shrink: 0;
  transition: max-height var(--transition-normal), padding var(--transition-normal), opacity var(--transition-normal);
  max-height: 110px;
  opacity: 1;
}

.ribbon.collapsed .ribbon-body {
  max-height: 0;
  padding-top: 0;
  padding-bottom: 0;
  opacity: 0;
  overflow: hidden;
}

/* ─── Ribbon panels ─── */
.ribbon-panel {
  display: none;
  gap: 0;
  align-items: stretch;
  width: 100%;
}

.ribbon-panel.active {
  display: flex;
}

/* ─── Ribbon groups ─── */
.ribbon-group {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 3px;
  padding: 0 12px;
  border-right: 1px solid var(--color-gray-150);
  flex-shrink: 0;
}

.ribbon-group:last-child {
  border-right: none;
}

.ribbon-group-label {
  font-size: 10px;
  font-weight: 500;
  color: var(--text-tertiary);
  white-space: nowrap;
  line-height: 1;
  padding-bottom: 2px;
  letter-spacing: 0.3px;
}

.ribbon-group-buttons {
  display: flex;
  gap: 1px;
  align-items: center;
}

.ribbon-group-buttons .btn-sep {
  width: 1px;
  height: 28px;
  background: var(--color-gray-150);
  margin: 0 4px;
  flex-shrink: 0;
}

.toolbar-group {
  display: flex;
  gap: 2px;
  padding-right: var(--space-3);
  border-right: 1px solid var(--border-color);
  align-items: center;
  min-height: 32px;
}

.toolbar-group:last-child {
  border-right: none;
}

.toolbar-dropdown {
  position: relative;
}

.ruler-container {
  height: 25px;
  background: var(--color-gray-100);
  border-bottom: 1px solid var(--color-gray-300);
  display: flex;
  justify-content: center;
  position: relative;
  flex-shrink: 0;
}

.ruler {
  box-sizing: border-box;
  width: var(--page-width);
  background: white;
  height: 100%;
  position: relative;
  border-left: 1px solid var(--color-gray-300);
  border-right: 1px solid var(--color-gray-300);
}

.ruler-marker {
  position: absolute;
  top: 0;
  width: 0;
  height: 100%;
  border-left: 1px dashed var(--color-gray-400);
  cursor: col-resize;
  z-index: var(--z-ruler);
}

.ruler-marker::before {
  content: '\25BC';
  position: absolute;
  top: -5px;
  left: -5px;
  color: var(--color-gray-500);
  font-size: 10px;
}

.ruler-marker:hover::before {
  color: var(--color-primary-500);
}

.main-layout {
  display: flex;
  flex: 1;
  overflow: hidden;
  position: relative;
}

#workspace-wrapper {
  flex: 1;
  overflow: auto;
  background: var(--bg-page-view);
  display: flex;
  justify-content: center;
  align-items: flex-start;
  padding: var(--space-8);
  padding-bottom: 50px;
  min-width: 0;
}

#workspace {
  transform-origin: top center;
  transition: transform var(--transition-fast);
}

.mode-page {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-5);
}

.mode-pageless {
  background: white;
  padding: var(--space-10);
  display: block;
  width: 800px;
  min-height: 1000px;
  margin: auto;
}

.status-bar {
  background: var(--bg-status-bar);
  border-top: 1px solid var(--border-color);
  padding: var(--space-1) var(--space-4);
  font-size: var(--text-sm);
  color: var(--text-secondary);
  display: flex;
  justify-content: space-between;
  align-items: center;
  height: 32px;
  z-index: var(--z-toolbar);
  flex-shrink: 0;
  gap: var(--space-3);
}

.status-left {
  display: flex;
  gap: var(--space-2);
  align-items: center;
  flex-shrink: 0;
}

.status-mid {
  display: flex;
  gap: 2px;
  align-items: center;
  flex-shrink: 0;
}

.status-right {
  display: flex;
  gap: var(--space-1);
  align-items: center;
  flex-shrink: 0;
}

.sep {
  color: var(--color-gray-300);
}

#save-status {
  font-weight: 600;
  color: var(--color-primary-500);
}

#lang-display {
  color: var(--text-secondary);
  cursor: pointer;
  padding: 1px 4px;
  border-radius: var(--radius-sm);
  font-size: var(--text-sm);
  transition: background var(--transition-fast);
}

#lang-display:hover {
  background: var(--color-gray-100);
}

.status-view-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  padding: 0;
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  cursor: pointer;
  color: var(--text-tertiary);
  transition: background var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
}

.status-view-btn:hover {
  background: var(--color-gray-50);
  color: var(--text-primary);
}

.status-view-btn.active {
  background: var(--color-primary-50);
  color: var(--color-primary-500);
  border-color: var(--color-primary-200);
}

.status-view-btn svg {
  width: 14px;
  height: 14px;
  stroke-width: 2;
}

.zoom-slider {
  width: 80px;
  height: 4px;
  -webkit-appearance: none;
  appearance: none;
  background: var(--color-gray-200);
  border-radius: 2px;
  outline: none;
  cursor: pointer;
  margin: 0;
  padding: 0;
}

.zoom-slider::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: var(--color-primary-500);
  cursor: pointer;
  border: none;
  transition: background var(--transition-fast);
}

.zoom-slider::-webkit-slider-thumb:hover {
  background: var(--color-primary-600);
}

.zoom-slider::-moz-range-thumb {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: var(--color-primary-500);
  cursor: pointer;
  border: none;
}

.workspace-split-wrapper {
  flex: 1;
  display: flex;
  overflow: hidden;
  background: var(--bg-page-view);
}

.workspace-split-wrapper.hidden {
  display: none;
}

.workspace-split-pane {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: auto;
  position: relative;
}

.workspace-split-pane .split-pane-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 4px 12px;
  background: var(--color-gray-100);
  border-bottom: 1px solid var(--border-color);
  font-size: var(--text-sm);
  font-weight: 500;
  flex-shrink: 0;
  position: sticky;
  top: 0;
  z-index: 5;
}

.split-pane-header .split-close-btn {
  width: 22px;
  height: 22px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: none;
  background: transparent;
  border-radius: var(--radius-sm);
  cursor: pointer;
  color: var(--text-tertiary);
}

.split-pane-header .split-close-btn:hover {
  background: var(--color-gray-200);
  color: var(--text-primary);
}

.workspace-split-pane .mode-page {
  padding: var(--space-5);
  align-items: center;
}

.workspace-split-divider {
  width: 5px;
  background: var(--color-gray-300);
  cursor: col-resize;
  flex-shrink: 0;
  transition: background var(--transition-fast);
}

.workspace-split-divider:hover {
  background: var(--color-primary-300);
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/css/mobile.css
// ================================================================
/* Mobile styles – loaded after all other CSS */

/* Utility: show/hide on mobile */
.mobile-only { display: none !important; }

/* ─── Toolbar toggle button ─── */
#btn-toolbar-toggle {
  display: none;
  min-width: 36px;
  min-height: 36px;
  padding: var(--space-1);
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--radius-md);
  cursor: pointer;
  color: var(--text-primary);
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
#btn-toolbar-toggle:hover {
  background: var(--color-gray-100);
}
#btn-toolbar-toggle svg {
  width: 22px;
  height: 22px;
  stroke-width: 2;
  pointer-events: none;
}

.mobile-toolbar-drawer {
  display: none;
  width: 100%;
  background: var(--bg-panel);
  border-bottom: 1px solid var(--border-color);
  box-shadow: var(--shadow-md);
  padding: var(--space-2);
  max-height: 60vh;
  overflow-y: auto;
  -webkit-overflow-scrolling: touch;
}
.mobile-toolbar-drawer.open {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

/* ─── Bottom nav bar ─── */
.mobile-nav-bar {
  display: none;
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  height: 56px;
  background: var(--bg-toolbar);
  border-top: 1px solid var(--border-color);
  z-index: 200;
  justify-content: space-around;
  align-items: center;
  padding-bottom: env(safe-area-inset-bottom, 0px);
}
.mobile-nav-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 2px;
  padding: 4px 8px;
  min-width: 48px;
  min-height: 48px;
  background: transparent;
  border: none;
  border-radius: var(--radius-md);
  color: var(--text-secondary);
  font-size: 10px;
  font-family: var(--font-sans);
  cursor: pointer;
  transition: color var(--transition-fast), background var(--transition-fast);
}
.mobile-nav-item svg {
  width: 20px;
  height: 20px;
  stroke-width: 2;
}
.mobile-nav-item.active {
  color: var(--color-primary-500);
  background: var(--color-primary-50);
}

/* ─── Bottom sheet overlay (for panels on mobile) ─── */
.mobile-sheet-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.4);
  z-index: 4500;
}
.mobile-sheet-overlay.open {
  display: block;
}
.mobile-sheet {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  max-height: 70vh;
  background: white;
  border-radius: var(--radius-lg) var(--radius-lg) 0 0;
  box-shadow: 0 -4px 20px rgba(0,0,0,0.15);
  z-index: 4600;
  transform: translateY(100%);
  transition: transform 300ms ease;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  padding-bottom: env(safe-area-inset-bottom, 0px);
}
.mobile-sheet.open {
  transform: translateY(0);
}
.mobile-sheet-handle {
  width: 36px;
  height: 5px;
  background: var(--color-gray-300);
  border-radius: 3px;
  margin: 8px auto;
  flex-shrink: 0;
}
.mobile-sheet-header {
  padding: 8px 16px;
  font-weight: 600;
  font-size: var(--text-base);
  border-bottom: 1px solid var(--color-gray-200);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-shrink: 0;
}
.mobile-sheet-body {
  flex: 1;
  overflow-y: auto;
  padding: 12px 16px;
}

/* ─── Breakpoints ─── */

/* Tablets & small laptops */
@media (max-width: 1024px) {
  .outline-sidebar,
  .outline-rail {
    display: none;
  }

  #workspace-wrapper {
    padding: var(--space-4);
    padding-bottom: 50px;
  }

  .mode-page .page {
    margin-bottom: var(--space-4);
  }
}

/* Mobile phones */
@media (max-width: 768px) {
  .mobile-only { display: flex !important; }

  #btn-toolbar-toggle { display: flex; }

  /* ─── Bottom nav bar ─── */
  .mobile-nav-bar {
    display: flex;
  }

  /* ─── Safe area padding on body ─── */
  body {
    padding-top: env(safe-area-inset-top, 0px);
    padding-left: env(safe-area-inset-left, 0px);
    padding-right: env(safe-area-inset-right, 0px);
  }

  /* Hide ribbon tabs, body, and collapse toggle on mobile */
  .ribbon-tab-row,
  .ribbon-body,
  .ribbon-toggle,
  .save-indicator,
  .ribbon-bar-sep,
  .ribbon-bar-spacer,
  .docs-chevron,
  .ribbon-docs-btn span {
    display: none;
  }

  .floating-toolbar {
    display: none !important;
  }

  .welcome-template-grid {
    grid-template-columns: repeat(2, 1fr);
  }

  .welcome-actions {
    flex-direction: column;
  }

  .workspace-split-wrapper {
    flex-direction: column;
  }

  .workspace-split-divider {
    width: 100%;
    height: 5px;
  }

  .status-mid {
    display: none;
  }

  .zoom-slider {
    width: 50px;
  }

  .ribbon-font-sel {
    min-width: 60px;
    max-width: 80px;
  }

  /* App bar becomes compact on mobile */
  .ribbon-bar {
    height: 44px;
    padding: 0 var(--space-2);
    gap: var(--space-1);
  }

  .ribbon-docs-btn {
    padding: 4px 6px;
    min-height: 36px;
  }

  .ribbon-docs-btn svg {
    width: 20px;
    height: 20px;
  }

  /* Toolbar shrinks */
  .toolbar.ribbon {
    padding: 0;
    min-height: 44px;
  }

  .doc-title {
    font-size: var(--text-sm);
    margin-left: var(--space-1);
    min-width: 60px;
    max-width: 140px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .ribbon-bar-btn {
    width: 36px;
    height: 36px;
  }

  /* ─── Stack main-layout vertically ─── */
  .main-layout {
    flex-direction: column;
  }

  /* Ruler – hide on small screens */
  .ruler-container {
    display: none;
  }

  /* ─── Workspace / page scaling ─── */
  #workspace-wrapper {
    padding: var(--space-2);
    padding-bottom: 80px;
    overflow: auto;
    -webkit-overflow-scrolling: touch;
  }

  .mode-page .page {
    margin-bottom: var(--space-3);
  }

  /* Scale pages to fit viewport width with some padding */
  .mode-page {
    gap: var(--space-3);
    align-items: center;
  }

  /* Scale individual pages to fit viewport */
  .page {
    max-width: calc(100vw - 16px);
    height: auto;
    aspect-ratio: 8.5/11;
  }

  .page-content-area {
    position: relative;
    left: 8px;
    right: 8px;
    top: 8px;
    bottom: 8px;
  }

  .page-header {
    position: relative;
    left: 8px;
    right: 8px;
    top: 0;
    height: auto;
    min-height: 1em;
  }
  .page-footer {
    position: relative;
    left: 8px;
    right: 8px;
    bottom: 0;
    height: auto;
    min-height: 1em;
  }

  .page-footnotes-area {
    position: relative;
    left: 8px;
    right: 8px;
    bottom: 0;
    max-height: none;
  }

  .mode-pageless {
    padding: var(--space-4);
    width: 100%;
    min-height: auto;
  }

  /* ─── Review panel as bottom sheet ─── */
  .review-panel {
    position: fixed;
    top: auto;
    bottom: 0;
    left: 0;
    right: 0;
    width: 100%;
    max-height: 60vh;
    border-radius: var(--radius-lg) var(--radius-lg) 0 0;
    border-left: none;
    border-top: 1px solid var(--color-gray-300);
    transform: translateY(100%);
    transition: transform 300ms ease;
    box-shadow: 0 -4px 20px rgba(0,0,0,0.15);
  }
  .review-panel:not(.hidden) {
    transform: translateY(0);
  }

  /* ─── Outline sidebar as bottom sheet on mobile ─── */
  .outline-sidebar {
    display: none;
    position: fixed;
    top: auto;
    bottom: 0;
    left: 0;
    right: 0;
    width: 100%;
    max-height: 60vh;
    border-radius: var(--radius-lg) var(--radius-lg) 0 0;
    border-right: none;
    border-top: 1px solid var(--color-gray-300);
    z-index: var(--z-sidebar);
    box-shadow: 0 -4px 20px rgba(0,0,0,0.15);
    overflow-y: auto;
  }
  .outline-sidebar.mobile-open {
    display: flex;
  }

  /* Status bar – compact */
  .status-bar {
    height: 36px;
    padding: var(--space-1) var(--space-2);
    font-size: var(--text-xs);
  }

  .status-right button {
    min-width: 36px;
    min-height: 36px;
  }

  /* Modals – full-screen on mobile */
  .modal-content {
    width: 100% !important;
    max-width: 100% !important;
    height: 100%;
    border-radius: 0;
    padding: var(--space-4);
    padding-top: calc(var(--space-4) + env(safe-area-inset-top, 0px));
    display: flex;
    flex-direction: column;
  }

  .modal-body {
    flex: 1;
    overflow-y: auto;
  }

  .modal {
    align-items: flex-end;
  }

  .modal:not(.hidden) .modal-content {
    animation: mobile-modal-enter 250ms ease-out;
  }

  @keyframes mobile-modal-enter {
    from {
      opacity: 0;
      transform: translateY(30px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  /* Document sidebar – full width on mobile */
  .sidebar {
    width: 100%;
    max-width: 100%;
  }

  /* ─── Tap targets – at least 44px ─── */
  button,
  select,
  .toolbar button,
  .status-bar button,
  .sidebar button,
  .modal button {
    min-height: 44px;
  }

  button:has(> svg:only-child) {
    min-width: 44px;
    min-height: 44px;
  }

  .toolbar button svg {
    width: 22px;
    height: 22px;
  }

  /* ─── Touch-friendly editor ─── */
  #workspace {
    touch-action: manipulation;
  }

  .page-content-area {
    -webkit-user-select: text;
    user-select: text;
    -webkit-touch-callout: default;
  }

  /* Prevent iOS zoom on double-tap in editor */
  .page-content-area,
  .mode-pageless,
  #workspace {
    touch-action: pan-x pan-y pinch-zoom;
  }

  /* Responsive font sizing */
  @media (max-width: 480px) {
    .style-normal {
      font-size: 14px;
    }
    .style-h1 {
      font-size: 22px;
    }
    .style-h2 {
      font-size: 16px;
    }
    .style-h3 {
      font-size: 14px;
    }
    .style-h4 {
      font-size: 13px;
    }
    .welcome-title {
      font-size: 22px;
    }
    .welcome-page {
      padding: var(--space-4);
    }
  }

  /* Mobile toolbar drawer – full-width row groups */
  .mobile-toolbar-drawer .toolbar-group {
    display: flex !important;
    flex-wrap: wrap;
    gap: var(--space-1);
    padding: var(--space-1) 0;
    border-right: none;
    border-bottom: 1px solid var(--border-color);
  }

  .mobile-toolbar-drawer .toolbar-group:last-child {
    border-bottom: none;
  }

  .mobile-toolbar-drawer select {
    min-height: 44px;
    font-size: var(--text-base);
  }

  /* ─── Mobile ribbon tabs in drawer ─── */
  .mobile-ribbon-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    padding: 4px 0;
    border-bottom: 1px solid var(--border-color);
    margin-bottom: 4px;
  }
  .mobile-ribbon-tab {
    padding: 6px 12px;
    font-size: 12px;
    font-weight: 500;
    border-radius: var(--radius-full);
    border: 1px solid var(--border-color);
    background: var(--color-gray-50);
    color: var(--text-secondary);
    cursor: pointer;
    white-space: nowrap;
    transition: background var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
  }
  .mobile-ribbon-tab.active {
    background: var(--color-primary-500);
    color: white;
    border-color: var(--color-primary-500);
  }

  /* Image resize handles – larger for touch */
  .img-handle {
    width: 24px;
    height: 24px;
  }

  .img-handle.se { bottom: -12px; right: -12px; }
  .img-handle.sw { bottom: -12px; left: -12px; }

  /* Floating box resize handle */
  .resize-handle {
    width: 24px;
    height: 24px;
  }

  /* Context menu – larger on mobile */
  .context-menu {
    min-width: 200px;
    padding: 8px 0;
    font-size: var(--text-base);
    border-radius: var(--radius-lg);
  }
  .context-menu-item {
    padding: 12px 16px;
    font-size: var(--text-base);
  }
}

/* Prevent text selection on toolbar interactions */
.toolbar,
.mobile-toolbar-drawer {
  -webkit-user-select: none;
  user-select: none;
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/css/reset.css
// ================================================================
*, *::before, *::after {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: var(--font-sans);
  background: var(--bg-app);
  color: var(--text-primary);
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

::selection {
  background: var(--color-primary-200);
  color: var(--text-primary);
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/css/shell.css
// ================================================================
/* Phase 3 application shell -------------------------------------------------
   This layer intentionally sits after components.css so the redesigned shell
   can reuse the existing ribbon/editor commands without changing the editor. */

.toolbar.ribbon {
  background: #fff;
  box-shadow: 0 1px 3px rgba(17, 24, 39, 0.08);
  border-bottom: 1px solid var(--color-gray-200);
  isolation: isolate;
}

/* Application bar */
.ribbon-bar.app-bar {
  min-height: 56px;
  height: 56px;
  padding: 6px 12px;
  gap: 12px;
  background: #fff;
  border-bottom: 1px solid var(--color-gray-150);
  justify-content: space-between;
}

.app-bar-left,
.app-bar-actions,
.document-title-row {
  display: flex;
  align-items: center;
}

.app-bar-left {
  min-width: 0;
  flex: 1 1 380px;
  gap: 6px;
}

.app-bar-actions {
  flex: 1 1 380px;
  justify-content: flex-end;
  gap: 4px;
  min-width: 0;
}

.app-brand {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 3px 6px 3px 3px;
  min-height: 40px;
  background: transparent;
  border: 1px solid transparent;
  border-radius: 8px;
  color: var(--color-primary-500);
  cursor: pointer;
}

.app-brand:hover {
  background: var(--color-primary-50);
  border-color: var(--color-primary-100);
}

.app-brand-mark {
  width: 34px;
  height: 34px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  background: linear-gradient(145deg, var(--color-primary-500), var(--color-primary-700));
  border-radius: 8px;
  box-shadow: 0 2px 5px rgba(43, 87, 154, 0.24);
}

.app-brand-mark svg {
  width: 21px;
  height: 21px;
}

.app-brand-name {
  font-size: 15px;
  font-weight: 650;
  letter-spacing: -0.15px;
}

.file-menu-trigger {
  min-height: 34px;
  padding: 0 11px;
  border: 1px solid transparent;
  border-radius: 6px;
  background: transparent;
  color: var(--text-primary);
  font: inherit;
  font-weight: 550;
  cursor: pointer;
}

.file-menu-trigger:hover,
.file-menu-trigger[aria-expanded="true"] {
  background: var(--color-primary-50);
  border-color: var(--color-primary-100);
  color: var(--color-primary-700);
}

.document-identity {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  justify-content: center;
  min-width: 120px;
  max-width: 330px;
  overflow: hidden;
  line-height: 1;
}

.document-title-row {
  min-width: 0;
  width: 100%;
  gap: 1px;
}

.document-title-row .doc-title {
  margin: 0;
  min-width: 90px;
  max-width: 230px;
  padding: 3px 5px;
  font-size: 14px;
  font-weight: 600;
  line-height: 18px;
  border-radius: 5px;
}

.document-title-row .doc-title:hover {
  border-color: var(--color-gray-200);
}

.shell-save-state {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  max-width: 160px;
  min-height: 18px;
  margin: 0 0 0 5px;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--color-gray-500);
  font-size: 11px;
  font-weight: 500;
  cursor: pointer;
}

.shell-save-state:hover {
  color: var(--color-primary-600);
}

.shell-save-state svg {
  width: 13px;
  height: 13px;
}

.shell-icon-btn,
.shell-action-btn,
.share-button,
.user-avatar,
.compact-command {
  font-family: var(--font-sans);
}

.shell-icon-btn {
  width: 34px;
  height: 34px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  padding: 0;
  border: 1px solid transparent;
  border-radius: 7px;
  background: transparent;
  color: var(--text-secondary);
  cursor: pointer;
}

.shell-icon-btn:hover,
.shell-icon-btn.active {
  background: var(--color-gray-50);
  border-color: var(--color-gray-200);
  color: var(--text-primary);
}

.shell-icon-btn-subtle {
  width: 27px;
  height: 27px;
}

.shell-icon-btn svg {
  width: 17px;
  height: 17px;
}

.shell-icon-btn-subtle svg {
  width: 15px;
  height: 15px;
}

.app-bar-divider {
  width: 1px;
  height: 24px;
  margin: 0 3px;
  background: var(--color-gray-200);
}

.shell-action-btn {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  height: 34px;
  padding: 0 9px;
  border: 1px solid transparent;
  border-radius: 7px;
  background: transparent;
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 550;
  cursor: pointer;
  white-space: nowrap;
}

.shell-action-btn:hover,
.shell-action-btn[aria-pressed="true"] {
  background: var(--color-gray-50);
  border-color: var(--color-gray-200);
  color: var(--text-primary);
}

.shell-action-btn svg {
  width: 17px;
  height: 17px;
}

.shell-count-badge {
  min-width: 17px;
  height: 17px;
  padding: 0 5px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 999px;
  background: var(--color-primary-500);
  color: #fff;
  font-size: 10px;
}

.share-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 7px;
  height: 36px;
  padding: 0 14px;
  border: 1px solid var(--color-primary-600);
  border-radius: 8px;
  background: var(--color-primary-500);
  color: #fff;
  font-size: 12px;
  font-weight: 650;
  cursor: pointer;
  box-shadow: 0 1px 2px rgba(43, 87, 154, 0.22);
}

.share-button:hover {
  background: var(--color-primary-700);
}

.share-button svg {
  width: 17px;
  height: 17px;
}

.user-avatar {
  width: 34px;
  height: 34px;
  padding: 0;
  border: 0;
  border-radius: 50%;
  background: #e8eef8;
  color: var(--color-primary-700);
  font-size: 11px;
  font-weight: 700;
  cursor: pointer;
}

.command-search {
  position: relative;
  flex: 0 1 460px;
  height: 38px;
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 220px;
  padding: 0 10px;
  border: 1px solid var(--color-gray-200);
  border-radius: 9px;
  background: var(--color-gray-50);
  color: var(--color-gray-500);
  transition: border-color var(--transition-fast), background var(--transition-fast), box-shadow var(--transition-fast);
}

.command-search:focus-within {
  background: #fff;
  border-color: var(--color-primary-300);
  box-shadow: 0 0 0 3px var(--color-primary-50);
}

.command-search > svg {
  width: 17px;
  height: 17px;
  flex-shrink: 0;
}

.command-search input {
  width: 100%;
  min-width: 0;
  height: 100%;
  padding: 0;
  border: 0;
  outline: 0;
  background: transparent;
  color: var(--text-primary);
  font: inherit;
  font-size: 12px;
}

.command-search kbd,
.file-menu-popover kbd {
  border: 1px solid var(--color-gray-200);
  border-bottom-color: var(--color-gray-300);
  border-radius: 4px;
  background: #fff;
  color: var(--color-gray-500);
  font-family: var(--font-sans);
  font-size: 10px;
  line-height: 18px;
  padding: 0 5px;
  white-space: nowrap;
}

.command-search-results {
  position: absolute;
  top: calc(100% + 6px);
  left: 0;
  right: 0;
  z-index: 5500;
  max-height: 330px;
  overflow: auto;
  padding: 6px;
  border: 1px solid var(--color-gray-200);
  border-radius: 9px;
  background: #fff;
  box-shadow: var(--shadow-lg);
}

.command-search-result {
  width: 100%;
  min-height: 38px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 7px 9px;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--text-primary);
  text-align: left;
  font: inherit;
  cursor: pointer;
}

.command-search-result:hover,
.command-search-result.active {
  background: var(--color-primary-50);
  color: var(--color-primary-700);
}

.command-search-result small {
  color: var(--text-tertiary);
}

.command-search-empty {
  padding: 14px;
  color: var(--text-tertiary);
  text-align: center;
  font-size: 12px;
}

/* Compact toolbar */
.compact-toolbar {
  min-height: 42px;
  display: flex;
  align-items: center;
  gap: 2px;
  padding: 4px 12px;
  overflow-x: auto;
  overflow-y: hidden;
  background: #fff;
  border-bottom: 1px solid var(--color-gray-200);
  scrollbar-width: thin;
}

.compact-command {
  width: 32px;
  height: 32px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: 0 0 auto;
  padding: 0;
  border: 1px solid transparent;
  border-radius: 6px;
  background: transparent;
  color: var(--text-secondary);
  cursor: pointer;
}

.compact-command:hover,
.compact-command.active {
  background: var(--color-primary-50);
  border-color: var(--color-primary-100);
  color: var(--color-primary-700);
}

.compact-command svg {
  width: 17px;
  height: 17px;
}

.compact-separator {
  width: 1px;
  height: 23px;
  margin: 0 4px;
  flex: 0 0 auto;
  background: var(--color-gray-200);
}

.compact-toolbar select {
  height: 30px;
  flex: 0 0 auto;
  padding: 0 24px 0 8px;
  border: 1px solid transparent;
  border-radius: 5px;
  background-color: transparent;
  color: var(--text-primary);
  font: inherit;
  font-size: 12px;
  cursor: pointer;
}

.compact-toolbar select:hover,
.compact-toolbar select:focus {
  outline: 0;
  border-color: var(--color-gray-200);
  background-color: var(--color-gray-50);
}

.compact-style-select { width: 112px; }
.compact-font-select { width: 110px; }
.compact-size-select { width: 58px; }
.compact-line-select { width: 64px; }

.compact-color-control {
  position: relative;
  width: 32px;
  height: 32px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: 0 0 auto;
  border: 1px solid transparent;
  border-radius: 6px;
  color: var(--text-secondary);
  cursor: pointer;
  overflow: hidden;
}

.compact-color-control:hover {
  background: var(--color-gray-50);
  border-color: var(--color-gray-200);
}

.compact-color-control span {
  font-size: 16px;
  font-weight: 650;
  text-decoration: underline;
  text-decoration-color: currentColor;
  text-decoration-thickness: 3px;
}

.compact-color-control svg {
  width: 17px;
  height: 17px;
}

.compact-color-control input {
  position: absolute;
  inset: auto 3px 2px 3px;
  width: 26px;
  height: 4px;
  padding: 0;
  border: 0;
  opacity: 0;
  cursor: pointer;
}

/* Toolbar mode switching. Compact is the safe first-paint/default mode. */
.toolbar.ribbon:not(.toolbar-mode-expanded) .ribbon-tab-row,
.toolbar.ribbon:not(.toolbar-mode-expanded) .ribbon-body {
  display: none;
}

.toolbar.ribbon.toolbar-mode-expanded .compact-toolbar {
  display: none;
}

.toolbar.ribbon.toolbar-mode-expanded .ribbon-tab-row,
.toolbar.ribbon.toolbar-mode-expanded .ribbon-body {
  display: flex;
}

.toolbar.ribbon.toolbar-mode-expanded.collapsed .ribbon-body {
  display: flex;
}

.toolbar.ribbon.toolbar-mode-expanded.collapsed.pinned .ribbon-body {
  position: absolute;
  top: 88px;
  left: 0;
  right: 0;
  z-index: 3000;
  max-height: 110px;
  padding: 6px 12px;
  opacity: 1;
  overflow-x: auto;
  background: #fff;
  box-shadow: var(--shadow-md);
}

.ribbon-tab-row {
  align-items: center;
  min-height: 34px;
  padding-right: 8px;
}

.ribbon-tab-spacer {
  flex: 1;
}

.ribbon-tab-row .ribbon-toggle {
  width: 30px;
  height: 28px;
}

/* File menu */
.shell-command-host {
  position: fixed;
  width: 1px;
  height: 1px;
  left: -10000px;
  top: -10000px;
  overflow: hidden;
}

.file-menu-popover {
  position: fixed;
  top: 54px;
  left: 62px;
  z-index: 5600;
  width: 286px;
  max-height: calc(100vh - 70px);
  overflow: auto;
  padding: 7px;
  border: 1px solid var(--color-gray-200);
  border-radius: 10px;
  background: #fff;
  box-shadow: var(--shadow-lg);
}

.file-menu-popover button {
  width: 100%;
  min-height: 37px;
  display: grid;
  grid-template-columns: 22px 1fr auto;
  align-items: center;
  gap: 9px;
  padding: 6px 9px;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--text-primary);
  font: inherit;
  font-size: 12px;
  text-align: left;
  cursor: pointer;
}

.file-menu-popover button:hover {
  background: var(--color-primary-50);
  color: var(--color-primary-700);
}

.file-menu-popover button svg {
  width: 17px;
  height: 17px;
}

.file-menu-separator {
  height: 1px;
  margin: 5px 4px;
  background: var(--color-gray-200);
}

.file-menu-subheading {
  padding: 7px 9px 3px 40px;
  color: var(--text-tertiary);
  font-size: 10px;
  font-weight: 650;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.file-menu-popover .file-menu-danger {
  color: var(--color-danger);
}

/* Side panels and share dialog */
.shell-panel-backdrop {
  position: fixed;
  inset: 0;
  z-index: 5090;
  background: rgba(17, 24, 39, 0.18);
}

.shell-side-panel {
  position: fixed;
  top: 0;
  right: 0;
  bottom: 0;
  z-index: 5100;
  width: min(390px, 94vw);
  display: flex;
  flex-direction: column;
  background: #fff;
  border-left: 1px solid var(--color-gray-200);
  box-shadow: -12px 0 35px rgba(17, 24, 39, 0.14);
}

.shell-side-panel-header,
.share-dialog-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
}

.shell-side-panel-header {
  padding: 18px 18px 14px;
  border-bottom: 1px solid var(--color-gray-200);
}

.shell-side-panel h2,
.share-dialog-card h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 18px;
  line-height: 1.25;
}

.shell-panel-eyebrow {
  color: var(--color-primary-500);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.shell-side-panel-body {
  flex: 1;
  overflow: auto;
  padding: 18px;
}

.shell-empty-state {
  min-height: 240px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 9px;
  padding: 24px;
  color: var(--text-secondary);
  text-align: center;
}

.shell-empty-state svg {
  width: 34px;
  height: 34px;
  color: var(--color-primary-400);
}

.shell-empty-state h3 {
  margin: 0;
  color: var(--text-primary);
  font-size: 15px;
}

.shell-empty-state p {
  max-width: 280px;
  margin: 0;
  font-size: 12px;
  line-height: 1.55;
}

.version-entry {
  position: relative;
  display: grid;
  grid-template-columns: 30px 1fr;
  gap: 10px;
  padding: 12px 0;
}

.version-entry-icon {
  width: 30px;
  height: 30px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background: var(--color-primary-50);
  color: var(--color-primary-600);
}

.version-entry-icon svg {
  width: 15px;
  height: 15px;
}

.version-entry strong,
.version-entry span {
  display: block;
}

.version-entry span {
  margin-top: 4px;
  color: var(--text-tertiary);
  font-size: 11px;
}

.share-dialog-backdrop {
  position: fixed;
  inset: 0;
  z-index: 5900;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  background: rgba(17, 24, 39, 0.38);
}

.share-dialog-card {
  width: min(520px, 96vw);
  padding: 20px;
  border: 1px solid var(--color-gray-200);
  border-radius: 12px;
  background: #fff;
  box-shadow: var(--shadow-modal);
}

.share-dialog-note {
  margin: 16px 0;
  padding: 10px 12px;
  border-radius: 7px;
  background: var(--color-primary-50);
  color: var(--color-primary-800);
  font-size: 12px;
  line-height: 1.5;
}

.share-field-label {
  display: block;
  margin: 13px 0 6px;
  color: var(--text-secondary);
  font-size: 11px;
  font-weight: 650;
}

.share-link-row {
  display: flex;
  gap: 8px;
}

.share-link-row input,
.share-dialog-card select {
  width: 100%;
  min-height: 38px;
  padding: 0 10px;
  border: 1px solid var(--color-gray-300);
  border-radius: 7px;
  background: #fff;
  color: var(--text-primary);
  font: inherit;
}

.share-link-row .btn-primary {
  min-width: 112px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  white-space: nowrap;
}

.share-link-row .btn-primary svg {
  width: 15px;
  height: 15px;
}

.shell-toast {
  position: fixed;
  left: 50%;
  bottom: 48px;
  z-index: 7000;
  transform: translateX(-50%);
  max-width: min(520px, calc(100vw - 24px));
  padding: 10px 14px;
  border-radius: 8px;
  background: var(--color-gray-900);
  color: #fff;
  box-shadow: var(--shadow-lg);
  font-size: 12px;
}

@media (max-width: 1180px) {
  .shell-action-btn span:not(.shell-count-badge),
  .app-brand-name {
    display: none;
  }

  .shell-action-btn {
    width: 34px;
    padding: 0;
  }

  .command-search {
    flex-basis: 350px;
  }
}

@media (max-width: 960px) {
  .command-search {
    flex-basis: 250px;
    min-width: 180px;
  }

  .command-search kbd,
  #btn-version-history,
  #btn-toolbar-mode {
    display: none;
  }

  .document-identity {
    max-width: 250px;
  }
}

/* Phase 4: Quick-Insert menu ------------------------------------------------ */
.quick-insert-menu {
  position: absolute;
  z-index: 4000;
  min-width: 220px;
  max-height: 300px;
  overflow-y: auto;
  padding: 5px;
  border: 1px solid var(--color-gray-200);
  border-radius: 9px;
  background: #fff;
  box-shadow: var(--shadow-lg);
}

.quick-insert-menu.hidden { display: none; }

.quick-insert-item {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  min-height: 36px;
  padding: 6px 9px;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--text-primary);
  font: inherit;
  font-size: 12px;
  text-align: left;
  cursor: pointer;
}

.quick-insert-item:hover,
.quick-insert-item.active {
  background: var(--color-primary-50);
  color: var(--color-primary-700);
}

.quick-insert-item svg { width: 16px; height: 16px; color: var(--color-primary-500); }

.quick-insert-item small { color: var(--text-tertiary); font-size: 11px; margin-left: auto; }

/* Phase 4: Smart chips ------------------------------------------------------- */
.smart-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 1px 7px;
  border: 1px solid var(--color-primary-200);
  border-radius: 4px;
  background: var(--color-primary-50);
  color: var(--color-primary-700);
  font-size: 12px;
  font-weight: 500;
  vertical-align: baseline;
  cursor: default;
}

.smart-chip svg { width: 12px; height: 12px; }

/* Phase 4: Checklist --------------------------------------------------------- */
.block-checklist {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 4px 0;
}

.block-checklist .checklist-checkbox {
  flex: 0 0 auto;
  width: 18px;
  height: 18px;
  margin-top: 2px;
  border: 2px solid var(--color-gray-400);
  border-radius: 4px;
  background: #fff;
  cursor: pointer;
  accent-color: var(--color-primary-500);
}

.block-checklist .checklist-checkbox:checked {
  background: var(--color-primary-500);
  border-color: var(--color-primary-600);
}

.block-checklist .checklist-text {
  flex: 1 1 auto;
  min-height: 22px;
  outline: 0;
  font: inherit;
  font-size: 14px;
  line-height: 1.55;
  color: var(--text-primary);
}

.block-checklist .checklist-text[data-checked="true"] {
  text-decoration: line-through;
  color: var(--text-tertiary);
}

/* Phase 4: Horizontal rule --------------------------------------------------- */
.block-horizontal-rule {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 12px 0;
  cursor: pointer;
}

.block-horizontal-rule hr {
  width: 100%;
  border: 0;
  height: 1px;
  background: var(--color-gray-300);
}

.block-horizontal-rule:hover hr { background: var(--color-gray-400); }

/* Phase 4: Footnotes / Endnotes ---------------------------------------------- */
.footnote-anchor,
.endnote-anchor {
  display: inline;
  vertical-align: super;
  font-size: 10px;
  font-weight: 600;
  color: var(--color-primary-600);
  cursor: pointer;
  text-decoration: none;
  margin: 0 1px;
}

.footnote-anchor:hover,
.endnote-anchor:hover { text-decoration: underline; }

.footnote-section,
.endnote-section {
  margin-top: 24px;
  padding-top: 12px;
  border-top: 1px solid var(--color-gray-200);
}

.footnote-section h4,
.endnote-section h4 {
  margin: 0 0 6px;
  font-size: 12px;
  font-weight: 700;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.footnote-item,
.endnote-item {
  display: flex;
  gap: 6px;
  padding: 3px 0;
  font-size: 12px;
  color: var(--text-secondary);
}

.footnote-item .fn-num,
.endnote-item .fn-num {
  flex: 0 0 auto;
  font-weight: 600;
  color: var(--color-primary-600);
}

/* Phase 5: Persistence dialogs ----------------------------------------------- */
.persistence-dialog-backdrop {
  position: fixed;
  inset: 0;
  z-index: 8000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  background: rgba(17, 24, 39, 0.38);
}

.persistence-dialog-backdrop.hidden { display: none; }

.persistence-dialog-card {
  width: min(460px, 96vw);
  padding: 20px;
  border: 1px solid var(--color-gray-200);
  border-radius: 12px;
  background: #fff;
  box-shadow: var(--shadow-modal);
}

.persistence-dialog-card h3 {
  margin: 0 0 12px;
  font-size: 16px;
  font-weight: 650;
}

.persistence-dialog-card p {
  margin: 0 0 16px;
  font-size: 13px;
  line-height: 1.55;
  color: var(--text-secondary);
}

.persistence-dialog-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

.persistence-dialog-actions button {
  min-height: 34px;
  padding: 0 14px;
  border: 1px solid var(--color-gray-200);
  border-radius: 7px;
  background: #fff;
  color: var(--text-primary);
  font: inherit;
  font-size: 12px;
  font-weight: 550;
  cursor: pointer;
}

.persistence-dialog-actions .btn-primary {
  background: var(--color-primary-500);
  border-color: var(--color-primary-600);
  color: #fff;
}

.persistence-dialog-actions .btn-primary:hover { background: var(--color-primary-700); }

/* Phase 5: Save spinner ------------------------------------------------------ */
.save-spinner {
  display: inline-flex;
  width: 14px;
  height: 14px;
  border: 2px solid var(--color-gray-300);
  border-top-color: var(--color-primary-500);
  border-radius: 50%;
  animation: save-spin 0.6s linear infinite;
  margin-right: 4px;
  vertical-align: middle;
}

@keyframes save-spin { to { transform: rotate(360deg); } }

/* Phase 5: Version history panel enhancements -------------------------------- */
.version-entry-actions {
  display: flex;
  gap: 6px;
  margin-top: 8px;
}

.version-entry-actions button {
  min-height: 28px;
  padding: 0 10px;
  border: 1px solid var(--color-gray-200);
  border-radius: 6px;
  background: #fff;
  color: var(--text-primary);
  font: inherit;
  font-size: 11px;
  font-weight: 550;
  cursor: pointer;
}

.version-entry-actions .btn-primary {
  background: var(--color-primary-500);
  border-color: var(--color-primary-600);
  color: #fff;
}

/* Phase 5: Conflict badge ---------------------------------------------------- */
.conflict-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 999px;
  background: #fef3cd;
  color: #856404;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
}

.conflict-badge svg { width: 12px; height: 12px; }

/* Account and sharing */
.account-dialog-card form { display:grid; gap:12px; }
.account-dialog-card form.hidden,.account-current.hidden { display:none; }
.account-dialog-card label { display:grid; gap:5px; font-size:13px; color:var(--text-secondary); }
.account-dialog-card input { border:1px solid var(--color-gray-300); min-height:36px; padding:8px; }
.auth-tabs { display:flex; gap:6px; margin-bottom:14px; }
.auth-tabs button { flex:1; }
.auth-tabs button.active { background:var(--color-primary-100); color:var(--color-primary-700); }
.auth-error { color:#b91c1c; min-height:1.25em; }
.share-dialog-section { display:grid; gap:10px; padding:12px 0; border-top:1px solid var(--color-gray-200); }
.share-dialog-section h3 { margin:0; font-size:14px; }
.share-invite-row,.share-link-role { display:grid; grid-template-columns:1fr auto auto; gap:7px; }
.share-invite-row input,.share-invite-row select,.share-link-role select { border:1px solid var(--color-gray-300); min-height:34px; }
.share-members-list,.share-links-list { display:grid; gap:6px; }
.share-entry { display:flex; align-items:center; gap:6px; padding:8px; border:1px solid var(--color-gray-200); border-radius:7px; }
.share-entry span { min-width:0; flex:1; display:grid; }
.share-entry small { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--text-secondary); }
.share-empty { margin:0; color:var(--text-secondary); font-size:13px; }

/* Role-aware document access */
#workspace.document-read-only [contenteditable] { cursor: text; }
body[data-document-role="viewer"] #save-indicator,
body[data-document-role="commenter"] #save-indicator { opacity: .78; }


// ================================================================
// FILE: /home/luanngo/opendoc/public/css/typography.css
// ================================================================
.block-text {
  min-height: 1.5em;
  margin: 0 0 10px 0;
  outline: none;
  position: relative;
  display: block;
  overflow-wrap: break-word;
  word-break: normal;
}

.block-text code {
  font-family: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', 'Consolas', monospace;
  font-size: 0.9em;
  background: var(--color-gray-100);
  color: var(--color-red-700);
  padding: 1px 4px;
  border-radius: 3px;
  border: 1px solid var(--color-gray-200);
}

.block-text.preserve-whitespace {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  word-break: break-word;
  tab-size: 4;
  font-family: var(--font-mono);
}

.style-normal {
  font-size: 12pt;
  line-height: var(--leading-normal);
}

.style-h1 {
  font-size: var(--text-3xl);
  font-weight: 700;
  color: var(--text-heading);
  margin-top: var(--space-5);
  margin-bottom: var(--space-3);
  line-height: var(--leading-tight);
  letter-spacing: -0.01em;
}

.style-h2 {
  font-size: var(--text-xl);
  font-weight: 700;
  color: var(--color-gray-700);
  margin-top: var(--space-4);
  margin-bottom: var(--space-3);
  line-height: var(--leading-tight);
}

.style-h3 {
  font-size: var(--text-lg);
  font-weight: 600;
  color: var(--color-gray-700);
  margin-top: var(--space-4);
  margin-bottom: var(--space-2);
  line-height: var(--leading-tight);
}

.style-h4 {
  font-size: var(--text-base);
  font-weight: 600;
  color: var(--color-gray-600);
  margin-top: var(--space-3);
  margin-bottom: var(--space-2);
  line-height: var(--leading-tight);
}

.style-h5 {
  font-size: var(--text-sm);
  font-weight: 600;
  color: var(--color-gray-600);
  margin-top: var(--space-3);
  margin-bottom: var(--space-1);
  line-height: var(--leading-tight);
  text-transform: uppercase;
  letter-spacing: 0.02em;
}

.style-h6 {
  font-size: var(--text-xs);
  font-weight: 600;
  color: var(--color-gray-500);
  margin-top: var(--space-3);
  margin-bottom: var(--space-1);
  line-height: var(--leading-tight);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.style-quote {
  font-size: 12pt;
  font-style: italic;
  border-left: 4px solid var(--color-gray-300);
  padding-left: var(--space-3);
  color: var(--text-secondary);
  margin: 15px 0;
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/css/variables.css
// ================================================================
:root {
  /* Primary Blue */
  --color-primary-50: #eff6ff;
  --color-primary-100: #e1e9f4;
  --color-primary-200: #c7dffc;
  --color-primary-300: #a3c4f3;
  --color-primary-400: #60a5fa;
  --color-primary-500: #2b579a;
  --color-primary-600: #1d4ed8;
  --color-primary-700: #1e40af;
  --color-primary-800: #1e3a5f;
  --color-primary-900: #172554;

  /* Neutral Gray */
  --color-gray-50: #f8f9fa;
  --color-gray-100: #f0f0f0;
  --color-gray-150: #e5e7eb;
  --color-gray-200: #e0e0e0;
  --color-gray-300: #d1d5db;
  --color-gray-400: #9ca3af;
  --color-gray-500: #6b7280;
  --color-gray-600: #4b5563;
  --color-gray-700: #374151;
  --color-gray-800: #1f2937;
  --color-gray-900: #111827;

  /* Semantic */
  --color-success: #16a34a;
  --color-warning: #d97706;
  --color-danger: #dc2626;
  --color-info: #2563eb;

  /* Backgrounds */
  --bg-app: var(--color-gray-100);
  --bg-panel: #ffffff;
  --bg-page-view: #e9e9e9;
  --bg-sidebar: var(--color-gray-50);
  --bg-toolbar: #ffffff;
  --bg-status-bar: #ffffff;
  --bg-modal-overlay: rgba(0, 0, 0, 0.4);

  /* Text */
  --text-primary: var(--color-gray-900);
  --text-secondary: var(--color-gray-600);
  --text-tertiary: var(--color-gray-400);
  --text-inverse: #ffffff;
  --text-link: var(--color-primary-500);
  --text-heading: var(--color-primary-500);

  /* Borders */
  --border-color: var(--color-gray-200);
  --border-color-hover: var(--color-primary-300);
  --border-color-light: var(--color-gray-100);

  /* Spacing */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 20px;
  --space-6: 24px;
  --space-8: 32px;
  --space-10: 40px;
  --space-12: 48px;

  /* Typography */
  --font-sans: 'Segoe UI', system-ui, -apple-system, sans-serif;
  --font-serif: Georgia, 'Times New Roman', Garamond, serif;
  --font-mono: 'Cascadia Code', 'Fira Code', Consolas, 'Courier New', monospace;
  --font-mono: 'Cascadia Code', 'Fira Code', Consolas, monospace;
  --text-xs: 10px;
  --text-sm: 12px;
  --text-base: 13px;
  --text-lg: 14px;
  --text-xl: 18px;
  --text-2xl: 24px;
  --text-3xl: 30px;
  --leading-tight: 1.25;
  --leading-normal: 1.5;
  --leading-relaxed: 1.75;

  /* Border Radius */
  --radius-sm: 2px;
  --radius-md: 4px;
  --radius-lg: 6px;
  --radius-xl: 8px;
  --radius-full: 9999px;

  /* Shadows */
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
  --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
  --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1);
  --shadow-page: 0 4px 15px rgba(0, 0, 0, 0.15);
  --shadow-modal: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1);

  /* Transitions */
  --transition-fast: 150ms ease;
  --transition-normal: 250ms ease;
  --transition-slow: 350ms ease;

  /* Z-Index */
  --z-toolbar: 100;
  --z-ruler: 10;
  --z-sidebar: 5000;
  --z-modal: 6000;
  --z-tooltip: 7000;

  /* Dynamic Page Props (updated by JS at runtime) */
  --page-width: 8.5in;
  --page-height: 11in;
  --page-margin-top: 1in;
  --page-margin-bottom: 1in;
  --page-margin-left: 1in;
  --page-margin-right: 1in;
}


// ================================================================
// FILE: /home/luanngo/opendoc/public/index.html
// ================================================================
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="default">
    <meta name="apple-mobile-web-app-title" content="OpenWord">
    <meta name="theme-color" content="#2b579a">
    <link rel="manifest" href="/manifest.json">
    <title>OpenWord - Phase 9 (Complete)</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Open+Sans:wght@400;700&family=Lato:wght@400;700&family=Montserrat:wght@400;700&family=Merriweather:wght@400;700&family=Playfair+Display:wght@400;700&family=Source+Sans+Pro:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/variables.css">
    <link rel="stylesheet" href="css/reset.css">
    <link rel="stylesheet" href="css/layout.css">
    <link rel="stylesheet" href="css/typography.css">
    <link rel="stylesheet" href="css/components.css">
    <link rel="stylesheet" href="css/mobile.css">
</head>
<body>

    <div class="toolbar ribbon">

        <!-- Layer 1: App/Document bar -->
        <div class="ribbon-bar">
            <button id="btn-toolbar-toggle" class="mobile-only" title="Toggle Toolbar">
                <i data-lucide="menu"></i>
            </button>
            <button id="btn-docs" class="ribbon-docs-btn" title="Manage Documents">
                <i data-lucide="folder-open"></i>
                <span>Documents</span>
                <i data-lucide="chevron-down" class="docs-chevron"></i>
            </button>
            <span id="doc-title-display" contenteditable="true" class="doc-title">Untitled</span>
            <span id="save-indicator" class="save-indicator">Saved</span>
            <span class="ribbon-bar-sep"></span>
            <button id="btn-save" class="ribbon-bar-btn" title="Save (Ctrl+S)"><i data-lucide="save"></i></button>
            <button id="btn-undo" class="ribbon-bar-btn" title="Undo (Ctrl+Z)"><i data-lucide="undo-2"></i></button>
            <button id="btn-redo" class="ribbon-bar-btn" title="Redo (Ctrl+Y)"><i data-lucide="redo-2"></i></button>
            <span class="ribbon-bar-spacer"></span>
            <button class="ribbon-toggle" id="ribbon-toggle" title="Collapse the Ribbon">
                <i data-lucide="chevron-up"></i>
            </button>
        </div>

        <!-- Layer 2: Ribbon tabs -->
        <div class="ribbon-tab-row">
            <span class="ribbon-tab active" data-tab="home">Home</span>
            <span class="ribbon-tab" data-tab="insert">Insert</span>
            <span class="ribbon-tab" data-tab="layout">Layout</span>
            <span class="ribbon-tab" data-tab="references">References</span>
            <span class="ribbon-tab" data-tab="review">Review</span>
            <span class="ribbon-tab" data-tab="view">View</span>
        </div>

        <!-- Layer 3: Active ribbon commands (collapsible) -->
        <div class="ribbon-body" id="ribbon-body">
            <!-- ──── Home tab ──── -->
            <div class="ribbon-panel active" data-panel="home">
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Clipboard</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-format-painter" title="Format Painter"><i data-lucide="paintbrush"></i></button>
                        <button id="btn-manage-styles" title="Manage named styles"><i data-lucide="palette"></i></button>
                        <button id="btn-clear-fmt" title="Clear Formatting"><i data-lucide="remove-formatting"></i></button>
                    </div>
                </div>
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Font</span>
                    <div class="ribbon-group-buttons">
                        <select id="sel-font" title="Font Family" class="ribbon-font-sel">
                            <option value="Segoe UI">Segoe UI</option>
                            <option value="Arial">Arial</option>
                            <option value="Calibri">Calibri</option>
                            <option value="Verdana">Verdana</option>
                            <option value="Georgia">Georgia</option>
                            <option value="Times New Roman">Times New Roman</option>
                            <option value="Garamond">Garamond</option>
                            <option value="Tahoma">Tahoma</option>
                            <option value="Trebuchet MS">Trebuchet MS</option>
                            <option value="Courier New">Courier New</option>
                            <option value="Comic Sans MS">Comic Sans MS</option>
                            <option value="Impact">Impact</option>
                            <option value="Roboto">Roboto</option>
                            <option value="Open Sans">Open Sans</option>
                            <option value="Lato">Lato</option>
                            <option value="Montserrat">Montserrat</option>
                            <option value="Merriweather">Merriweather</option>
                            <option value="Playfair Display">Playfair Display</option>
                            <option value="Source Sans Pro">Source Sans Pro</option>
                        </select>
                        <select id="sel-font-size" title="Font Size" class="ribbon-font-sel">
                            <option value="8">8</option>
                            <option value="9">9</option>
                            <option value="10">10</option>
                            <option value="11">11</option>
                            <option value="12" selected>12</option>
                            <option value="14">14</option>
                            <option value="16">16</option>
                            <option value="18">18</option>
                            <option value="20">20</option>
                            <option value="22">22</option>
                            <option value="24">24</option>
                            <option value="26">26</option>
                            <option value="28">28</option>
                            <option value="36">36</option>
                            <option value="48">48</option>
                            <option value="72">72</option>
                        </select>
                        <button id="btn-bold" title="Bold (Ctrl+B)"><i data-lucide="bold"></i></button>
                        <button id="btn-italic" title="Italic (Ctrl+I)"><i data-lucide="italic"></i></button>
                        <button id="btn-underline" title="Underline (Ctrl+U)"><i data-lucide="underline"></i></button>
                        <button id="btn-strikethrough" title="Strikethrough"><i data-lucide="strikethrough"></i></button>
                        <button id="btn-superscript" title="Superscript (Ctrl+Shift+>)">x<sup>2</sup></button>
                        <button id="btn-subscript" title="Subscript">x<sub>2</sub></button>
                        <button id="btn-code" title="Inline Code (Ctrl+Shift+`)"><code>&lt;/&gt;</code></button>
                    </div>
                </div>
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Paragraph</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-ul" title="Bullet List"><i data-lucide="list"></i></button>
                        <button id="btn-ol" title="Numbered List"><i data-lucide="list-ordered"></i></button>
                        <button id="btn-indent-dec" title="Decrease Indent"><i data-lucide="arrow-left-to-line"></i></button>
                        <button id="btn-indent-inc" title="Increase Indent"><i data-lucide="arrow-right-to-line"></i></button>
                        <span class="btn-sep"></span>
                        <button id="btn-align-left" title="Align Left"><i data-lucide="align-left"></i></button>
                        <button id="btn-align-center" title="Align Center"><i data-lucide="align-center"></i></button>
                        <button id="btn-align-right" title="Align Right"><i data-lucide="align-right"></i></button>
                        <button id="btn-align-justify" title="Justify"><i data-lucide="align-justify"></i></button>
                    </div>
                </div>
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Colors</span>
                    <div class="ribbon-group-buttons">
                        <button class="ribbon-color-btn" title="Text Color">
                            <span class="ribbon-color-label">A</span>
                            <input type="color" id="inp-text-color" value="#000000" class="ribbon-color-input">
                        </button>
                        <button class="ribbon-color-btn" title="Highlight Color">
                            <i data-lucide="highlighter"></i>
                            <input type="color" id="inp-highlight-color" value="#ffff00" class="ribbon-color-input">
                        </button>
                    </div>
                </div>
            </div>

            <!-- ──── Insert tab ──── -->
            <div class="ribbon-panel" data-panel="insert">
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Elements</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-table" title="Insert Table"><i data-lucide="table"></i>Table</button>
                        <button id="btn-page-break" title="Insert Page Break"><i data-lucide="file-minus"></i>Page Br.</button>
                        <button id="btn-toc" title="Table of Contents"><i data-lucide="list-tree"></i>TOC</button>
                    </div>
                </div>
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Media</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-img-inline" title="Insert Image"><i data-lucide="image"></i>Image</button>
                        <button id="btn-box-text" title="Insert Text Box"><i data-lucide="square"></i>Text Box</button>
                    </div>
                </div>
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Links</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-link" title="Insert Link (Ctrl+K)"><i data-lucide="link"></i>Link</button>
                    </div>
                </div>
                <input type="file" id="inp-image-upload" accept="image/*" style="display:none">
            </div>

            <!-- ──── Layout tab ──── -->
            <div class="ribbon-panel" data-panel="layout">
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Style</span>
                    <div class="ribbon-group-buttons">
                        <select id="sel-block-style" title="Text Style">
                            <option value="normal">Normal</option>
                            <option value="h1">Heading 1</option>
                            <option value="h2">Heading 2</option>
                            <option value="h3">Heading 3</option>
                            <option value="h4">Heading 4</option>
                            <option value="h5">Heading 5</option>
                            <option value="h6">Heading 6</option>
                            <option value="quote">Quote</option>
                        </select>
                    </div>
                </div>
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Spacing</span>
                    <div class="ribbon-group-buttons">
                        <select id="sel-line-height" title="Line Height">
                            <option value="1.0">1.0</option>
                            <option value="1.15" selected>1.15</option>
                            <option value="1.5">1.5</option>
                            <option value="2.0">2.0</option>
                        </select>
                        <select id="sel-space-before" title="Space Before">
                            <option value="0">0 pt</option>
                            <option value="6">6 pt</option>
                            <option value="12" selected>12 pt</option>
                            <option value="18">18 pt</option>
                            <option value="24">24 pt</option>
                            <option value="36">36 pt</option>
                        </select>
                        <select id="sel-space-after" title="Space After">
                            <option value="0">0 pt</option>
                            <option value="6">6 pt</option>
                            <option value="12" selected>12 pt</option>
                            <option value="18">18 pt</option>
                            <option value="24">24 pt</option>
                            <option value="36">36 pt</option>
                        </select>
                    </div>
                </div>
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Page Setup</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-page-setup" title="Page Setup"><i data-lucide="settings"></i>Page Setup</button>
                        <button id="btn-insert-section-break" title="Insert section break"><i data-lucide="between-horizontal-start"></i>Section</button>
                    </div>
                </div>
            </div>

            <!-- ──── References tab ──── -->
            <div class="ribbon-panel" data-panel="references">
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Table of Contents</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-toc-ref" title="Insert Table of Contents"><i data-lucide="list-tree"></i>Insert TOC</button>
                    </div>
                </div>
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Footnotes</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-footnote" title="Insert Footnote"><i data-lucide="corner-down-right"></i>Insert Footnote</button>
                        <button id="btn-endnote" title="Insert Endnote"><i data-lucide="sticky-note"></i>Insert Endnote</button>
                    </div>
                </div>
            </div>

            <!-- ──── Review tab ──── -->
            <div class="ribbon-panel" data-panel="review">
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Find</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-find" title="Find (Ctrl+F)"><i data-lucide="search"></i>Find</button>
                    </div>
                </div>
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Tracking</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-track-changes" title="Track Changes"><i data-lucide="diff"></i>Track Changes</button>
                        <button id="btn-add-comment" title="Add comment"><i data-lucide="message-square-plus"></i>Comment</button>
                        <button id="btn-accept-all" title="Accept All Changes"><i data-lucide="check-check"></i>Accept All</button>
                        <button id="btn-reject-all" title="Reject All Changes"><i data-lucide="x-circle"></i>Reject All</button>
                    </div>
                </div>
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Document</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-print" title="Print (Ctrl+P)"><i data-lucide="printer"></i>Print</button>
                        <button id="btn-exp-pdf" title="Export PDF"><i data-lucide="file-text"></i>PDF</button>
                        <button id="btn-import-docx" title="Import DOCX"><i data-lucide="file-input"></i>Import</button>
                        <button id="btn-export-docx" title="Export DOCX"><i data-lucide="file-output"></i>Export</button>
                        <input type="file" id="inp-docx-import" accept=".docx" style="display:none">
                    </div>
                </div>
            </div>

            <!-- ──── View tab ──── -->
            <div class="ribbon-panel" data-panel="view">
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Views</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-view-page" title="Page Layout"><i data-lucide="layout-panel-left"></i>Page</button>
                        <button id="btn-view-web" title="Web Layout"><i data-lucide="layout-list"></i>Web</button>
                    </div>
                </div>
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Show</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-toggle-outline" title="Toggle Outline"><i data-lucide="list"></i></button>
                        <button id="btn-toggle-ruler" title="Toggle Ruler"><i data-lucide="ruler"></i></button>
                    </div>
                </div>
                <div class="ribbon-group">
                    <span class="ribbon-group-label">Split</span>
                    <div class="ribbon-group-buttons">
                        <button id="btn-split-view" title="Split View"><i data-lucide="columns-2"></i>Split</button>
                    </div>
                </div>
            </div>

            <!-- ──── Contextual groups ──── -->
            <div class="ribbon-group contextual contextual-text-selection hidden">
                <span class="ribbon-group-label">Link</span>
                <div class="ribbon-group-buttons">
                    <button id="ctx-btn-link" title="Insert Link (Ctrl+K)"><i data-lucide="link"></i></button>
                </div>
            </div>

            <div class="ribbon-group contextual contextual-list hidden">
                <span class="ribbon-group-label">List</span>
                <div class="ribbon-group-buttons">
                    <button id="ctx-btn-indent-dec" title="Outdent"><i data-lucide="arrow-left-to-line"></i></button>
                    <button id="ctx-btn-indent-inc" title="Indent"><i data-lucide="arrow-right-to-line"></i></button>
                    <button id="ctx-btn-ul" title="Bullet List"><i data-lucide="list"></i></button>
                    <button id="ctx-btn-ol" title="Numbered List"><i data-lucide="list-ordered"></i></button>
                    <button id="ctx-btn-toggle-list-type" title="Toggle List Type">&harr;</button>
                    <button id="ctx-btn-list-to-text" title="Convert to Text"><i data-lucide="text"></i></button>
                </div>
            </div>

            <div class="ribbon-group contextual contextual-image hidden">
                <span class="ribbon-group-label">Image</span>
                <div class="ribbon-group-buttons">
                    <button class="active" id="ctx-btn-align-left" title="Align Left"><i data-lucide="align-left"></i></button>
                    <button id="ctx-btn-align-center" title="Align Center"><i data-lucide="align-center"></i></button>
                    <button id="ctx-btn-align-right" title="Align Right"><i data-lucide="align-right"></i></button>
                    <button id="ctx-btn-del-image" title="Delete Image" class="btn-danger-outline"><i data-lucide="x"></i></button>
                </div>
            </div>

            <div class="ribbon-group contextual contextual-table hidden">
                <span class="ribbon-group-label">Table</span>
                <div class="ribbon-group-buttons">
                    <button id="ctx-btn-insert-row" title="Insert Row"><i data-lucide="plus"></i>Row</button>
                    <button id="ctx-btn-insert-col" title="Insert Column"><i data-lucide="plus"></i>Col</button>
                    <button id="ctx-btn-del-row" title="Delete Row" class="btn-danger-outline"><i data-lucide="x"></i></button>
                    <button id="ctx-btn-del-col" title="Delete Column" class="btn-danger-outline"><i data-lucide="x"></i></button>
                    <button id="ctx-btn-merge-cells" title="Merge selected cells"><i data-lucide="combine"></i>Merge</button>
                    <button id="ctx-btn-split-cell" title="Split merged cell"><i data-lucide="unfold-horizontal"></i>Split</button>
                    <button id="ctx-btn-header-row" title="Toggle header row"><i data-lucide="panel-top"></i>Header</button>
                    <button id="ctx-btn-del-table" title="Delete Table" class="btn-danger-outline"><i data-lucide="trash"></i></button>
                </div>
            </div>

            <div class="ribbon-group" id="hf-controls" style="display:none;">
                <span class="ribbon-group-label">Hdr/Ftr</span>
                <div class="ribbon-group-buttons">
                    <button id="btn-close-hf" class="btn-danger">Close Header/Footer</button>
                </div>
            </div>
        </div>
    </div>

    <div id="mobile-toolbar-drawer" class="mobile-toolbar-drawer"></div>

    <div class="ruler-container">
        <div class="ruler" id="ruler-bar">
            <div class="ruler-marker margin-left" id="marker-margin-left" title="Left Margin"></div>
            <div class="ruler-marker margin-right" id="marker-margin-right" title="Right Margin"></div>
        </div>
    </div>

    <div id="floating-toolbar" class="floating-toolbar hidden">
        <div class="floating-toolbar-buttons">
            <button id="flt-btn-bold" title="Bold"><i data-lucide="bold"></i></button>
            <button id="flt-btn-italic" title="Italic"><i data-lucide="italic"></i></button>
            <button id="flt-btn-underline" title="Underline"><i data-lucide="underline"></i></button>
            <button id="flt-btn-strikethrough" title="Strikethrough"><i data-lucide="strikethrough"></i></button>
            <button id="flt-btn-code" title="Inline Code"><code>&lt;/&gt;</code></button>
            <span class="flt-sep"></span>
            <select id="flt-sel-font-size" title="Font Size" class="flt-font-size">
                <option value="8">8</option><option value="10">10</option><option value="12" selected>12</option>
                <option value="14">14</option><option value="16">16</option><option value="18">18</option>
                <option value="24">24</option><option value="36">36</option>
            </select>
            <select id="flt-sel-style" title="Style" class="flt-style">
                <option value="normal">Normal</option>
                <option value="h1">H1</option><option value="h2">H2</option><option value="h3">H3</option>
                <option value="quote">Quote</option>
            </select>
        </div>
    </div>

    <div class="main-layout">
        <div id="outline-sidebar" class="outline-sidebar">
            <div class="outline-header">
                <span>Navigation</span>
                <button id="btn-outline-collapse" title="Collapse"><i data-lucide="chevron-left"></i></button>
            </div>
            <div class="nav-pane-tabs">
                <span class="nav-pane-tab active" data-nav-tab="headings">Headings</span>
                <span class="nav-pane-tab" data-nav-tab="pages">Pages</span>
                <span class="nav-pane-tab" data-nav-tab="results">Results</span>
            </div>
            <div class="outline-search-wrapper">
                <input type="text" id="inp-outline-search" placeholder="Search headings..." class="outline-search-input">
            </div>
            <div id="outline-content" class="nav-pane-content"></div>
            <div id="pages-content" class="nav-pane-content hidden">loading pages...</div>
            <div id="results-content" class="nav-pane-content hidden">
                <div class="results-empty">0 results</div>
            </div>
        </div>
        <div id="outline-rail" class="outline-rail hidden">
            <button id="btn-outline-expand" title="Show outline"><i data-lucide="list"></i></button>
        </div>
        <div id="review-panel" class="review-panel hidden">
            <div class="review-panel-header">
                <span>Tracked Changes</span>
                <button id="btn-review-close" title="Close"><i data-lucide="x"></i></button>
            </div>
            <div class="review-panel-actions">
                <button id="rp-btn-accept-all" class="review-btn review-btn-accept">Accept All</button>
                <button id="rp-btn-reject-all" class="review-btn review-btn-reject">Reject All</button>
            </div>
            <div id="review-list" class="review-list">
                <div class="review-empty">No tracked changes</div>
            </div>
        </div>
        <div id="workspace-wrapper">
            <div id="welcome-page" class="welcome-page">
                <div class="welcome-container">
                    <div class="welcome-logo">
                        <i data-lucide="file-text" class="welcome-icon"></i>
                    </div>
                    <h1 class="welcome-title">OpenWord</h1>
                    <div class="welcome-actions">
                        <button id="btn-welcome-new" class="welcome-btn welcome-btn-primary">
                            <i data-lucide="plus"></i>New Blank Document
                        </button>
                        <button id="btn-welcome-open" class="welcome-btn welcome-btn-secondary">
                            <i data-lucide="folder-open"></i>Open Document
                        </button>
                    </div>
                    <div class="welcome-recent" id="welcome-recent">
                        <h3 class="welcome-section-title">Recent</h3>
                        <div id="welcome-recent-list" class="welcome-recent-list"></div>
                    </div>
                    <div class="welcome-templates" id="welcome-templates">
                        <h3 class="welcome-section-title">Templates</h3>
                        <div class="welcome-template-grid">
                            <div class="welcome-template-card" data-template="blank">
                                <div class="template-preview blank-preview"><i data-lucide="file"></i></div>
                                <span>Blank Document</span>
                            </div>
                            <div class="welcome-template-card" data-template="report">
                                <div class="template-preview report-preview"><i data-lucide="file-text"></i></div>
                                <span>Report</span>
                            </div>
                            <div class="welcome-template-card" data-template="letter">
                                <div class="template-preview letter-preview"><i data-lucide="mail"></i></div>
                                <span>Letter</span>
                            </div>
                            <div class="welcome-template-card" data-template="notes">
                                <div class="template-preview notes-preview"><i data-lucide="sticky-note"></i></div>
                                <span>Meeting Notes</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div id="workspace" class="mode-page"></div>
        </div>
        <div id="workspace-split-wrapper" class="workspace-split-wrapper hidden">
            <div id="workspace-split-left" class="workspace-split-pane">
                <div class="split-pane-header"><span id="split-left-title">Document 1</span><button class="split-close-btn" data-pane="left"><i data-lucide="x"></i></button></div>
                <div id="workspace-split-l" class="mode-page"></div>
            </div>
            <div class="workspace-split-divider"></div>
            <div id="workspace-split-right" class="workspace-split-pane">
                <div class="split-pane-header"><span id="split-right-title">Document 2</span><button class="split-close-btn" data-pane="right"><i data-lucide="x"></i></button></div>
                <div id="workspace-split-r" class="mode-page"></div>
            </div>
        </div>
    </div>

    <div class="status-bar">
        <div class="status-left">
            <span id="save-status">Saved</span>
            <span class="sep">·</span>
            <span id="lang-display" title="Document Language">English (US)</span>
            <span class="sep">·</span>
            <span id="word-count">0 words</span>
            <span class="sep">·</span>
            <span id="char-count">0 chars</span>
            <span class="sep">·</span>
            <span id="page-count">Page 1</span>
        </div>
        <div class="status-mid">
            <button id="btn-view-page-sb" class="status-view-btn active" title="Page Layout"><i data-lucide="layout-panel-left"></i></button>
            <button id="btn-view-web-sb" class="status-view-btn" title="Web Layout"><i data-lucide="layout-list"></i></button>
            <button id="btn-split-view-sb" class="status-view-btn" title="Split View"><i data-lucide="columns-2"></i></button>
        </div>
        <div class="status-right">
            <button id="btn-zoom-out" title="Zoom Out"><i data-lucide="minus"></i></button>
            <input type="range" id="zoom-slider" class="zoom-slider" min="50" max="200" value="100" step="5" title="Zoom">
            <span id="zoom-display">100%</span>
            <button id="btn-zoom-in" title="Zoom In"><i data-lucide="plus"></i></button>
        </div>
    </div>

    <div class="mobile-nav-bar">
        <button class="mobile-nav-item" data-nav="docs">
            <i data-lucide="folder-open"></i>
            <span>Docs</span>
        </button>
        <button class="mobile-nav-item" data-nav="outline">
            <i data-lucide="list"></i>
            <span>Outline</span>
        </button>
        <button class="mobile-nav-item" data-nav="find">
            <i data-lucide="search"></i>
            <span>Find</span>
        </button>
        <button class="mobile-nav-item" data-nav="review">
            <i data-lucide="diff"></i>
            <span>Review</span>
        </button>
        <button class="mobile-nav-item" data-nav="more">
            <i data-lucide="more-horizontal"></i>
            <span>More</span>
        </button>
    </div>

    <div class="mobile-sheet-overlay" id="mobile-sheet-overlay">
        <div class="mobile-sheet" id="mobile-sheet-outline">
            <div class="mobile-sheet-handle"></div>
            <div class="mobile-sheet-header">
                <span>Navigation</span>
                <button class="mobile-sheet-close-btn"><i data-lucide="x"></i></button>
            </div>
            <div class="nav-pane-tabs">
                <span class="nav-pane-tab active" data-nav-tab="headings">Headings</span>
                <span class="nav-pane-tab" data-nav-tab="pages">Pages</span>
                <span class="nav-pane-tab" data-nav-tab="results">Results</span>
            </div>
            <div class="outline-search-wrapper">
                <input type="text" id="inp-mob-outline-search" placeholder="Search headings..." class="outline-search-input">
            </div>
            <div id="mob-outline-content" class="nav-pane-content mobile-sheet-body"></div>
            <div id="mob-pages-content" class="nav-pane-content mobile-sheet-body hidden">loading pages...</div>
            <div id="mob-results-content" class="nav-pane-content mobile-sheet-body hidden">
                <div class="results-empty">0 results</div>
            </div>
        </div>
    </div>

    <div id="doc-sidebar" class="sidebar hidden">
        <div class="sidebar-header">
            <h3>Documents</h3>
            <button id="btn-sidebar-close"><i data-lucide="x"></i></button>
        </div>
        <div class="sidebar-actions">
            <button id="btn-new-doc" class="btn-primary">New Document</button>
        </div>
        <div id="doc-list" class="doc-list"></div>
    </div>

    <div id="modal-page" class="modal hidden">
        <div class="modal-content">
            <div class="modal-header">Page Setup <span class="close-modal"><i data-lucide="x"></i></span></div>
            <div class="modal-body">
                <label>Margins (inches):</label>
                <div style="display:flex; gap:10px;">
                    <input id="inp-margin-top" placeholder="Top" value="1">
                    <input id="inp-margin-bottom" placeholder="Bottom" value="1">
                </div>
                <div style="display:flex; gap:10px; margin-top:5px;">
                    <input id="inp-margin-left" placeholder="Left" value="1">
                    <input id="inp-margin-right" placeholder="Right" value="1">
                </div>
                <button id="btn-apply-page" class="btn-primary">Apply</button>
            </div>
        </div>
    </div>

    <div id="modal-find" class="modal hidden">
        <div class="modal-content" style="width: 420px;">
            <div class="modal-header">Find & Replace <span class="close-modal"><i data-lucide="x"></i></span></div>
            <div class="modal-body">
                <div style="display:flex; gap:5px; margin-bottom:8px;">
                    <input type="text" id="inp-find-text" placeholder="Find..." style="flex:1; padding:4px 6px;" autofocus>
                    <button id="btn-find-next">Next (F3)</button>
                    <button id="btn-find-prev">Prev</button>
                </div>
                <div style="display:flex; gap:5px; margin-bottom:8px;">
                    <input type="text" id="inp-replace-text" placeholder="Replace with..." style="flex:1; padding:4px 6px;">
                    <button id="btn-replace-one">Replace</button>
                    <button id="btn-replace-all">All</button>
                </div>
                <div style="display:flex; gap:12px; margin-bottom:8px; font-size:12px; align-items:center;">
                    <label><input type="checkbox" id="chk-case-sensitive"> Case-sensitive</label>
                    <label><input type="checkbox" id="chk-regex"> Regex</label>
                </div>
                <div id="find-status" style="font-size:12px; color:#666; text-align:right;"></div>
            </div>
        </div>
    </div>

    <div id="context-menu-outline" class="context-menu hidden">
        <div class="context-menu-item" data-action="rename">Rename Heading</div>
        <div class="context-menu-item" data-action="delete">Delete Heading</div>
        <div class="context-menu-separator"></div>
        <div class="context-menu-item" data-action="promote">Promote to H1</div>
        <div class="context-menu-item" data-action="demote">Demote to H2</div>
    </div>

    <div id="context-menu" class="context-menu hidden">
        <div class="context-menu-item" data-action="cut">Cut</div>
        <div class="context-menu-item" data-action="copy">Copy</div>
        <div class="context-menu-item" data-action="paste">Paste</div>
        <div class="context-menu-separator"></div>
        <div class="context-menu-item" data-action="bold">Bold</div>
        <div class="context-menu-item" data-action="italic">Italic</div>
        <div class="context-menu-item" data-action="underline">Underline</div>
        <div class="context-menu-item" data-action="strikethrough">Strikethrough</div>
        <div class="context-menu-item" data-action="code">Inline Code</div>
        <div class="context-menu-separator"></div>
        <div class="context-menu-item" data-action="link">Insert Link</div>
        <div class="context-menu-item" data-action="footnote">Insert Footnote</div>
        <div class="context-menu-item" data-action="endnote">Insert Endnote</div>
        <div class="context-menu-separator"></div>
        <div class="context-menu-item ctx-image" data-action="alignLeft">Align Left</div>
        <div class="context-menu-item ctx-image" data-action="alignCenter">Align Center</div>
        <div class="context-menu-item ctx-image" data-action="alignRight">Align Right</div>
        <div class="context-menu-separator ctx-table-sep"></div>
        <div class="context-menu-item ctx-table" data-action="insertRow">Insert Row</div>
        <div class="context-menu-item ctx-table" data-action="insertCol">Insert Column</div>
        <div class="context-menu-item ctx-table" data-action="deleteRow">Delete Row</div>
        <div class="context-menu-item ctx-table" data-action="deleteCol">Delete Column</div>
        <div class="context-menu-separator ctx-list-sep"></div>
        <div class="context-menu-item ctx-list" data-action="checklistToggle">Toggle Checkbox</div>
        <div class="context-menu-item ctx-list" data-action="listToText">Convert to Text</div>
        <div class="context-menu-separator"></div>
        <div class="context-menu-item" data-action="deleteBlock">Delete Block</div>
        <div class="context-menu-item" data-action="removeFormat">Clear Formatting</div>
    </div>

    <div id="quick-insert-menu" class="quick-insert-menu hidden"></div>

    <div id="persistence-dialog-backdrop" class="persistence-dialog-backdrop hidden">
        <div class="persistence-dialog-card">
            <h3 id="persistence-dialog-title">Save Conflict</h3>
            <p id="persistence-dialog-body">Another version of this document was saved. What would you like to do?</p>
            <div class="persistence-dialog-actions">
                <button id="persistence-dialog-cancel">Cancel</button>
                <button id="persistence-dialog-secondary">Keep Server Version</button>
                <button id="persistence-dialog-primary" class="btn-primary">Keep My Version</button>
            </div>
        </div>
    </div>

    <div id="recovery-dialog-backdrop" class="persistence-dialog-backdrop hidden">
        <div class="persistence-dialog-card">
            <h3>Recover Unsaved Changes</h3>
            <p>We found unsaved changes from a previous session. Would you like to restore them?</p>
            <div class="persistence-dialog-actions">
                <button id="recovery-dialog-discard">Discard</button>
                <button id="recovery-dialog-restore" class="btn-primary">Restore</button>
            </div>
        </div>
    </div>

    <script src="https://unpkg.com/lucide@0.468.0"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/mammoth/1.6.0/mammoth.browser.min.js"></script>
    <script src="https://unpkg.com/docx@7.8.2/build/index.js"></script>
    <script type="module" src="/main.js"></script>
    <script>
      document.addEventListener('DOMContentLoaded', function () {
        if (typeof lucide !== 'undefined') {
          lucide.createIcons();
        }
      });

      if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/sw.js').catch(() => {});
      }
    </script>
</body>
</html>

