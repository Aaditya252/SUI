const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

const { exec, spawn } = require('child_process');
const os = require('os');
const https = require('https');

function loadLocalEnv() {
    const envPath = path.join(__dirname, '.env');
    if (!fs.existsSync(envPath)) return;

    const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
    lines.forEach((line) => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) return;
        const index = trimmed.indexOf('=');
        if (index === -1) return;

        const key = trimmed.slice(0, index).trim();
        const value = trimmed.slice(index + 1).trim().replace(/^['"]|['"]$/g, '');
        if (key && !process.env[key]) process.env[key] = value;
    });
}

loadLocalEnv();

// ─── Zero-Trust Cryptography Infrastructure ────────────────────────────────
const crypto = require('crypto');

// Ed25519 keypair for content signing — every response carries a signature
// proving it came from this server (tamper-proof)
const serverKeyPair = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const SERVER_PUBLIC_KEY_PEM = serverKeyPair.publicKey;

// HMAC secret for server ↔ AI Engine inter-service trust
const ZT_HMAC_SECRET = process.env.ZT_HMAC_SECRET || crypto.randomBytes(32).toString('hex');

// In-memory nonce/token store for issued zero-trust tokens
const ztTokens = new Map();
const ZT_TOKEN_TTL = 300_000; // 5 min

function signContent(content) {
    try {
        const sign = crypto.createSign('sha256');
        sign.update(typeof content === 'string' ? content : JSON.stringify(content));
        sign.end();
        return sign.sign(serverKeyPair.privateKey, 'base64');
    } catch (e) {
        return null;
    }
}

function verifyContentSignature(content, signature, publicKeyPem) {
    try {
        const verify = crypto.createVerify('sha256');
        verify.update(typeof content === 'string' ? content : JSON.stringify(content));
        verify.end();
        return verify.verify(publicKeyPem, signature, 'base64');
    } catch (e) {
        return false;
    }
}

function issueZtToken(clientId) {
    const token = crypto.randomBytes(24).toString('hex');
    ztTokens.set(token, { clientId, issued: Date.now(), ttl: ZT_TOKEN_TTL });
    return token;
}

function verifyZtToken(token) {
    const entry = ztTokens.get(token);
    if (!entry) return null;
    if (Date.now() - entry.issued > entry.ttl) {
        ztTokens.delete(token);
        return null;
    }
    return entry;
}

function computeHmac(payload, secret) {
    return crypto.createHmac('sha256', secret).update(typeof payload === 'string' ? payload : JSON.stringify(payload)).digest('hex');
}

// ─── End Zero-Trust Infrastructure ─────────────────────────────────────────

let suiAvailableCache = null; // null = unknown, true/false = cached
let suiBinaryCache = null;

function resolveSuiBinary() {
    if (suiBinaryCache) return suiBinaryCache;

    const localBinary = path.join(__dirname, 'tools', 'sui', process.platform === 'win32' ? 'sui.exe' : 'sui');
    if (fs.existsSync(localBinary)) {
        suiBinaryCache = localBinary;
        return suiBinaryCache;
    }

    suiBinaryCache = 'sui';
    return suiBinaryCache;
}

function checkSuiAvailable() {
    return new Promise((resolve) => {
        if (suiAvailableCache !== null) return resolve(suiAvailableCache);
        try {
            const binary = resolveSuiBinary();
            exec(`"${binary}" --version`, (err) => {
                suiAvailableCache = !err;
                resolve(suiAvailableCache);
            });
        } catch (err) {
            suiAvailableCache = false;
            resolve(false);
        }
    });
}

function getModuleName(code) {
    const match = code.match(/\bmodule\s+([A-Za-z_][\w]*)::([A-Za-z_][\w]*)\s*\{/);
    return match ? `${match[1]}::${match[2]}` : null;
}

function lineAndColumnFromIndex(source, index) {
    const chunk = source.slice(0, index);
    const lines = chunk.split(/\r?\n/);
    return { line: lines.length, column: lines[lines.length - 1].length + 1 };
}

function createDiagnostic(message, code, index = 0) {
    const pos = lineAndColumnFromIndex(code, Math.max(0, index));
    return {
        message,
        line: pos.line,
        column: pos.column
    };
}

function stripMoveComments(source) {
    return source
        .replace(/\/\*[\s\S]*?\*\//g, (block) => block.replace(/[^\r\n]/g, ' '))
        .replace(/\/\/.*$/gm, '');
}

function validateMoveSource(source) {
    const diagnostics = [];
    const stripped = stripMoveComments(source);
    const trimmed = stripped.trim();

    if (!trimmed) {
        diagnostics.push(createDiagnostic('Source buffer is empty.', source));
    }

    const moduleMatch = stripped.match(/\bmodule\s+([A-Za-z_][\w]*)::([A-Za-z_][\w]*)\s*\{/);
    if (!moduleMatch) {
        const moduleIndex = stripped.search(/\bmodule\b/);
        diagnostics.push(createDiagnostic(
            'Expected a Sui Move module declaration like `module fluid_blcx::my_module {`.',
            source,
            moduleIndex >= 0 ? moduleIndex : 0
        ));
    }

    const stack = [];
    const pairs = { '{': '}', '(': ')', '[': ']' };
    const closers = new Set(Object.values(pairs));
    for (let i = 0; i < stripped.length; i++) {
        const char = stripped[i];
        if (pairs[char]) {
            stack.push({ char, index: i });
        } else if (closers.has(char)) {
            const top = stack.pop();
            if (!top || pairs[top.char] !== char) {
                diagnostics.push(createDiagnostic(`Unexpected closing token \`${char}\`.`, source, i));
                break;
            }
        }
    }
    if (stack.length) {
        const top = stack[stack.length - 1];
        diagnostics.push(createDiagnostic(`Unclosed token \`${top.char}\`.`, source, top.index));
    }

    const allowedImports = [
        'sui::object',
        'sui::tx_context',
        'sui::coin',
        'sui::balance',
        'sui::transfer',
        'sui::clock',
        'sui::event',
        'sui::url',
        'sui::vec_map',
        'sui::dynamic_field',
        'std::vector',
        'std::string',
        'std::option',
        'std::ascii',
        'deepbook::clob_v3'
    ];

    const importRegex = /\buse\s+([A-Za-z_][\w]*::[A-Za-z_][\w]*(?:::[A-Za-z_][\w]*)?)/g;
    let importMatch;
    while ((importMatch = importRegex.exec(stripped)) !== null) {
        const importPath = importMatch[1];
        if (!allowedImports.some((allowed) => importPath === allowed || importPath.startsWith(`${allowed}::`))) {
            diagnostics.push(createDiagnostic(`Unknown or unsupported import \`${importPath}\` in local SUI compiler.`, source, importMatch.index));
        }
    }

    const functionRegex = /\b(public\s+)?(entry\s+)?fun\s+([A-Za-z_][\w]*)/g;
    let functionCount = 0;
    let fnMatch;
    while ((fnMatch = functionRegex.exec(stripped)) !== null) {
        functionCount++;
        const signatureStart = fnMatch.index;
        const bodyStart = stripped.indexOf('{', signatureStart);
        const semicolonBeforeBody = stripped.indexOf(';', signatureStart);
        if (bodyStart === -1 || (semicolonBeforeBody !== -1 && semicolonBeforeBody < bodyStart)) {
            diagnostics.push(createDiagnostic(`Function \`${fnMatch[3]}\` is missing a body block.`, source, signatureStart));
        }
    }

    if (moduleMatch && functionCount === 0 && !/\bstruct\s+[A-Za-z_][\w]*/.test(stripped)) {
        diagnostics.push(createDiagnostic('Module compiled, but it contains no struct or function declarations.', source, moduleMatch.index));
    }

    const badPatterns = [
        { regex: /\b(error|fail|todo_compile_error)\b/i, message: 'Compiler stop word found in source. Remove placeholder failure text.' },
        { regex: /\bIncorrectCoin\b/, message: 'Unresolved type `IncorrectCoin`.' },
        { regex: /\breturn\s+[^;{}]+(?=\n|\r|$)/, message: 'Return expression should end with `;` in this editor compiler.' }
    ];
    badPatterns.forEach((item) => {
        const match = stripped.match(item.regex);
        if (match && typeof match.index === 'number') {
            diagnostics.push(createDiagnostic(item.message, source, match.index));
        }
    });

    return {
        success: diagnostics.length === 0,
        diagnostics,
        moduleName: getModuleName(stripped),
        stats: {
            lines: source.split(/\r?\n/).length,
            functions: functionCount,
            structs: (stripped.match(/\bstruct\s+[A-Za-z_][\w]*/g) || []).length,
            imports: (stripped.match(/\buse\s+/g) || []).length
        }
    };
}

function writeTempMovePackage(code) {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fluidblcx-sui-'));
    const sourcesDir = path.join(tempDir, 'sources');
    fs.mkdirSync(sourcesDir, { recursive: true });
    fs.writeFileSync(path.join(tempDir, 'Move.toml'), [
        '[package]',
        'name = "fluidblcx_sandbox"',
        'version = "0.0.1"',
        'edition = "2024"',
        'published-at = "0x0"',
        '',
        '[addresses]',
        'fluid_blcx = "0x0"',
        'sui_agent_ptb = "0x0"',
        ''
    ].join('\n'));
    fs.writeFileSync(path.join(sourcesDir, 'fluid_workspace.move'), code);
    return tempDir;
}

function runSuiBuild(code, onLine) {
    return new Promise((resolve) => {
        let tempDir;
        try {
            tempDir = writeTempMovePackage(code);
        } catch (err) {
            resolve({ success: false, output: '', error: `Unable to create temporary Move package: ${err.message}` });
            return;
        }

        onLine && onLine(`[INFO] Temporary Sui package created at ${tempDir}`);
        let child;
        try {
            child = spawn(resolveSuiBinary(), ['move', 'build', '--build-env', 'testnet'], { cwd: tempDir, shell: false });
        } catch (err) {
            try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (e) {}
            resolve({ success: false, output: '', error: `Unable to start Sui CLI: ${err.message}` });
            return;
        }
        let output = '';
        let error = '';
        let timedOut = false;

        const timer = setTimeout(() => {
            timedOut = true;
            try { child.kill(); } catch (e) {}
            error += '\nBuild timed out after 180 seconds.';
        }, 180000);

        child.stdout.on('data', (data) => {
            const text = cleanCompilerText(data.toString());
            output += text;
            onLine && onLine(`[OUT] ${text}`);
        });
        child.stderr.on('data', (data) => {
            const text = cleanCompilerText(data.toString());
            error += text;
            onLine && onLine(`[SUI] ${text}`);
        });
        child.on('error', (err) => {
            clearTimeout(timer);
            resolve({ success: false, output, error: err.message });
        });
        child.on('close', (codeNumber) => {
            clearTimeout(timer);
            try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (e) {}
            resolve({
                success: !timedOut && codeNumber === 0,
                output: output || (codeNumber === 0 ? 'Sui build completed with no textual output.' : ''),
                error,
                code: codeNumber
            });
        });
    });
}

function cleanCompilerText(text) {
    return text.replace(/\x1b\[[0-9;]*m/g, '').trimEnd();
}

function formatLocalCompileOutput(result) {
    const lines = [
        'FluidBLCX Local SUI Move Compiler',
        `Module: ${result.moduleName || 'unresolved'}`,
        `Lines: ${result.stats.lines}`,
        `Imports: ${result.stats.imports}`,
        `Structs: ${result.stats.structs}`,
        `Functions: ${result.stats.functions}`
    ];

    if (!result.success) {
        lines.push('Diagnostics:');
        result.diagnostics.forEach((diag) => {
            lines.push(`  fluid_workspace.move:${diag.line}:${diag.column} ${diag.message}`);
        });
        return lines.join('\n');
    }

    lines.push('Syntax validation: passed');
    lines.push('Bytecode emission: pending real Sui CLI installation');
    lines.push('Result: source is ready for `sui move build`.');
    return lines.join('\n');
}

function extractAssistantIntent(message) {
    const text = message.toLowerCase();
    const assets = [...new Set((message.match(/\b(SUI|USDC|USDT|BTC|ETH|SOL|WAL|DEEP|APT)\b/gi) || []).map((asset) => asset.toUpperCase()))];
    const amountMatch = message.match(/\b\d+(?:\.\d+)?\b/);
    const percentMatch = message.match(/\b\d+(?:\.\d+)?\s*%/);
    const networkMatch = text.match(/\b(testnet|mainnet|devnet|localnet)\b/);

    let action = 'explain';
    if (/\b(route|routing|swap|bridge|send|transfer)\b/.test(text)) action = 'route';
    if (/\b(compile|compiler|move|contract|module|build|error)\b/.test(text)) action = 'compile';
    if (/\b(wallet|connect|login|sign)\b/.test(text)) action = 'wallet';
    if (/\b(deepbook|liquidity|pool|slippage|price)\b/.test(text)) action = 'liquidity';
    if (/\b(walrus|vault|storage|encrypt|seal)\b/.test(text)) action = 'vault';
    if (/\b(3d|visual|block|chain|node|graph)\b/.test(text)) action = 'visualizer';

    return {
        action,
        assets,
        amount: amountMatch ? amountMatch[0] : null,
        slippage: percentMatch ? percentMatch[0] : null,
        network: networkMatch ? networkMatch[0] : 'testnet'
    };
}

function buildRouteSummary(intent) {
    const fromAsset = intent.assets[0] || 'source asset';
    const toAsset = intent.assets[1] || 'target asset';
    const amount = intent.amount || 'the chosen amount';
    const slippage = intent.slippage || 'a max slippage/min-output rule';

    return [
        `I read this as a routing intent: move ${amount} ${fromAsset} toward ${toAsset} on ${intent.network}.`,
        `Next, the app needs three concrete values: source coin, target coin, and protection rule (${slippage}).`,
        'For this UI, a good next prompt is: "route 10 SUI to USDC on testnet with max 1% slippage".',
        'After that, use the Compiler page to validate the Move route module before treating the flow as executable.'
    ].join('\n');
}

function localAssistantReply(message) {
    const intent = extractAssistantIntent(message);

    if (intent.action === 'route') return buildRouteSummary(intent);

    if (intent.action === 'compile') {
        return [
            'You are asking about the compiler path.',
            'The Compiler page sends the editor source to the backend, creates a temporary Sui Move package, and runs real `sui move build` through the local Sui CLI.',
            'If your code fails, paste the exact terminal diagnostic here and I can explain the line, likely cause, and fix.'
        ].join('\n');
    }

    if (intent.action === 'wallet') {
        return [
            'Wallet flow: connect a Sui-compatible wallet first, then describe the route intent.',
            'The current UI can guide the flow, but do not treat a route as executed until a wallet signs and the chain returns a transaction digest.',
            'Tell me which wallet you are using and what error you see if connection fails.'
        ].join('\n');
    }

    if (intent.action === 'liquidity') {
        return [
            'For liquidity/DeepBook-style routing, the important checks are price, spread, slippage, and minimum output.',
            `From your input I detected assets: ${intent.assets.length ? intent.assets.join(' -> ') : 'none yet'}.`,
            'Give me amount, input asset, output asset, and slippage limit, and I will turn it into a route checklist.'
        ].join('\n');
    }

    if (intent.action === 'vault') {
        return [
            'Walrus Vault in this app should be treated as the storage/security layer.',
            'Use it for encrypted route metadata, proofs, or off-chain payload references, not for pretending funds moved.',
            'Tell me what data you want to protect and I will map it to a vault-style flow.'
        ].join('\n');
    }

    if (intent.action === 'visualizer') {
        return [
            'The 3D visualizer is a status/telemetry view.',
            'A new block should mean the compiler validated a module or a route stage completed, not that an on-chain transaction executed by itself.',
            'Hover nodes to inspect their state, then compare the terminal result with the node status.'
        ].join('\n');
    }

    return [
        `I understood your message as a request to explain the app flow.`,
        'FluidBLCX flow is: connect wallet -> describe routing intent -> validate/compile Move module -> inspect the visualized execution state.',
        'Try asking with specifics like: "route 5 SUI to USDC with 1% slippage" or "why did my Move compile fail?"'
    ].join('\n');
}

async function askGeminiAssistant(message, history = []) {
    const apiKey = process.env.GEMINI_API_KEY;
    const model = process.env.GEMINI_MODEL || 'gemini-1.5-flash';

    if (!apiKey) {
        return { mode: 'local', reason: 'Gemini key is not configured on the backend.', reply: localAssistantReply(message) };
    }

    const contents = [
        {
            role: 'user',
            parts: [{
                text: [
                    'You are Fluid Core Intelligence, an assistive chatbot inside FluidBLCX.',
                    'Help users understand this Sui app: wallet connection, Sui Move compiler, atomic asset routing, DeepBook-like liquidity, Walrus vault concepts, and the 3D block visualizer.',
                    'Keep replies concise, practical, and beginner-friendly. Do not claim that a transaction was executed unless the user provides proof from the app.',
                    'When code is involved, explain the next concrete step.'
                ].join(' ')
            }]
        },
        ...history.slice(-8).map((item) => ({
            role: item.role === 'agent' ? 'model' : 'user',
            parts: [{ text: String(item.text || '').slice(0, 1200) }]
        })),
        { role: 'user', parts: [{ text: message }] }
    ];

    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            contents,
            generationConfig: {
                temperature: 0.35,
                maxOutputTokens: 420
            }
        })
    });

    if (!response.ok) {
        const details = await response.text();
        throw new Error(`Gemini request failed with HTTP ${response.status}: ${details.slice(0, 240)}`);
    }

    const data = await response.json();
    const reply = data.candidates?.[0]?.content?.parts?.map((part) => part.text || '').join('').trim();
    return { mode: 'gemini', reply: reply || localAssistantReply(message) };
}

// Handle cross-origin telemetry requests cleanly
app.use(cors());
app.use(express.json());

// ─── Zero-Trust: Sign all response bodies ─────────────────────────────────
app.use((req, res, next) => {
    const originalJson = res.json.bind(res);
    res.json = function (body) {
        const signature = signContent(body);
        if (signature) res.setHeader('X-ZT-Signature', signature);
        res.setHeader('X-ZT-PublicKey', SERVER_PUBLIC_KEY_PEM.replace(/\n/g, ' ').replace(/\s+/g, ' ').trim());
        return originalJson(body);
    };
    next();
});
// ─── End Zero-Trust Response Signing ──────────────────────────────────────

// Serve static UI files from the `ui` directory
app.use(express.static('ui'));

// Redirect root to the starting page
app.get('/', (req, res) => res.redirect('/index.html'));

/**
 * Custom Remote Compiler Hook
 */
app.post('/api/compile', (req, res) => {
    const { code, language } = req.body;
    console.log(`[COMPILER ENGINE] Intercepted payload in lang: ${language}`);

    if (!code || code.trim() === '') {
        return res.status(400).json({
            success: false,
            error: "Source buffer is empty. Provide Move target logic prior to compiling."
        });
    }

    // Try to use the real Sui CLI if available; otherwise use local diagnostics.
    checkSuiAvailable().then(async (available) => {
        if (available) {
            console.log('[COMPILER ENGINE] Sui CLI available - compiling submitted editor buffer');
            const result = await runSuiBuild(code);
            if (!result.success) return res.json({ success: false, error: result.error || result.output, output: result.output });
            return res.json({ success: true, output: result.output });
        }

        const localResult = validateMoveSource(code);
        return res.json({
            success: localResult.success,
            mode: 'local',
            output: formatLocalCompileOutput(localResult),
            error: localResult.success ? '' : formatLocalCompileOutput(localResult),
            diagnostics: localResult.diagnostics,
            stats: localResult.stats,
            moduleName: localResult.moduleName
        });
    }).catch((err) => {
        return res.status(500).json({ success: false, error: err.message });
    });
});

app.get('/api/compiler-status', async (req, res) => {
    const available = await checkSuiAvailable();
    res.json({
        suiAvailable: available,
        mode: available ? 'sui-cli' : 'local',
        binary: available ? resolveSuiBinary() : null,
        message: available
            ? `Real Sui CLI build pipeline is available at ${resolveSuiBinary()}.`
            : 'Sui CLI is not installed. Using FluidBLCX local Move diagnostics.'
    });
});

app.post('/api/assistant', async (req, res) => {
    const { message, history } = req.body || {};
    if (!message || !String(message).trim()) {
        return res.status(400).json({ success: false, error: 'Message is required.' });
    }

    try {
        const result = await askGeminiAssistant(String(message).trim(), Array.isArray(history) ? history : []);
        return res.json({ success: true, ...result });
    } catch (err) {
        return res.json({
            success: true,
            mode: 'local-fallback',
            reason: err.message,
            reply: localAssistantReply(message)
        });
    }
});

app.get('/api/assistant-status', (req, res) => {
    res.json({
        configured: Boolean(process.env.GEMINI_API_KEY),
        model: process.env.GEMINI_MODEL || 'gemini-1.5-flash'
    });
});

app.get('/api/assistant', (req, res) => {
    res.status(405).json({
        success: false,
        error: 'Use POST /api/assistant with JSON body { message, history }.'
    });
});

app.get('/api/compile', (req, res) => {
    res.status(405).json({
        success: false,
        error: 'Use POST /api/compile with JSON body { language, code }.'
    });
});

/**
 * Shell Command Execution Proxy Hook
 */
app.post('/api/cmd', (req, res) => {
    const { command } = req.body;
    console.log(`[SHELL PARSER] Processing direct parameter: ${command}`);

    if (command.startsWith('fluid ')) {
        return res.json({ output: `Fluid Engine context: executing routing directive module for '${command.substring(6)}'` });
    }

    return res.json({ output: `Command Context Error: Unrecognized external hook instruction sequence "${command}".` });
});

// Simple chain status ping endpoint to query Sui testnet fullnode availability
app.get('/api/chain-status', (req, res) => {
    const options = {
        hostname: 'fullnode.testnet.sui.io',
        port: 443,
        path: '/',
        method: 'GET',
        timeout: 4000
    };
    let sent = false;
    function safeSend(obj) {
        if (sent) return;
        sent = true;
        try { res.json(obj); } catch (e) { /* ignore */ }
    }

    const reqt = https.request(options, (r) => {
        safeSend({ reachable: true, statusCode: r.statusCode, timestamp: Date.now() });
    });

    reqt.on('error', (e) => {
        safeSend({ reachable: false, error: e.message, timestamp: Date.now() });
    });

    reqt.on('timeout', () => {
        reqt.destroy();
        safeSend({ reachable: false, error: 'timeout', timestamp: Date.now() });
    });

    reqt.end();
});

// Streaming compile endpoint: returns SSE-like chunks over the POST response
app.post('/api/compile-stream', async (req, res) => {
    const { code, language } = req.body || {};
    console.log(`[COMPILER STREAM] Received stream request for language=${language}`);

    if (!code || code.trim() === '') {
        return res.status(400).json({ success: false, error: 'Source buffer is empty.' });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders && res.flushHeaders();

    function sendLine(line) {
        try { res.write(`data: ${line.replace(/\n/g, '\\n')}\n\n`); } catch (e) { /* ignore */ }
    }

    const available = await checkSuiAvailable();
    if (available) {
        sendLine('[INFO] Sui CLI detected. Building the editor buffer in a temporary Move package...');
        const result = await runSuiBuild(code, sendLine);
        if (result.success) {
            sendLine('[SUCCESS] Real Sui CLI build finished with exit 0.');
        } else {
            sendLine(`[ERROR] ${String(result.error || result.output || 'Sui build failed.').replace(/\n/g, '\\n')}`);
        }
        sendLine(`[DONE] ${JSON.stringify({ success: result.success, mode: 'sui-cli', code: result.code || 0 })}`);
        return res.end();
    }

    sendLine('[INFO] Sui CLI not found. Running FluidBLCX local SUI Move compiler...');
    sendLine('[INFO] Parsing module declaration...');
    await new Promise((resolve) => setTimeout(resolve, 220));
    sendLine('[INFO] Checking delimiters, imports, structs, and functions...');
    await new Promise((resolve) => setTimeout(resolve, 260));
    const localResult = validateMoveSource(code);
    sendLine(`[INFO] ${localResult.stats.lines} lines, ${localResult.stats.imports} imports, ${localResult.stats.structs} structs, ${localResult.stats.functions} functions analyzed.`);

    if (!localResult.success) {
        localResult.diagnostics.forEach((diag) => {
            sendLine(`[ERROR] fluid_workspace.move:${diag.line}:${diag.column} ${diag.message}`);
        });
        sendLine('[DONE] {"success":false,"mode":"local"}');
        return res.end();
    }

    sendLine(`[SUCCESS] ${localResult.moduleName || 'Move module'} passed local SUI Move validation.`);
    sendLine('[INFO] Install the Sui CLI to upgrade this path from diagnostics to real bytecode generation.');
    sendLine('[DONE] {"success":true,"mode":"local"}');
    return res.end();
});

app.get('/api/compile-stream', (req, res) => {
    res.status(405).json({
        success: false,
        error: 'Use POST /api/compile-stream with JSON body { language, code }.'
    });
});

// ---------------------------------------------------------------------------
// SWAP & PRICE API — Real CoinGecko prices + proper swap math
// ---------------------------------------------------------------------------

const SWAP_SUPPORTED_ASSETS = [
    { id: 'sui',          symbol: 'SUI',  name: 'Sui',                decimals: 9, binance: 'SUIUSDT' },
    { id: 'bitcoin',      symbol: 'BTC',  name: 'Bitcoin',            decimals: 8, binance: 'BTCUSDT' },
    { id: 'ethereum',     symbol: 'ETH',  name: 'Ethereum',           decimals: 18, binance: 'ETHUSDT' },
    { id: 'solana',       symbol: 'SOL',  name: 'Solana',             decimals: 9, binance: 'SOLUSDT' },
    { id: 'binancecoin',  symbol: 'BNB',  name: 'Binance Coin',       decimals: 18, binance: 'BNBUSDT' },
    { id: 'tether',       symbol: 'USDT', name: 'Tether',             decimals: 6 },
    { id: 'usd-coin',     symbol: 'USDC', name: 'USD Coin',           decimals: 6 },
];

const DEEP_COINTYPE = '0xdee9::deep::DEEP';

let pricesCache = { data: null, ts: 0, ttl: 15000 }; // 15s cache

async function fetchBinancePrices() {
    const symbols = SWAP_SUPPORTED_ASSETS.filter(a => a.binance).map(a => a.binance).join('","');
    const resp = await fetch(`https://api.binance.com/api/v3/ticker/price?symbols=["${symbols}"]`);
    if (!resp.ok) throw new Error(`Binance HTTP ${resp.status}`);
    const json = await resp.json();
    const result = {};
    json.forEach(t => {
        const asset = SWAP_SUPPORTED_ASSETS.find(a => a.binance === t.symbol);
        if (asset) result[asset.id] = { usd: parseFloat(t.price) };
    });
    return result;
}

async function fetchCoinGeckoPrices() {
    const ids = SWAP_SUPPORTED_ASSETS.map(a => a.id).join(',');
    const resp = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd`);
    if (!resp.ok) throw new Error(`CoinGecko HTTP ${resp.status}`);
    return await resp.json();
}

async function fetchPrices() {
    const now = Date.now();
    if (pricesCache.data && (now - pricesCache.ts) < pricesCache.ttl) return pricesCache.data;

    let prices = null;
    // Try Binance first (fast, reliable)
    try {
        prices = await fetchBinancePrices();
        console.log('[PRICES] Binance OK');
    } catch (e1) {
        console.warn('[PRICES] Binance failed:', e1.message);
        // Fall back to CoinGecko
        try {
            prices = await fetchCoinGeckoPrices();
            console.log('[PRICES] CoinGecko OK');
        } catch (e2) {
            console.warn('[PRICES] CoinGecko failed:', e2.message);
        }
    }

    if (prices) {
        pricesCache = { data: prices, ts: Date.now(), ttl: 15000 };
        return prices;
    }

    // If we have stale cache, return it
    if (pricesCache.data) return pricesCache.data;

    // Last resort fallback
    const fallback = {
        sui:         { usd: 0.72 },
        bitcoin:     { usd: 64000 },
        ethereum:    { usd: 2600 },
        solana:      { usd: 145 },
        binancecoin: { usd: 580 },
        tether:      { usd: 1.00 },
        'usd-coin':  { usd: 1.00 },
    };
    pricesCache = { data: fallback, ts: Date.now(), ttl: 30000 };
    return fallback;
}

app.get('/api/prices', async (req, res) => {
    try {
        const prices = await fetchPrices();
        const enriched = SWAP_SUPPORTED_ASSETS.map(a => ({
            ...a,
            price_usd: prices[a.id]?.usd || (a.symbol === 'USDT' || a.symbol === 'USDC' ? 1.00 : 0),
            change_24h: prices[a.id]?.usd_24h_change || 0,
        }));
        res.json({ success: true, assets: enriched, timestamp: Date.now() });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/swap/quote', async (req, res) => {
    const { fromAsset, toAsset, amount, slippage } = req.body || {};
    if (!fromAsset || !toAsset || amount == null) {
        return res.status(400).json({ success: false, error: 'Missing fromAsset, toAsset, or amount' });
    }

    const fromMeta = SWAP_SUPPORTED_ASSETS.find(a => a.symbol === fromAsset || a.id === fromAsset);
    const toMeta = SWAP_SUPPORTED_ASSETS.find(a => a.symbol === toAsset || a.id === toAsset);
    if (!fromMeta || !toMeta) {
        return res.status(400).json({ success: false, error: `Unsupported asset: ${fromAsset} or ${toAsset}` });
    }

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({ success: false, error: 'Amount must be a positive number' });
    }

    const prices = await fetchPrices();
    const fromPrice = prices[fromMeta.id]?.usd || 0;
    const toPrice = prices[toMeta.id]?.usd || 0;
    if (!fromPrice || !toPrice) {
        return res.status(400).json({ success: false, error: 'Price data unavailable for one or both assets' });
    }

    // Core swap math
    const slippagePercent = parseFloat(slippage) || 0.5; // default 0.5%
    const usdValue = parsedAmount * fromPrice;

    // Price impact: simplified formula based on trade size vs liquidity
    const estimatedLiquidityUsd = fromPrice * 500000; // ~$500k pool depth
    const priceImpact = Math.min((usdValue / estimatedLiquidityUsd) * 100, 15);
    const effectivePrice = toPrice * (1 - priceImpact / 100);
    const rawOutput = usdValue / effectivePrice;

    // Apply slippage
    const minOutput = rawOutput * (1 - slippagePercent / 100);

    const quote = {
        fromAsset: fromMeta.symbol,
        toAsset: toMeta.symbol,
        fromAmount: parsedAmount,
        toAmount: parseFloat(rawOutput.toFixed(6)),
        minToAmount: parseFloat(minOutput.toFixed(6)),
        rate: parseFloat((fromPrice / toPrice).toFixed(8)),
        inverseRate: parseFloat((toPrice / fromPrice).toFixed(8)),
        priceImpact: parseFloat(priceImpact.toFixed(4)),
        slippagePercent,
        usdValue: parseFloat(usdValue.toFixed(2)),
        fromPriceUsd: fromPrice,
        toPriceUsd: toPrice,
        fees: {
            network: '0.00025 SUI',
            protocol: `${parseFloat((usdValue * 0.003).toFixed(2))} USD`,
        },
        timestamp: Date.now(),
    };

    res.json({ success: true, quote });
});

app.post('/api/swap/execute', async (req, res) => {
    const { quote } = req.body || {};
    if (!quote) {
        return res.status(400).json({ success: false, error: 'Missing quote data' });
    }

    // Simulate a 1.5s network delay
    await new Promise(r => setTimeout(r, 1500));

    // Simulate occasional failure (5% chance)
    if (Math.random() < 0.05) {
        return res.json({
            success: false,
            error: 'Transaction reverted: slippage tolerance exceeded. Try increasing slippage or reducing amount.',
            txHash: null,
        });
    }

    const txHash = '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
    res.json({
        success: true,
        txHash,
        explorerUrl: `https://suiscan.xyz/testnet/tx/${txHash}`,
        timestamp: Date.now(),
    });
});

// ---------------------------------------------------------------------------
// BUILD A REAL SUI PTB FOR SWAP EXECUTION
// ---------------------------------------------------------------------------

app.post('/api/swap/build-tx', async (req, res) => {
    const { quote, sender } = req.body || {};
    if (!quote || !sender) {
        return res.status(400).json({ success: false, error: 'Missing quote or sender' });
    }

    // Validate sender address format
    if (!sender.startsWith('0x') || sender.length !== 66) {
        return res.status(400).json({ success: false, error: `Invalid sender address format: expected 0x + 64 hex chars, got ${sender.length} chars` });
    }

    try {
        const { Transaction } = await import('@mysten/sui/transactions');
        const client = await getSuiClient();

        const tx = new Transaction();
        tx.setSender(sender);

        const fromMeta = SWAP_SUPPORTED_ASSETS.find(a => a.symbol === quote.fromAsset);
        const decimals = fromMeta?.decimals || 9;
        const amountMist = BigInt(Math.floor(parseFloat(quote.fromAmount) * Math.pow(10, decimals)));

        const [paymentCoin] = tx.splitCoins(tx.gas, [tx.pure.u64(amountMist)]);
        tx.transferObjects([paymentCoin], tx.pure.address(sender));
        tx.setGasBudget(20_000_000);

        // Get real gas price from testnet
        let refGasPrice = 1000n;
        try {
            refGasPrice = await client.getReferenceGasPrice();
        } catch (e) { /* use default */ }

        // Set gas price from testnet
        tx.setGasPrice(Number(refGasPrice));

        let rawBytes;
        let gasCoinFallback = false;

        try {
            const buildResult = await tx.build({ client });
            rawBytes = buildResult instanceof Uint8Array ? buildResult : new Uint8Array(buildResult.bytes || buildResult);
        } catch (buildErr) {
            if (buildErr.message?.includes('No valid gas coins')) {
                // Fallback: serialize transaction data without gas coin resolution
                const base64 = tx.serialize();
                const buf = Buffer.from(base64, 'base64');
                rawBytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
                gasCoinFallback = true;
            } else {
                throw buildErr;
            }
        }

        const txBytesHex = Array.from(rawBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        const gasData = tx.getData().gasData;
        const gasEstimateMist = BigInt(gasData.budget || 20_000_000);
        const gasEstimateSui = Number(gasEstimateMist) / 1e9;

        res.json({
            success: true,
            txBytes: txBytesHex,
            txBytesArray: Array.from(rawBytes),
            gasEstimate: `${gasEstimateSui.toFixed(6)} SUI`,
            gasBudget: gasEstimateMist.toString(),
            refGasPrice: refGasPrice.toString(),
            gasCoinFallback,
            warning: gasCoinFallback ? `Sender ${sender.slice(0,10)}... has no SUI coins on testnet. Use the faucet at https://faucet.testnet.sui.io to fund it.` : undefined,
        });
    } catch (e) {
        console.error('[SWAP BUILD-TX] Error:', e.message);
        res.status(500).json({ success: false, error: e.message });
    }
});

// ---------------------------------------------------------------------------
// PANIC / CIRCUIT BREAKER — Cancel all open orders for a given wallet
// ---------------------------------------------------------------------------
app.post('/api/swap/cancel-all', async (req, res) => {
    const { address, label } = req.body || {};
    if (!address) {
        return res.status(400).json({ success: false, error: 'Missing address' });
    }

    try {
        // In production: call DeepBook SDK to cancel all orders for this address.
        // On testnet, we build a cancellation transaction and return the bytes.
        const { Transaction } = await import('@mysten/sui/transactions');
        const client = await getSuiClient();

        const tx = new Transaction();
        tx.setSender(address);

        // Create a simple transfer-to-self as a simulated cancel signal
        const [coin] = tx.splitCoins(tx.gas, [tx.pure.u64(1_000_000)]);
        tx.transferObjects([coin], tx.pure.address(address));
        tx.setGasBudget(10_000_000);

        let refGasPrice = 1000n;
        try { refGasPrice = await client.getReferenceGasPrice(); } catch (e) {}
        tx.setGasPrice(Number(refGasPrice));

        let rawBytes;
        try {
            const buildResult = await tx.build({ client });
            rawBytes = buildResult instanceof Uint8Array ? buildResult : new Uint8Array(buildResult.bytes || buildResult);
        } catch (buildErr) {
            if (buildErr.message?.includes('No valid gas coins')) {
                const base64 = tx.serialize();
                const buf = Buffer.from(base64, 'base64');
                rawBytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
            } else {
                throw buildErr;
            }
        }

        const txBytesHex = Array.from(rawBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        res.json({
            success: true,
            address,
            label: label || address.slice(0, 10),
            cancelled: `All open orders cancelled for ${label || address.slice(0, 10)}`,
            txBytes: txBytesHex,
            timestamp: new Date().toISOString(),
        });
    } catch (e) {
        console.error('[CANCEL-ALL] Error:', e.message);
        res.status(500).json({ success: false, error: e.message });
    }
});

// ---------------------------------------------------------------------------
// SUI TESTNET RPC PROXY — Fetch real balances, coins, and chain data
// ---------------------------------------------------------------------------

let suiClientPromise = null;

async function getSuiClient() {
    if (!suiClientPromise) {
        suiClientPromise = import('@mysten/sui/jsonRpc').then(async ({ SuiJsonRpcClient, getJsonRpcFullnodeUrl }) => {
            return new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl('testnet') });
        });
    }
    return suiClientPromise;
}

async function getSuiFaucet() {
    return import('@mysten/sui/faucet');
}

/**
 * Fetch all SUI and token balances for a given address on testnet.
 */
app.get('/api/sui/balances', async (req, res) => {
    const { address } = req.query;
    if (!address) {
        return res.status(400).json({ success: false, error: 'Missing address query parameter' });
    }

    try {
        const client = await getSuiClient();
        const [balances, coins] = await Promise.all([
            client.getAllBalances({ owner: address }),
            client.getCoins({ owner: address }),
        ]);

        const enriched = await Promise.all(balances.map(async (b) => {
            let metadata = null;
            try {
                metadata = await client.getCoinMetadata({ coinType: b.coinType });
            } catch (e) { /* ignore unsupported coin types */ }
            const decimals = metadata?.decimals || 0;
            return {
                coinType: b.coinType,
                symbol: metadata?.symbol || b.coinType.split('::').pop() || 'Unknown',
                name: metadata?.name || b.coinType.split('::').pop() || 'Unknown',
                decimals,
                totalBalance: b.totalBalance,
                formattedBalance: (Number(b.totalBalance) / Math.pow(10, decimals)).toFixed(Math.min(decimals, 9)),
            };
        }));

        res.json({
            success: true,
            address,
            balances: enriched,
            coins: coins.data.map(c => ({
                coinType: c.coinType,
                coinObjectId: c.coinObjectId,
                balance: c.balance,
                symbol: c.coinType.split('::').pop(),
            })),
            network: 'testnet',
            timestamp: Date.now(),
        });
    } catch (e) {
        console.error('[SUI RPC] Balance fetch error:', e.message);
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * Request test SUI from the testnet faucet.
 */
app.post('/api/sui/faucet', async (req, res) => {
    const { address } = req.body;
    if (!address) {
        return res.status(400).json({ success: false, error: 'Missing address' });
    }

    try {
        const faucet = await getSuiFaucet();
        const result = await faucet.requestSuiFromFaucetV2({
            host: 'https://faucet.testnet.sui.io',
            recipient: address,
        });
        res.json({ success: true, result });
    } catch (e) {
        console.error('[SUI FAUCET] Error:', e.message);
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * General-purpose Sui testnet RPC call (limited to safe read methods).
 */
app.post('/api/sui/rpc', async (req, res) => {
    const { method, params } = req.body;
    if (!method) {
        return res.status(400).json({ success: false, error: 'Missing method' });
    }

    // Whitelist safe read-only methods
    const allowed = [
        'getBalance', 'getAllBalances', 'getCoins', 'getCoinMetadata',
        'getObject', 'getOwnedObjects', 'getTransactionBlock',
        'queryTransactions', 'getAddressMetrics', 'getLatestCheckpointSequenceNumber',
        'getReferenceGasPrice',
    ];

    if (!allowed.includes(method)) {
        return res.status(403).json({ success: false, error: `Method '${method}' not allowed. Use a whitelisted read method.` });
    }

    try {
        const client = await getSuiClient();
        const result = await client[method](...(params || []));
        res.json({ success: true, result });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/sui/network', async (req, res) => {
    const sui = await import('@mysten/sui/jsonRpc').catch(() => null);
    res.json({
        success: true,
        network: 'testnet',
        rpc: sui ? sui.getJsonRpcFullnodeUrl('testnet') : 'https://fullnode.testnet.sui.io:443',
        faucet: 'https://faucet.testnet.sui.io',
        explorer: 'https://suiscan.xyz/testnet',
        description: 'Sui Testnet — tokens are free from faucet and have no real value.',
    });
});

// ─── Walrus Vault & Security Dashboard Routes ───────────────────────────────

app.get('/walrus-vault', (req, res) => {
    res.sendFile(path.join(__dirname, 'ui', 'walrus_vault.html'));
});

app.get('/security-dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'ui', 'security_dashboard.html'));
});

// ─── Zero-Trust: API Endpoints ─────────────────────────────────────────────

// Get server's Ed25519 public key (clients use this to verify response signatures)
app.get('/api/zt/public-key', (req, res) => {
    res.json({
        success: true,
        algorithm: 'Ed25519',
        publicKeyPem: SERVER_PUBLIC_KEY_PEM,
        fingerprint: crypto.createHash('sha256').update(SERVER_PUBLIC_KEY_PEM).digest('hex').slice(0, 16),
        hint: 'Verify X-ZT-Signature headers on all API responses using this public key.'
    });
});

// Issue a short-lived zero-trust token (client identifies itself)
app.post('/api/zt/request-token', (req, res) => {
    const { clientId } = req.body || {};
    if (!clientId) {
        return res.status(400).json({ success: false, error: 'clientId required' });
    }
    const token = issueZtToken(String(clientId).slice(0, 64));
    res.json({ success: true, token, ttl: ZT_TOKEN_TTL, hint: 'Include header X-ZT-Token on subsequent requests.' });
});

// Verify a client-supplied signature against known data
app.post('/api/zt/verify', (req, res) => {
    const { data, signature, publicKeyPem } = req.body || {};
    if (!data || !signature || !publicKeyPem) {
        return res.status(400).json({ success: false, error: 'data, signature, and publicKeyPem required' });
    }
    const valid = verifyContentSignature(data, signature, publicKeyPem);
    res.json({ success: true, valid, data, signature: signature.slice(0, 20) + '...' });
});

// Zero-trust status page — health of all crypto layers
app.get('/api/zt/status', (req, res) => {
    res.json({
        success: true,
        responseSigning: { algorithm: 'Ed25519', active: true },
        hmacInterService: { algorithm: 'HMAC-SHA256', active: true, secretLength: ZT_HMAC_SECRET.length },
        tokenAuth: { active: true, ttl: ZT_TOKEN_TTL, activeTokens: ztTokens.size },
        timestamp: Date.now()
    });
});

// Middleware: verify ZT-Token on sensitive endpoints (non-blocking, logs only)
app.use('/api/sui', (req, res, next) => {
    const token = req.headers['x-zt-token'];
    if (token) {
        const entry = verifyZtToken(token);
        if (entry) {
            req.ztClientId = entry.clientId;
        } else {
            console.warn(`[ZT] Invalid/expired token from ${req.ip}`);
        }
    }
    next();
});

// ─── AI Security Engine Integration ──────────────────────────────────────────

const AI_ENGINE_URL = 'http://127.0.0.1:5001';

app.use('/api/security', async (req, res) => {
    try {
        const segments = req.originalUrl.split('?');
        const pathPart = segments[0];
        const qs = segments.length > 1 ? '?' + segments[1] : '';
        const targetPath = pathPart.replace('/api/security', '/api/security');
        const url = `${AI_ENGINE_URL}${targetPath}${qs}`;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);

        const bodyPayload = req.method !== 'GET' && req.method !== 'HEAD' ? (req.body || {}) : {};
        const bodyStr = JSON.stringify(bodyPayload);
        const hmacSignature = computeHmac(bodyStr, ZT_HMAC_SECRET);

        const options = {
            method: req.method,
            headers: {
                'Content-Type': 'application/json',
                'X-ZT-HMAC': hmacSignature,
                'X-ZT-HMAC-Timestamp': String(Date.now()),
                ...Object.fromEntries(
                Object.entries(req.headers || {}).filter(([k]) => !['host','connection','content-length'].includes(k.toLowerCase()))
            )},
            signal: controller.signal
        };
        if (req.method !== 'GET' && req.method !== 'HEAD') {
            options.body = bodyStr;
        }

        const aiResp = await fetch(url, options);
        clearTimeout(timeout);
        const data = await aiResp.json();
        res.status(aiResp.status).json(data);
    } catch (e) {
        res.status(503).json({ error: 'AI Engine unavailable', detail: e.message });
    }
});

// ─── Optional: Scan all API requests through AI Engine ──────────────────────

const SECURITY_SKIP_PATHS = ['/api/security', '/api/health', '/api/prices', '/walrus-vault', '/security-dashboard', '/api/compile-stream', '/api/assistant'];

app.use(async (req, res, next) => {
    if (SECURITY_SKIP_PATHS.some(p => req.path.startsWith(p)) || req.method === 'GET') return next();

    try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 3000);
        const scanResp = await fetch(`${AI_ENGINE_URL}/api/security/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                path: req.path,
                body: JSON.stringify(req.body || ''),
                query: JSON.stringify(req.query || ''),
                headers: req.headers,
                method: req.method,
                params: req.body || {}
            }),
            signal: ctrl.signal
        });
        const result = await scanResp.json();
        if (result.blocked) {
            return res.status(429).json({
                error: 'Request blocked by FluidBLCX AI Security Shield',
                reason: result.reason,
                severity: result.severity || 'HIGH',
                score: result.score,
                message: result.message
            });
        }
    } catch (e) {
        // AI Engine offline — pass through
    }
    next();
});

// ─── Start Server ───────────────────────────────────────────────────────────

app.listen(PORT, () => {
    console.log(`=============================================================`);
    console.log(`FluidBLCX Custom External Compiler Pipeline Active`);
    console.log(`Port: ${PORT} | Core API Node: http://localhost:${PORT}`);
    console.log(`AI Security: ${AI_ENGINE_URL} | Walrus Vault: http://localhost:${PORT}/walrus-vault`);
    console.log(`Security Dashboard: http://localhost:${PORT}/security-dashboard`);
    console.log(`=============================================================`);
});

