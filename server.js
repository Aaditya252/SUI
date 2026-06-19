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
            child = spawn(resolveSuiBinary(), ['move', 'build'], { cwd: tempDir, shell: false });
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
// Serve static UI files from the `ui` directory
app.use(express.static('ui'));

// Redirect root to the starting page
app.get('/', (req, res) => res.redirect('/startingpart.html'));

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

app.listen(PORT, () => {
    console.log(`=============================================================`);
    console.log(`FluidBLCX Custom External Compiler Pipeline Active`);
    console.log(`Port: ${PORT} | Core API Node: http://localhost:${PORT}`);
    console.log(`=============================================================`);
});

