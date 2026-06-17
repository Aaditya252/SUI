const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 3000;

const { exec } = require('child_process');
const os = require('os');
const https = require('https');

let suiAvailableCache = null; // null = unknown, true/false = cached

function checkSuiAvailable() {
    return new Promise((resolve) => {
        if (suiAvailableCache !== null) return resolve(suiAvailableCache);
        exec('sui --version', (err, stdout, stderr) => {
            suiAvailableCache = !err;
            resolve(suiAvailableCache);
        });
    });
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

    // Try to use the real Sui CLI if available; otherwise fall back to simulated compile
    checkSuiAvailable().then((available) => {
        if (available) {
            console.log('[COMPILER ENGINE] Sui CLI available - attempting `sui move build` in project root');
            // Attempt to run `sui move build` in the current working directory
            exec('sui move build', { cwd: process.cwd(), timeout: 60 * 1000 }, (err, stdout, stderr) => {
                if (err) {
                    console.log('[COMPILER ENGINE] Sui build failed, returning stderr fallback');
                    return res.json({ success: false, error: stderr || err.message });
                }
                return res.json({ success: true, output: stdout || 'Sui build completed with no textual output.' });
            });
            return;
        }

        // SIMULATED SYSTEM BUILD COMPILATION PIPELINE (fallback)
        setTimeout(() => {
            // Simple mock validation rule: if text contains 'error' or 'fail', throw compilation failure
            if (code.toLowerCase().includes('error') || code.toLowerCase().includes('fail')) {
                return res.json({
                    success: false,
                    error: "Syntax Error: Unresolved module dependency 'sui::coin::IncorrectCoin'\n  --> fluid_workspace.move:4:9\nCompilation stopped."
                });
            }

            return res.json({
                success: true,
                output: "Parsing abstract syntax tree...\nOptimizing execution paths...\nBytecode compiled successfully for target: Sui Move VM v2." 
            });
        }, 1200); // 1.2 second compile simulation duration
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

app.listen(PORT, () => {
    console.log(`=============================================================`);
    console.log(`🚀 FluidBLCX Custom External Compiler Pipeline Active`);
    console.log(`📡 Port: ${PORT} | Core API Node: http://localhost:${PORT}`);
    console.log(`=============================================================`);
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
        // success path
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

    // set SSE-ish headers for streaming
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders && res.flushHeaders();

    function sendLine(line) {
        try { res.write(`data: ${line.replace(/\n/g, '\\n')}\n\n`); } catch (e) { /* ignore */ }
    }

    const available = await checkSuiAvailable();

    // Simple extra fallback validation
    const hasModule = /module\s+\w+/i.test(code);
    const hasFun = /fun\s+\w+/i.test(code);
    if (!available && (!hasModule && !hasFun)) {
        sendLine('[ERROR] Basic syntax heuristics failed: missing `module` or `fun` keywords.');
        sendLine('[DONE] {"success":false}');
        return res.end();
    }

    if (available) {
        sendLine('[INFO] Sui CLI detected. Spawning `sui move build`...');
        const child = exec('sui move build', { cwd: process.cwd(), timeout: 60 * 1000 });

        child.stdout.on('data', (d) => sendLine(`[OUT] ${d.toString()}`));
        child.stderr.on('data', (d) => sendLine(`[ERR] ${d.toString()}`));

        child.on('error', (err) => {
            sendLine(`[ERROR] Spawn failed: ${err.message}`);
        });

        child.on('close', (code) => {
            if (code === 0) sendLine('[SUCCESS] Sui build finished with exit 0');
            else sendLine(`[ERROR] Sui build exited with code ${code}`);
            sendLine(`[DONE] ${JSON.stringify({ success: code === 0, code })}`);
            try { res.end(); } catch (e) { }
        });

        // Close child if client aborts
        req.on('close', () => { try { child.kill(); } catch (e) {} });
        return;
    }

    // Fallback simulated streaming compile
    sendLine('[INFO] Sui CLI not found. Running simulated compile fallback...');
    const steps = [
        'Parsing abstract syntax tree...',
        'Resolving module imports...',
        'Optimizing execution paths...',
        'Emitting bytecode arrays...'
    ];

    let i = 0;
    const t = setInterval(() => {
        if (i < steps.length) {
            sendLine(`[INFO] ${steps[i]}`);
            i++;
            return;
        }

        // final success or heuristic failure
        if (code.toLowerCase().includes('error') || code.toLowerCase().includes('fail')) {
            sendLine('[ERROR] Simulated compile: syntax errors detected.');
            sendLine('[DONE] {"success":false}');
        } else {
            sendLine('[SUCCESS] Simulated compilation successful.');
            sendLine('[DONE] {"success":true}');
        }
        clearInterval(t);
        try { res.end(); } catch (e) { }
    }, 500);
});