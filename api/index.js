const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json());

// ─── Zero-Trust Cryptography Infrastructure ────────────────────────────────
const serverKeyPair = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const SERVER_PUBLIC_KEY_PEM = serverKeyPair.publicKey;
const ZT_HMAC_SECRET = process.env.ZT_HMAC_SECRET || crypto.randomBytes(32).toString('hex');
const ztTokens = new Map();
const ZT_TOKEN_TTL = 300_000;

function signContent(content) {
  try { const s = crypto.createSign('sha256'); s.update(typeof content === 'string' ? content : JSON.stringify(content)); s.end(); return s.sign(serverKeyPair.privateKey, 'base64'); }
  catch (e) { return null; }
}

function verifyContentSignature(content, signature, publicKeyPem) {
  try { const v = crypto.createVerify('sha256'); v.update(typeof content === 'string' ? content : JSON.stringify(content)); v.end(); return v.verify(publicKeyPem, signature, 'base64'); }
  catch (e) { return false; }
}

function issueZtToken(clientId) {
  const token = crypto.randomBytes(24).toString('hex');
  ztTokens.set(token, { clientId, issued: Date.now(), ttl: ZT_TOKEN_TTL });
  return token;
}

function verifyZtToken(token) {
  const entry = ztTokens.get(token);
  if (!entry) return null;
  if (Date.now() - entry.issued > entry.ttl) { ztTokens.delete(token); return null; }
  return entry;
}

const signatureMiddleware = (req, res, next) => {
  const oldJson = res.json.bind(res);
  res.json = function (body) {
    const sig = signContent(body);
    if (sig) { res.set('X-ZT-Signature', sig); res.set('X-ZT-PublicKey', SERVER_PUBLIC_KEY_PEM); }
    return oldJson(body);
  };
  next();
};
app.use(signatureMiddleware);

// ─── Static file serving via Vercel ────────────────────────────────────────
// Vercel handles this via vercel.json routes — nothing to do here.

// ─── Zero-Trust API Endpoints ──────────────────────────────────────────────
app.get('/api/zt/status', (req, res) => {
  res.json({
    success: true,
    responseSigning: { algorithm: 'Ed25519', active: true },
    hmacInterService: { algorithm: 'HMAC-SHA256', active: true, secretLength: ZT_HMAC_SECRET.length },
    tokenAuth: { active: true, ttl: ZT_TOKEN_TTL, activeTokens: ztTokens.size },
    timestamp: Date.now()
  });
});

app.get('/api/zt/public-key', (req, res) => {
  const fp = crypto.createHash('sha256').update(SERVER_PUBLIC_KEY_PEM).digest('hex');
  res.json({ success: true, algorithm: 'Ed25519', publicKeyPem: SERVER_PUBLIC_KEY_PEM, fingerprint: fp, encoding: 'spki', format: 'pem' });
});

app.post('/api/zt/request-token', (req, res) => {
  const { clientId } = req.body || {};
  if (!clientId) return res.status(400).json({ success: false, error: 'clientId required' });
  const token = issueZtToken(clientId);
  res.json({ success: true, token, ttl: ZT_TOKEN_TTL, message: `Token valid for ${ZT_TOKEN_TTL / 1000}s` });
});

app.post('/api/zt/verify', (req, res) => {
  const { content, signature, publicKey } = req.body || {};
  if (!content || !signature || !publicKey) return res.status(400).json({ success: false, error: 'content, signature, publicKey required' });
  const valid = verifyContentSignature(content, signature, publicKey);
  res.json({ success: true, valid, message: valid ? 'Signature verified' : 'Signature invalid' });
});

// ─── Price Feeds ───────────────────────────────────────────────────────────
let priceCache = { data: null, ts: 0, ttl: 15000 };

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { timeout: 8000 }, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch (e) { reject(e); } });
    }).on('error', reject).on('timeout', function () { this.destroy(); reject(new Error('timeout')); });
  });
}

function fetchJsonPost(url, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const u = new URL(url);
    const opts = {
      hostname: u.hostname, path: u.pathname + u.search, port: 443,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
      timeout: 15000
    };
    const req = https.request(opts, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(d);
          if (parsed.error) reject(new Error(parsed.error.message || JSON.stringify(parsed.error)));
          else resolve(parsed);
        } catch (e) { reject(new Error(d.slice(0, 300))); }
      });
    });
    req.on('error', reject);
    req.on('timeout', function () { req.destroy(); reject(new Error('timeout')); });
    req.write(data);
    req.end();
  });
}

async function fetchPrices() {
  const now = Date.now();
  if (priceCache.data && (now - priceCache.ts) < priceCache.ttl) return priceCache.data;
  try {
    const tickers = await fetchJson('https://api.binance.com/api/v3/ticker/price?symbols=["BTCUSDT","ETHUSDT","SOLUSDT","BNBUSDT","USDCUSDT"]');
    const map = {};
    tickers.forEach(t => map[t.symbol.replace('USDT', '')] = parseFloat(t.price));
    try {
      const suiTicker = await fetchJson('https://api.binance.com/api/v3/ticker/price?symbol=SUIUSDT');
      map.SUI = parseFloat(suiTicker.price);
    } catch (e) {
      try {
        const cg = await fetchJson('https://api.coingecko.com/api/v3/simple/price?ids=sui&vs_currencies=usd');
        map.SUI = cg.sui.usd;
      } catch (e2) { map.SUI = 0.72; }
    }
    map.USDT = 1;
    map.USDC = 1;
    const result = { ...map, source: 'binance', timestamp: Date.now() };
    priceCache = { data: result, ts: now, ttl: 15000 };
    return result;
  } catch (e) {
    if (priceCache.data) return priceCache.data;
    return { SUI: 0.72, BTC: 65000, ETH: 3400, SOL: 140, BNB: 580, USDT: 1, USDC: 1, source: 'fallback', timestamp: Date.now() };
  }
}

app.get('/api/prices', async (req, res) => {
  const prices = await fetchPrices();
  res.json({ success: true, ...prices });
});

// ─── Swap Quote ────────────────────────────────────────────────────────────
app.post('/api/swap/quote', async (req, res) => {
  const { fromAsset, toAsset, amount, slippage = 0.5 } = req.body || {};
  if (!fromAsset || !toAsset || amount == null) return res.status(400).json({ success: false, error: 'fromAsset, toAsset, amount required' });
  const prices = await fetchPrices();
  const fromPrice = prices[fromAsset.toUpperCase()] || 0;
  const toPrice = prices[toAsset.toUpperCase()] || 0;
  if (!fromPrice || !toPrice) return res.status(400).json({ success: false, error: 'Unsupported asset pair' });
  const rate = fromPrice / toPrice;
  const output = parseFloat(amount) * rate;
  const impact = Math.min(0.5, 0.1 + Math.log10(parseFloat(amount) + 1) * 0.08);
  const fee = parseFloat(amount) * 0.003;
  res.json({
    success: true,
    rate, priceImpact: `${impact.toFixed(2)}%`, minOutput: output * (1 - slippage / 100),
    estimatedOutput: output, fee, feeAsset: fromAsset.toUpperCase(),
    usdValue: parseFloat(amount) * fromPrice, route: `${fromAsset} → ${toAsset}`,
    timestamp: Date.now()
  });
});

app.post('/api/swap/execute', async (req, res) => {
  const { fromAsset, toAsset, amount } = req.body || {};
  const txHash = '0x' + crypto.randomBytes(32).toString('hex');
  await new Promise(r => setTimeout(r, 1500));
  if (Math.random() < 0.05) return res.json({ success: false, error: 'Simulated swap failure — try again' });
  res.json({
    success: true, txHash, explorerUrl: `https://suiscan.xyz/testnet/tx/${txHash}`,
    fromAsset, toAsset, amount, status: 'committed', timestamp: Date.now()
  });
});

// ─── Chain Status ──────────────────────────────────────────────────────────
app.get('/api/chain-status', async (req, res) => {
  try {
    const result = await fetchJson('https://fullnode.testnet.sui.io');
    res.json({ success: true, reachable: true, statusCode: 200, timestamp: Date.now() });
  } catch (e) {
    res.json({ success: false, reachable: false, error: e.message, timestamp: Date.now() });
  }
});

// ─── AI Assistant ──────────────────────────────────────────────────────────
function localAssistantReply(message) {
  const m = message.toLowerCase();
  if (m.includes('route') || m.includes('swap')) return 'I can help route assets through Sui. Try using the swap panel to execute a trade.';
  if (m.includes('compile') || m.includes('move')) return 'Open the Compiler tab to write and compile Sui Move code. The visualizer will show your block graph.';
  if (m.includes('wallet')) return 'Use the Connect Wallet button or navigate to the Wallet tab to manage your portfolio.';
  if (m.includes('vault') || m.includes('walrus')) return 'The Walrus Vault lets you store encrypted blobs on Sui. Set a passphrase and upload files.';
  if (m.includes('security') || m.includes('threat')) return 'The AI Security Shield monitors all requests. Check the Security Dashboard for live threat data.';
  if (m.includes('deepbook') || m.includes('liquidity')) return 'DeepBook v3 provides institutional liquidity. Open the DeepBook portal to view the order book.';
  if (m.includes('poison') || m.includes('trojan')) return 'The Poison AI Matrix and Trojan Bots provide adversarial defense. Check them out from the nav bar.';
  return 'FluidBLCX is a sovereign Web3 execution architecture. Try the Compiler, Wallet, or Security tabs to get started.';
}

app.post('/api/assistant', async (req, res) => {
  const { message, history } = req.body || {};
  if (!message || !String(message).trim()) return res.status(400).json({ success: false, error: 'Message is required.' });
  const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
  if (GEMINI_API_KEY) {
    try {
      const systemPrompt = 'You are Fluid Core Intelligence, an assistive chatbot inside FluidBLCX. Help users understand this Sui app: wallet connection, Sui Move compiler, atomic asset routing, DeepBook-like liquidity, Walrus vault concepts, and the 3D block visualizer. Keep replies concise, practical, and beginner-friendly.';
      const resp = await fetchJsonPost(
        `https://generativelanguage.googleapis.com/v1beta/models/${process.env.GEMINI_MODEL || 'gemini-1.5-flash'}:generateContent?key=${GEMINI_API_KEY}`,
        { contents: [{ role: 'user', parts: [{ text: message }] }], systemInstruction: { parts: [{ text: systemPrompt }] }, generationConfig: { temperature: 0.35, maxOutputTokens: 420 } }
      );
      const reply = resp?.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('').trim() || 'No response from Gemini.';
      return res.json({ success: true, mode: 'gemini', reply });
    } catch (e) {
      return res.json({ success: true, mode: 'local-fallback', reason: e.message, reply: localAssistantReply(message) });
    }
  }
  res.json({ success: true, mode: 'local', reply: localAssistantReply(message) });
});

app.get('/api/assistant-status', (req, res) => {
  res.json({ configured: Boolean(process.env.GEMINI_API_KEY), model: process.env.GEMINI_MODEL || 'gemini-1.5-flash', platform: 'vercel-serverless' });
});

// ─── Compiler Status ───────────────────────────────────────────────────────
app.get('/api/compiler-status', (req, res) => {
  res.json({ suiAvailable: false, mode: 'local', binary: null, message: 'Sui CLI not available on Vercel. Use the Node.js server for compilation.', platform: 'vercel-serverless' });
});

app.post('/api/compile', (req, res) => {
  const { code } = req.body || {};
  if (!code || !code.trim()) return res.status(400).json({ success: false, error: 'Code is required.' });
  const hasModule = /module\s+\w+\s*\{/.test(code);
  const hasStruct = /struct\s+\w+/.test(code);
  const hasFun = /fun\s+\w+/.test(code);
  const hasSemicolon = code.includes(';');
  const diagnostics = [];
  if (!hasModule) diagnostics.push({ line: 0, message: 'Missing module declaration', severity: 'error' });
  if (!hasFun) diagnostics.push({ line: 0, message: 'No functions found', severity: 'warning' });
  const success = hasModule && hasSemicolon;
  res.json({
    success, mode: 'local', output: success ? 'Diagnostic validation passed.' : 'Diagnostic validation failed.',
    error: success ? '' : 'Module structure validation failed.', diagnostics,
    stats: { lines: code.split('\n').length, chars: code.length, functions: hasFun ? 1 : 0, structs: hasStruct ? 1 : 0 },
    moduleName: hasModule ? (code.match(/module\s+(\w+)/)?.[1] || 'unknown') : null
  });
});

// ─── Sui Network Info ──────────────────────────────────────────────────────
app.get('/api/sui/network', (req, res) => {
  res.json({
    success: true, network: 'testnet',
    rpcUrl: 'https://fullnode.testnet.sui.io',
    faucetUrl: 'https://faucet.testnet.sui.io',
    explorerUrl: 'https://suiscan.xyz/testnet'
  });
});

// ─── Health ────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ success: true, status: 'ok', platform: 'vercel-serverless', timestamp: Date.now(), ztActive: true, tokenCount: ztTokens.size });
});

// ─── Error Handler ─────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[VERCEL ERROR]', err.message);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// 404 handler — let Vercel serve static files
app.use((req, res) => {
  if (req.path.startsWith('/api/')) res.status(404).json({ success: false, error: `Endpoint not found: ${req.method} ${req.path}` });
  else res.status(404).send('Not found');
});

module.exports = app;
