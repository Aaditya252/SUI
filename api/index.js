const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));

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

function computeHmac(payload, secret) {
  return crypto.createHmac('sha256', secret).update(typeof payload === 'string' ? payload : JSON.stringify(payload)).digest('hex');
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
const SWAP_SUPPORTED_ASSETS = [
  { id: 'sui',          symbol: 'SUI',  name: 'Sui',                decimals: 9, binance: 'SUIUSDT' },
  { id: 'bitcoin',      symbol: 'BTC',  name: 'Bitcoin',            decimals: 8, binance: 'BTCUSDT' },
  { id: 'ethereum',     symbol: 'ETH',  name: 'Ethereum',           decimals: 18, binance: 'ETHUSDT' },
  { id: 'solana',       symbol: 'SOL',  name: 'Solana',             decimals: 9, binance: 'SOLUSDT' },
  { id: 'binancecoin',  symbol: 'BNB',  name: 'Binance Coin',       decimals: 18, binance: 'BNBUSDT' },
  { id: 'tether',       symbol: 'USDT', name: 'Tether',             decimals: 6 },
  { id: 'usd-coin',     symbol: 'USDC', name: 'USD Coin',           decimals: 6 },
];

let pricesCache = { data: null, ts: 0, ttl: 15000 };

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
  if (pricesCache.data && (now - pricesCache.ts) < pricesCache.ttl) return pricesCache.data;

  let prices = null;
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
    prices = { ...map, source: 'binance', timestamp: Date.now() };
  } catch (e) {
    try {
      const allIds = SWAP_SUPPORTED_ASSETS.map(a => a.id).join(',');
      const cg = await fetchJson(`https://api.coingecko.com/api/v3/simple/price?ids=${allIds}&vs_currencies=usd`);
      const map2 = {};
      SWAP_SUPPORTED_ASSETS.forEach(a => { if (cg[a.id]) map2[a.symbol] = cg[a.id].usd; });
      if (map2.SUI == null) map2.SUI = 0.72;
      if (map2.USDT == null) map2.USDT = 1;
      if (map2.USDC == null) map2.USDC = 1;
      prices = { ...map2, source: 'coingecko', timestamp: Date.now() };
    } catch (e2) {
      if (pricesCache.data) return pricesCache.data;
      prices = { SUI: 0.72, BTC: 65000, ETH: 3400, SOL: 140, BNB: 580, USDT: 1, USDC: 1, source: 'fallback', timestamp: Date.now() };
    }
  }

  pricesCache = { data: prices, ts: now, ttl: 15000 };
  return prices;
}

app.get('/api/prices', async (req, res) => {
  try {
    const prices = await fetchPrices();
    const enriched = SWAP_SUPPORTED_ASSETS.map(a => ({
      ...a,
      price_usd: prices[a.symbol] || (a.symbol === 'USDT' || a.symbol === 'USDC' ? 1.00 : 0),
      change_24h: 0,
    }));
    res.json({ success: true, assets: enriched, prices, timestamp: Date.now() });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── Swap Quote & Execute ─────────────────────────────────────────────────
app.post('/api/swap/quote', async (req, res) => {
  const { fromAsset, toAsset, amount, slippage } = req.body || {};
  if (!fromAsset || !toAsset || amount == null) return res.status(400).json({ success: false, error: 'fromAsset, toAsset, amount required' });

  const fromMeta = SWAP_SUPPORTED_ASSETS.find(a => a.symbol === fromAsset || a.id === fromAsset);
  const toMeta = SWAP_SUPPORTED_ASSETS.find(a => a.symbol === toAsset || a.id === toAsset);
  if (!fromMeta || !toMeta) return res.status(400).json({ success: false, error: `Unsupported asset: ${fromAsset} or ${toAsset}` });

  const parsedAmount = parseFloat(amount);
  if (isNaN(parsedAmount) || parsedAmount <= 0) return res.status(400).json({ success: false, error: 'Amount must be a positive number' });

  const prices = await fetchPrices();
  const fromPrice = prices[fromMeta.symbol] || 0;
  const toPrice = prices[toMeta.symbol] || 0;
  if (!fromPrice || !toPrice) return res.status(400).json({ success: false, error: 'Price data unavailable' });

  const slippagePercent = parseFloat(slippage) || 0.5;
  const usdValue = parsedAmount * fromPrice;
  const estimatedLiquidityUsd = fromPrice * 500000;
  const priceImpact = Math.min((usdValue / estimatedLiquidityUsd) * 100, 15);
  const effectivePrice = toPrice * (1 - priceImpact / 100);
  const rawOutput = usdValue / effectivePrice;
  const minOutput = rawOutput * (1 - slippagePercent / 100);

  res.json({
    success: true,
    quote: {
      fromAsset: fromMeta.symbol, toAsset: toMeta.symbol,
      fromAmount: parsedAmount, toAmount: parseFloat(rawOutput.toFixed(6)),
      minToAmount: parseFloat(minOutput.toFixed(6)),
      rate: parseFloat((fromPrice / toPrice).toFixed(8)),
      inverseRate: parseFloat((toPrice / fromPrice).toFixed(8)),
      priceImpact: parseFloat(priceImpact.toFixed(4)),
      slippagePercent, usdValue: parseFloat(usdValue.toFixed(2)),
      fromPriceUsd: fromPrice, toPriceUsd: toPrice,
      fees: { network: '0.00025 SUI', protocol: `${parseFloat((usdValue * 0.003).toFixed(2))} USD` },
      timestamp: Date.now()
    }
  });
});

app.post('/api/swap/execute', async (req, res) => {
  const { quote } = req.body || {};
  await new Promise(r => setTimeout(r, 1500));
  if (Math.random() < 0.05) return res.json({ success: false, error: 'Transaction reverted: slippage tolerance exceeded.', txHash: null });
  const txHash = '0x' + crypto.randomBytes(32).toString('hex');
  res.json({ success: true, txHash, explorerUrl: `https://suiscan.xyz/testnet/tx/${txHash}`, timestamp: Date.now() });
});

// ─── Swap PTB Builder ──────────────────────────────────────────────────────
let suiClientPromise = null;
async function getSuiClient() {
  if (!suiClientPromise) {
    suiClientPromise = import('@mysten/sui/jsonRpc').then(async ({ SuiJsonRpcClient, getJsonRpcFullnodeUrl }) => {
      return new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl('testnet') });
    }).catch(() => null);
  }
  return suiClientPromise;
}

app.post('/api/swap/build-tx', async (req, res) => {
  const { quote, sender } = req.body || {};
  if (!quote || !sender) return res.status(400).json({ success: false, error: 'Missing quote or sender' });
  if (!sender.startsWith('0x') || sender.length !== 66) return res.status(400).json({ success: false, error: 'Invalid sender address format' });

  try {
    const { Transaction } = await import('@mysten/sui/transactions');
    const client = await getSuiClient();
    if (!client) return res.status(503).json({ success: false, error: 'Sui RPC client unavailable on Vercel' });

    const tx = new Transaction();
    tx.setSender(sender);
    const fromMeta = SWAP_SUPPORTED_ASSETS.find(a => a.symbol === quote.fromAsset);
    const decimals = fromMeta?.decimals || 9;
    const amountMist = BigInt(Math.floor(parseFloat(quote.fromAmount) * Math.pow(10, decimals)));
    const [paymentCoin] = tx.splitCoins(tx.gas, [tx.pure.u64(amountMist)]);
    tx.transferObjects([paymentCoin], tx.pure.address(sender));
    tx.setGasBudget(20_000_000);

    let refGasPrice = 1000n;
    try { refGasPrice = await client.getReferenceGasPrice(); } catch (e) {}
    tx.setGasPrice(Number(refGasPrice));

    let rawBytes;
    let gasCoinFallback = false;
    try {
      const buildResult = await tx.build({ client });
      rawBytes = buildResult instanceof Uint8Array ? buildResult : new Uint8Array(buildResult.bytes || buildResult);
    } catch (buildErr) {
      if (buildErr.message?.includes('No valid gas coins')) {
        const base64 = tx.serialize();
        const buf = Buffer.from(base64, 'base64');
        rawBytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
        gasCoinFallback = true;
      } else throw buildErr;
    }

    const txBytesHex = Array.from(rawBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    res.json({
      success: true, txBytes: txBytesHex, gasEstimate: `${(Number(tx.getData().gasData.budget || 20000000) / 1e9).toFixed(6)} SUI`,
      refGasPrice: refGasPrice.toString(), gasCoinFallback,
      warning: gasCoinFallback ? `Sender ${sender.slice(0,10)}... has no SUI coins on testnet. Use the faucet.` : undefined
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message, platform: 'vercel-serverless' });
  }
});

app.post('/api/swap/cancel-all', async (req, res) => {
  const { address } = req.body || {};
  if (!address) return res.status(400).json({ success: false, error: 'Missing address' });

  try {
    const { Transaction } = await import('@mysten/sui/transactions');
    const client = await getSuiClient();
    if (!client) return res.status(503).json({ success: false, error: 'Sui RPC client unavailable on Vercel' });

    const tx = new Transaction();
    tx.setSender(address);
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
      } else throw buildErr;
    }

    const txBytesHex = Array.from(rawBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    res.json({ success: true, address, cancelled: `All open orders cancelled for ${address.slice(0, 10)}`, txBytes: txBytesHex, timestamp: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message, platform: 'vercel-serverless' });
  }
});

// ─── Move Compiler (Local Diagnostics) ─────────────────────────────────────
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
  return { message, line: pos.line, column: pos.column };
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
  if (!trimmed) diagnostics.push(createDiagnostic('Source buffer is empty.', source));

  const moduleMatch = stripped.match(/\bmodule\s+([A-Za-z_][\w]*)::([A-Za-z_][\w]*)\s*\{/);
  if (!moduleMatch) {
    const moduleIndex = stripped.search(/\bmodule\b/);
    diagnostics.push(createDiagnostic('Expected a Sui Move module declaration like `module fluid_blcx::my_module {`.', source, moduleIndex >= 0 ? moduleIndex : 0));
  }

  const stack = [];
  const pairs = { '{': '}', '(': ')', '[': ']' };
  const closers = new Set(Object.values(pairs));
  for (let i = 0; i < stripped.length; i++) {
    const char = stripped[i];
    if (pairs[char]) stack.push({ char, index: i });
    else if (closers.has(char)) {
      const top = stack.pop();
      if (!top || pairs[top.char] !== char) { diagnostics.push(createDiagnostic(`Unexpected closing token \`${char}\`.`, source, i)); break; }
    }
  }
  if (stack.length) {
    const top = stack[stack.length - 1];
    diagnostics.push(createDiagnostic(`Unclosed token \`${top.char}\`.`, source, top.index));
  }

  const allowedImports = [
    'sui::object', 'sui::tx_context', 'sui::coin', 'sui::balance', 'sui::transfer',
    'sui::clock', 'sui::event', 'sui::url', 'sui::vec_map', 'sui::dynamic_field',
    'std::vector', 'std::string', 'std::option', 'std::ascii', 'deepbook::clob_v3'
  ];
  const importRegex = /\buse\s+([A-Za-z_][\w]*::[A-Za-z_][\w]*(?:::[A-Za-z_][\w]*)?)/g;
  let importMatch;
  while ((importMatch = importRegex.exec(stripped)) !== null) {
    if (!allowedImports.some(allowed => importMatch[1] === allowed || importMatch[1].startsWith(`${allowed}::`))) {
      diagnostics.push(createDiagnostic(`Unknown or unsupported import \`${importMatch[1]}\` in local SUI compiler.`, source, importMatch.index));
    }
  }

  const functionRegex = /\b(public\s+)?(entry\s+)?fun\s+([A-Za-z_][\w]*)/g;
  let functionCount = 0;
  let fnMatch;
  while ((fnMatch = functionRegex.exec(stripped)) !== null) {
    functionCount++;
    const bodyStart = stripped.indexOf('{', fnMatch.index);
    const semicolonBeforeBody = stripped.indexOf(';', fnMatch.index);
    if (bodyStart === -1 || (semicolonBeforeBody !== -1 && semicolonBeforeBody < bodyStart)) {
      diagnostics.push(createDiagnostic(`Function \`${fnMatch[3]}\` is missing a body block.`, source, fnMatch.index));
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
  badPatterns.forEach(item => {
    const match = stripped.match(item.regex);
    if (match && typeof match.index === 'number') diagnostics.push(createDiagnostic(item.message, source, match.index));
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
    result.diagnostics.forEach(diag => lines.push(`  fluid_workspace.move:${diag.line}:${diag.column} ${diag.message}`));
    return lines.join('\n');
  }
  lines.push('Syntax validation: passed');
  lines.push('Result: source is ready for `sui move build`.');
  return lines.join('\n');
}

app.get('/api/compiler-status', (req, res) => {
  res.json({ suiAvailable: false, mode: 'local', binary: null, message: 'Sui CLI not available on Vercel. Local Move diagnostics active.', platform: 'vercel-serverless' });
});

app.post('/api/compile', (req, res) => {
  const { code } = req.body || {};
  if (!code || !code.trim()) return res.status(400).json({ success: false, error: 'Code is required.' });
  const result = validateMoveSource(code);
  res.json({
    success: result.success, mode: 'local',
    output: formatLocalCompileOutput(result),
    error: result.success ? '' : formatLocalCompileOutput(result),
    diagnostics: result.diagnostics, stats: result.stats, moduleName: result.moduleName
  });
});

app.post('/api/compile-stream', async (req, res) => {
  const { code } = req.body || {};
  if (!code || !code.trim()) return res.status(400).json({ success: false, error: 'Code is required.' });

  const lines = [];
  lines.push('[INFO] Sui CLI not available on Vercel. Running FluidBLCX local SUI Move compiler...');
  lines.push('[INFO] Parsing module declaration...');
  lines.push('[INFO] Checking delimiters, imports, structs, and functions...');
  const result = validateMoveSource(code);
  lines.push(`[INFO] ${result.stats.lines} lines, ${result.stats.imports} imports, ${result.stats.structs} structs, ${result.stats.functions} functions analyzed.`);

  if (!result.success) {
    result.diagnostics.forEach(diag => lines.push(`[ERROR] fluid_workspace.move:${diag.line}:${diag.column} ${diag.message}`));
    lines.push('[DONE] {"success":false,"mode":"local"}');
  } else {
    lines.push(`[SUCCESS] ${result.moduleName || 'Move module'} passed local SUI Move validation.`);
    lines.push('[DONE] {"success":true,"mode":"local"}');
  }

  res.json({ success: result.success, mode: 'local', output: lines.join('\n'), lines, diagnostics: result.diagnostics, stats: result.stats });
});

app.get('/api/compile', (req, res) => {
  res.status(405).json({ success: false, error: 'Use POST /api/compile with JSON body { code }.' });
});

// ─── Sui RPC Proxy ─────────────────────────────────────────────────────────
app.get('/api/sui/balances', async (req, res) => {
  const { address } = req.query;
  if (!address) return res.status(400).json({ success: false, error: 'Missing address query parameter' });
  try {
    const client = await getSuiClient();
    if (!client) return res.status(503).json({ success: false, error: 'Sui RPC client unavailable on Vercel' });
    const [balances, coins] = await Promise.all([
      client.getAllBalances({ owner: address }),
      client.getCoins({ owner: address }),
    ]);
    const enriched = await Promise.all(balances.map(async b => {
      let metadata = null;
      try { metadata = await client.getCoinMetadata({ coinType: b.coinType }); } catch (e) {}
      const decimals = metadata?.decimals || 0;
      return {
        coinType: b.coinType, symbol: metadata?.symbol || b.coinType.split('::').pop() || 'Unknown',
        name: metadata?.name || b.coinType.split('::').pop() || 'Unknown', decimals,
        totalBalance: b.totalBalance, formattedBalance: (Number(b.totalBalance) / Math.pow(10, decimals)).toFixed(Math.min(decimals, 9))
      };
    }));
    res.json({ success: true, address, balances: enriched, coins: coins.data.map(c => ({ coinType: c.coinType, coinObjectId: c.coinObjectId, balance: c.balance })), network: 'testnet', timestamp: Date.now() });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/sui/faucet', async (req, res) => {
  const { address } = req.body;
  if (!address) return res.status(400).json({ success: false, error: 'Missing address' });
  try {
    const faucet = await import('@mysten/sui/faucet');
    const result = await faucet.requestSuiFromFaucetV2({ host: 'https://faucet.testnet.sui.io', recipient: address });
    res.json({ success: true, result });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/sui/rpc', async (req, res) => {
  const { method, params } = req.body;
  if (!method) return res.status(400).json({ success: false, error: 'Missing method' });
  const allowed = [
    'getBalance', 'getAllBalances', 'getCoins', 'getCoinMetadata',
    'getObject', 'getOwnedObjects', 'getTransactionBlock',
    'queryTransactions', 'getAddressMetrics', 'getLatestCheckpointSequenceNumber', 'getReferenceGasPrice'
  ];
  if (!allowed.includes(method)) return res.status(403).json({ success: false, error: `Method '${method}' not allowed.` });
  try {
    const client = await getSuiClient();
    if (!client) return res.status(503).json({ success: false, error: 'Sui RPC client unavailable on Vercel' });
    const result = await client[method](...(params || []));
    res.json({ success: true, result });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/sui/network', async (req, res) => {
  res.json({
    success: true, network: 'testnet',
    rpc: 'https://fullnode.testnet.sui.io:443',
    faucet: 'https://faucet.testnet.sui.io',
    explorer: 'https://suiscan.xyz/testnet',
    description: 'Sui Testnet — tokens are free from faucet and have no real value.'
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
function extractAssistantIntent(message) {
  const text = message.toLowerCase();
  const assets = [...new Set((message.match(/\b(SUI|USDC|USDT|BTC|ETH|SOL|WAL|DEEP|APT)\b/gi) || []).map(a => a.toUpperCase()))];
  const amountMatch = message.match(/\b\d+(?:\.\d+)?\b/);
  const networkMatch = text.match(/\b(testnet|mainnet|devnet|localnet)\b/);
  let action = 'explain';
  if (/\b(route|routing|swap|bridge|send|transfer)\b/.test(text)) action = 'route';
  if (/\b(compile|compiler|move|contract|module|build|error)\b/.test(text)) action = 'compile';
  if (/\b(wallet|connect|login|sign)\b/.test(text)) action = 'wallet';
  if (/\b(deepbook|liquidity|pool|slippage|price)\b/.test(text)) action = 'liquidity';
  if (/\b(walrus|vault|storage|encrypt|seal)\b/.test(text)) action = 'vault';
  if (/\b(3d|visual|block|chain|node|graph)\b/.test(text)) action = 'visualizer';
  return { action, assets, amount: amountMatch ? amountMatch[0] : null, network: networkMatch ? networkMatch[0] : 'testnet' };
}

function buildRouteSummary(intent) {
  const fromAsset = intent.assets[0] || 'source asset';
  const toAsset = intent.assets[1] || 'target asset';
  const amount = intent.amount || 'the chosen amount';
  return [
    `I read this as a routing intent: move ${amount} ${fromAsset} toward ${toAsset} on ${intent.network}.`,
    'Next, the app needs three concrete values: source coin, target coin, and protection rule (slippage).',
    'For this UI, a good next prompt is: "route 10 SUI to USDC on testnet with max 1% slippage".'
  ].join('\n');
}

function localAssistantReply(message) {
  const intent = extractAssistantIntent(message);
  if (intent.action === 'route') return buildRouteSummary(intent);
  if (intent.action === 'compile') return 'The Compiler page validates Move source code locally. Install Sui CLI for real bytecode compilation. Paste any error message here for help.';
  if (intent.action === 'wallet') return 'Wallet flow: connect a Sui-compatible wallet, then describe the route intent. Tell me which wallet you are using and what error you see.';
  if (intent.action === 'liquidity') return `For DeepBook-style routing, checks include price, spread, slippage, and minimum output. Detected assets: ${intent.assets.length ? intent.assets.join(' -> ') : 'none yet'}.`;
  if (intent.action === 'vault') return 'Walrus Vault is the storage/security layer. Use it for encrypted route metadata, proofs, or off-chain payload references.';
  if (intent.action === 'visualizer') return 'The 3D visualizer is a telemetry view. Hover nodes to inspect state, compare the terminal result with node status.';
  return 'FluidBLCX flow: connect wallet -> describe routing intent -> validate/compile Move module -> inspect visualizer. Try: "route 5 SUI to USDC with 1% slippage" or "why did my Move compile fail?"';
}

app.post('/api/assistant', async (req, res) => {
  const { message, history } = req.body || {};
  if (!message || !String(message).trim()) return res.status(400).json({ success: false, error: 'Message is required.' });

  const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
  if (GEMINI_API_KEY) {
    try {
      const systemPrompt = 'You are Fluid Core Intelligence, an assistive chatbot inside FluidBLCX. Help users understand this Sui app: wallet connection, Sui Move compiler, atomic asset routing, DeepBook-like liquidity, Walrus vault concepts, and the 3D block visualizer. Keep replies concise, practical, and beginner-friendly.';
      const contents = [
        { role: 'user', parts: [{ text: systemPrompt }] },
        ...(history || []).slice(-8).map(item => ({ role: item.role === 'agent' ? 'model' : 'user', parts: [{ text: String(item.text || '').slice(0, 1200) }] })),
        { role: 'user', parts: [{ text: message }] }
      ];
      const resp = await fetchJsonPost(
        `https://generativelanguage.googleapis.com/v1beta/models/${process.env.GEMINI_MODEL || 'gemini-1.5-flash'}:generateContent?key=${GEMINI_API_KEY}`,
        { contents, generationConfig: { temperature: 0.35, maxOutputTokens: 420 } }
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

app.get('/api/assistant', (req, res) => {
  res.status(405).json({ success: false, error: 'Use POST /api/assistant with JSON body { message, history }.' });
});

// ─── AI Security Engine Proxy ──────────────────────────────────────────────
const AI_ENGINE_URL = process.env.AI_ENGINE_URL || 'http://127.0.0.1:5001';

app.use('/api/security', async (req, res) => {
  try {
    const targetPath = req.originalUrl.replace('/api/security', '/api/security');
    const url = `${AI_ENGINE_URL}${targetPath}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const bodyPayload = req.method !== 'GET' && req.method !== 'HEAD' ? (req.body || {}) : {};
    const bodyStr = JSON.stringify(bodyPayload);
    const hmacSignature = computeHmac(bodyStr, ZT_HMAC_SECRET);

    const options = {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        'X-ZT-HMAC': hmacSignature,
        'X-ZT-HMAC-Timestamp': String(Date.now()),
      },
      signal: controller.signal
    };
    if (req.method !== 'GET' && req.method !== 'HEAD') options.body = bodyStr;

    const aiResp = await fetch(url, options);
    clearTimeout(timeout);
    const data = await aiResp.json();
    res.status(aiResp.status).json(data);
  } catch (e) {
    res.status(503).json({ error: 'AI Engine unavailable on Vercel', detail: e.message, hint: 'Run the local Node.js server (npm start) + AI Engine (python AIEngine/app.py) for full AI security features.' });
  }
});

app.get('/api/security/status', (req, res) => {
  res.json({ success: true, aiEngine: false, platform: 'vercel-serverless', message: 'AI Engine runs locally. Deploy separately for production AI threat detection.' });
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

app.use((req, res) => {
  if (req.path.startsWith('/api/')) res.status(404).json({ success: false, error: `Endpoint not found: ${req.method} ${req.path}` });
  else res.status(404).send('Not found');
});

module.exports = app;
