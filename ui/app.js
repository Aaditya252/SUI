/**
 * Sui Agent PTB - App Controller
 * Manages UI interactivity, live order book tickers, SVG path calculations, and dry run loops.
 */

document.addEventListener('DOMContentLoaded', () => {

  // --- STATE ---
  let activePtb = null;
  let isExecuting = false;
  let suiPrice = 1.1824;
  let orderbookData = { bids: [], asks: [] };

  // --- DOM ELEMENTS ---
  const intentInput = document.getElementById('intent-input');
  const btnParse = document.getElementById('btn-parse');
  const btnClear = document.getElementById('btn-clear');
  const btnDryRun = document.getElementById('btn-dry-run');
  const charCounter = document.getElementById('char-count');
  const emptyState = document.getElementById('empty-state');
  const nodesContainer = document.getElementById('nodes-container');
  const termWindow = document.getElementById('term-window');
  const termStatus = document.getElementById('term-status');
  const agentStatus = document.getElementById('agent-status');
  const suiPriceMetric = document.getElementById('sui-price-metric');
  const suiSpreadMetric = document.getElementById('sui-spread-metric');
  const orderbookBody = document.getElementById('orderbook-body');
  const codePreview = document.getElementById('code-preview');
  const svgConnections = document.getElementById('svg-connections');
  const graphWrapper = document.getElementById('graph-wrapper');

  const colInputs = document.getElementById('col-inputs');
  const colGuardrails = document.getElementById('col-guardrails');
  const colCommands = document.getElementById('col-commands');
  const colOutputs = document.getElementById('col-outputs');

  // --- INITIALIZATION ---
  initOrderbook();
  updateOrderbookUI();
  
  // Update order book prices periodically
  setInterval(tickOrderbook, 2000);

  // Character limit counter
  intentInput.addEventListener('input', () => {
    const len = intentInput.value.length;
    charCounter.textContent = `${len} / 300`;
    if (len > 300) {
      charCounter.style.color = 'var(--cyber-pink)';
    } else {
      charCounter.style.color = 'var(--text-muted)';
    }
  });

  // Clear button
  btnClear.addEventListener('click', () => {
    intentInput.value = '';
    charCounter.textContent = '0 / 300';
    charCounter.style.color = 'var(--text-muted)';
    resetPTBView();
  });

  // Preset scenarios click
  document.querySelectorAll('.preset-item').forEach(item => {
    item.addEventListener('click', () => {
      intentInput.value = item.getAttribute('data-intent');
      charCounter.textContent = `${intentInput.value.length} / 300`;
      compileIntent();
    });
  });

  // Compile button
  btnParse.addEventListener('click', compileIntent);

  // Dry Run button
  btnDryRun.addEventListener('click', executeDryRun);

  // Redraw SVG wires when window resizes
  window.addEventListener('resize', () => {
    if (activePtb) {
      drawConnections();
    }
  });


  // --- PARSE & RENDER LOGIC ---
  function compileIntent() {
    const text = intentInput.value.trim();
    if (text === '') {
      addTerminalLine('system', 'Error: Please enter a financial intent or select a preset.');
      return;
    }

    addTerminalLine('info', 'Analyzing input intent string...');
    
    // Parse natural language
    const parsed = IntentParser.parse(text);
    if (!parsed) {
      addTerminalLine('err', 'Failed to parse. Please try a different scenario.');
      return;
    }

    // Build PTB Graph
    activePtb = PtbBuilder.buildPTB(parsed);
    
    // Render PTB
    renderPTB(activePtb);

    // Update dynamic metric metrics based on compiled actions
    const walrusNodesMetric = document.getElementById('walrus-nodes-metric');
    const safeguardMetric = document.getElementById('safeguard-metric');

    const hasWalrus = parsed.actions.some(a => a.type === 'WALRUS_STORE');
    if (hasWalrus) {
      walrusNodesMetric.textContent = '150 Nodes (Online)';
      walrusNodesMetric.style.color = 'var(--cyber-green)';
    } else {
      walrusNodesMetric.textContent = 'Inactive';
      walrusNodesMetric.style.color = 'var(--text-muted)';
    }

    const marginGuard = parsed.guardrails.find(g => g.type === 'MARGIN_RISK_CHECK');
    if (marginGuard) {
      safeguardMetric.textContent = `${marginGuard.limit} Target`;
      safeguardMetric.style.color = 'var(--cyber-pink)';
    } else {
      safeguardMetric.textContent = 'Inactive';
      safeguardMetric.style.color = 'var(--text-muted)';
    }
    
    btnDryRun.removeAttribute('disabled');
    addTerminalLine('success', `Intents successfully compiled! Simulated gas cost: ${activePtb.gasEstimate}. Ready for dry-run.`);
  }

  function renderPTB(ptb) {
    // Hide empty state, show columns
    emptyState.style.display = 'none';
    nodesContainer.style.display = 'flex';

    // Clear column HTML (keep headers)
    clearColumn(colInputs);
    clearColumn(colGuardrails);
    clearColumn(colCommands);
    clearColumn(colOutputs);

    // Render nodes
    ptb.nodes.forEach(node => {
      const card = createNodeCard(node);
      if (node.column === 'inputs') colInputs.appendChild(card);
      if (node.column === 'guardrails') colGuardrails.appendChild(card);
      if (node.column === 'commands') colCommands.appendChild(card);
      if (node.column === 'outputs') colOutputs.appendChild(card);
    });

    // Render guardrail code block
    codePreview.innerHTML = ptb.moveCode;

    // Draw connecting vectors (timeout to allow browser layout compute)
    setTimeout(drawConnections, 50);
  }

  function clearColumn(col) {
    const header = col.querySelector('.preset-header');
    col.innerHTML = '';
    if (header) col.appendChild(header);
  }

  function createNodeCard(node) {
    const card = document.createElement('div');
    card.className = `node-card node-${node.type}`;
    card.id = `node-dom-${node.id}`;

    // Header
    const header = document.createElement('div');
    header.className = 'node-header';
    header.innerHTML = `<span>${node.icon}</span> <span>${node.title}</span>`;
    card.appendChild(header);

    // Title
    const title = document.createElement('div');
    title.className = 'node-title';
    title.textContent = node.id;
    card.appendChild(title);

    // Details / Params
    for (const [key, value] of Object.entries(node.details)) {
      const det = document.createElement('div');
      det.className = 'node-details';
      det.innerHTML = `<span>${key}:</span> <span>${value}</span>`;
      card.appendChild(det);
    }

    return card;
  }

  // --- DRAW CONNECTIONS (SVG PATHS) ---
  function drawConnections() {
    // Clear old lines
    const paths = svgConnections.querySelectorAll('path');
    paths.forEach(p => p.remove());

    if (!activePtb || activePtb.connections.length === 0) return;

    const wrapperRect = graphWrapper.getBoundingClientRect();

    activePtb.connections.forEach(conn => {
      const fromEl = document.getElementById(`node-dom-${conn.from}`);
      const toEl = document.getElementById(`node-dom-${conn.to}`);

      if (!fromEl || !toEl) return;

      const fromRect = fromEl.getBoundingClientRect();
      const toRect = toEl.getBoundingClientRect();

      // Coordinates relative to wrapper container
      const startX = fromRect.right - wrapperRect.left;
      const startY = (fromRect.top + fromRect.bottom) / 2 - wrapperRect.top;
      
      const endX = toRect.left - wrapperRect.left;
      const endY = (toRect.top + toRect.bottom) / 2 - wrapperRect.top;

      // Draw beautiful bezier line
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      const controlX1 = startX + 50;
      const controlY1 = startY;
      const controlX2 = endX - 50;
      const controlY2 = endY;

      const d = `M ${startX} ${startY} C ${controlX1} ${controlY1}, ${controlX2} ${controlY2}, ${endX} ${endY}`;
      
      path.setAttribute('d', d);
      path.setAttribute('class', 'connection-line');
      path.setAttribute('data-from', conn.from);
      path.setAttribute('data-to', conn.to);
      svgConnections.appendChild(path);
    });
  }

  // --- DRY RUN LOOP ---
  async function executeDryRun() {
    if (!activePtb || isExecuting) return;

    isExecuting = true;
    btnDryRun.setAttribute('disabled', 'true');
    btnParse.setAttribute('disabled', 'true');
    agentStatus.className = 'agent-status-value status-active';
    agentStatus.textContent = 'EXECUTING PTB';
    termStatus.textContent = 'RUNNING';
    termStatus.style.color = 'var(--cyber-green)';

    addTerminalLine('info', 'Starting atomic execution dry-run of Programmable Transaction Block...');
    addTerminalLine('system', `Estimated Gas Budget: ${activePtb.gasEstimate}`);

    // Clean up previous active states
    document.querySelectorAll('.node-card').forEach(n => n.classList.remove('active-node'));
    document.querySelectorAll('.connection-line').forEach(l => l.classList.remove('active'));

    // Execute each command step-by-step
    for (let i = 0; i < activePtb.executionSteps.length; i++) {
      const step = activePtb.executionSteps[i];
      addTerminalLine('info', `[Step ${i + 1}/${activePtb.executionSteps.length}] Calling ${step.name}(${step.args})...`);
      
      // Find and highlight active command node in visual graph
      const activeCmdNode = activePtb.nodes.filter(n => n.column === 'commands')[i];
      if (activeCmdNode) {
        const cmdEl = document.getElementById(`node-dom-${activeCmdNode.id}`);
        if (cmdEl) {
          cmdEl.classList.add('active-node');
          
          // Highlight incoming wires
          const wires = svgConnections.querySelectorAll(`path[data-to="${activeCmdNode.id}"]`);
          wires.forEach(w => w.classList.add('active'));
        }
      }

      // Simulate network roundtrip latency
      await delay(800);

      // Print step results
      if (step.status === 'success') {
        addTerminalLine('success', `✔ ${step.result}`);
      } else {
        addTerminalLine('err', `✘ Aborted: ${step.result}`);
        termStatus.textContent = 'ABORTED';
        termStatus.style.color = 'var(--cyber-pink)';
        isExecuting = false;
        agentStatus.className = 'agent-status-value status-idle';
        agentStatus.textContent = 'IDLE';
        btnParse.removeAttribute('disabled');
        return;
      }
    }

    // Wrap-up
    addTerminalLine('success', '✨ Dry run completed successfully! All atomic checks passed. 0 objects leaked.');
    termStatus.textContent = 'SUCCESS';
    termStatus.style.color = 'var(--cyber-green)';
    
    // Highlight inputs and outputs as active to show the flow completion
    document.querySelectorAll('.node-input, .node-output, .node-guard').forEach(n => n.classList.add('active-node'));
    document.querySelectorAll('.connection-line').forEach(l => l.classList.add('active'));

    isExecuting = false;
    btnParse.removeAttribute('disabled');
    btnDryRun.removeAttribute('disabled');
    agentStatus.className = 'agent-status-value status-idle';
    agentStatus.textContent = 'IDLE';
  }

  function resetPTBView() {
    activePtb = null;
    btnDryRun.setAttribute('disabled', 'true');
    emptyState.style.display = 'flex';
    nodesContainer.style.display = 'none';
    codePreview.innerHTML = `<span class="code-comment">// No active guardrails.</span><br><span class="code-comment">// Compile an intent with guardrails</span><br><span class="code-comment">// to view the Move validation code.</span>`;
    
    // Reset metrics
    document.getElementById('walrus-nodes-metric').textContent = 'Inactive';
    document.getElementById('walrus-nodes-metric').style.color = 'var(--text-muted)';
    document.getElementById('safeguard-metric').textContent = 'Inactive';
    document.getElementById('safeguard-metric').style.color = 'var(--text-muted)';

    // Clear terminal
    termWindow.innerHTML = `
      <div class="term-line">
        <span class="term-prompt">&gt;</span>
        <span class="term-system">Sui Intent-to-PTB Engine initialized. Ready to simulate transactions.</span>
      </div>`;
    termStatus.textContent = 'READY';
    termStatus.style.color = 'var(--text-secondary)';

    // Remove SVG lines
    const paths = svgConnections.querySelectorAll('path');
    paths.forEach(p => p.remove());
  }


  // --- SIMULATED DEEPBOOK MARKET TICKER ---
  function initOrderbook() {
    // Generate static mid-depth order book
    orderbookData.asks = [];
    orderbookData.bids = [];

    // Bids (Buy orders, below SUI price 1.1824)
    for (let i = 0; i < 6; i++) {
      const price = suiPrice - (0.0002 + i * 0.0006);
      const size = Math.floor(500 + Math.random() * 2500);
      orderbookData.bids.push({ price, size });
    }

    // Asks (Sell orders, above SUI price 1.1824)
    for (let i = 0; i < 6; i++) {
      const price = suiPrice + (0.0002 + i * 0.0006);
      const size = Math.floor(500 + Math.random() * 2500);
      orderbookData.asks.unshift({ price, size });
    }
  }

  function tickOrderbook() {
    // Wiggle price randomly
    const change = (Math.random() - 0.5) * 0.0015;
    suiPrice = Math.max(0.5, suiPrice + change);
    suiPriceMetric.textContent = `${suiPrice.toFixed(4)} USDC`;

    // Recalculate bids and asks around the new price
    orderbookData.asks = [];
    orderbookData.bids = [];

    let totalAskDepth = 0;
    let totalBidDepth = 0;

    for (let i = 0; i < 6; i++) {
      const price = suiPrice + (0.0003 + i * 0.0005);
      const size = Math.floor(400 + Math.random() * 3000);
      totalAskDepth += size;
      orderbookData.asks.unshift({ price, size, depth: totalAskDepth });
    }

    for (let i = 0; i < 6; i++) {
      const price = suiPrice - (0.0003 + i * 0.0005);
      const size = Math.floor(400 + Math.random() * 3000);
      totalBidDepth += size;
      orderbookData.bids.push({ price, size, depth: totalBidDepth });
    }

    // Calculate dynamic spread
    const bestBid = orderbookData.bids[0].price;
    const bestAsk = orderbookData.asks[orderbookData.asks.length - 1].price;
    const spread = bestAsk - bestBid;
    const spreadPercent = (spread / bestAsk) * 100;
    suiSpreadMetric.textContent = `${spreadPercent.toFixed(3)}%`;

    updateOrderbookUI();
  }

  function updateOrderbookUI() {
    orderbookBody.innerHTML = '';

    // Render Asks (Sells, red) - rendered from highest to lowest
    orderbookData.asks.forEach(ask => {
      const maxAskDepth = Math.max(...orderbookData.asks.map(a => a.depth));
      const depthPercent = (ask.depth / maxAskDepth) * 100;

      const row = document.createElement('tr');
      row.className = 'orderbook-row';
      row.innerHTML = `
        <td class="ob-price ob-ask">${ask.price.toFixed(4)}</td>
        <td style="text-align: right;">${ask.size.toLocaleString()}</td>
        <td style="text-align: right;">${ask.depth.toLocaleString()}
          <div class="ob-depth-bar-ask" style="width: ${depthPercent}%"></div>
        </td>
      `;
      orderbookBody.appendChild(row);
    });

    // Spread divider
    const bestBid = orderbookData.bids[0]?.price || suiPrice - 0.0002;
    const bestAsk = orderbookData.asks[orderbookData.asks.length - 1]?.price || suiPrice + 0.0002;
    const spreadVal = bestAsk - bestBid;

    const divRow = document.createElement('tr');
    divRow.innerHTML = `
      <td colspan="3" class="ob-spread-divider">
        Spread: <span>${spreadVal.toFixed(4)} USDC</span>
      </td>
    `;
    orderbookBody.appendChild(divRow);

    // Render Bids (Buys, green) - rendered from highest to lowest
    orderbookData.bids.forEach(bid => {
      const maxBidDepth = Math.max(...orderbookData.bids.map(b => b.depth));
      const depthPercent = (bid.depth / maxBidDepth) * 100;

      const row = document.createElement('tr');
      row.className = 'orderbook-row';
      row.innerHTML = `
        <td class="ob-price ob-bid">${bid.price.toFixed(4)}</td>
        <td style="text-align: right;">${bid.size.toLocaleString()}</td>
        <td style="text-align: right;">${bid.depth.toLocaleString()}
          <div class="ob-depth-bar-bid" style="width: ${depthPercent}%"></div>
        </td>
      `;
      orderbookBody.appendChild(row);
    });
  }


  // --- CONSOLE UTILS ---
  function addTerminalLine(type, text) {
    const line = document.createElement('div');
    line.className = 'term-line';
    
    let typeClass = 'term-system';
    if (type === 'success') typeClass = 'term-success';
    if (type === 'info') typeClass = 'term-info';
    if (type === 'warn') typeClass = 'term-warn';
    if (type === 'err') typeClass = 'term-err';

    line.innerHTML = `
      <span class="term-prompt">&gt;</span>
      <span class="${typeClass}">${text}</span>
    `;

    termWindow.appendChild(line);
    
    // Auto-scroll console
    termWindow.scrollTop = termWindow.scrollHeight;
  }

  function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

});
