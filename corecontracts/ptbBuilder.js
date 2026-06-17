/**
 * Sui Agent PTB - PTB Compiler & Graph Builder
 * Converts structured intents into concrete Sui PTB steps, UI nodes, connections, and Move guardrail code.
 */

const PtbBuilder = (() => {

  function buildPTB(parsedIntent) {
    if (!parsedIntent) return null;

    // Auto-inject slippage guardrail for all Swap intents
    if (parsedIntent.actions.some(a => a.type === 'SWAP')) {
      const alreadyHasSlip = parsedIntent.guardrails.some(g => g.type === 'SLIPPAGE_ASSERT');
      if (!alreadyHasSlip) {
        parsedIntent.guardrails.push({
          type: 'SLIPPAGE_ASSERT',
          limit: 0.5,
          description: 'Assert maximum slippage budget <= 0.5%'
        });
      }
    }

    const graph = {
      nodes: [],
      connections: [],
      executionSteps: [],
      gasEstimate: '0.0084 SUI',
      moveCode: ''
    };

    let nodeIdCounter = 1;
    function nextId(prefix) {
      return `${prefix}-${nodeIdCounter++}`;
    }

    // 1. PROCESS INPUTS
    const inputNodes = [];
    parsedIntent.inputs.forEach(input => {
      const id = input.id || nextId('input');
      const node = {
        id: id,
        column: 'inputs',
        type: 'input',
        title: input.type === 'SUI' ? 'Gas / SUI Coin' : `${input.type} Coin`,
        icon: '💵',
        details: {
          'Amt': `${input.amount}`,
          'Ref': '0x2::sui::SUI'
        }
      };
      graph.nodes.push(node);
      inputNodes.push(node);
    });

    // 2. PROCESS GUARDRAILS
    const guardNodes = [];
    parsedIntent.guardrails.forEach(guard => {
      const id = nextId('guard');
      let details = {};
      let title = 'Guard';
      if (guard.type === 'PRICE_GUARD') {
        title = 'Price Guard';
        details = { 'Min Price': `${guard.priceLimit} USDC`, 'Action': 'Abort on fail' };
      } else if (guard.type === 'SPREAD_CHECK') {
        title = 'Spread Guard';
        details = { 'Max Spread': `${guard.threshold}%`, 'Action': 'Conditional Route' };
      } else if (guard.type === 'WALRUS_SEAL_AUTH') {
        title = 'Seal Guard';
        details = { 'Auth': 'Walrus Seal Key', 'Type': 'Decryption Lock' };
      } else if (guard.type === 'MARGIN_RISK_CHECK') {
        title = 'Margin Risk Guard';
        details = { 'Risk Limit': `${guard.limit}`, 'Action': 'Trigger Safeguard' };
      } else if (guard.type === 'ZKLOGIN_PROOF_VERIFY') {
        title = 'zkLogin Guard';
        details = { 'Signature': 'OpenID Cryptographic', 'Policy': 'Verify Session' };
      } else if (guard.type === 'SLIPPAGE_ASSERT') {
        title = 'Slippage Guard';
        details = { 'Max Slippage': `${guard.limit}%`, 'Safety': 'Sandwich Protection' };
      }

      const node = {
        id: id,
        column: 'guardrails',
        type: 'guard',
        title: title,
        icon: '🛡️',
        details: details
      };
      graph.nodes.push(node);
      guardNodes.push(node);
    });

    // 3. PROCESS COMMANDS & OUTPUTS
    const commandNodes = [];
    const outputNodes = [];

    // Auxiliary trackers for connecting nodes
    let currentAssetSourceId = inputNodes[0]?.id;

    parsedIntent.actions.forEach((action, index) => {
      if (action.type === 'SWAP') {
        // Command Node: Split SUI if swapping from gas
        let splitNodeId = null;
        if (action.fromToken === 'SUI' && index === 0) {
          splitNodeId = nextId('cmd');
          const splitNode = {
            id: splitNodeId,
            column: 'commands',
            type: 'command',
            title: 'SplitCoins',
            icon: '⚙️',
            details: {
              'Into': `${action.amount} SUI`,
              'From': 'Gas Coin'
            }
          };
          graph.nodes.push(splitNode);
          commandNodes.push(splitNode);

          graph.connections.push({ from: currentAssetSourceId, to: splitNodeId });
          currentAssetSourceId = splitNodeId;
        }

        // Command Node: Swap MoveCall
        const swapNodeId = nextId('cmd');
        const swapNode = {
          id: swapNodeId,
          column: 'commands',
          type: 'command',
          title: action.venue.includes('DeepBook') ? 'DeepBook::swap' : 'Cetus::swap',
          icon: '⚙️',
          details: {
            'In': `${action.amount} ${action.fromToken}`,
            'Out': action.toToken,
            'Venue': action.venue
          }
        };
        graph.nodes.push(swapNode);
        commandNodes.push(swapNode);

        graph.connections.push({ from: currentAssetSourceId, to: swapNodeId });

        // If there is a price guard, connect it to the swap command
        if (guardNodes.length > 0 && parsedIntent.guardrails.some(g => g.type === 'PRICE_GUARD')) {
          const priceGuard = guardNodes.find(n => n.title === 'Price Guard');
          if (priceGuard) {
            graph.connections.push({ from: priceGuard.id, to: swapNodeId });
          }
        }

        // Add On-Chain Sandwich Invariant Assertion Command
        const assertNodeId = nextId('cmd');
        const minOutAmt = action.fromToken === 'SUI' ? (action.amount * 1.18 * 0.995).toFixed(2) : (action.amount / 1.18 * 0.995).toFixed(2);
        const assertNode = {
          id: assertNodeId,
          column: 'commands',
          type: 'command',
          title: 'dapp_security::enforce_output',
          icon: '🛡️',
          details: {
            'Min Out': `${minOutAmt} ${action.toToken}`,
            'Slippage': '0.5% Cap'
          }
        };
        graph.nodes.push(assertNode);
        commandNodes.push(assertNode);
        graph.connections.push({ from: swapNodeId, to: assertNodeId });

        // Connect slippage guard to the assertion command
        const slipGuard = guardNodes.find(n => n.title === 'Slippage Guard');
        if (slipGuard) {
          graph.connections.push({ from: slipGuard.id, to: assertNodeId });
        }

        currentAssetSourceId = assertNodeId;

        // Dry run step mapping
        if (splitNodeId) {
          graph.executionSteps.push({
            name: 'SplitCoins',
            args: `[GasCoin, [${action.amount} SUI]]`,
            status: 'success',
            result: `Created Coin<SUI> Object (id: 0x5a21...d91e, Balance: ${action.amount} SUI)`
          });
        }
        graph.executionSteps.push({
          name: 'MoveCall',
          args: `${action.venue.includes('DeepBook') ? 'deepbook::clob_v3::swap_exact_base_for_quote' : 'cetus::pool::swap'}`,
          status: 'success',
          result: `Exchanged ${action.amount} ${action.fromToken} for simulated ${action.fromToken === 'SUI' ? (action.amount * 1.18).toFixed(2) : (action.amount / 1.18).toFixed(2)} ${action.toToken}`
        });

        graph.executionSteps.push({
          name: 'MoveCall',
          args: 'dapp_security::enforce_minimum_output',
          status: 'success',
          result: `Sandwich guard invariant check: Swapped output balance matches computed constraints (Limit: >= ${minOutAmt} ${action.toToken}). OK.`
        });

      } else if (action.type === 'CONDITIONAL_ROUTE') {
        // Spread logic routing
        const splitNodeId = nextId('cmd');
        const splitNode = {
          id: splitNodeId,
          column: 'commands',
          type: 'command',
          title: 'SplitCoins',
          icon: '⚙️',
          details: { 'Into': `${action.amount} USDC`, 'From': 'Wallet' }
        };
        graph.nodes.push(splitNode);
        commandNodes.push(splitNode);
        graph.connections.push({ from: currentAssetSourceId, to: splitNodeId });

        // Smart Router Route
        const routeNodeId = nextId('cmd');
        const routeNode = {
          id: routeNodeId,
          column: 'commands',
          type: 'command',
          title: 'SmartRouteCall',
          icon: '⚙️',
          details: { 'Condition': action.condition, 'Opt A': 'DeepBook', 'Opt B': 'Cetus' }
        };
        graph.nodes.push(routeNode);
        commandNodes.push(routeNode);

        graph.connections.push({ from: splitNodeId, to: routeNodeId });

        // Connect spread guard to routing command
        const spreadGuard = guardNodes.find(n => n.title === 'Spread Guard');
        if (spreadGuard) {
          graph.connections.push({ from: spreadGuard.id, to: routeNodeId });
        }

        currentAssetSourceId = routeNodeId;

        graph.executionSteps.push({
          name: 'SplitCoins',
          args: `[Wallet USDC, [${action.amount} USDC]]`,
          status: 'success',
          result: `Split ${action.amount} USDC from active balances`
        });

        graph.executionSteps.push({
          name: 'MoveCall',
          args: 'intent_router::conditional_route',
          status: 'success',
          result: 'Sui Orderbook Spread is 0.034% (< 0.1%). Routed 100% to DeepBook v3 CLOB. Placed Ask.'
        });

      } else if (action.type === 'SPLIT') {
        const splitId = nextId('cmd');
        const splitNode = {
          id: splitId,
          column: 'commands',
          type: 'command',
          title: 'SplitCoins',
          icon: '⚙️',
          details: { 'Into': '3 Coins', 'From': 'Gas' }
        };
        graph.nodes.push(splitNode);
        commandNodes.push(splitNode);
        graph.connections.push({ from: currentAssetSourceId, to: splitId });
        currentAssetSourceId = splitId;

        graph.executionSteps.push({
          name: 'SplitCoins',
          args: `[GasCoin, [250 SUI, 500 SUI, 250 SUI]]`,
          status: 'success',
          result: 'Created 3 SUI Coin objects: Coin_A (250 SUI), Coin_B (500 SUI), Coin_C (250 SUI)'
        });

      } else if (action.type === 'TRANSFER') {
        const cmdId = nextId('cmd');
        const transferNode = {
          id: cmdId,
          column: 'commands',
          type: 'command',
          title: 'TransferObjects',
          icon: '⚙️',
          details: { 'To': action.recipient, 'Amt': `${action.amount} SUI` }
        };
        graph.nodes.push(transferNode);
        commandNodes.push(transferNode);
        graph.connections.push({ from: currentAssetSourceId, to: cmdId });

        graph.executionSteps.push({
          name: 'TransferObjects',
          args: `[[Coin_A], ${action.recipient}]`,
          status: 'success',
          result: `Transferred ownership of Coin_A (250 SUI) to ${action.recipient}`
        });

      } else if (action.type === 'DEPOSIT') {
        const cmdId = nextId('cmd');
        const depositNode = {
          id: cmdId,
          column: 'commands',
          type: 'command',
          title: 'Vault::deposit',
          icon: '⚙️',
          details: { 'Vault': action.destination, 'Amt': `${action.amount} SUI` }
        };
        graph.nodes.push(depositNode);
        commandNodes.push(depositNode);
        graph.connections.push({ from: currentAssetSourceId, to: cmdId });

        graph.executionSteps.push({
          name: 'MoveCall',
          args: 'margin_vault::deposit_liquidity',
          status: 'success',
          result: `Deposited Coin_B (500 SUI) into Vault. Minted LP-Receipt object.`
        });

      } else if (action.type === 'STAKE') {
        const cmdId = nextId('cmd');
        const stakeNode = {
          id: cmdId,
          column: 'commands',
          type: 'command',
          title: 'sui::stake',
          icon: '⚙️',
          details: { 'Validator': '0x1::validator_5', 'Amt': `${action.amount} SUI` }
        };
        graph.nodes.push(stakeNode);
        commandNodes.push(stakeNode);
        graph.connections.push({ from: currentAssetSourceId, to: cmdId });

        graph.executionSteps.push({
          name: 'MoveCall',
          args: 'sui_system::request_add_stake',
          status: 'success',
          result: `Staked Coin_C (250 SUI) on Validator 0x1::validator_5. Created StakedSui Object.`
        });

      } else if (action.type === 'WALRUS_STORE') {
        const encId = nextId('cmd');
        const encNode = {
          id: encId,
          column: 'commands',
          type: 'command',
          title: 'walrus::seal::encrypt',
          icon: '⚙️',
          details: { 'Method': action.encryption, 'Input': 'State Logs' }
        };
        graph.nodes.push(encNode);
        commandNodes.push(encNode);
        graph.connections.push({ from: currentAssetSourceId, to: encId });

        const sealGuard = guardNodes.find(n => n.title === 'Seal Guard');
        if (sealGuard) {
          graph.connections.push({ from: sealGuard.id, to: encId });
        }

        const storeId = nextId('cmd');
        const storeNode = {
          id: storeId,
          column: 'commands',
          type: 'command',
          title: 'walrus::store_slivers',
          icon: '⚙️',
          details: { 'Size': `${action.size} ${action.unit}`, 'Nodes': '150 Online' }
        };
        graph.nodes.push(storeNode);
        commandNodes.push(storeNode);
        graph.connections.push({ from: encId, to: storeId });

        currentAssetSourceId = storeId;

        graph.executionSteps.push({
          name: 'MoveCall',
          args: 'walrus_seal::encrypt_logs_data',
          status: 'success',
          result: `Encrypted AI agent interaction state logs using Walrus Seal. Encrypted bytes: ${action.size} MB`
        });

        graph.executionSteps.push({
          name: 'MoveCall',
          args: 'walrus::storage::write_slivers',
          status: 'success',
          result: `Decentralized sharding completed: Distributed ${action.size} MB data into 150 slivers across active Walrus storage nodes`
        });

      } else if (action.type === 'MARGIN_VAULT_DEPOSIT') {
        const splitId = nextId('cmd');
        const splitNode = {
          id: splitId,
          column: 'commands',
          type: 'command',
          title: 'SplitCoins',
          icon: '⚙️',
          details: { 'Into': `${action.amount} SUI`, 'From': 'Gas' }
        };
        graph.nodes.push(splitNode);
        commandNodes.push(splitNode);
        graph.connections.push({ from: currentAssetSourceId, to: splitId });

        const depId = nextId('cmd');
        const depNode = {
          id: depId,
          column: 'commands',
          type: 'command',
          title: 'margin_vault::deposit',
          icon: '⚙️',
          details: { 'Amt': `${action.amount} SUI`, 'Vault': '0xmargin_vault_v3' }
        };
        graph.nodes.push(depNode);
        commandNodes.push(depNode);
        graph.connections.push({ from: splitId, to: depId });

        currentAssetSourceId = depId;

        graph.executionSteps.push({
          name: 'SplitCoins',
          args: `[GasCoin, [${action.amount} SUI]]`,
          status: 'success',
          result: `Split ${action.amount} SUI from active wallet gas balance`
        });

        graph.executionSteps.push({
          name: 'MoveCall',
          args: 'margin_vault::deposit_liquidity',
          status: 'success',
          result: `Deposited ${action.amount} SUI into safeguarding pool. Vault placed bid on DeepBook to earn DEEP market maker rebates.`
        });

      } else if (action.type === 'MARGIN_VAULT_SAFEGUARD') {
        const checkId = nextId('cmd');
        const checkNode = {
          id: checkId,
          column: 'commands',
          type: 'command',
          title: 'vault::verify_risk',
          icon: '⚙️',
          details: { 'Limit': `${action.threshold}`, 'Position': '0xpos_0' }
        };
        graph.nodes.push(checkNode);
        commandNodes.push(checkNode);
        graph.connections.push({ from: currentAssetSourceId, to: checkId });

        const loanId = nextId('cmd');
        const loanNode = {
          id: loanId,
          column: 'commands',
          type: 'command',
          title: 'deepbook::margin::flash_loan',
          icon: '⚙️',
          details: { 'Amt': `${action.flashLoanAmount} USDC`, 'Route': 'Paydown Debt' }
        };
        graph.nodes.push(loanNode);
        commandNodes.push(loanNode);
        graph.connections.push({ from: checkId, to: loanId });

        const riskGuard = guardNodes.find(n => n.title === 'Margin Risk Guard');
        if (riskGuard) {
          graph.connections.push({ from: riskGuard.id, to: checkId });
        }

        currentAssetSourceId = loanId;

        graph.executionSteps.push({
          name: 'MoveCall',
          args: 'margin_vault::check_account_liquidation_ratio',
          status: 'success',
          result: `Position risk factor evaluated: 1.14 (< target ${action.threshold}). Safely triggered safeguard protocol.`
        });

        graph.executionSteps.push({
          name: 'MoveCall',
          args: 'deepbook::clob_v3::execute_margin_flash_loan',
          status: 'success',
          result: `Issued atomic flash loan of ${action.flashLoanAmount} USDC from DeepBook. Paid down debt to adjust risk factor to 1.45. Prevented liquidation.`
        });

      } else if (action.type === 'ZK_ALLOWANCE_CREATE') {
        const authId = nextId('cmd');
        const authNode = {
          id: authId,
          column: 'commands',
          type: 'command',
          title: 'allowance::auth_zklogin',
          icon: '⚙️',
          details: { 'Key': 'zkLogin Proof', 'Agent': action.agent }
        };
        graph.nodes.push(authNode);
        commandNodes.push(authNode);
        graph.connections.push({ from: currentAssetSourceId, to: authId });

        const zkGuard = guardNodes.find(n => n.title === 'zkLogin Guard');
        if (zkGuard) {
          graph.connections.push({ from: zkGuard.id, to: authId });
        }

        const policyId = nextId('cmd');
        const policyNode = {
          id: policyId,
          column: 'commands',
          type: 'command',
          title: 'allowance::create_policy',
          icon: '⚙️',
          details: { 'Daily Cap': `${action.dailyLimit} USDC`, 'Max Cap': `${action.maxLimit} USDC` }
        };
        graph.nodes.push(policyNode);
        commandNodes.push(policyNode);
        graph.connections.push({ from: authId, to: policyId });

        currentAssetSourceId = policyId;

        graph.executionSteps.push({
          name: 'MoveCall',
          args: 'allowance::zklogin::verify_proof_session',
          status: 'success',
          result: `Cryptographic proof for zkLogin ephemeral session verified successfully for wallet 0x9a83...4f21.`
        });

        graph.executionSteps.push({
          name: 'MoveCall',
          args: 'allowance::policy::register_allowance_limits',
          status: 'success',
          result: `Allowance policy active: daily limit = ${action.dailyLimit} USDC. Max arbitrage fallback limit = ${action.maxLimit} USDC.`
        });
      }
    });

    // Populate Outputs
    parsedIntent.outputs.forEach(output => {
      const outputId = nextId('output');
      const outNode = {
        id: outputId,
        column: 'outputs',
        type: 'output',
        title: output.type,
        icon: '📥',
        details: { 'Receiver': 'Wallet Owner', 'Source': 'PTB Exec' }
      };
      graph.nodes.push(outNode);
      outputNodes.push(outNode);

      graph.connections.push({ from: currentAssetSourceId, to: outputId });
    });

    // 4. GENERATE MOVE CODE DYNAMICALLY
    graph.moveCode = generateMoveCode(parsedIntent.guardrails);

    // Adjust gas estimate based on complexity
    const stepsCount = graph.executionSteps.length;
    graph.gasEstimate = `${(0.003 + stepsCount * 0.0018).toFixed(4)} SUI`;

    return graph;
  }

  function generateMoveCode(guardrails) {
    if (!guardrails || guardrails.length === 0) {
      return `\n<span class="code-comment">// No active guardrails deployed.</span>\n<span class="code-comment">// Move safety checks will not be compiled.</span>`;
    }

    let code = `<span class="code-keyword">module</span> <span class="code-type">sui_agent_ptb::guardrails</span> {
    <span class="code-keyword">use</span> sui::coin::{Self, Coin};
    <span class="code-keyword">use</span> sui::clock::Clock;
    <span class="code-keyword">use</span> deepbook::clob_v3::{Self, Pool};

    <span class="code-keyword">const</span> EPriceTooLow: u64 = <span class="code-number">101</span>;
    <span class="code-keyword">const</span> ESpreadTooHigh: u64 = <span class="code-number">102</span>;
    <span class="code-keyword">const</span> EUnauthorizedSeal: u64 = <span class="code-number">103</span>;
    <span class="code-keyword">const</span> EPositionLiquidatable: u64 = <span class="code-number">104</span>;
    <span class="code-keyword">const</span> EAllowanceExceeded: u64 = <span class="code-number">105</span>;
`;

    guardrails.forEach(guard => {
      if (guard.type === 'PRICE_GUARD') {
        code += `
    <span class="code-comment">/// Asserts that the CLOB price is above the safety threshold before swapping</span>
    <span class="code-keyword">public entry fun</span> <span class="code-type">check_price_and_swap</span>&lt;Base, Quote&gt;(
        pool: &Pool&lt;Base, Quote&gt;,
        clock: &Clock,
        min_price: u64,
        base_coin: Coin&lt;Base&gt;,
        ctx: &mut TxContext
      ) {
        <span class="code-keyword">let</span> current_price = clob_v3::get_market_price(pool, clock);
        <span class="code-comment">// Assert safety price threshold</span>
        <span class="code-keyword">assert!</span>(current_price &gt;= min_price, EPriceTooLow);
        clob_v3::swap_exact_base_for_quote(pool, base_coin, ctx);
    }
`;
      } else if (guard.type === 'SPREAD_CHECK') {
        code += `
    <span class="code-comment">/// Asserts orderbook spread is below limit, otherwise routes via Cetus</span>
    <span class="code-keyword">public fun</span> <span class="code-type">check_spread_and_route</span>&lt;Base, Quote&gt;(
        pool: &Pool&lt;Base, Quote&gt;,
        clock: &Clock,
        max_spread_bps: u64
      ): bool {
        <span class="code-keyword">let</span> (bid_price, ask_price) = clob_v3::get_spread(pool, clock);
        <span class="code-keyword">let</span> spread = ask_price - bid_price;
        <span class="code-keyword">let</span> spread_bps = (spread * <span class="code-number">10000</span>) / ask_price;
        spread_bps &lt;= max_spread_bps
    }
`;
      } else if (guard.type === 'WALRUS_SEAL_AUTH') {
        code += `
    <span class="code-comment">/// Asserts that the caller has valid Walrus Seal key registration before storage</span>
    <span class="code-keyword">public fun</span> <span class="code-type">assert_walrus_seal_authority</span>(
        session_proof: &vector<u8>,
        agent_key: &vector<u8>
      ) {
        <span class="code-keyword">let</span> is_valid = walrus_seal::verify_session(session_proof, agent_key);
        <span class="code-keyword">assert!</span>(is_valid, EUnauthorizedSeal);
    }
`;
      } else if (guard.type === 'MARGIN_RISK_CHECK') {
        code += `
    <span class="code-comment">/// Evaluates margin risk ratio and triggers emergency flash loan if critical</span>
    <span class="code-keyword">public entry fun</span> <span class="code-type">assert_margin_risk_and_safeguard</span>&lt;Asset&gt;(
        position: &Position,
        vault: &mut MarginVault&lt;Asset&gt;,
        loan_amount: u64,
        ctx: &mut TxContext
      ) {
        <span class="code-keyword">let</span> risk_factor = margin_vault::get_risk_factor(position);
        <span class="code-keyword">if</span> (risk_factor < <span class="code-number">120</span>) { // 1.2 target
            <span class="code-keyword">let</span> loan = deepbook::margin::borrow_flash_loan(loan_amount);
            margin_vault::settle_debt(position, &mut loan);
            deepbook::margin::repay_flash_loan(loan);
        }
      }
`;
      } else if (guard.type === 'ZKLOGIN_PROOF_VERIFY') {
        code += `
    <span class="code-comment">/// Verifies the ephemeral session and checks limits against active allowance policies</span>
    <span class="code-keyword">public fun</span> <span class="code-type">verify_zklogin_spending_policy</span>(
        zk_proof: &vector<u8>,
        requested_amount: u64,
        daily_cap: u64
      ) {
        <span class="code-keyword">let</span> sig_valid = sui::zklogin::verify_proof(zk_proof);
        assert!(sig_valid, EUnauthorizedSeal);
        assert!(requested_amount <= daily_cap, EAllowanceExceeded);
      }
      } else if (guard.type === 'SLIPPAGE_ASSERT') {
        code += `
          < span class="code-comment" >/// Enforces slippage threshold checks inside the execution block to block front-running</span>
    <span class="code-keyword">public fun</span> <span class="code-type">enforce_minimum_output</span> & lt; Asset & gt; (
            output_coin: & Coin & lt; Asset & gt;,
        min_expected: u64
      ) {
      <span class="code-keyword">let</span> output_value = coin:: value(output_coin);
        <span class="code-comment">// Assert return balance >= min_expected</span>
        <span class="code-keyword">assert!</span>(output_value & gt= min_expected, EPriceTooLow);
    }
    `;
      }
    });

    code += `} `;
    return code;
  }

  return {
    buildPTB
  };
})();

// Export for browser script
if (typeof module !== 'undefined') {
  module.exports = PtbBuilder;
}
