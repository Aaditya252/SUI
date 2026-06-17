/**
 * Sui Agent PTB - Test Suite for Intent Parser
 * Execute via terminal: `node test_parser.js`
 */

const IntentParser = require('./intentParser');
const PtbBuilder = require('./ptbBuilder');

function assert(condition, message) {
  if (!condition) {
    console.error(`❌ FAILED: ${message}`);
    process.exit(1);
  }
  console.log(`✓ PASSED: ${message}`);
}

console.log('🧪 Starting Intent Parser and PTB Builder Tests...\n');

// --- Test 1: Single Swap with Price Guardrail ---
const intent1 = "Swap 500 SUI for USDC on DeepBook, but abort the transaction if SUI price falls below 1.15 USDC";
const parsed1 = IntentParser.parse(intent1);

assert(parsed1 !== null, 'Parse intent 1');
assert(parsed1.actions.length === 1, 'Intent 1 should have 1 action');
assert(parsed1.actions[0].type === 'SWAP', 'Intent 1 action should be SWAP');
assert(parsed1.actions[0].amount === 500, 'Intent 1 swap amount should be 500');
assert(parsed1.actions[0].fromToken === 'SUI', 'Intent 1 from token should be SUI');
assert(parsed1.actions[0].toToken === 'USDC', 'Intent 1 to token should be USDC');
assert(parsed1.guardrails.length === 1, 'Intent 1 should have 1 guardrail');
assert(parsed1.guardrails[0].type === 'PRICE_GUARD', 'Intent 1 guardrail should be PRICE_GUARD');
assert(parsed1.guardrails[0].priceLimit === 1.15, 'Intent 1 price limit should be 1.15');

const ptb1 = PtbBuilder.buildPTB(parsed1);
assert(ptb1.nodes.length > 0, 'PTB 1 should generate graph nodes');
assert(ptb1.connections.length > 0, 'PTB 1 should generate connections');
assert(ptb1.executionSteps.length === 2, 'PTB 1 should have 2 steps (SplitCoins + Swap)');

// --- Test 2: Split and Multi-action ---
const intent2 = "Split 1000 SUI: send 250 to Address_A, deposit 500 to Vault, and stake 250";
const parsed2 = IntentParser.parse(intent2);

assert(parsed2 !== null, 'Parse intent 2');
assert(parsed2.actions.length === 4, 'Intent 2 should have 4 actions (Split, Transfer, Deposit, Stake)');
assert(parsed2.actions[0].type === 'SPLIT', 'First action should be SPLIT');
assert(parsed2.actions[1].type === 'TRANSFER', 'Second action should be TRANSFER');
assert(parsed2.actions[1].recipient === 'Address_A', 'Recipient should be Address_A');
assert(parsed2.actions[2].type === 'DEPOSIT', 'Third action should be DEPOSIT');
assert(parsed2.actions[3].type === 'STAKE', 'Fourth action should be STAKE');

// --- Test 3: Triangular Arbitrage ---
const intent3 = "Execute triangular arbitrage: swap 100 USDC to USDT on DeepBook, swap USDT to SUI on Cetus, and swap SUI back to USDC on DeepBook";
const parsed3 = IntentParser.parse(intent3);

assert(parsed3 !== null, 'Parse intent 3');
assert(parsed3.actions.length === 3, 'Intent 3 should have 3 swap actions');
assert(parsed3.actions[0].fromToken === 'USDC' && parsed3.actions[0].toToken === 'USDT', 'First swap: USDC -> USDT');
assert(parsed3.actions[1].fromToken === 'USDT' && parsed3.actions[1].toToken === 'SUI', 'Second swap: USDT -> SUI');
assert(parsed3.actions[2].fromToken === 'SUI' && parsed3.actions[2].toToken === 'USDC', 'Third swap: SUI -> USDC');

// --- Test 4: Walrus Cortex Storage ---
const intent4 = "Encrypt interaction logs using Walrus Seal, and store 350 MB logs split into slivers on the Walrus Protocol decentralized memory drive.";
const parsed4 = IntentParser.parse(intent4);
assert(parsed4 !== null, 'Parse intent 4');
assert(parsed4.actions.length === 1, 'Intent 4 should have 1 action');
assert(parsed4.actions[0].type === 'WALRUS_STORE', 'Intent 4 action should be WALRUS_STORE');
assert(parsed4.actions[0].size === 350, 'Intent 4 store size should be 350 MB');
assert(parsed4.guardrails.length === 1, 'Intent 4 should have 1 guardrail');
assert(parsed4.guardrails[0].type === 'WALRUS_SEAL_AUTH', 'Intent 4 guardrail should be WALRUS_SEAL_AUTH');

const ptb4 = PtbBuilder.buildPTB(parsed4);
assert(ptb4.nodes.filter(n => n.type === 'command').length === 2, 'PTB 4 should have 2 command nodes (encrypt + store)');

// --- Test 5: DeepBook Margin Safeguard ---
const intent5 = "Deposit 1000 SUI to Margin Safeguard Vault. If margin position drops below 1.2 risk factor, trigger a DeepBook flash loan of 400 USDC to prevent liquidation.";
const parsed5 = IntentParser.parse(intent5);
assert(parsed5 !== null, 'Parse intent 5');
assert(parsed5.actions.length === 2, 'Intent 5 should have 2 actions');
assert(parsed5.actions[0].type === 'MARGIN_VAULT_DEPOSIT', 'Action 0 should be MARGIN_VAULT_DEPOSIT');
assert(parsed5.actions[1].type === 'MARGIN_VAULT_SAFEGUARD', 'Action 1 should be MARGIN_VAULT_SAFEGUARD');
assert(parsed5.guardrails.length === 1, 'Intent 5 should have 1 guardrail');
assert(parsed5.guardrails[0].type === 'MARGIN_RISK_CHECK', 'Intent 5 guardrail should be MARGIN_RISK_CHECK');
assert(parsed5.guardrails[0].limit === 1.2, 'Intent 5 risk limit threshold should be 1.2');

const ptb5 = PtbBuilder.buildPTB(parsed5);
assert(ptb5.nodes.filter(n => n.type === 'command').length === 4, 'PTB 5 should have 4 command nodes (split + deposit + check + loan)');

// --- Test 6: zkLogin Allowance Stream ---
const intent6 = "Set up zkLogin allowance of 50 USDC per day for ephemeral AI agent 0x9a83...4f21, scaling up to 500 USDC if arbitrage is detected.";
const parsed6 = IntentParser.parse(intent6);
assert(parsed6 !== null, 'Parse intent 6');
assert(parsed6.actions.length === 1, 'Intent 6 should have 1 action');
assert(parsed6.actions[0].type === 'ZK_ALLOWANCE_CREATE', 'Intent 6 action should be ZK_ALLOWANCE_CREATE');
assert(parsed6.actions[0].dailyLimit === 50, 'Intent 6 daily limit should be 50 USDC');
assert(parsed6.actions[0].maxLimit === 500, 'Intent 6 max scale limit should be 500 USDC');
assert(parsed6.guardrails.length === 1, 'Intent 6 should have 1 guardrail');
assert(parsed6.guardrails[0].type === 'ZKLOGIN_PROOF_VERIFY', 'Intent 6 guardrail should be ZKLOGIN_PROOF_VERIFY');

const ptb6 = PtbBuilder.buildPTB(parsed6);
assert(ptb6.nodes.filter(n => n.type === 'command').length === 2, 'PTB 6 should have 2 command nodes (auth + create policy)');

console.log('\n🎉 All tests passed successfully!');
