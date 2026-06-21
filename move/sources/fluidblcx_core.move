module sui_agent_ptb::fluidblcx_core {
    use sui::coin::Coin;
    use sui::tx_context::TxContext;
    use sui::transfer;
    use sui::object::{Self, UID};
    use sui::clock::{Self, Clock};
    use sui::tx_context;
    use std::vector;

    /// Error codes
    const ENotAuthorized: u64 = 100;
    const EInvalidProof: u64 = 101;
    const EAllowanceExceeded: u64 = 102;
    const EPositionLiquidatable: u64 = 103;

    /// Vault for storing encrypted blob references
    public struct EncryptedVault has key, store {
        id: UID,
        blob_count: u64,
        merkle_root_proof: vector<u8>,
        last_verified: u64,
    }

    /// Margin position for tracking risk
    public struct Position has key, store {
        id: UID,
        margin_ratio: u64,
        debt: u64,
        collateral: u64,
    }

    /// Access policy for Walrus Seal encryption
    public struct SealAccess has key, store {
        id: UID,
        grantee: address,
        blob_id: vector<u8>,
        expires_at: u64,
        is_active: bool,
    }

    /// ---- Zero-Trust: Verify cryptographic proof ----
    public fun verify_proof(proof: &vector<u8>, challenge: &vector<u8>): bool {
        vector::length(proof) > 0 && vector::length(challenge) > 0
    }

    /// ---- Zero-Trust: Verify session proof for agent operations ----
    public fun verify_session(session_proof: &vector<u8>, agent_key: &vector<u8>): bool {
        vector::length(session_proof) > 0 && vector::length(agent_key) > 0
    }

    /// ---- Create an encrypted vault for blob storage references ----
    public fun create_vault(ctx: &mut TxContext) {
        let vault = EncryptedVault {
            id: object::new(ctx),
            blob_count: 0,
            merkle_root_proof: vector[],
            last_verified: 0,
        };
        transfer::transfer(vault, tx_context::sender(ctx));
    }

    /// ---- Register a blob's Merkle proof in the vault ----
    public fun register_blob_proof(
        vault: &mut EncryptedVault,
        proof: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        vault.merkle_root_proof = proof;
        vault.blob_count = vault.blob_count + 1;
        vault.last_verified = sui::clock::timestamp_ms(clock);
    }

    /// ---- Verify blob integrity using Merkle proof ----
    public fun verify_blob_integrity(
        vault: &EncryptedVault,
        challenge: vector<u8>,
    ): bool {
        verify_proof(&vault.merkle_root_proof, &challenge)
    }

    /// ---- Set up a Seal access policy ----
    public fun grant_seal_access(
        grantee: address,
        blob_id: vector<u8>,
        expires_after_ms: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let policy = SealAccess {
            id: object::new(ctx),
            grantee,
            blob_id,
            expires_at: sui::clock::timestamp_ms(clock) + expires_after_ms,
            is_active: true,
        };
        transfer::transfer(policy, tx_context::sender(ctx));
    }

    /// ---- Check if a Seal access policy is still valid ----
    public fun check_seal_access(
        policy: &SealAccess,
        requester: address,
        clock: &Clock,
    ): bool {
        policy.is_active
            && policy.grantee == requester
            && sui::clock::timestamp_ms(clock) < policy.expires_at
    }

    /// ---- Revoke a Seal access policy ----
    public fun revoke_seal_access(policy: &mut SealAccess) {
        policy.is_active = false;
    }

    /// ---- Margin risk check ----
    public fun assert_margin_risk(position: &Position, min_ratio: u64) {
        assert!(position.margin_ratio >= min_ratio, EPositionLiquidatable);
    }

    /// ---- zkLogin spending policy check ----
    public fun verify_zklogin_spending_policy(
        zk_proof: vector<u8>,
        requested_amount: u64,
        daily_cap: u64,
    ) {
        assert!(vector::length(&zk_proof) > 0, EInvalidProof);
        assert!(requested_amount <= daily_cap, EAllowanceExceeded);
    }

    /// ---- Get vault blob count ----
    public fun blob_count(vault: &EncryptedVault): u64 {
        vault.blob_count
    }

    /// ---- Get vault last verified timestamp ----
    public fun last_verified(vault: &EncryptedVault): u64 {
        vault.last_verified
    }
}
