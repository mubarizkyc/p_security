#![allow(unexpected_cfgs)]
use pinocchio::{
    ProgramResult, account_info::AccountInfo, default_panic_handler, no_allocator,
    program_entrypoint, pubkey::Pubkey, sysvars::Sysvar,
};
pinocchio_pubkey::declare_id!("ENrRns55VechXJiq4bMbdx7idzQh7tvaEJoYeWxRNe7Y");
// This is the entrypoint for the program.
program_entrypoint!(process_instruction);
//Do not allocate memory.
no_allocator!();
// Use the no_std panic handler.
default_panic_handler!();
pub const PRICE_MAX_AGE: u64 = 3;

// Trusted oracle program (e.g. Pyth)
pub const ORACLE_PROVIDER: [u8; 32] = [0u8; 32];

// Canonical feed account (hardcoded official feed address)
pub const FEED_ACCOUNT_KEY: [u8; 32] = [1u8; 32];

/// SECURE: Validates canonical feed + enforces monotonic updates
/// Fixes:
/// 1. Canonical feed enforcement: Only accepts hardcoded official oracle address
/// 2. Monotonicity: Rejects prices older than last seen (prevents rollbacks)
#[inline(always)]
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let oracle = &accounts[0];
    let asset_info = &accounts[1];

    // ✅ FIX #1: Canonical feed enforcement (PRIMARY)
    // Reject any account that isn't the official feed address
    if oracle.key().as_ref() != FEED_ACCOUNT_KEY {
        return Err(pinocchio::program_error::ProgramError::InvalidAccountData);
    }

    // ✅ Verify oracle program ownership (SECONDARY)
    if oracle.owner() != ORACLE_PROVIDER.as_ref() {
        return Err(pinocchio::program_error::ProgramError::IllegalOwner);
    }

    let oracle_data: &OracleInfo =
        unsafe { &*(oracle.borrow_data_unchecked().as_ptr() as *const OracleInfo) };

    let current_slot = pinocchio::sysvars::clock::Clock::get()?.slot;

    // Freshness check (price not too old)
    if current_slot
        .checked_sub(oracle_data.update_slot)
        .ok_or(pinocchio::program_error::ProgramError::InvalidAccountData)?
        > PRICE_MAX_AGE
    {
        return Err(pinocchio::program_error::ProgramError::InvalidAccountData);
    }

    let asset_info_data: &mut AssetInfo =
        unsafe { &mut *(asset_info.borrow_mut_data_unchecked().as_mut_ptr() as *mut AssetInfo) };

    let last_seen_slot = u64::from_le_bytes(asset_info_data.last_update_slot);

    // ✅ FIX #2: Monotonic publish-time enforcement
    // Only accept strictly newer prices (prevents rollback attacks)
    if oracle_data.update_slot <= last_seen_slot {
        return Err(pinocchio::program_error::ProgramError::InvalidAccountData);
    }

    // Update state with validated price
    asset_info_data.price = oracle_data.price;
    asset_info_data.last_update_slot = oracle_data.update_slot.to_le_bytes();

    Ok(())
}

#[repr(C)]
struct AssetInfo {
    pub price: [u8; 8],
    pub last_update_slot: [u8; 8],
}

#[repr(C)]
struct OracleInfo {
    pub update_slot: u64,
    pub price: [u8; 8],
}

#[test]
fn test_canonical_feed_accepted() {
    use solana_sdk::{
        account::Account,
        instruction::Instruction,
        pubkey::Pubkey,
        signature::{Keypair, Signer},
    };

    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

    let mut svm = litesvm::LiteSVM::new();

    // Use canonical feed key (official oracle address)
    let oracle_key = Pubkey::new_from_array(FEED_ACCOUNT_KEY);
    let asset_info = Keypair::new();
    let fee_payer = Keypair::new();

    svm.warp_to_slot(17_000_000);

    // Oracle provides newer price (slot 16,999,999 vs stored 16,999,998)
    let oracle_update_slot: u64 = 16_999_999;
    let new_price: u64 = 600;

    let mut oracle_data = vec![];
    oracle_data.extend_from_slice(&oracle_update_slot.to_le_bytes());
    oracle_data.extend_from_slice(&new_price.to_le_bytes());

    svm.set_account(
        oracle_key,
        Account {
            lamports: 1_000_000,
            data: oracle_data,
            owner: ORACLE_PROVIDER.into(),
            executable: false,
            rent_epoch: 100,
        },
    )
    .unwrap();

    // Existing state: older price at slot 16,999,998
    let last_update_slot: u64 = 16_999_998;
    let old_price: u64 = 500;

    let mut asset_data = vec![];
    asset_data.extend_from_slice(&old_price.to_le_bytes());
    asset_data.extend_from_slice(&last_update_slot.to_le_bytes());

    svm.set_account(
        asset_info.pubkey(),
        Account {
            lamports: 1_000_000,
            data: asset_data,
            owner: crate::ID.into(),
            executable: false,
            rent_epoch: 100,
        },
    )
    .unwrap();

    svm.airdrop(&fee_payer.pubkey(), LAMPORTS_PER_SOL).unwrap();

    svm.add_program_from_file(
        &crate::ID.into(),
        "../../target/deploy/sneaky_oracle_secure.so",
    )
    .unwrap();

    let tx = solana_sdk::transaction::Transaction::new(
        &[fee_payer.insecure_clone()],
        solana_sdk::message::Message::new(
            &[Instruction {
                program_id: crate::ID.into(),
                accounts: vec![
                    solana_sdk::instruction::AccountMeta::new_readonly(oracle_key, false),
                    solana_sdk::instruction::AccountMeta::new(asset_info.pubkey(), false),
                ],
                data: vec![],
            }],
            Some(&fee_payer.pubkey()),
        ),
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Should accept canonical feed with newer price"
    );

    // ✅ Verify state updated correctly
    let acc = svm
        .get_account(&asset_info.pubkey())
        .expect("Asset account should exist");

    let stored_price = u64::from_le_bytes(acc.data[0..8].try_into().unwrap());
    let stored_slot = u64::from_le_bytes(acc.data[8..16].try_into().unwrap());

    assert_eq!(stored_price, new_price, "Price should update to new value");
    assert_eq!(
        stored_slot, oracle_update_slot,
        "Slot should update to newer slot"
    );

    println!(
        "✅ Fix working: Accepted price {} from canonical feed at slot {}",
        stored_price, stored_slot
    );
}

#[test]
fn test_rollback_rejected() {
    use solana_sdk::{
        account::Account,
        instruction::Instruction,
        pubkey::Pubkey,
        signature::{Keypair, Signer},
    };

    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

    let mut svm = litesvm::LiteSVM::new();
    let oracle_key = Pubkey::new_from_array(FEED_ACCOUNT_KEY);
    let asset_info = Keypair::new();
    let fee_payer = Keypair::new();

    svm.warp_to_slot(17_000_000);

    // Try to submit OLDER price (rollback attempt)
    let oracle_update_slot: u64 = 16_999_998; // Older than stored
    let stale_price: u64 = 400;

    let mut oracle_data = vec![];
    oracle_data.extend_from_slice(&oracle_update_slot.to_le_bytes());
    oracle_data.extend_from_slice(&stale_price.to_le_bytes());

    svm.set_account(
        oracle_key,
        Account {
            lamports: 1_000_000,
            data: oracle_data,
            owner: ORACLE_PROVIDER.into(),
            executable: false,
            rent_epoch: 100,
        },
    )
    .unwrap();

    // Existing state: already has newer price at slot 16,999,999
    let existing_slot: u64 = 16_999_999;
    let existing_price: u64 = 600;

    let mut asset_data = vec![];
    asset_data.extend_from_slice(&existing_price.to_le_bytes());
    asset_data.extend_from_slice(&existing_slot.to_le_bytes());

    svm.set_account(
        asset_info.pubkey(),
        Account {
            lamports: 1_000_000,
            data: asset_data,
            owner: crate::ID.into(),
            executable: false,
            rent_epoch: 100,
        },
    )
    .unwrap();

    svm.airdrop(&fee_payer.pubkey(), LAMPORTS_PER_SOL).unwrap();

    svm.add_program_from_file(
        &crate::ID.into(),
        "../../target/deploy/sneaky_oracle_secure.so",
    )
    .unwrap();

    let tx = solana_sdk::transaction::Transaction::new(
        &[fee_payer.insecure_clone()],
        solana_sdk::message::Message::new(
            &[Instruction {
                program_id: crate::ID.into(),
                accounts: vec![
                    solana_sdk::instruction::AccountMeta::new_readonly(oracle_key, false),
                    solana_sdk::instruction::AccountMeta::new(asset_info.pubkey(), false),
                ],
                data: vec![],
            }],
            Some(&fee_payer.pubkey()),
        ),
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);

    // ✅ Should reject because oracle_update_slot (16,999,998) <= last_seen_slot (16,999,999)
    assert!(result.is_err(), "Should reject rollback (older slot)");
    println!("✅ Fix working: Rejected older price (rollback prevented)");
}
