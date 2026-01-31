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
// Maximum allowed staleness (in slots)
pub const PRICE_MAX_AGE: u64 = 3;

// Supposed oracle program (e.g. Pyth)
// NOTE: Ownership alone does NOT imply canonical feed
pub const ORACLE_PROVIDER: [u8; 32] = [0u8; 32];

/// INSECURE: Accepts any oracle account owned by ORACLE_PROVIDER
/// Vulnerable to:
/// 1. Non-canonical feeds: Attacker creates their own price account with stale data
/// 2. Price rollback: Older prices can overwrite newer ones (no monotonicity check)
#[inline(always)]
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let oracle = &accounts[0];
    let asset_info = &accounts[1];

    //  Only checks oracle *program ownership*
    if oracle.owner() != ORACLE_PROVIDER.as_ref() {
        return Err(pinocchio::program_error::ProgramError::IllegalOwner);
    }

    //  Blindly trust oracle account contents, No canonical feed key validation
    let oracle_data: &OracleInfo =
        unsafe { &*(oracle.borrow_data_unchecked().as_ptr() as *const OracleInfo) };

    let current_slot = pinocchio::sysvars::clock::Clock::get()?.slot;

    //  Freshness-only validation
    // Ensures price was valid *recently*, not that it is the latest
    if current_slot
        .checked_sub(oracle_data.update_slot)
        .ok_or(pinocchio::program_error::ProgramError::InvalidAccountData)?
        > PRICE_MAX_AGE
    {
        return Err(pinocchio::program_error::ProgramError::InvalidAccountData);
    }

    //  Core bug: No monotonicity check
    // A newer price can be processed first, followed by an older-but-still-fresh price.
    // This enables oracle price rollback attacks.

    let asset_info_data: &mut AssetInfo =
        unsafe { &mut *(asset_info.borrow_mut_data_unchecked().as_mut_ptr() as *mut AssetInfo) };

    //  Overwrites state without checking if this price is newer than stored price
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
    pub update_slot: u64, // Replayable publish slot
    pub price: [u8; 8],
}

#[test]
fn test_non_canonical_oracle_accepted() {
    use solana_sdk::{
        account::Account,
        instruction::Instruction,
        signature::{Keypair, Signer},
    };

    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

    let mut svm = litesvm::LiteSVM::new();
    let (oracle, asset_info) = (Keypair::new(), Keypair::new());
    let fee_payer = Keypair::new();

    // Simulate current chain state at slot 17M
    svm.warp_to_slot(17_000_000);

    // Attacker-controlled oracle account with stale price (2 slots old, within MAX_AGE)
    // In reality, canonical feed might be at slot 17M with price 600,
    // but attacker provides slot 16,999,998 with price 500
    let oracle_update_slot: u64 = 16_999_998;
    let attacker_price: u64 = 500;

    let mut oracle_data = vec![];
    oracle_data.extend_from_slice(&oracle_update_slot.to_le_bytes());
    oracle_data.extend_from_slice(&attacker_price.to_le_bytes());

    //  VULNERABILITY: Any account owned by ORACLE_PROVIDER is accepted
    // Attacker can create their own feed with arbitrary data
    svm.set_account(
        oracle.pubkey(),
        Account {
            lamports: 1_000_000,
            data: oracle_data,
            owner: [0u8; 32].into(), // matches ORACLE_PROVIDER
            executable: false,
            rent_epoch: 100,
        },
    )
    .unwrap();

    svm.set_account(
        asset_info.pubkey(),
        Account {
            lamports: 1_000_000,
            data: [0u8; 16].to_vec(), // Empty state
            owner: crate::ID.into(),
            executable: false,
            rent_epoch: 100,
        },
    )
    .unwrap();

    svm.airdrop(&fee_payer.pubkey(), LAMPORTS_PER_SOL).unwrap();

    svm.add_program_from_file(
        &crate::ID.into(),
        "../../target/deploy/sneaky_oracle_insecure.so",
    )
    .unwrap();

    let tx = solana_sdk::transaction::Transaction::new(
        &[fee_payer.insecure_clone()],
        solana_sdk::message::Message::new(
            &[Instruction {
                program_id: crate::ID.into(),
                accounts: vec![
                    solana_sdk::instruction::AccountMeta::new_readonly(oracle.pubkey(), false),
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
        "Transaction should succeed (vulnerability!)"
    );

    // ✅ CRITICAL: Verify the attack actually worked
    // The protocol should have rejected this non-canonical feed, but it accepted it
    let acc = svm
        .get_account(&asset_info.pubkey())
        .expect("Asset account should exist");

    let stored_price = u64::from_le_bytes(acc.data[0..8].try_into().unwrap());
    let stored_slot = u64::from_le_bytes(acc.data[8..16].try_into().unwrap());

    assert_eq!(
        stored_price, attacker_price,
        "Price should be attacker's stale price"
    );
    assert_eq!(
        stored_slot, oracle_update_slot,
        "Slot should be attacker's stale slot"
    );

    println!(
        " Exploit successful: Accepted price {} from slot {} (current slot 17,000,000)",
        stored_price, stored_slot
    );
    println!("   Attacker can now arbitrage against this stale price!");
}
