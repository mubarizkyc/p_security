#![allow(unexpected_cfgs)]
use pinocchio::{
    ProgramResult,
    account_info::AccountInfo,
    default_panic_handler, no_allocator, program_entrypoint,
    pubkey::{self, Pubkey},
    sysvars::Sysvar,
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

#[inline(always)]
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let oracle = &accounts[0];
    let asset_info = &accounts[1];

    //  Only checks oracle *program ownership*
    // Any user can create an account owned by the oracle program
    if oracle.owner() != ORACLE_PROVIDER.as_ref() {
        return Err(pinocchio::program_error::ProgramError::IllegalOwner);
    }

    //  Blindly trust oracle account contents
    // No canonical feed key validation
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

    //  Core bug:
    // A newer price can be processed first,
    // followed by an older-but-still-valid price.
    // This enables oracle price rollback.

    let asset_info_data: &mut AssetInfo =
        unsafe { &mut *(asset_info.borrow_mut_data_unchecked().as_mut_ptr() as *mut AssetInfo) };

    //  Overwrites state without monotonicity check
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
fn test_program() {
    use solana_sdk::{
        account::Account,
        instruction::Instruction,
        signature::{Keypair, Signer},
    };

    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

    let mut svm = litesvm::LiteSVM::new();
    let (oracle, asset_info) = (Keypair::new(), Keypair::new());
    let fee_payer = Keypair::new();

    // Simulate current chain state
    svm.warp_to_slot(17_000_000);

    // Oracle update is older, but still within PRICE_MAX_AGE
    let oracle_update_slot: u64 = 16_999_998;

    let mut data = vec![];
    data.extend_from_slice(&oracle_update_slot.to_le_bytes());
    data.extend_from_slice(&500u64.to_le_bytes()); // price

    //  Attacker-controlled oracle account
    svm.set_account(
        oracle.pubkey(),
        Account {
            lamports: 1_000_000,
            data,
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
            data: [0u8; 16].to_vec(),
            owner: crate::ID.into(),
            executable: false,
            rent_epoch: 100,
        },
    )
    .unwrap();

    svm.airdrop(&oracle.pubkey(), LAMPORTS_PER_SOL).unwrap();
    svm.airdrop(&asset_info.pubkey(), LAMPORTS_PER_SOL).unwrap();
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
            Some(&fee_payer.insecure_clone().pubkey()),
        ),
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);
    println!("tx result: {:?}", result);
}
