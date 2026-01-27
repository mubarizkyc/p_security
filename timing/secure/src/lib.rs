#![allow(unexpected_cfgs)]
use pinocchio::{
    ProgramResult, account_info::AccountInfo, default_panic_handler, no_allocator,
    program_entrypoint, program_error::ProgramError, pubkey::Pubkey, sysvars::Sysvar,
};
pinocchio_pubkey::declare_id!("ENrRns55VechXJiq4bMbdx7idzQh7tvaEJoYeWxRNe7Y");
// This is the entrypoint for the program.
program_entrypoint!(process_instruction);
//Do not allocate memory.
no_allocator!();
// Use the no_std panic handler.
default_panic_handler!();
#[inline(always)]
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    match instruction_data[0] {
        0 => deposit(accounts, &instruction_data[1..]),
        1 => claim(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[repr(C)]
pub struct Pool {
    pub start_time: i64,
    pub end_time: i64,
    pub claim_time: i64,
    pub total_deposited: u64,
}

#[repr(C)]
pub struct User {
    pub deposited: u64,
    pub claimed: bool,
}

pub fn deposit(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let amount = u64::from_le_bytes(data[..8].try_into().unwrap());

    let pool = unsafe { &mut *(accounts[0].borrow_mut_data_unchecked().as_mut_ptr() as *mut Pool) };
    let user = unsafe { &mut *(accounts[1].borrow_mut_data_unchecked().as_mut_ptr() as *mut User) };

    let now = pinocchio::sysvars::clock::Clock::get()?.unix_timestamp;

    // ✅ STRICT boundary
    // start <= now < end
    if now < pool.start_time || now >= pool.end_time {
        return Err(ProgramError::InvalidInstructionData);
    }

    user.deposited = user.deposited.saturating_add(amount);
    pool.total_deposited = pool.total_deposited.saturating_add(amount);

    Ok(())
}

pub fn claim(accounts: &[AccountInfo]) -> ProgramResult {
    let pool = unsafe { &mut *(accounts[0].borrow_mut_data_unchecked().as_mut_ptr() as *mut Pool) };
    let user = unsafe { &mut *(accounts[1].borrow_mut_data_unchecked().as_mut_ptr() as *mut User) };

    let now = pinocchio::sysvars::clock::Clock::get()?.unix_timestamp;

    // ✅ STRICT boundary
    // claim only AFTER claim_time
    if now < pool.claim_time {
        return Err(ProgramError::InvalidInstructionData);
    }

    if user.claimed {
        return Err(ProgramError::InvalidAccountData);
    }

    let reward = user.deposited.saturating_mul(1_000) / pool.total_deposited.max(1);

    user.claimed = true;

    let _ = reward; // mint reward

    Ok(())
}
#[test]
fn test_secure_reject_deposit_at_boundary() {
    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    let mut svm = litesvm::LiteSVM::new();

    let user = Keypair::new();
    let pool = Keypair::new();
    let user_state = Keypair::new();

    svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();

    svm.add_program_from_file(crate::id(), "../../target/deploy/timing_secure.so")
        .unwrap();

    let t: i64 = 100;

    // end_time == claim_time
    svm.set_account(
        pool.pubkey(),
        Account {
            lamports: 1_000_000,
            data: {
                let mut d = vec![];
                d.extend_from_slice(&0i64.to_le_bytes()); // start
                d.extend_from_slice(&t.to_le_bytes()); // end
                d.extend_from_slice(&t.to_le_bytes()); // claim
                d.extend_from_slice(&1u64.to_le_bytes());
                d
            },
            owner: crate::id().into(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    svm.set_account(
        user_state.pubkey(),
        Account {
            lamports: 1_000_000,
            data: {
                let mut d = vec![];
                d.extend_from_slice(&0u64.to_le_bytes());
                d.push(0);
                d
            },
            owner: crate::id().into(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    let mut clock = svm.get_sysvar::<solana_sdk::sysvar::clock::Clock>();
    clock.unix_timestamp = t; //some programs require specififc timestamp to allow swap
    svm.set_sysvar::<solana_sdk::sysvar::clock::Clock>(&clock);

    let deposit_ix = Instruction {
        program_id: crate::id().into(),
        accounts: vec![
            AccountMeta::new(pool.pubkey(), false),
            AccountMeta::new(user_state.pubkey(), false),
        ],
        data: {
            let mut d = vec![0u8];
            d.extend_from_slice(&100u64.to_le_bytes());
            d
        },
    };

    let tx = Transaction::new(
        &[user.insecure_clone()],
        solana_sdk::message::Message::new(&[deposit_ix], Some(&user.pubkey())),
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);

    // ✅ FIX: deposit is rejected
    assert!(result.is_err());
}
#[test]
fn test_secure_claim_at_claim_time() {
    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    let mut svm = litesvm::LiteSVM::new();

    let user = Keypair::new();
    let pool = Keypair::new();
    let user_state = Keypair::new();

    svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();

    svm.add_program_from_file(crate::id(), "../../target/deploy/timing_secure.so")
        .unwrap();

    let t: i64 = 500;

    svm.set_account(
        pool.pubkey(),
        Account {
            lamports: 1_000_000,
            data: {
                let mut d = vec![];
                d.extend_from_slice(&0i64.to_le_bytes());
                d.extend_from_slice(&(t - 1).to_le_bytes()); // end
                d.extend_from_slice(&t.to_le_bytes()); // claim
                d.extend_from_slice(&100u64.to_le_bytes());
                d
            },
            owner: crate::id().into(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    svm.set_account(
        user_state.pubkey(),
        Account {
            lamports: 1_000_000,
            data: {
                let mut d = vec![];
                d.extend_from_slice(&10u64.to_le_bytes());
                d.push(0); // not claimed
                d
            },
            owner: crate::id().into(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    let mut clock = svm.get_sysvar::<solana_sdk::sysvar::clock::Clock>();
    clock.unix_timestamp = t; //some programs require specififc timestamp to allow swap
    svm.set_sysvar::<solana_sdk::sysvar::clock::Clock>(&clock);

    let claim_ix = Instruction {
        program_id: crate::id().into(),
        accounts: vec![
            AccountMeta::new(pool.pubkey(), false),
            AccountMeta::new(user_state.pubkey(), false),
        ],
        data: vec![1u8],
    };

    let tx = Transaction::new(
        &[user.insecure_clone()],
        solana_sdk::message::Message::new(&[claim_ix], Some(&user.pubkey())),
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);

    // ✅ claim succeeds
    assert!(result.is_ok());
}
