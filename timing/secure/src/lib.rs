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

/// SECURE IMPLEMENTATION: Strict Time Boundaries
///
/// Fix: Eliminate boundary overlap by using half-open intervals [start, end) for deposits
/// and [claim_time, ∞) for claims. When end_time == claim_time, no timestamp satisfies
/// both conditions simultaneously, preventing same-slot deposit+claim attacks.
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

    // FIX: Strict boundary [start_time, end_time)
    // Rejects deposits at exactly end_time, preventing overlap with claim window
    if now < pool.start_time || now >= pool.end_time {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Overflow protection: saturating math prevents deposit manipulation
    user.deposited = user.deposited.saturating_add(amount);
    pool.total_deposited = pool.total_deposited.saturating_add(amount);

    Ok(())
}

pub fn claim(accounts: &[AccountInfo]) -> ProgramResult {
    let pool = unsafe { &mut *(accounts[0].borrow_mut_data_unchecked().as_mut_ptr() as *mut Pool) };
    let user = unsafe { &mut *(accounts[1].borrow_mut_data_unchecked().as_mut_ptr() as *mut User) };

    let now = pinocchio::sysvars::clock::Clock::get()?.unix_timestamp;

    // FIX: Strict boundary [claim_time, ∞)
    // Requires timestamp >= claim_time, but deposit already rejected at end_time
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

#[cfg(test)]
mod tests {
    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    /// FIX VERIFICATION: Deposit rejected at end_time boundary
    ///
    /// Setup: end_time == claim_time == 100
    /// Insecure: deposit at t=100 succeeds → claim at t=100 succeeds (exploit)
    /// Secure: deposit at t=100 fails (now >= end_time), breaking the attack chain
    #[test]
    fn test_secure_reject_deposit_at_boundary() {
        let mut svm = litesvm::LiteSVM::new();
        let user = Keypair::new();
        let pool = Keypair::new();
        let user_state = Keypair::new();

        svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();
        svm.add_program_from_file(crate::id(), "../../target/deploy/timing_secure.so")
            .unwrap();

        let t: i64 = 100;

        // Critical configuration: deposit window ends exactly when claim window opens
        svm.set_account(
            pool.pubkey(),
            Account {
                lamports: 1_000_000,
                data: {
                    let mut d = vec![];
                    d.extend_from_slice(&0i64.to_le_bytes()); // start_time
                    d.extend_from_slice(&t.to_le_bytes()); // end_time = 100
                    d.extend_from_slice(&t.to_le_bytes()); // claim_time = 100
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

        // Set clock to the overlap point
        let mut clock = svm.get_sysvar::<solana_sdk::sysvar::clock::Clock>();
        clock.unix_timestamp = t;
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

        // FIX CONFIRMED: Strict boundary rejects deposit at end_time
        assert!(result.is_err(), "Fix working: Deposit rejected at boundary");
    }

    /// FIX VERIFICATION: Claim succeeds at claim_time when deposit window is closed
    ///
    /// Setup: end_time = 499, claim_time = 500
    /// At t=500: deposit fails (500 >= 499), claim succeeds (500 >= 500)
    /// This ensures legitimate users can claim while preventing new deposits
    #[test]
    fn test_secure_claim_at_claim_time() {
        let mut svm = litesvm::LiteSVM::new();
        let user = Keypair::new();
        let pool = Keypair::new();
        let user_state = Keypair::new();

        svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();
        svm.add_program_from_file(crate::id(), "../../target/deploy/timing_secure.so")
            .unwrap();

        let t: i64 = 500;

        // Gap between end_time (499) and claim_time (500) - no overlap possible
        svm.set_account(
            pool.pubkey(),
            Account {
                lamports: 1_000_000,
                data: {
                    let mut d = vec![];
                    d.extend_from_slice(&0i64.to_le_bytes());
                    d.extend_from_slice(&(t - 1).to_le_bytes()); // end_time = 499
                    d.extend_from_slice(&t.to_le_bytes()); // claim_time = 500
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
        clock.unix_timestamp = t; // Exactly at claim time
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

        // Legitimate claim succeeds at claim_time
        assert!(result.is_ok(), "Fix working: Claim allowed at claim_time");
    }
}
