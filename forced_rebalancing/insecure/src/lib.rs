#![allow(unexpected_cfgs)]
use pinocchio::{
    ProgramResult, account_info::AccountInfo, default_panic_handler, no_allocator,
    program_entrypoint, program_error::ProgramError, pubkey::Pubkey,
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
    let (ix_disc, instruction_data) = instruction_data
        .split_first()
        .ok_or(pinocchio::program_error::ProgramError::InvalidInstructionData)?;

    match ix_disc {
        0 => {
            // Deposit stake into the pool
            deposit_stake(accounts, instruction_data)?;
        }
        1 => {
            // Withdraw stake from a single validator
            withdraw_stake(accounts, instruction_data)?;
        }
        _ => {
            return Err(pinocchio::program_error::ProgramError::InvalidInstructionData);
        }
    }
    Ok(())
}

fn deposit_stake(
    accounts: &[AccountInfo],
    data: &[u8],
) -> Result<(), pinocchio::program_error::ProgramError> {
    // All passed accounts are treated as validators
    let validators = accounts;

    let stake = unsafe { *(data[0..8].as_ptr() as *const u64) };

    // Evenly split deposit across all validators
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

fn withdraw_stake(
    accounts: &[AccountInfo],
    data: &[u8],
) -> Result<(), pinocchio::program_error::ProgramError> {
    // User chooses which validator to withdraw from
    let validator_to_withdraw = &accounts[0];

    let stake = unsafe { *(data[0..8].as_ptr() as *const u64) };

    let validator_data: &mut Validator = unsafe {
        &mut *(validator_to_withdraw
            .borrow_mut_data_unchecked()
            .as_mut_ptr() as *mut Validator)
    };

    let current_stake = u64::from_le_bytes(validator_data.stake_amount);

    // No balancing or global invariant enforced
    let new_stake = current_stake
        .checked_sub(stake)
        .ok_or(pinocchio::program_error::ProgramError::InvalidAccountData)?;

    validator_data.stake_amount = new_stake.to_le_bytes();

    Ok(())
}

#[repr(C)]
struct Validator {
    pub stake_amount: [u8; 8],
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
    let (validator_a, validator_b, validator_c) = (Keypair::new(), Keypair::new(), Keypair::new());
    let fee_payer = Keypair::new();
    let stake = 3u64;
    svm.set_account(
        validator_a.pubkey(),
        Account {
            lamports: 1000_000,
            data: stake.to_le_bytes().to_vec(),
            owner: crate::ID.into(),
            executable: false,
            rent_epoch: 100,
        },
    )
    .unwrap();
    svm.set_account(
        validator_b.pubkey(),
        Account {
            lamports: 1000_000,
            data: stake.to_le_bytes().to_vec(),
            owner: crate::ID.into(),
            executable: false,
            rent_epoch: 100,
        },
    )
    .unwrap();
    svm.set_account(
        validator_c.pubkey(),
        Account {
            lamports: 1000_000,
            data: stake.to_le_bytes().to_vec(),
            owner: crate::ID.into(),
            executable: false,
            rent_epoch: 100,
        },
    )
    .unwrap();
    svm.airdrop(&validator_a.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    svm.airdrop(&validator_b.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    svm.airdrop(&validator_c.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    svm.airdrop(&fee_payer.pubkey(), LAMPORTS_PER_SOL).unwrap();
    svm.add_program_from_file(
        &crate::ID.into(),
        "../../target/deploy/rebalancing_insecure.so",
    )
    .unwrap();
    let mut data = vec![0u8];
    data.extend_from_slice(&3u64.to_le_bytes()); // stake to deposit
    let deposit_1 = Instruction {
        program_id: crate::ID.into(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(validator_a.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(validator_b.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(validator_c.pubkey(), false),
        ],

        data,
    };
    data = vec![1u8];
    data.extend_from_slice(&3u64.to_le_bytes()); // stake to withdraw
    let withdraw_1 = Instruction {
        program_id: crate::ID.into(),
        accounts: vec![solana_sdk::instruction::AccountMeta::new(
            validator_a.pubkey(),
            false,
        )],

        data,
    };
    data = vec![0u8];
    data.extend_from_slice(&3u64.to_le_bytes()); // stake to deposit
    let deposit_2 = Instruction {
        program_id: crate::ID.into(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(validator_a.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(validator_b.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(validator_c.pubkey(), false),
        ],

        data,
    };
    data = vec![1u8];
    data.extend_from_slice(&3u64.to_le_bytes()); // stake to withdraw
    let withdraw_2 = Instruction {
        program_id: crate::ID.into(),
        accounts: vec![solana_sdk::instruction::AccountMeta::new(
            validator_b.pubkey(),
            false,
        )],

        data,
    };
    let tx = solana_sdk::transaction::Transaction::new(
        &[fee_payer.insecure_clone()],
        solana_sdk::message::Message::new(
            &[deposit_1, withdraw_1, deposit_2, withdraw_2],
            Some(&fee_payer.insecure_clone().pubkey()),
        ),
        svm.latest_blockhash(),
    );
    let result = svm.send_transaction(tx);

    println!("tx result: {:?}", result);
} //this is insecure poc,kinldy give me secure poc ,wirh test cases
