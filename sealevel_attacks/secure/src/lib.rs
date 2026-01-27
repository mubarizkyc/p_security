#![allow(unexpected_cfgs)]
use pinocchio::{
    ProgramResult,
    account_info::AccountInfo,
    default_panic_handler, no_allocator, program_entrypoint,
    pubkey::{self, Pubkey},
};

/// Explicit discriminators to prevent type confusion
pub const PERSON_DISCRIMINATOR: u8 = 0;
pub const EMPLOYEE_DISCRIMINATOR: u8 = 1;

pinocchio_pubkey::declare_id!("ENrRns55VechXJiq4bMbdx7idzQh7tvaEJoYeWxRNe7Y");

// Entrypoint
program_entrypoint!(process_instruction);

// Disallow heap allocation
no_allocator!();

// no_std panic handler
default_panic_handler!();

#[inline(always)]
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    // Ensure the expected number of accounts is provided
    if accounts.len() < 3 {
        return Err(pinocchio::program_error::ProgramError::NotEnoughAccountKeys);
    }

    // Explicitly verify the Rent sysvar instead of trusting account order
    if accounts[0].key() != &pinocchio::sysvars::rent::RENT_ID {
        return Err(pinocchio::program_error::ProgramError::InvalidAccountData);
    }
    let _rent_account = &accounts[0];

    let (person, employee) = (&accounts[1], &accounts[2]);

    // Prevent aliasing the same account as two mutable inputs
    if person.key() == employee.key() {
        return Err(pinocchio::program_error::ProgramError::InvalidAccountData);
    }

    // Derive PDA canonically on-chain instead of accepting a user-supplied bump
    let (_pda, _bump) = pubkey::find_program_address(&[person.key().as_ref()], &crate::ID);

    // Enforce a discriminator to prevent type cosplay
    let person_data_raw = person.try_borrow_data()?;
    if person_data_raw.len() < 9 || person_data_raw[0] != PERSON_DISCRIMINATOR {
        return Err(pinocchio::program_error::ProgramError::InvalidAccountData);
    }

    // Safe only after discriminator and size checks
    let _person_data: &mut Person =
        unsafe { &mut *(person.borrow_mut_data_unchecked().as_mut_ptr() as *mut Person) };

    unsafe {
        // Mutate distinct accounts with deterministic state updates
        person.borrow_mut_data_unchecked().fill(11u8);
        employee.borrow_mut_data_unchecked().fill(12u8);
    }

    Ok(())
}

#[repr(C)]
struct Person {
    pub discriminator: u8,
    pub age: [u8; 8],
}

#[repr(C)]
struct _Employee {
    pub discriminator: u8,
    pub salary: [u8; 8],
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

    let (account_a, account_b) = (Keypair::new(), Keypair::new());
    let fee_payer = Keypair::new();

    // Initialize Person account with correct discriminator
    svm.set_account(
        account_a.pubkey(),
        Account {
            lamports: 100_000,
            data: [PERSON_DISCRIMINATOR; 9].to_vec(),
            owner: crate::ID.into(),
            executable: false,
            rent_epoch: 100,
        },
    )
    .unwrap();

    // Initialize Employee account with distinct discriminator
    svm.set_account(
        account_b.pubkey(),
        Account {
            lamports: 100_000,
            data: [EMPLOYEE_DISCRIMINATOR; 9].to_vec(),
            owner: crate::ID.into(),
            executable: false,
            rent_epoch: 100,
        },
    )
    .unwrap();

    svm.airdrop(&account_a.pubkey(), LAMPORTS_PER_SOL).unwrap();
    svm.airdrop(&account_b.pubkey(), LAMPORTS_PER_SOL).unwrap();
    svm.airdrop(&fee_payer.pubkey(), LAMPORTS_PER_SOL).unwrap();

    // Load secure program binary
    svm.add_program_from_file(&crate::ID.into(), "../../target/deploy/checks_secure.so")
        .unwrap();

    // Execute instruction with properly separated accounts
    let tx = solana_sdk::transaction::Transaction::new(
        &[
            fee_payer.insecure_clone(),
            account_a.insecure_clone(),
            account_b.insecure_clone(),
        ],
        solana_sdk::message::Message::new(
            &[Instruction {
                program_id: crate::ID.into(),
                accounts: vec![
                    solana_sdk::instruction::AccountMeta::new(solana_sdk::sysvar::rent::ID, false),
                    solana_sdk::instruction::AccountMeta::new(account_a.pubkey(), true),
                    solana_sdk::instruction::AccountMeta::new(account_b.pubkey(), true),
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
