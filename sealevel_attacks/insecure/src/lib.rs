#![allow(unexpected_cfgs)]
use pinocchio::{
    ProgramResult,
    account_info::AccountInfo,
    default_panic_handler, no_allocator, program_entrypoint,
    pubkey::{self, Pubkey},
};

pinocchio_pubkey::declare_id!("ENrRns55VechXJiq4bMbdx7idzQh7tvaEJoYeWxRNe7Y");

// Entrypoint
program_entrypoint!(process_instruction);

// Disable heap allocations
no_allocator!();

// Use no_std panic handler
default_panic_handler!();

#[inline(always)]
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    /*
        SECURITY ISSUES DEMONSTRATED IN THIS PoC:

        1. Unchecked sysvar account
        2. Non-canonical PDA derivation (user-controlled bump)
        3. Duplicate mutable accounts
        4. Type confusion ("type cosplay") via unchecked account data
    */

    // ISSUE: Instruction data is assumed to exist and be well-formed.
    // Only the first byte is used as a bump seed without validation.
    let bump = instruction_data[0];

    // ISSUE: Blindly trusting the first account to be the Rent sysvar.
    // No verification that accounts[0] == sysvar::rent::ID.
    let rent_account = &accounts[0];
    let _ = rent_account; // intentionally unused, shown only for demonstration

    // Accounts representing logical types, but without any validation.
    let (person, employee) = (&accounts[1], &accounts[2]);

    // ISSUE: Non-canonical PDA derivation.
    // The bump is attacker-controlled, allowing multiple valid PDAs.
    // Programs must either derive the bump internally or verify it strictly.
    let _pda = pubkey::create_program_address(&[person.key().as_ref(), &[bump]], &crate::ID)?;

    // ISSUE: Type confusion ("type cosplay").
    // No discriminator or owner/size checks are performed.
    // Any account with sufficient data length can be treated as `Person`.
    let _person_data: &mut Person =
        unsafe { &mut *(person.borrow_mut_data_unchecked().as_mut_ptr() as *mut Person) };

    unsafe {
        // ISSUE: Duplicate mutable accounts.
        // The same account can be passed for both `person` and `employee`,
        // causing multiple mutable references to the same underlying data.
        // This violates Rust aliasing guarantees and can corrupt state.
        person.borrow_mut_data_unchecked().fill(11u8);
        employee.borrow_mut_data_unchecked().fill(11u8);
    }

    Ok(())
}

#[repr(C)]
struct Person {
    pub age: [u8; 8],
}

#[repr(C)]
struct _Employee {
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
    let account_a = Keypair::new();
    let fee_payer = Keypair::new();

    // Create a single account reused for multiple logical roles.
    svm.set_account(
        account_a.pubkey(),
        Account {
            lamports: 100_000,
            data: [0u8; 8].to_vec(),
            owner: crate::ID.into(),
            executable: false,
            rent_epoch: 100,
        },
    )
    .unwrap();

    svm.airdrop(&account_a.pubkey(), LAMPORTS_PER_SOL).unwrap();
    svm.airdrop(&fee_payer.pubkey(), LAMPORTS_PER_SOL).unwrap();

    // Load the insecure program
    svm.add_program_from_file(&crate::ID.into(), "../../target/deploy/checks_insecure.so")
        .unwrap();

    // Construct a transaction where:
    // - The Rent sysvar is not validated
    // - The same account is passed twice as mutable
    // - No type or ownership checks are enforced
    let tx = solana_sdk::transaction::Transaction::new(
        &[fee_payer.insecure_clone(), account_a.insecure_clone()],
        solana_sdk::message::Message::new(
            &[Instruction {
                program_id: crate::ID.into(),
                accounts: vec![
                    solana_sdk::instruction::AccountMeta::new(solana_sdk::sysvar::rent::ID, false),
                    solana_sdk::instruction::AccountMeta::new(account_a.pubkey(), true),
                    solana_sdk::instruction::AccountMeta::new(account_a.pubkey(), true),
                ],
                data: vec![0u8], // attacker-controlled bump
            }],
            Some(&fee_payer.insecure_clone().pubkey()),
        ),
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);
    println!("tx result: {:?}", result);
}
