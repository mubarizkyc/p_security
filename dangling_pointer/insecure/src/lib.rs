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
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    match instruction_data[0] {
        0 => close_child(accounts),
        1 => close_parent(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/*
INSECURE: Dangling Pointer Vulnerability

This code demonstrates a dangling pointer vulnerability:
1. A parent account is created
2. Child accounts store the parent's address as a pointer
3. The parent can be closed at ANY TIME without checking for children
4. This leaves children with dangling pointers to a closed account
5. The closed parent address can be recreated with different data
6. Children now point to potentially malicious accounts
*/

#[repr(C)]
struct _ParentAccount {
    pub units: u64,
}

#[repr(C)]
struct ChildAccount {
    pub parent: Pubkey,
    pub units: u64,
}

fn close_child(accounts: &[AccountInfo]) -> ProgramResult {
    let child_account = &accounts[0];
    let parent_account = &accounts[1];
    let user = &accounts[2];

    let child =
        unsafe { &*(child_account.borrow_data_unchecked().as_ptr() as *const ChildAccount) };

    // VULNERABILITY
    // lamports > 0 does NOT mean this is a valid parent account.
    // The account may have been closed and recreated.
    // A closed parent will have 0 lamports, but this doesn't validate the pointer!
    if parent_account.lamports() == 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    if child.units != 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Close the child account
    {
        let mut data = child_account.try_borrow_mut_data()?;
        data[0] = 0xff;
    }

    *user.try_borrow_mut_lamports()? += *child_account.try_borrow_lamports()?;

    unsafe {
        child_account.assign(&pinocchio_system::ID);
    }

    child_account.resize(0)?;
    child_account.close()
}

fn close_parent(accounts: &[AccountInfo]) -> ProgramResult {
    let parent_account = &accounts[0];
    let user = &accounts[1];

    // CRITICAL VULNERABILITY: No check for existing children!
    // Parent can be closed even if children still reference it

    {
        let mut data = parent_account.try_borrow_mut_data()?;
        data[0] = 0xff;
    }

    *user.try_borrow_mut_lamports()? += *parent_account.try_borrow_lamports()?;

    unsafe {
        parent_account.assign(&pinocchio_system::ID);
    }
    parent_account.resize(0)?;
    parent_account.close()
}

#[cfg(test)]
mod tests {

    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    #[test]
    fn test_dangling_pointer_attack() {
        let mut svm = litesvm::LiteSVM::new();

        let user = Keypair::new();
        let parent = Keypair::new();
        let child = Keypair::new();

        svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();

        svm.add_program_from_file(crate::id(), "../../target/deploy/dp_insecure.so")
            .unwrap();

        // Create parent account with 5 units
        let mut parent_data = vec![0u8; 8];
        parent_data[..8].copy_from_slice(&5u64.to_le_bytes());

        svm.set_account(
            parent.pubkey(),
            Account {
                lamports: 1_000_000,
                data: parent_data,
                owner: crate::id().into(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Create child account pointing to parent with 5 units
        let mut child_data = vec![0u8; 40];
        child_data[..32].copy_from_slice(&parent.pubkey().to_bytes());
        child_data[32..40].copy_from_slice(&5u64.to_le_bytes());

        svm.set_account(
            child.pubkey(),
            Account {
                lamports: 1_000_000,
                data: child_data,
                owner: crate::id().into(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // ATTACK: Close parent first (should fail but doesn't in insecure version)
        let close_parent_tx = Transaction::new_signed_with_payer(
            &[Instruction {
                program_id: crate::id().into(),
                accounts: vec![
                    AccountMeta::new(parent.pubkey(), false),
                    AccountMeta::new(user.pubkey(), true),
                ],
                data: vec![1u8], // close_parent instruction
            }],
            Some(&user.pubkey()),
            &[&user],
            svm.latest_blockhash(),
        );

        // VULNERABILITY: This succeeds when it should fail!
        let result = svm.send_transaction(close_parent_tx);
        println!("Close parent result: {:?}", result);
        assert!(result.is_ok(), "Parent closed despite having children!");

        // Now child has a dangling pointer - parent account is closed
        // The parent address could be recreated with malicious data

        // Attempting to close child should fail (parent is gone)
        let close_child_tx = Transaction::new_signed_with_payer(
            &[Instruction {
                program_id: crate::id().into(),
                accounts: vec![
                    AccountMeta::new(child.pubkey(), false),
                    AccountMeta::new(parent.pubkey(), false),
                    AccountMeta::new(user.pubkey(), true),
                ],
                data: vec![0u8], // close_child instruction
            }],
            Some(&user.pubkey()),
            &[&user],
            svm.latest_blockhash(),
        );

        let result = svm.send_transaction(close_child_tx);
        // This should fail because parent is closed (lamports == 0)
        assert!(
            result.is_err(),
            "Child closure should fail when parent is gone"
        );
    }
}
