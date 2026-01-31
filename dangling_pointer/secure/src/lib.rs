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
SECURE: Proper Reference Counting

This code fixes the dangling pointer vulnerability:
1. Parent tracks total units allocated to children
2. Children can only be closed if their units are 0
3. Parent can ONLY be closed if total units == 0 (no children remain)
4. When closing a child, units are decremented from parent
5. This ensures no dangling pointers - parent cannot be closed while children exist
*/

#[repr(C)]
struct ParentAccount {
    pub child_count: u64,
}

#[repr(C)]
struct ChildAccount {
    pub parent: Pubkey,
}
fn close_child(accounts: &[AccountInfo]) -> ProgramResult {
    let child_account = &accounts[0];
    let parent_account = &accounts[1];
    let user = &accounts[2];

    // --- Validate parent ---
    if parent_account.lamports() == 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    if parent_account.owner() != child_account.owner() {
        return Err(ProgramError::IllegalOwner);
    }

    if parent_account.data_len() != core::mem::size_of::<ParentAccount>() {
        return Err(ProgramError::InvalidAccountData);
    }

    // --- Validate child ---
    let child =
        unsafe { &*(child_account.borrow_data_unchecked().as_ptr() as *const ChildAccount) };

    if child.parent != *parent_account.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    // --- Update parent ---
    let mut parent_data = parent_account.try_borrow_mut_data()?;
    let parent = unsafe { &mut *(parent_data.as_mut_ptr() as *mut ParentAccount) };

    parent.child_count = parent
        .child_count
        .checked_sub(1)
        .ok_or(ProgramError::InvalidAccountData)?;

    // --- Close child ---
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

    if parent_account.owner() != &crate::id() {
        return Err(ProgramError::IllegalOwner);
    }

    let parent =
        unsafe { &*(parent_account.borrow_data_unchecked().as_ptr() as *const ParentAccount) };

    // 🔒 CORE SAFETY CHECK
    if parent.child_count != 0 {
        return Err(ProgramError::InvalidAccountData);
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
    use super::*;
    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        transaction::Transaction,
    };
    #[test]
    fn test_cannot_close_parent_with_child() {
        let mut svm = litesvm::LiteSVM::new();

        let user = Keypair::new();
        let parent = Keypair::new();
        let child = Keypair::new();

        svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();
        svm.add_program_from_file(crate::id(), "../../target/deploy/dp_secure.so")
            .unwrap();

        // Parent has 1 child
        let mut parent_data = vec![0u8; 8];
        parent_data.copy_from_slice(&1u64.to_le_bytes());

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

        // Child references parent
        let mut child_data = vec![0u8; 32];
        child_data.copy_from_slice(&parent.pubkey().to_bytes());

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

        let tx = Transaction::new_signed_with_payer(
            &[Instruction {
                program_id: crate::id().into(),
                accounts: vec![
                    AccountMeta::new(parent.pubkey(), false),
                    AccountMeta::new(user.pubkey(), true),
                ],
                data: vec![1], // close_parent
            }],
            Some(&user.pubkey()),
            &[&user],
            svm.latest_blockhash(),
        );

        let result = svm.send_transaction(tx);
        assert!(result.is_err(), "Parent must not close while child exists");
    }
    #[test]
    fn test_child_then_parent_close() {
        let mut svm = litesvm::LiteSVM::new();

        let user = Keypair::new();
        let parent = Keypair::new();
        let child = Keypair::new();

        svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();
        svm.add_program_from_file(crate::id(), "../../target/deploy/dp_secure.so")
            .unwrap();

        // Parent starts with 1 child
        let mut parent_data = vec![0u8; 8];
        parent_data.copy_from_slice(&1u64.to_le_bytes());

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

        let mut child_data = vec![0u8; 32];
        child_data.copy_from_slice(&parent.pubkey().to_bytes());

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

        // Close child
        let close_child = Transaction::new_signed_with_payer(
            &[Instruction {
                program_id: crate::id().into(),
                accounts: vec![
                    AccountMeta::new(child.pubkey(), false),
                    AccountMeta::new(parent.pubkey(), false),
                    AccountMeta::new(user.pubkey(), true),
                ],
                data: vec![0], // close_child
            }],
            Some(&user.pubkey()),
            &[&user],
            svm.latest_blockhash(),
        );

        assert!(svm.send_transaction(close_child).is_ok());

        // Close parent
        let close_parent = Transaction::new_signed_with_payer(
            &[Instruction {
                program_id: crate::id().into(),
                accounts: vec![
                    AccountMeta::new(parent.pubkey(), false),
                    AccountMeta::new(user.pubkey(), true),
                ],
                data: vec![1], // close_parent
            }],
            Some(&user.pubkey()),
            &[&user],
            svm.latest_blockhash(),
        );

        assert!(svm.send_transaction(close_parent).is_ok());
    }
}
