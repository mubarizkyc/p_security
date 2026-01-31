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

    //  WEAK VALIDATION: lamports > 0
    if parent_account.lamports() == 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    if child.units != 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Close child account (zero out data)
    {
        let mut data = child_account.try_borrow_mut_data()?;
        data.fill(0xff);
    }

    // Transfer lamports to user
    *user.try_borrow_mut_lamports()? += *child_account.try_borrow_lamports()?;
    *child_account.try_borrow_mut_lamports()? = 0;

    unsafe {
        child_account.assign(&pinocchio_system::ID);
    }
    child_account.realloc(0, false)?;

    Ok(())
}

///  CRITICAL VULNERABILITY: Close parent without checking for children
///
/// This allows the dangling pointer scenario:
/// 1. Parent closed here
/// 2. Child still stores parent's address (now pointing to closed account)
/// 3. Attacker recreates account at same address with malicious data
/// 4. Child's "parent" pointer now references attacker-controlled account
fn close_parent(accounts: &[AccountInfo]) -> ProgramResult {
    let parent_account = &accounts[0];
    let user = &accounts[1];

    //  MISSING: No check if child accounts still reference this parent!
    // No reference counting, no child validation - parent can be closed anytime

    {
        let mut data = parent_account.try_borrow_mut_data()?;
        data.fill(0xff);
    }

    // Transfer lamports to user
    *user.try_borrow_mut_lamports()? += *parent_account.try_borrow_lamports()?;
    *parent_account.try_borrow_mut_lamports()? = 0;

    unsafe {
        parent_account.assign(&pinocchio_system::ID);
    }
    parent_account.realloc(0, false)?;

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

    /// Dangling Pointer Exploit Test
    ///
    /// Attack Flow:
    /// 1. Create legitimate parent with sensitive data (5 units)
    /// 2. Create child that trusts this parent (stores parent's address)
    /// 3. ❌ VULNERABILITY: Close parent while child still references it
    /// 4. Child now has dangling pointer to closed address
    /// 5. Attacker recreates account at same address with MALICIOUS data (999 units)
    /// 6. Child's parent pointer now references attacker-controlled account
    #[test]
    fn test_dangling_pointer_exploit() {
        let mut svm = litesvm::LiteSVM::new();
        let user = Keypair::new();
        let parent = Keypair::new();
        let child = Keypair::new();

        svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();
        svm.add_program_from_file(crate::id(), "../../target/deploy/dp_insecure.so")
            .unwrap();

        // Setup: Create legitimate parent with 5 units
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

        // Setup: Create child pointing to legitimate parent
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

        // STEP 1: Close parent (this is the vulnerability - no child check!)
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
        assert!(
            result.is_ok(),
            "Parent closed despite active child reference"
        );
        println!("❌ Vulnerability: Parent closed while child still references it");

        // STEP 2: Simulate attacker reclaiming the address
        // In a real exploit, attacker creates new account at parent's address
        // We simulate this by recreating with different (malicious) data
        let malicious_data = {
            let mut d = vec![0u8; 8];
            d[..8].copy_from_slice(&999u64.to_le_bytes()); // Attacker sets units to 999
            d
        };

        svm.set_account(
            parent.pubkey(),
            Account {
                lamports: 1_000_000,
                data: malicious_data,
                owner: crate::id().into(), // Attacker controls this account now
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        println!("❌ Attacker recreated parent address with malicious data (999 units)");

        // STEP 3: Child closure attempts to validate parent
        // Child's logic: if parent.lamports > 0, trust it
        // Attacker's recreated account has lamports > 0, so check passes!
        // Child now processes based on attacker-controlled "parent" data

        let close_child_ix = Instruction {
            program_id: crate::id().into(),
            accounts: vec![
                AccountMeta::new(child.pubkey(), false),
                AccountMeta::new(parent.pubkey(), false), // ❌ Points to attacker account!
                AccountMeta::new(user.pubkey(), true),
            ],
            data: vec![0u8], // close_child
        };

        let close_child_tx = Transaction::new_signed_with_payer(
            &[close_child_ix],
            Some(&user.pubkey()),
            &[&user],
            svm.latest_blockhash(),
        );

        let result = svm.send_transaction(close_child_tx);

        // In the insecure version, this might succeed or behave unexpectedly
        // because it's reading from attacker-controlled parent data
        println!(
            "Child closure result (interacting with malicious parent): {:?}",
            result
        );

        // The core vulnerability is demonstrated: child has a dangling pointer
        // that now references attacker-controlled state
        println!(
            "❌ Exploit complete: Child's parent pointer is now dangling (references attacker account)"
        );
    }
}
