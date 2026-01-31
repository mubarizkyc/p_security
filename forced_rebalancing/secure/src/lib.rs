#![allow(unexpected_cfgs)]

use pinocchio::{
    ProgramResult, account_info::AccountInfo, default_panic_handler, no_allocator,
    program_entrypoint, pubkey::Pubkey,
};

pinocchio_pubkey::declare_id!("ENrRns55VechXJiq4bMbdx7idzQh7tvaEJoYeWxRNe7Y");

program_entrypoint!(process_instruction);
no_allocator!();
default_panic_handler!();

/// SECURE: Enforces global stake invariant via forced rebalancing
///
/// Fix: All operations (deposit/withdraw) update global total_stake, then
/// forcibly rebalance all validators to equal shares. Users cannot cherry-pick
/// which validators to withdraw from—distribution is always uniform.
#[inline(always)]
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (ix, data) = instruction_data
        .split_first()
        .ok_or(pinocchio::program_error::ProgramError::InvalidInstructionData)?;

    match ix {
        0 => deposit(accounts, data),
        1 => withdraw(accounts, data),
        _ => Err(pinocchio::program_error::ProgramError::InvalidInstructionData),
    }
}

/// ✅ Deposit increases global total, then forces even redistribution
fn deposit(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let amount = u64::from_le_bytes(data[..8].try_into().unwrap());
    let pool = &accounts[0];
    let authority = &accounts[1];
    let validators = &accounts[2..];

    enforce_authority(pool, authority)?;

    let pool_state = unsafe { &mut *(pool.borrow_mut_data_unchecked().as_mut_ptr() as *mut Pool) };

    pool_state.total_stake = pool_state
        .total_stake
        .checked_add(amount)
        .ok_or(pinocchio::program_error::ProgramError::InvalidAccountData)?;

    // ✅ Always rebalance after state change
    rebalance(pool_state.total_stake, validators)
}

/// ✅ Withdraw decreases global total, then forces even redistribution
fn withdraw(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let amount = u64::from_le_bytes(data[..8].try_into().unwrap());
    let pool = &accounts[0];
    let authority = &accounts[1];
    let validators = &accounts[2..];

    enforce_authority(pool, authority)?;

    let pool_state = unsafe { &mut *(pool.borrow_mut_data_unchecked().as_mut_ptr() as *mut Pool) };

    pool_state.total_stake = pool_state
        .total_stake
        .checked_sub(amount)
        .ok_or(pinocchio::program_error::ProgramError::InvalidAccountData)?;

    // ✅ Always rebalance—prevents selective withdrawal drain
    rebalance(pool_state.total_stake, validators)
}

/// ✅ Forces equal distribution of total stake across all validators
/// Remainder (total % count) is distributed 1 lamport per validator until exhausted
fn rebalance(total: u64, validators: &[AccountInfo]) -> ProgramResult {
    let count = validators.len() as u64;
    if count == 0 {
        return Err(pinocchio::program_error::ProgramError::InvalidAccountData);
    }

    let base = total / count;
    let mut remainder = total % count;

    for v in validators {
        let vstate =
            unsafe { &mut *(v.borrow_mut_data_unchecked().as_mut_ptr() as *mut Validator) };

        // Distribute remainder 1:1 to first N validators
        let extra = if remainder > 0 {
            remainder -= 1;
            1
        } else {
            0
        };

        vstate.stake_amount = base + extra;
    }

    Ok(())
}

fn enforce_authority(pool: &AccountInfo, authority: &AccountInfo) -> ProgramResult {
    if !authority.is_signer() {
        return Err(pinocchio::program_error::ProgramError::MissingRequiredSignature);
    }

    let pool_state = unsafe { &*(pool.borrow_data_unchecked().as_ptr() as *const Pool) };

    if authority.key() != &pool_state.authority {
        return Err(pinocchio::program_error::ProgramError::IllegalOwner);
    }

    Ok(())
}

#[repr(C)]
struct Pool {
    pub authority: Pubkey,
    pub total_stake: u64,
}

#[repr(C)]
struct Validator {
    pub stake_amount: u64,
}

/// ✅ FIX VERIFICATION: Forced rebalancing maintains invariant
///
/// Sequence: Deposit 3 (each gets 1), Withdraw 3 (each goes to 0),
/// Deposit 3 (each gets 1), Withdraw 3 (each goes to 0)
///
/// Key: Validators always remain balanced (equal stake) throughout operations
#[test]
fn test_secure_rebalancing_maintains_balance() {
    use litesvm::LiteSVM;
    use solana_sdk::{
        account::Account,
        instruction::Instruction,
        message::Message,
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    let mut svm = LiteSVM::new();
    let pool = Keypair::new();
    let authority = Keypair::new();
    let fee_payer = Keypair::new();
    let (va, vb, vc) = (Keypair::new(), Keypair::new(), Keypair::new());

    // Setup pool with authority
    let mut pool_data = vec![0u8; 40];
    pool_data[..32].copy_from_slice(authority.pubkey().as_ref());
    svm.set_account(
        pool.pubkey(),
        Account {
            lamports: 1_000_000,
            data: pool_data,
            owner: crate::ID.into(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    // Setup validators at 0 stake
    for v in [&va, &vb, &vc] {
        svm.set_account(
            v.pubkey(),
            Account {
                lamports: 1_000_000,
                data: 0u64.to_le_bytes().to_vec(),
                owner: crate::ID.into(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    }

    for k in [&authority, &fee_payer] {
        svm.airdrop(&k.pubkey(), 1_000_000_000).unwrap();
    }

    svm.add_program_from_file(
        &crate::ID.into(),
        "../../target/deploy/rebalancing_secure.so",
    )
    .unwrap();

    let make_ix = |disc, amt: u64| Instruction {
        program_id: crate::ID.into(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(pool.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(authority.pubkey(), true),
            solana_sdk::instruction::AccountMeta::new(va.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(vb.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(vc.pubkey(), false),
        ],
        data: {
            let mut d = vec![disc];
            d.extend_from_slice(&amt.to_le_bytes());
            d
        },
    };

    // Helper to check if validators are balanced
    let assert_balanced = |svm: &LiteSVM| {
        let sa = u64::from_le_bytes(
            svm.get_account(&va.pubkey()).unwrap().data[..8]
                .try_into()
                .unwrap(),
        );
        let sb = u64::from_le_bytes(
            svm.get_account(&vb.pubkey()).unwrap().data[..8]
                .try_into()
                .unwrap(),
        );
        let sc = u64::from_le_bytes(
            svm.get_account(&vc.pubkey()).unwrap().data[..8]
                .try_into()
                .unwrap(),
        );

        // All should be equal (or differ by at most 1 due to remainder)
        assert!(
            sa == sb && sb == sc,
            "Validators must remain balanced: A={}, B={}, C={}",
            sa,
            sb,
            sc
        );
        (sa, sb, sc)
    };

    // Deposit 3: Each gets 1 (3/3 = 1)
    let tx1 = Transaction::new(
        &[fee_payer.insecure_clone(), authority.insecure_clone()],
        Message::new(&[make_ix(0, 3)], Some(&fee_payer.pubkey())),
        svm.latest_blockhash(),
    );
    assert!(svm.send_transaction(tx1).is_ok());
    let (sa, sb, sc) = assert_balanced(&svm);
    assert_eq!(sa, 1, "After deposit 3, each should have 1");
    println!("✅ After deposit: A={}, B={}, C={} (balanced)", sa, sb, sc);

    // Withdraw 3: Each goes to 0
    let tx2 = Transaction::new(
        &[fee_payer.insecure_clone(), authority.insecure_clone()],
        Message::new(&[make_ix(1, 3)], Some(&fee_payer.pubkey())),
        svm.latest_blockhash(),
    );
    assert!(svm.send_transaction(tx2).is_ok());
    let (sa, sb, sc) = assert_balanced(&svm);
    assert_eq!(sa, 0, "After withdraw 3, each should have 0");
    println!("✅ After withdraw: A={}, B={}, C={} (balanced)", sa, sb, sc);

    // Second cycle
    svm.expire_blockhash();
    let tx3 = Transaction::new(
        &[fee_payer.insecure_clone(), authority.insecure_clone()],
        Message::new(&[make_ix(0, 3)], Some(&fee_payer.pubkey())),
        svm.latest_blockhash(),
    );

    assert!(svm.send_transaction(tx3).is_ok());
    assert_balanced(&svm);

    let tx4 = Transaction::new(
        &[fee_payer.insecure_clone(), authority.insecure_clone()],
        Message::new(&[make_ix(1, 3)], Some(&fee_payer.pubkey())),
        svm.latest_blockhash(),
    );
    assert!(svm.send_transaction(tx4).is_ok());
    assert_balanced(&svm);

    println!(
        "✅ Fix working: Forced rebalancing maintains equal distribution across all operations"
    );
}

/// ✅ FIX VERIFICATION: Attempted selective drain fails (validators stay balanced)
#[test]
fn test_cannot_selectively_drain_validators() {
    use litesvm::LiteSVM;
    use solana_sdk::{
        account::Account,
        instruction::Instruction,
        message::Message,
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    let mut svm = LiteSVM::new();
    let pool = Keypair::new();
    let authority = Keypair::new();
    let fee_payer = Keypair::new();
    let (va, vb, vc) = (Keypair::new(), Keypair::new(), Keypair::new());

    let mut pool_data = vec![0u8; 40];
    pool_data[..32].copy_from_slice(authority.pubkey().as_ref());
    svm.set_account(
        pool.pubkey(),
        Account {
            lamports: 1_000_000,
            data: pool_data,
            owner: crate::ID.into(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    for v in [&va, &vb, &vc] {
        svm.set_account(
            v.pubkey(),
            Account {
                lamports: 1_000_000,
                data: 0u64.to_le_bytes().to_vec(),
                owner: crate::ID.into(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    }

    for k in [&authority, &fee_payer] {
        svm.airdrop(&k.pubkey(), 1_000_000_000).unwrap();
    }

    svm.add_program_from_file(
        &crate::ID.into(),
        "../../target/deploy/rebalancing_secure.so",
    )
    .unwrap();

    // Try the attack pattern: Deposit evenly, then attempt to "withdraw from A only"
    // In secure version, "withdraw from A only" is impossible—all validators are rebalanced equally

    let deposit_ix = Instruction {
        program_id: crate::ID.into(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(pool.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(authority.pubkey(), true),
            solana_sdk::instruction::AccountMeta::new(va.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(vb.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(vc.pubkey(), false),
        ],
        data: {
            let mut d = vec![0u8]; // deposit
            d.extend_from_slice(&9u64.to_le_bytes()); // 9 lamports
            d
        },
    };

    let tx = Transaction::new(
        &[fee_payer.insecure_clone(), authority.insecure_clone()],
        Message::new(&[deposit_ix], Some(&fee_payer.pubkey())),
        svm.latest_blockhash(),
    );
    assert!(svm.send_transaction(tx).is_ok());

    // After deposit 9: Each validator has 3 (9/3 = 3)
    let sa = u64::from_le_bytes(
        svm.get_account(&va.pubkey()).unwrap().data[..8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(sa, 3, "Each validator should have 3 after deposit 9");

    // Attempt "attack": Withdraw 3 (this withdraws from pool globally, then rebalances to 2,2,2)
    let withdraw_ix = Instruction {
        program_id: crate::ID.into(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(pool.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(authority.pubkey(), true),
            solana_sdk::instruction::AccountMeta::new(va.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(vb.pubkey(), false),
            solana_sdk::instruction::AccountMeta::new(vc.pubkey(), false),
        ],
        data: {
            let mut d = vec![1u8]; // withdraw
            d.extend_from_slice(&3u64.to_le_bytes());
            d
        },
    };

    let tx2 = Transaction::new(
        &[fee_payer.insecure_clone(), authority.insecure_clone()],
        Message::new(&[withdraw_ix], Some(&fee_payer.pubkey())),
        svm.latest_blockhash(),
    );
    assert!(svm.send_transaction(tx2).is_ok());

    // ✅ FIX: All validators reduced equally to 2 (not just A)
    let sa = u64::from_le_bytes(
        svm.get_account(&va.pubkey()).unwrap().data[..8]
            .try_into()
            .unwrap(),
    );
    let sb = u64::from_le_bytes(
        svm.get_account(&vb.pubkey()).unwrap().data[..8]
            .try_into()
            .unwrap(),
    );
    let sc = u64::from_le_bytes(
        svm.get_account(&vc.pubkey()).unwrap().data[..8]
            .try_into()
            .unwrap(),
    );

    assert_eq!(sa, 2, "Validator A should have 2 (rebalanced)");
    assert_eq!(sb, 2, "Validator B should have 2 (rebalanced)");
    assert_eq!(sc, 2, "Validator C should have 2 (rebalanced)");

    println!("✅ Fix working: Cannot selectively drain. All validators at 2 (balanced)");
}
