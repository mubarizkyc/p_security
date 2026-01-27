#![allow(unexpected_cfgs)]

use pinocchio::{
    ProgramResult, account_info::AccountInfo, default_panic_handler, no_allocator,
    program_entrypoint, pubkey::Pubkey,
};

pinocchio_pubkey::declare_id!("ENrRns55VechXJiq4bMbdx7idzQh7tvaEJoYeWxRNe7Y");

program_entrypoint!(process_instruction);
no_allocator!();
default_panic_handler!();

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

    rebalance(pool_state.total_stake, validators)
}

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

    rebalance(pool_state.total_stake, validators)
}

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
#[test]
fn test_secure_rebalancing() {
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

    let pool_data = {
        let mut d = vec![0u8; 40];
        d[..32].copy_from_slice(authority.pubkey().as_ref());
        d
    };

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

    let ix = |disc, amt: u64| Instruction {
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

    let tx = Transaction::new(
        &[fee_payer.insecure_clone(), authority.insecure_clone()],
        Message::new(
            &[
                ix(0, 3), // deposit
                ix(1, 3), // withdraw
                ix(0, 3),
                ix(1, 3),
            ],
            Some(&fee_payer.pubkey()),
        ),
        svm.latest_blockhash(),
    );

    assert!(svm.send_transaction(tx).is_ok());

    for v in [&va, &vb, &vc] {
        let acc = svm.get_account(&v.pubkey()).unwrap();
        let stake = u64::from_le_bytes(acc.data[..8].try_into().unwrap());
        assert_eq!(stake, 0);
    }
}
