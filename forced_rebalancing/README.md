# Forced Rebalancing Vulnerability

## Overview

A forced rebalancing attack occurs in **pooled staking protocols** when users can deposit stake evenly across validators but withdraw from specific validators. This creates an imbalance that malicious validators exploit to increase their stake share and revenue.

## The Vulnerability

**Insecure Pattern:**
```rust
fn deposit_stake(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let validators = accounts;
    let stake = /* amount to deposit */;
    
    // ✅ Evenly split deposit across ALL validators
    let per_validator = stake / validators.len() as u64;
    
    for validator in validators.iter() {
        validator.stake_amount += per_validator;
    }
}

fn withdraw_stake(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    // WRONG: User chooses WHICH validator to withdraw from
    let validator_to_withdraw = &accounts[0];
    let stake = /* amount to withdraw */;
    
    validator_to_withdraw.stake_amount -= stake;
    // No rebalancing enforced!
}
```

**Attack Scenario:**

Starting state: `A: 3, B: 3, C: 3`

1. Deposit 3 SOL → evenly distributed → `A: 4, B: 4, C: 4`
2. **Withdraw 3 SOL from A** → `A: 1, B: 4, C: 4`
3. Deposit 3 SOL → evenly distributed → `A: 2, B: 5, C: 5`
4. **Withdraw 3 SOL from B** → `A: 2, B: 2, C: 5`

**Result:** Validator C now has 5 SOL while A and B have only 2 SOL each. Validator C can repeatedly exploit this to increase their stake share and revenue.

## The Fix

**Secure Pattern:**
```rust
#[repr(C)]
struct Pool {
    pub authority: Pubkey,
    pub total_stake: u64,  // Global invariant
}

fn deposit(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let pool = &accounts[0];
    let validators = &accounts[2..];
    
    // Update global total
    pool.total_stake += amount;
    
    // ✅ Always rebalance after any operation
    rebalance(pool.total_stake, validators)?;
}

fn withdraw(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let pool = &accounts[0];
    let validators = &accounts[2..];
    
    // Update global total
    pool.total_stake -= amount;
    
    // ✅ Always rebalance after any operation
    rebalance(pool.total_stake, validators)?;
}

fn rebalance(total: u64, validators: &[AccountInfo]) -> ProgramResult {
    let base = total / validators.len() as u64;
    let remainder = total % validators.len() as u64;
    
    // Evenly distribute stake across all validators
    for (i, validator) in validators.iter().enumerate() {
        let extra = if i < remainder { 1 } else { 0 };
        validator.stake_amount = base + extra;
    }
}
```

**How It Works:**
- Maintain a **global `total_stake`** in the pool account
- **Force rebalancing** on every deposit and withdrawal
- No user can cherry-pick which validators to withdraw from
- All validators always maintain proportional stake distribution

## Key Takeaway

**Always enforce global invariants across related accounts.** If your protocol promises equal distribution, enforce it programmatically on every operation—don't trust users to maintain balance.

## Testing
```bash
# Build
cargo build-sbf

# Run tests
cargo test

# Test insecure version (imbalance succeeds)
cd insecure && cargo test

# Test secure version (always balanced)
cd secure && cargo test
```

## References

- [Advent of Bugs, Day 21: Forced Rebalancing](https://x.com/accretion_xyz/status/2002885188922044462)
