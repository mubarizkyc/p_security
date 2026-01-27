# Timing Vulnerability (Boundary Overlap)

## Overview

When protocols use timestamps to transition between states (deposit → claim), incorrect boundary checks can allow multiple states to be active simultaneously. This enables attackers to deposit and claim rewards in the same transaction, breaking reward distribution logic.

## The Vulnerability

**Insecure Pattern:**
```rust
pub fn deposit(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let now = Clock::get()?.unix_timestamp;
    
    // ❌ Allows deposit AT end_time
    if now <= pool.end_time {
        user.deposited += amount;
        pool.total_deposited += amount;
    }
}

pub fn claim(accounts: &[AccountInfo]) -> ProgramResult {
    let now = Clock::get()?.unix_timestamp;
    
    // ❌ Allows claim AT claim_time
    if now >= pool.claim_time {
        let reward = user.deposited * 1_000 / pool.total_deposited;
        user.claimed = true;
    }
}
```

**Attack Scenario:**

Pool config: `end_time = 100`, `claim_time = 100`

At timestamp `t = 100`:
- `deposit()` check: `100 <= 100` → ✅ allowed
- `claim()` check: `100 >= 100` → ✅ allowed

**Both operations are valid in the same slot!**

**Flash Loan Attack:**
```
1. Borrow 1,000,000 tokens (flash loan)
2. Deposit 1,000,000 at t=100
3. Claim rewards immediately at t=100
4. Withdraw deposit
5. Repay flash loan
6. Keep all rewards (only pay small fee)
```

## The Fix

**Secure Pattern:**
```rust
pub fn deposit(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let now = Clock::get()?.unix_timestamp;
    
    // ✅ STRICT boundary: start <= now < end
    if now < pool.start_time || now >= pool.end_time {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    user.deposited = user.deposited.saturating_add(amount);
    pool.total_deposited = pool.total_deposited.saturating_add(amount);
}

pub fn claim(accounts: &[AccountInfo]) -> ProgramResult {
    let now = Clock::get()?.unix_timestamp;
    
    // ✅ STRICT boundary: claim ONLY after claim_time
    if now < pool.claim_time {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    // ... claim logic
}
```

**State Transition:**
```
start_time <= t < end_time     → Deposit phase
end_time <= t < claim_time     → Cooldown (no operations)
claim_time <= t                → Claim phase
```

**How It Works:**
- Use `<` instead of `<=` for end boundaries
- Use `>=` becomes `<` (inverted) to enforce strict separation
- Each timestamp maps to **exactly one state**
- No overlap between deposit and claim windows

## Key Takeaway

**When using time-based state transitions, ensure boundaries are mutually exclusive.** Each timestamp must map to exactly one state. Use strict inequality checks (`<` not `<=`) to prevent boundary overlap.

## Testing
```bash
# Build
cargo build-sbf

# Run tests
cargo test

# Test insecure version (exploit succeeds)
cd insecure && cargo test

# Test secure version (exploit fails)
cd secure && cargo test
```

## References

- [Advent of Bugs, Day 2: LaunchPool Timing Issue](https://x.com/accretion_xyz/status/1995916134550536514)
