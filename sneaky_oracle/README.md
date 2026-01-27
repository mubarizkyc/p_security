# Sneaky Oracle (Non-Canonical Price Feed)

## Overview

Even when validating oracle feed IDs and price freshness, attackers can exploit oracle systems by creating their own price accounts with historical prices. This enables oracle price rollbacks where an older price overwrites a newer one.

## The Vulnerability

**Insecure Pattern:**
```rust
fn process_instruction(accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    let oracle = &accounts[0];
    
    // ❌ Only checks program ownership
    // ANY account owned by oracle program is accepted
    if oracle.owner() != ORACLE_PROVIDER {
        return Err(ProgramError::IllegalOwner);
    }
    
    let oracle_data = /* deserialize oracle */;
    let current_slot = Clock::get()?.slot;
    
    // ❌ Freshness-only validation
    // Ensures price is recent, not that it's the LATEST
    if current_slot - oracle_data.update_slot > PRICE_MAX_AGE {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ❌ No monotonicity check - accepts older prices!
    asset_info.price = oracle_data.price;
    asset_info.last_update_slot = oracle_data.update_slot;
}
```

**Attack Scenario:**

Current slot: `17,000,000` (max age: 3 slots)

1. Attacker creates own oracle account owned by `ORACLE_PROVIDER`
2. **TX 1:** Submit price at slot `16,999,999` (newest) → accepted ✅
3. **TX 2:** Submit price at slot `16,999,998` (older, still fresh) → accepted ✅
4. **Result:** Protocol now uses **stale price** despite seeing newer data

Both prices pass validation (within max age), but the protocol accepts a rollback.

## The Fix

**Secure Pattern:**
```rust
// Hardcoded canonical feed account
const FEED_ACCOUNT_KEY: [u8; 32] = [1u8; 32];

fn process_instruction(accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    let oracle = &accounts[0];
    
    // ✅ FIX #1: Canonical feed enforcement
    // Only accept the SPECIFIC oracle account, not just any account
    if oracle.key().as_ref() != FEED_ACCOUNT_KEY {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Verify oracle program ownership
    if oracle.owner() != ORACLE_PROVIDER {
        return Err(ProgramError::IllegalOwner);
    }
    
    let oracle_data = /* deserialize */;
    let current_slot = Clock::get()?.slot;
    
    // Freshness check
    if current_slot - oracle_data.update_slot > PRICE_MAX_AGE {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ✅ FIX #2: Monotonic publish-time enforcement
    // Reject prices older than last seen
    let last_seen_slot = u64::from_le_bytes(asset_info.last_update_slot);
    
    if oracle_data.update_slot <= last_seen_slot {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Only update if price is strictly newer
    asset_info.price = oracle_data.price;
    asset_info.last_update_slot = oracle_data.update_slot.to_le_bytes();
}
```

**How It Works:**

**Fix #1: Canonical Feed Key**
- Hardcode the exact oracle account address
- Reject any other account, even if owned by oracle program
- Prevents attackers from creating fake oracle accounts

**Fix #2: Monotonicity Check**
- Track `last_update_slot` for each price feed
- Only accept prices with `update_slot > last_seen_slot`
- Prevents oracle price rollbacks

## Key Takeaway

**Validating oracle ownership and freshness is not enough.** You must:
1. Validate the **canonical feed account key** (not just program ownership)
2. Enforce **monotonic timestamps** to prevent price rollbacks

Freshness tells you the price was valid *at some point*—it doesn't tell you it's the *most recent* valid price.

## Testing
```bash
# Build
cargo build-sbf

# Run tests
cargo test

# Test insecure version (accepts stale prices)
cd insecure && cargo test

# Test secure version (rejects rollbacks)
cd secure && cargo test
```

## References

- [Advent of Bugs, Day 11: Pyth Non-Canonical Price Feed](https://x.com/accretion_xyz/status/1999201534454935605)
