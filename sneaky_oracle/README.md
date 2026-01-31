# Sneaky Oracle (Non-Canonical Price Feed)

## Overview

Even when validating oracle program ownership and price freshness, protocols accept **any** price account owned by the oracle program. Attackers exploit this by creating their own price feeds with stale data, bypassing freshness checks because the data is technically "recent" (within max age) but not the *latest* market price.

This is particularly dangerous with Pyth: anyone can create a price feed for "SOL/USD", but only one is the canonical feed.

## The Vulnerability

**Insecure Pattern:**
```rust
fn process_instruction(accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    let price_account = &accounts[0];
    
    //  WRONG: Only validates program ownership
    // Accepts ANY Pyth price account, not just the official SOL/USD feed
    if price_account.owner() != &pyth_solana::ID {
        return Err(ProgramError::IllegalOwner);
    }
    
    let price_data = load_price(price_account)?;
    let current_slot = Clock::get()?.slot;
    
    //  WRONG: Freshness-only validation
    // This passes if price is from slot 100 and we're at slot 102
    // But attacker can pass their own feed with slot 100 while canonical feed is at slot 150
    if current_slot - price_data.update_slot > MAX_AGE_SLOTS {
        return Err(ProgramError::InvalidAccountData);
    }
    
    //  WRONG: No monotonicity check
    // Accepts older prices even if we've seen newer ones
    store_price(price_data.price);
}
```

## Attack Scenario:

Context: Protocol uses Pyth for SOL/USD. Canonical feed is at slot 100 with price $150. Max age = 10 slots

- Attacker creates their own SOL/USD feed (valid Pyth program, attacker-controlled data)

-  Attacker sets price to $140 (stale) but update_slot to 95 (within max age of current slot 100)
-  TX: Protocol accepts attacker's feed → stores $140
-  Result: Protocol operates on stale price despite "freshness" check passing. Attacker can now exploit DeFi positions with artificial price.

## The Fix

**Secure Pattern:**
```rust
// Hardcode the canonical feed address (e.g., SOL/USD from Pyth mainnet)
const PYTH_SOL_USD_FEED: Pubkey = pubkey!("H6ARHf6YXhGYeQfUzQNGk6rDNnLBQKrenN712K4AQJEG");

fn process_instruction(accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    let price_account = &accounts[0];
    
    // ✅ FIX #1: Canonical feed validation (PRIMARY DEFENSE)
    // Explicitly check this is the official feed address, not just any Pyth account
    if price_account.key() != &PYTH_SOL_USD_FEED {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Verify oracle program ownership (redundant but defensive)
    if price_account.owner() != &pyth_solana::ID {
        return Err(ProgramError::IllegalOwner);
    }
    
    let price_data = load_price(price_account)?;
    let current_slot = Clock::get()?.slot;
    
    // Freshness check
    if current_slot - price_data.update_slot > MAX_AGE_SLOTS {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ✅ FIX #2: Monotonicity check (SECONDARY DEFENSE)
    // Ensure we're not accepting historical prices from the canonical feed
    let last_slot = get_last_update_slot();
    if price_data.update_slot <= last_slot {
        return Err(ProgramError::InvalidAccountData);
    }
    
    update_price(price_data.price, price_data.update_slot);
}
```

**How It Works:**

Fix #1: Canonical Feed Address
- Hardcode the specific oracle account address (e.g., Pyth SOL/USD feed ID)
- Reject any other account, even if owned by Pyth program
- Prevents substitution attacks where attacker passes their own feed
Fix #2: Monotonicity Check
- Track the last seen slot for the canonical feed
- Reject prices that aren't strictly newer than the last update
- Prevents replay of historical prices even from the canonical feed

## Key Takeaway

Checking owner == Pyth only validates the program, not the data source.
You must validate:
- The canonical feed address (Is this actually the SOL/USD feed?)
- Monotonic updates (Is this newer than what we've seen?)
  
Freshness checks (current_slot - update_slot < max_age) are insufficient because they validate recency, not currency. A stale price from 5 minutes ago is "recent" but not "current."

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

