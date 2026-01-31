# Dangling Pointer

## Overview

A dangling pointer occurs when account B stores the address of account A, but account A can be closed while B still references it. The closed address can then be recreated with malicious data, causing B to point to an attacker-controlled account.

## The Vulnerability

**Insecure Pattern:**
```rust
fn close_parent(accounts: &[AccountInfo]) -> ProgramResult {
    let parent_account = &accounts[0];
    let user = &accounts[1];

    //  CRITICAL: No check for existing children!
    // Parent can be closed even if children still reference it
    
    // Close parent and return lamports...
}
```

**Attack Scenario:**
1. Parent account created with address `P`
2. Child account stores `P` as a pointer
3. **Parent closed** - no validation prevents this
4. Child now has a **dangling pointer** to closed account `P`
5. Attacker recreates account at address `P` with malicious data
6. Child's pointer now references attacker-controlled account

## The Fix

**Secure Pattern:**
```rust
#[repr(C)]
struct ParentAccount {
    pub child_count: u64,  // Track active children
}

fn close_parent(accounts: &[AccountInfo]) -> ProgramResult {
    let parent = /* deserialize parent */;
    
    // ✅ CORE SAFETY CHECK
    if parent.child_count != 0 {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Only close if no children exist
}
```

**How It Works:**
- Parent maintains `child_count` tracking active children
- `close_child()` decrements the count when child closes
- `close_parent()` **only succeeds when `child_count == 0`**
- Prevents dangling pointers by ensuring parent outlives all children

## Key Takeaway

**Never allow an account to be closed if other accounts still reference it.** Always implement reference counting or similar validation to maintain pointer integrity.

## Testing
```bash
# Build
cargo build-sbf

# Run tests
cargo test

# Test insecure version (attack succeeds)
cd insecure && cargo test

# Test secure version (attack fails)
cd secure && cargo test
```

## References

- [Account Lifecycle Bugs in Solana](https://x.com/accretion_xyz/status/2000363584312729673)
