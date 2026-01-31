# Sealevel Attacks (Combined Vulnerabilities)

## Overview

This example demonstrates four common Solana security vulnerabilities that frequently appear together in production code. Each represents a fundamental validation failure that can lead to critical exploits.

**Why "Sealevel"?** These are implementation-layer vulnerabilities specific to Solana's parallel execution model (Sealevel), distinct from consensus or economic attacks.

## The Vulnerabilities

### 1. Unchecked Sysvar Account

**Insecure:**
```rust
//  Blindly trusts first account is Rent sysvar
let rent_account = &accounts[0];
```

**Attack:** Pass any malicious account instead of the real sysvar.

**Fix:**
```rust
// ✅ Explicitly verify sysvar address
if accounts[0].key() != &pinocchio::sysvars::rent::RENT_ID {
    return Err(ProgramError::InvalidAccountData);
}
```

---

### 2. Non-Canonical PDA Derivation

**Insecure:**
```rust
//  User-controlled bump allows multiple valid PDAs
let bump = instruction_data[0];
let pda = create_program_address(&[seed, &[bump]], &program_id)?;
```

**Attack:** Use different bump seeds to create multiple PDAs for the same logical entity.

**Fix:**
```rust
// ✅ Derive canonical PDA on-chain
let (pda, bump) = find_program_address(&[seed], &program_id);
```

---

### 3. Duplicate Mutable Accounts

**Insecure:**
```rust
// ❌ Same account can be passed twice
let person = &accounts[1];
let employee = &accounts[2];

// Violates Rust aliasing rules!
person.borrow_mut_data_unchecked().fill(11u8);
employee.borrow_mut_data_unchecked().fill(11u8);
```

**Attack:** Pass the same account key for both `person` and `employee`, causing data corruption through aliased mutable references.

**Fix:**
```rust
// ✅ Enforce account uniqueness
if person.key() == employee.key() {
    return Err(ProgramError::InvalidAccountData);
}
```

---

### 4. Type Confusion ("Type Cosplay")

**Insecure:**
```rust
//  No discriminator check - any account can pretend to be Person
let person: &mut Person = 
    unsafe { &mut *(account.data.as_mut_ptr() as *mut Person) };
```

**Attack:** Pass an `Employee` account where `Person` is expected, causing type confusion and potential data corruption.

**Fix:**
```rust
#[repr(C)]
struct Person {
    pub discriminator: u8,  // Type identifier
    pub age: [u8; 8],
}

const PERSON_DISCRIMINATOR: u8 = 1;
const EMPLOYEE_DISCRIMINATOR: u8 = 2;

// ✅ Validate discriminator before casting
let data = account.try_borrow_data()?;
if data.len() < 9 || data[0] != PERSON_DISCRIMINATOR {
    return Err(ProgramError::InvalidAccountData);
}

let person: &mut Person = unsafe { /* safe cast */ };
```

---

## Combined Attack Scenario

**Insecure code allows:**
1. Pass fake sysvar account with manipulated rent data
2. Use non-canonical PDA bump to create duplicate accounts
3. Pass same account twice to corrupt state via aliasing
4. Use `Employee` account where `Person` expected (type confusion)

**All in a single transaction!**

---

## Key Takeaways

**Never trust user-provided accounts without validation:**
- ✅ Verify sysvar addresses explicitly
- ✅ Derive PDAs canonically on-chain
- ✅ Check for duplicate account keys
- ✅ Use discriminators to prevent type confusion
- ✅ Validate account ownership and data length

---

## Testing
```bash
# Build
cargo build-sbf

# Run tests
cargo test

# Test insecure version (all attacks succeed)
cd insecure && cargo test

# Test secure version (all attacks fail)
cd secure && cargo test
```

## References
- [Sealevel Attack Vectors](https://github.com/coral-xyz/sealevel-attacks)
