## Multiple Ways to Break (and Fix) Your Solana Programs
Real exploit patterns I've been digging into, ported to Pinocchio.

## What's This?

I took five real attack vectors that have burned Solana devs before and rebuilt them with Pinocchio. Each one has:
- The broken version (so you can see exactly how it fails)
- The patched version (showing the actual fix)
- A breakdown of why it works and what the attacker was thinking
## Repository Structure

Each vulnerability is contained in its own directory with both insecure and secure implementations:
```
├── dangling_pointer/
├── forced_rebalancing/
├── sealevel_attacks/
├── sneaky_oracle/
├── timing/
```

Each directory contains:
- `insecure/` - The vulnerable implementation
- `secure/` - The fixed implementation
- `README.md` - Detailed explanation of the vulnerability and fix

## Vulnerabilities Covered

1. **[Dangling Pointer](./dangling_pointer/README.md)** - Account references that point to closed accounts, allowing attackers to recreate malicious data at the same address
2. **[Forced Rebalancing](./forced_rebalancing/README.md)** - Users manipulating stake distribution by selectively depositing evenly but withdrawing from specific validators
3. **[Sealevel Attacks](./sealevel_attacks/README.md)** - Four common validation failures: unchecked sysvars, non-canonical PDAs, duplicate accounts, and type confusion
4. **[Sneaky Oracle](./sneaky_oracle/README.md)** - Oracle price rollback attacks using non-canonical feeds and missing monotonicity checks
5. **[Timing](./timing/README.md)** - Boundary overlap vulnerabilities allowing deposit and claim operations in the same slot

## Getting Started

### Prerequisites

- Rust 1.93+
- Solana CLI 3.1.3+

### Building
```bash
# Build all programs
cargo build-sbf

# Build a specific example
cd dangling_pointer/insecure && cargo build-sbf
```

### Testing
```bash
# Run all tests
cargo test -- --no-capture

# Test a specific example
cd dangling_pointer/insecure && cargo test -- --no-capture
```


