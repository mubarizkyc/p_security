# Solana Security Examples: Pinocchio Edition

A practical security reference for Solana developers, demonstrating sophisticated vulnerabilities and their fixes using the Pinocchio framework.

## Overview

This repository provides **5 real-world security vulnerabilities** with side-by-side comparisons of insecure and secure implementations. Each example is built with Pinocchio and includes detailed explanations of what went wrong and how to fix it correctly.

## Why This Matters

Frameworks like Anchor and Pinocchio provide powerful control, but they don't automatically make your programs safe. Understanding **why** a pattern is dangerous and **how** to secure it is essential for building robust Solana applications.

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

- Rust 1.75+
- Solana CLI 3.1.3+
- Pinocchio framework

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
cd dangling_pointer && cargo test -- --no-capture
```

