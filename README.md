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

1. **Dangling Pointer** - [What happens to child accounts stored in a parent account when the parent no longer exists]
2. **Forced Rebalancing** - [Rebalancing in any DeFi protocol should be handled by the protocol itself, not by the public]
3. **Sealevel Attacks** - [Common Solana vulnerabilities that are still actively exploited]
4. **Sneaky Oracle** - [Know and verify your oracle writer]
5. **Timing** - [How comparison operators written late at night can result in very cold nights]

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
