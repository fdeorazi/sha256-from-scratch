# SHA-256 From Scratch

A **from-scratch C implementation** of the SHA-256 message digest algorithm.
This project was developed as a personal exploration into the inner workings of this widely used and *computationally infeasible to invert* hash function.

<div style="text-align: center;">
  <img src="/docs/images/verbose-start.png" width="800">
</div>

---

## Overview

SHA-256 (Secure Hash Algorithm 256-bit) is a hashing function that turns any input, no matter the size, into a fixed 256-bit (32-byte) digest.
This project follows the [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) specification and tries to show how the algorithm really works inside.

At its core, SHA-256 mixes and scrambles bits in a way that even a tiny change in the input completely alters the output — a property known as the **avalanche effect**.
It does this through a combination of **bit rotations**, **shifts**, and **modular additions**, spreading information (diffusion) and adding non-linearity (confusion) so that no visible patterns remain.

The result is a digest that looks random, but is entirely deterministic and extremely hard to reverse — the foundation of its **preimage**, **second-preimage**, and **collision resistance**.

---

## Compilation

To build the program:

```bash
gcc -O2 print_sha256.c sha256.c -o sha256
```

`-O2` enables compiler optimizations that make the program run faster (about 30-40% improvement, verified through multiple test runs)

No external dependencies are required.

---

## Usage

### Basic Mode

Compute the SHA-256 digest of a file:

```bash
./sha256 <file_path>
```

Example:

```bash
./sha256 x-e4_manual_en_s_f.pdf
```
---

### Verbose Mode

Enable detailed step-by-step tracing:

```bash
./sha256 <file_path> -v
```

This mode prints:

* constants initialization,
* message block parsing,
* message schedule (`W0`–`W63`),
* compression loop rounds (`T1`, `T2`, `a`–`h`),
* and intermediate hash accumulation (`H0`–`H7`).

Verbose output automatically adapts to file size to avoid flooding the console:

| File Size     | Verbose Output Destination            |
| ------------- | ------------------------------------- |
| ≤ 1 KB        | Console                               |
| 1 KB – 100 KB | Redirected to `<filename>.sha256.log` |
| > 100 KB      | Verbose mode disabled automatically   |

Example:

```bash
./sha256 data.txt -v
```

Output:

```
File too large for console verbose output.
Verbose logging redirected to: data.sha256.log
```

---

## Example Output

### Standard Mode


<div>
  <img src="/docs/images/result-screen.png" width="800">
</div>

---

### Verbose Mode (Excerpt)

<div>
  <img src="/docs/images/verbose-screen.png" width="800">
</div>

---

## Algorithm Summary

This implementation performs the standard SHA-256 workflow:

1. **Preprocessing:**

   * Pad the message to a multiple of 512 bits
   * Append original length as a 64-bit big-endian integer

2. **Parsing:**

   * Split message into 512-bit blocks
   * Convert each block into 16 × 32-bit words

3. **Message Schedule Expansion:**

   * Extend to 64 words using logical and rotation functions
   * Uses σ₀ and σ₁ defined by bit rotations and shifts

4. **Compression Function:**

   * Run 64 rounds of modular additions, XORs, and rotations
   * Use constants derived from cube roots of the first 64 primes

5. **Digest Computation:**

   * Combine the eight working variables into a 256-bit result

> Each digest is deterministic: the same input will always yield the same output.

---

## Verification

You can verify the correctness of the computed digest using the system’s built-in tools:

```bash
sha256sum <target_file>
```

The output should match the **hexadecimal (contiguous)** value printed by this implementation.

---

## Performance

This project prioritizes **clarity and traceability** over raw performance.
It does **not** use CPU-specific SHA extensions or vectorization, unlike libraries such as OpenSSL.

Its purpose is to demonstrate **how** SHA-256 works internally, not just to compute it.

---

**SHA-256 From Scratch** was written by **Fabio De Orazi** and is released under the **MIT License**.
