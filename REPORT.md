# Polar-KEM (NICCS Round 1): Total Break of the Reference Implementation

**Date:** 2026-09-20
**Target:** Polar-KEM reference implementation and KATs, official NICCS round-1 package (`Polar-KEM.zip`, SHA-256 `3ae9d4f1a717fb473e76447014d585cd5d14fe38728f02b1a044cc6a2d03e16d`)
**Impact:** the shared secret of any honestly generated ciphertext can be computed from the public key and ciphertext alone.

## Summary

An independent Python reimplementation of the scheme's public operations reproduces the shared secret for **30/30 published KAT vectors** (10 each for PolarKEM-128/256/512), using no secret key, no KAT-generation seed, and none of the submitted C code. This is not a dispute about security margins: normal decapsulation is itself a public computation, so the implementation offers no confidentiality at all.

## The vulnerability

The flaw is that the normal decapsulation path requires no secret material:

```text
mu = polarkem_recover_message(pk, ct)
ss = polarkem_derive_valid_secret(mu, ct)
```

The calls appear in the original source at `polarkem_core.c` lines 96–99; the two functions are defined in `polarkem_ct.c` at lines 401 and 443.

Both steps are public computations:

- `polarkem_recover_message` undoes a permutation and sign flips derived by XOF **from the seed stored in the clear at `pk[16:48]`**, then applies an exact hard decision and inverts the public linear polar transform. The noise `e ∈ {−1, 0, +1}` is 3072–4608 times smaller than the signal `q/4`, so the hard decision is always correct — there is no decoding problem to solve.
- `polarkem_derive_valid_secret` is the same public KDF the encryptor uses: `ss = XOF("PolarKEM-SS-v1" ‖ mu ‖ SM3(ct))`.

The secret value `z` (the second keygen seed) enters only `polarkem_derive_reject_secret` — the implicit-rejection branch for *invalid* ciphertexts. It never protects honestly generated ones. There is no parameter-level fix: the construction has neither a secret trapdoor nor a hard decoding problem.

## Verification

| Instance | Recovered from (pk, ct) alone | Time (10 KATs) |
|---|---|---|
| PolarKEM-128 | 10 / 10 | ~0.006 s |
| PolarKEM-256 | 10 / 10 | ~0.011 s |
| PolarKEM-512 | 10 / 10 | ~0.024 s |

The PoC parses the unmodified official KAT files beside it, reading only the `PK` and `CT` fields; those files also contain `Seed` and `SK`, which are never used, and the expected `SS` is read only by the final comparator.

## Proof of Concept

```sh
python3 poc.py    # expected output ends with "30/30 vectors recovered", exit 0
```

Requires Python with SM3 in `hashlib` (3.11+ on OpenSSL 3.x).

## Scope

- Covers the reference implementation and bundled KATs of the downloaded package; the optimized implementation (different hashes, see `../sources.json`) was not separately verified.
- The specification describes a different lattice/LIP-style construction; this break concerns the submitted code, not the spec text or polar codes in cryptography generally. The spec is separately inconsistent (R₀ = 1 contradicts the claimed minimum distance; under its own noise model P(‖e‖ ≤ 15) ≈ 0.00348, contradicting its failure-rate claims).

## Files

- `REPORT.md`, `poc.py`
- `KAT_KEM_PolarKEM-{128,256,512}.txt` — unmodified, from the package's `Test_Vectors/`
- Full triage context: `../../README.zh-CN.md`; independent harness `../recover_public.py`; source hashes `../sources.json`
