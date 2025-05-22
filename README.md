# Set Non-Inclusion Accumulator

A toy implementation of a set non-inclusion accumulator using Pedersen vector commitments, inspired by Zcash's oblivious syncing service. Allows proving a value is not in a set without revealing the set's contents.

## How it Works

1. Represent set as roots of a polynomial
2. Use Pedersen commitments to commit to the polynomial
3. Prove non-membership by showing polynomial evaluates to non-zero at the value

## Example

```rust
use ark_bls12_377::{Fr, G1Affine};
use ark_ff::UniformRand;
use rand::thread_rng;

// Create set and accumulator
let mut rng = thread_rng();
let roots = (1..20).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
let state = insert(&roots, G1Affine::default(), Fr::rand(&mut rng))?;

// Prove non-membership
let v = Fr::rand(&mut rng);
let proof = check_non_membership(&roots, v, r, G1Affine::default())?;
```

---

**Note:** This is a toy implementation for educational purposes. 