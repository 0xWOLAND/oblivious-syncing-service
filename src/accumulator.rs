use ark_bls12_377::{Fr, G1Affine, G1Projective};
use ark_ff::{Field, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_ec::CurveGroup;
use sha2::{Digest, Sha256};
use anyhow::Result;
use ark_serialize::CanonicalSerialize;

use crate::pcs::{commit, POINTS};

/// Evaluate poly at v
fn evaluate_poly(coeffs: &[Fr], v: Fr) -> Fr {
    DensePolynomial::from_coefficients_vec(coeffs.to_vec()).evaluate(&v)
}

pub fn poly_from_roots(roots: &[Fr]) -> DensePolynomial<Fr> {
    let one = Fr::ONE;
    let mut poly = DensePolynomial::from_coefficients_vec(vec![one]); // constant 1

    for &root in roots {
        let neg_root = -root;
        let linear = DensePolynomial::from_coefficients_vec(vec![neg_root, one]); 

        poly = &poly * &linear; 
    }

    poly
}

fn hash_points_to_fr(p1: &G1Affine, p2: &G1Affine) -> Fr {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 96]; // 2 * 48-byte compressed points
    p1.serialize_compressed(&mut buf[..48]).unwrap();
    p2.serialize_compressed(&mut buf[48..]).unwrap();
    hasher.update(&buf);
    let hash_bytes = hasher.finalize();
    Fr::from_le_bytes_mod_order(&hash_bytes)
}

pub struct State {
    pub Accumulator: G1Affine,
    pub Commitment: G1Affine,
}

pub fn insert(roots: &[Fr], a_prev: G1Affine, r: Fr) -> Result<State> {
    // Build polynomial with given roots
    let poly = poly_from_roots(roots);
    let coeffs = &poly.coeffs;

    // Commit to polynomial
    let p_i = commit(coeffs, r)?;

    // Compute h = H(A_i, P_i)
    let h = hash_points_to_fr(&a_prev, &p_i);

    // Compute A_{i+1} = [h] A_i + P_i
    let next = a_prev * h + p_i;
    Ok(State {
        Accumulator: next.into_affine(),
        Commitment: p_i,
    })
}

pub fn check_non_membership(roots: &[Fr], v: Fr, r: Fr, s_prev: G1Affine) -> Result<State> {
    // Build polynomial
    let poly = poly_from_roots(roots);
    let coeffs = &poly.coeffs;

    // Evaluate poly at v
    let alpha = evaluate_poly(coeffs, v);
    if alpha.is_zero() {
        return Err(anyhow::anyhow!("v is in the root set; cannot prove non-membership"));
    }

    // Commit to poly
    let p_i = commit(coeffs, r)?;

    // P'_i = P_i - [α]G₀
    let p_i_prime = p_i - POINTS[0] * alpha;

    // Hash to get h'
    let h_prime = hash_points_to_fr(&s_prev, &p_i_prime.into_affine());

    // s_{i+1} = [h'] s_prev + P'_i
    let next = s_prev * h_prime + p_i_prime;
    Ok(State {
        Accumulator: next.into_affine(),
        Commitment: p_i,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_accumulator_operations() {
        let mut rng = thread_rng();
        
        // Create some test roots
        let roots = (0..20).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        
        // Initial accumulator value
        let a_0 = G1Affine::default();
        
        // Insert roots into accumulator
        let r = Fr::rand(&mut rng);
        let a_1 = insert(&roots, a_0, r).unwrap();
        
        // Test non-membership for a value not in roots
        let v = Fr::rand(&mut rng);
        let s_0 = G1Affine::default();
        let s_1 = check_non_membership(&roots, v, r, s_0).unwrap();
        
        // Test that a root value fails non-membership check
        assert!(check_non_membership(&roots, roots[0], r, s_0).is_err());
    }
}
