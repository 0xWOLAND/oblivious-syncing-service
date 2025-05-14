use ark_bls12_377::{G1Projective, G1Affine, g1::Config, Fq, Fr};
use ark_ec::hashing::{HashToCurve, map_to_curve_hasher::MapToCurveBasedHasher};
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::{CurveGroup};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::{FftField, Field, UniformRand};
use sha2::Sha256;
use anyhow::Result;

const NUM_POINTS: usize = 20;
include!(concat!(env!("OUT_DIR"), "/trusted_setup.rs"));

lazy_static::lazy_static! {
    static ref POINTS: [G1Affine; NUM_POINTS] = TRUSTED_SETUP[..NUM_POINTS]
        .iter()
        .map(|line| hash_message(line))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
}


fn hash_message(message: &str) -> G1Affine {
    MapToCurveBasedHasher::<G1Projective, DefaultFieldHasher<Sha256>, WBMap<Config>>::new(b"BLS12377G1_XMD:SHA-256_SSWU_RO_")
        .unwrap()
        .hash(message.as_bytes())
        .unwrap()
        .into()
}

fn commit(v: &[Fr], r: Fr) -> Result<G1Affine> {
    if v.len() != POINTS.len() - 1 {
        return Err(anyhow::anyhow!("POINTS must have 1 + v.len() entries"));
    }

    let h = POINTS[1..]
        .iter()
        .zip(v)
        .map(|(&p, v_i)| p * v_i)
        .fold(G1Projective::default(), |acc, x| acc + x);

    let c = POINTS[0] * r + h;
    Ok(c.into_affine())
}

fn open(v: &[Fr], r: Fr, j: usize) -> (Fr, Fr, G1Affine) {
    let witness = POINTS[1..].iter().enumerate()
        .filter(|(i, _)| *i != j)
        .map(|(i, &p)| p * v[i])
        .sum::<G1Projective>() + POINTS[0] * r;
    (v[j], r, witness.into_affine())
}

fn check(c: G1Affine, v_j: Fr, witness: G1Affine, h_j: G1Affine) -> bool {
    c == witness + h_j * v_j
}

fn batch_open(v: &[Fr], r: Fr, indices: &[usize]) -> (Vec<Fr>, Fr, G1Affine) {
    let witness = POINTS[1..].iter().enumerate()
        .filter(|(i, _)| !indices.contains(i))
        .map(|(i, &p)| p * v[i])
        .sum::<G1Projective>() + POINTS[0] * r;
    
    let values: Vec<Fr> = indices.iter().map(|&j| v[j]).collect();
    (values, r, witness.into_affine())
}

fn batch_check(c: G1Affine, values: &[Fr], witness: G1Affine, indices: &[usize]) -> bool {
    let mut sum = G1Projective::from(witness);
    for (&v_j, &j) in values.iter().zip(indices) {
        sum += POINTS[j + 1] * v_j;
    }
    c == sum.into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_commit_and_verify() {
        let mut rng = thread_rng();
        let v: Vec<Fr> = (0..NUM_POINTS-1).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        
        let commitment = commit(&v, r).unwrap();
        let j = 0; // test opening at index 0
        let (v_j, r_j, witness) = open(&v, r, j);
        
        assert!(check(commitment, v_j, witness, POINTS[j+1]));
    }

    #[test]
    fn test_multiple_indices() {
        let mut rng = thread_rng();
        let v: Vec<Fr> = (0..NUM_POINTS-1).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        let commitment = commit(&v, r).unwrap();

        // Test opening at different indices
        for j in 0..v.len() {
            let (v_j, r_j, witness) = open(&v, r, j);
            assert!(check(commitment, v_j, witness, POINTS[j+1]));
        }
    }

    #[test]
    fn test_invalid_opening() {
        let mut rng = thread_rng();
        let v: Vec<Fr> = (0..NUM_POINTS-1).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        let commitment = commit(&v, r).unwrap();

        // Create an invalid opening by modifying the value
        let j = 0;
        let (v_j, r_j, witness) = open(&v, r, j);
        let invalid_v_j = v_j + Fr::from(1u64); // Modify the value

        assert!(!check(commitment, invalid_v_j, witness, POINTS[j+1]));
    }

    #[test]
    fn test_zero_vector() {
        let mut rng = thread_rng();
        let v: Vec<Fr> = vec![Fr::from(0u64); NUM_POINTS-1];
        let r = Fr::rand(&mut rng);
        
        let commitment = commit(&v, r).unwrap();
        let j = 0;
        let (v_j, r_j, witness) = open(&v, r, j);
        
        assert!(check(commitment, v_j, witness, POINTS[j+1]));
    }

    #[test]
    fn test_invalid_vector_length() {
        let mut rng = thread_rng();
        let v: Vec<Fr> = (0..NUM_POINTS).map(|_| Fr::rand(&mut rng)).collect(); // Too long
        let r = Fr::rand(&mut rng);
        assert!(commit(&v, r).is_err());
    }

    #[test]
    fn test_batch_open() {
        let mut rng = thread_rng();
        let v: Vec<Fr> = (0..NUM_POINTS-1).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        let commitment = commit(&v, r).unwrap();

        // Test batch opening at indices 0 and 2
        let indices = vec![0, 2];
        let (values, r_j, witness) = batch_open(&v, r, &indices);
        
        assert!(batch_check(commitment, &values, witness, &indices));
    }
}
