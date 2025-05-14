use anyhow::{anyhow, Result};
use ark_bls12_377::{g1::Config, Fr, G1Affine, G1Projective};
use ark_ec::hashing::{
    curve_maps::wb::WBMap,
    map_to_curve_hasher::MapToCurveBasedHasher,
    HashToCurve,
};
use ark_ec::CurveGroup;
use ark_ff::field_hashers::DefaultFieldHasher;
use sha2::Sha256;

type Scalar = Fr;
type GroupAffine = G1Affine;
type GroupProjective = G1Projective;

const NUM_POINTS: usize = 20;
const BLINDING_INDEX: usize = 0;

include!(concat!(env!("OUT_DIR"), "/trusted_setup.rs"));

lazy_static::lazy_static! {
    static ref POINTS: [GroupAffine; NUM_POINTS] = TRUSTED_SETUP[..NUM_POINTS]
        .iter()
        .map(|line| hash_message(line))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
}

fn hash_message(message: &str) -> GroupAffine {
    MapToCurveBasedHasher::<GroupProjective, DefaultFieldHasher<Sha256>, WBMap<Config>>::new(b"BLS12377G1_XMD:SHA-256_SSWU_RO_")
        .unwrap()
        .hash(message.as_bytes())
        .unwrap()
        .into()
}

pub fn commit(v: &[Scalar], r: Scalar) -> Result<GroupAffine> {
    if v.len() != POINTS.len() - 1 {
        return Err(anyhow!("POINTS must have 1 + v.len() entries"));
    }

    let blind = POINTS[BLINDING_INDEX] * r;
    let h = POINTS[1..]
        .iter()
        .zip(v)
        .map(|(p, v_i)| *p * v_i)
        .fold(GroupProjective::default(), |acc, x| acc + x);

    Ok((blind + h).into_affine())
}

pub fn open(v: &[Scalar], r: Scalar, j: usize) -> Result<(Scalar, Scalar, GroupAffine)> {
    if j >= v.len() {
        return Err(anyhow!("Index out of bounds"));
    }

    let blind = POINTS[BLINDING_INDEX] * r;
    let witness = POINTS[1..].iter().enumerate()
        .filter(|(i, _)| *i != j)
        .map(|(i, p)| *p * v[i])
        .sum::<GroupProjective>() + blind;
    
    Ok((v[j], r, witness.into_affine()))
}

pub fn check(c: GroupAffine, v_j: Scalar, witness: GroupAffine, h_j: GroupAffine) -> bool {
    c == witness + h_j * v_j
}

pub fn batch_open(v: &[Scalar], r: Scalar, indices: impl IntoIterator<Item = usize>) -> Result<(Vec<Scalar>, Scalar, GroupAffine)> {
    let indices: Vec<usize> = indices.into_iter().collect();
    
    // Validate indices
    if indices.is_empty() {
        return Err(anyhow!("Empty indices"));
    }
    
    // Check for duplicates and bounds
    let mut sorted_indices = indices.clone();
    sorted_indices.sort_unstable();
    if sorted_indices.windows(2).any(|w| w[0] == w[1]) {
        return Err(anyhow!("Duplicate indices not allowed"));
    }
    if sorted_indices.iter().any(|&i| i >= v.len()) {
        return Err(anyhow!("Index out of bounds"));
    }
    
    let blind = POINTS[BLINDING_INDEX] * r;
    let witness = POINTS[1..].iter().enumerate()
        .filter(|(i, _)| !sorted_indices.contains(i))
        .map(|(i, p)| *p * v[i])
        .sum::<GroupProjective>() + blind;
    
    let values: Vec<Scalar> = sorted_indices.iter().map(|&j| v[j]).collect();
    Ok((values, r, witness.into_affine()))
}

pub fn batch_check(c: GroupAffine, values: &[Scalar], witness: GroupAffine, indices: &[usize]) -> Result<bool> {
    if values.len() != indices.len() {
        return Err(anyhow!("values and indices must match"));
    }
    
    // Verify indices are sorted and unique
    if indices.windows(2).any(|w| w[0] >= w[1]) {
        return Err(anyhow!("indices must be sorted and unique"));
    }
    
    let sum = values.iter().zip(indices).fold(GroupProjective::from(witness), |acc, (v_j, &j)| {
        acc + POINTS[j + 1] * *v_j
    });
    
    Ok(c == sum.into_affine())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Field, UniformRand};
    use rand::thread_rng;

    #[test]
    fn test_commit_and_verify() {
        let mut rng = thread_rng();
        let v: Vec<Scalar> = (0..NUM_POINTS-1).map(|_| Scalar::rand(&mut rng)).collect();
        let r = Scalar::rand(&mut rng);
        
        let commitment = commit(&v, r).unwrap();
        let j = 0;
        let (v_j, r_j, witness) = open(&v, r, j).unwrap();
        
        assert!(check(commitment, v_j, witness, POINTS[j+1]));
    }

    #[test]
    fn test_batch_open() {
        let mut rng = thread_rng();
        let v: Vec<Scalar> = (0..NUM_POINTS-1).map(|_| Scalar::rand(&mut rng)).collect();
        let r = Scalar::rand(&mut rng);
        let commitment = commit(&v, r).unwrap();

        let indices = vec![0, 2, 4];
        let (values, r_j, witness) = batch_open(&v, r, indices.clone()).unwrap();
        
        assert!(batch_check(commitment, &values, witness, &indices).unwrap());
    }

    #[test]
    fn test_batch_open_edge_cases() {
        let mut rng = thread_rng();
        let v: Vec<Scalar> = (0..NUM_POINTS-1).map(|_| Scalar::rand(&mut rng)).collect();
        let r = Scalar::rand(&mut rng);
        let commitment = commit(&v, r).unwrap();

        // Test with all indices
        let all_indices: Vec<usize> = (0..v.len()).collect();
        let (values, r_j, witness) = batch_open(&v, r, all_indices.clone()).unwrap();
        assert!(batch_check(commitment, &values, witness, &all_indices).unwrap());

        // Test with empty indices (should fail)
        assert!(batch_open(&v, r, Vec::<usize>::new()).is_err());

        // Test with duplicate indices (should fail)
        let duplicate_indices = vec![0, 0, 2];
        assert!(batch_open(&v, r, duplicate_indices).is_err());

        // Test with out of bounds index (should fail)
        let out_of_bounds = vec![0, v.len()];
        assert!(batch_open(&v, r, out_of_bounds).is_err());
    }

    #[test]
    fn test_invalid_opening() {
        let mut rng = thread_rng();
        let v: Vec<Scalar> = (0..NUM_POINTS-1).map(|_| Scalar::rand(&mut rng)).collect();
        let r = Scalar::rand(&mut rng);
        let commitment = commit(&v, r).unwrap();

        let j = 0;
        let (v_j, r_j, witness) = open(&v, r, j).unwrap();
        let invalid_v_j = v_j + Scalar::from(1u64);

        assert!(!check(commitment, invalid_v_j, witness, POINTS[j+1]));
    }

    #[test]
    fn test_invalid_vector_length() {
        let mut rng = thread_rng();
        let v: Vec<Scalar> = (0..NUM_POINTS).map(|_| Scalar::rand(&mut rng)).collect();
        let r = Scalar::rand(&mut rng);
        assert!(commit(&v, r).is_err());
    }
}
