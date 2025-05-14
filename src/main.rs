use ark_bls12_377::{G1Projective, G1Affine, g1::Config};
use ark_ec::hashing::{HashToCurve, map_to_curve_hasher::MapToCurveBasedHasher};
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_poly::Polynomial;
use sha2::Sha256;

const NUM_POINTS: usize = 20;

fn hash_message(message: &str) -> G1Affine {
    MapToCurveBasedHasher::<G1Projective, DefaultFieldHasher<Sha256>, WBMap<Config>>::new(b"BLS12377G1_XMD:SHA-256_SSWU_RO_")
        .unwrap()
        .hash(message.as_bytes())
        .unwrap()
        .into()
}

include!(concat!(env!("OUT_DIR"), "/trusted_setup.rs"));

lazy_static::lazy_static! {
    static ref POINTS: [G1Affine; NUM_POINTS] = TRUSTED_SETUP[..NUM_POINTS]
        .iter()
        .map(|line| hash_message(line))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
}

fn main() {
    println!("Processed {} points", POINTS.len());
}
