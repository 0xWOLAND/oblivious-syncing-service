use ark_bls12_377::{G1Projective, G1Affine, g1::Config};
use ark_ec::hashing::{HashToCurve, map_to_curve_hasher::MapToCurveBasedHasher};
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_poly::Polynomial;
use sha2::Sha256;
use std::fs::File;
use std::io::{self, BufRead, Error, ErrorKind};

fn hash_message(message: &str) -> G1Affine {
    MapToCurveBasedHasher::<G1Projective, DefaultFieldHasher<Sha256>, WBMap<Config>>::new(b"BLS12377G1_XMD:SHA-256_SSWU_RO_")
        .unwrap()
        .hash(message.as_bytes())
        .unwrap()
        .into()
}

fn read_trusted_setup(n: usize) -> io::Result<Vec<G1Affine>> {
    let mut lines = io::BufReader::new(File::open("trusted_setup.txt")?).lines();
    let max_points: usize = lines.next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Empty file"))??
        .trim()
        .parse()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid max points"))?;

    if n > max_points {
        return Err(Error::new(ErrorKind::InvalidInput, format!("Requested {} points but max is {}", n, max_points)));
    }

    lines.next(); // Skip description line
    Ok(lines.take(n)
        .collect::<io::Result<Vec<String>>>()?
        .iter()
        .map(|line| hash_message(line))
        .collect())
}


fn main() -> io::Result<()> {
    println!("Processed {} points", read_trusted_setup(4096)?.len());
    Ok(())
}
