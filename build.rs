use std::env;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("trusted_setup.rs");
    let mut f = File::create(&dest_path).expect("Failed to create output file");

    let file = File::open("trusted_setup.txt").expect("Failed to open trusted_setup.txt");
    let lines = io::BufReader::new(file).lines();
    
    writeln!(f, "pub const TRUSTED_SETUP: [&str; 8257] = [").expect("Failed to write");
    for line in lines.take(8257) {
        writeln!(f, "    \"{}\",", line.expect("Failed to read line")).expect("Failed to write");
    }
    writeln!(f, "];").expect("Failed to write");
    
    println!("cargo:rerun-if-changed=trusted_setup.txt");
} 