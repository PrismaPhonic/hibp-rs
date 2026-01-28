use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const ALL_CHARS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";

/// Generates a specified number of random passwords with uniform distribution.
/// Uses a fixed seed for reproducible benchmark results.
pub fn generate_random_passwords(count: usize) -> Vec<String> {
    let mut rng = StdRng::seed_from_u64(42);
    (0..count)
        .map(|_| {
            let length = rng.gen_range(8..=64);
            (0..length)
                .map(|_| ALL_CHARS[rng.gen_range(0..ALL_CHARS.len())] as char)
                .collect()
        })
        .collect()
}
