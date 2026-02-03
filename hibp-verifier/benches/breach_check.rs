use std::time::{Duration, Instant};

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use hibp_verifier::{BreachChecker, dataset_path_from_env};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Character sets for password generation
const ALL_CHARS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";

/// Generates a specified number of random passwords with uniform distribution
/// Uses a fixed seed for reproducible benchmark results
pub fn generate_random_passwords(count: usize) -> Vec<String> {
    let mut rng = StdRng::seed_from_u64(42); // Fixed seed for reproducibility
    let mut passwords = Vec::with_capacity(count);

    for _ in 0..count {
        let length = rng.gen_range(8..=64); // Random length between 8 and 64
        let mut password = String::with_capacity(length);

        for _ in 0..length {
            let char_index = rng.gen_range(0..ALL_CHARS.len());
            password.push(ALL_CHARS[char_index] as char);
        }

        passwords.push(password);
    }

    passwords
}

// 20 commonly used passwords (guaranteed to be in breaches)
const COMMON_PASSWORDS: &[&str] = &[
    "123456",
    "password",
    "123456789",
    "12345678",
    "12345",
    "qwerty",
    "qwerty123",
    "1234567",
    "111111",
    "1234567890",
    "abc123",
    "password1",
    "iloveyou",
    "sunshine",
    "princess",
    "admin",
    "welcome",
    "football",
    "monkey",
    "dragon",
];

// 20 randomly generated ULIDs (guaranteed to NOT be in breaches)
const RANDOM_PASSWORDS: &[&str] = &[
    "01KFC4WS41FAJ3ACEJXTF8HV44",
    "01KFC4WS42PTGBA3M7VAF27C13",
    "01KFC4WS421ZQX52RVBY33X00H",
    "01KFC4WS42PCR9YS9BE5H07J2N",
    "01KFC4WS422QH0NCA4V9GTDJM0",
    "01KFC4WS420YDDKKP1R6PB3306",
    "01KFC4WS42SA1YYSWB0EJBHZ17",
    "01KFC4WS42YE2HH2JCZQY4GCXC",
    "01KFC4WS42RY3P99C454YQ2RRE",
    "01KFC4WS43SEKHX766ZNXC6619",
    "01KFC4WS43CDZ2BEWY65T7XDZ0",
    "01KFC4WS43XYTYQB129ZY3W3T6",
    "01KFC4WS433XWM6JJ31G79XDDM",
    "01KFC4WS43YQ4JZJ7RMT26S7MT",
    "01KFC4WS43ZB04TM35752QNFKN",
    "01KFC4WS43XD0SYTKMGK1RP95R",
    "01KFC4WS4354B10X6C0K1MYVG7",
    "01KFC4WS433BWWFDWVYQQ2M22R",
    "01KFC4WS431B5S8ZCYXWEPPTT4",
    "01KFC4WS43N06B5JR15GYH5JX6",
];

fn bench_common_passwords(c: &mut Criterion) {
    let path = dataset_path_from_env();
    let checker = BreachChecker::new(&path);

    c.bench_function("common_passwords_20", |b| {
        b.iter(|| {
            for password in COMMON_PASSWORDS {
                black_box(checker.is_breached(black_box(password)).unwrap());
            }
        })
    });
}

fn bench_random_passwords(c: &mut Criterion) {
    let path = dataset_path_from_env();
    let checker = BreachChecker::new(&path);

    c.bench_function("random_passwords_20", |b| {
        b.iter(|| {
            for password in RANDOM_PASSWORDS {
                black_box(checker.is_breached(black_box(password)).unwrap());
            }
        })
    });
}

fn bench_mixed_passwords(c: &mut Criterion) {
    let path = dataset_path_from_env();
    let checker = BreachChecker::new(&path);

    c.bench_function("mixed_passwords_40", |b| {
        b.iter(|| {
            for password in COMMON_PASSWORDS.iter().chain(RANDOM_PASSWORDS.iter()) {
                black_box(checker.is_breached(black_box(password)).unwrap());
            }
        })
    });
}

/// Cold page benchmark
/// Tests performance with 100k random passwords to maximize cold page misses
fn bench_cold_pages(c: &mut Criterion) {
    let passwords = generate_random_passwords(100_000);
    let path = dataset_path_from_env();
    let checker = BreachChecker::new(&path);

    let mut group = c.benchmark_group("cold_pages");
    // We can't turn the warmup off, but we can set it to a comically low threshold to essentially
    // turn it off. Note: This panics if set to zero duration.
    group.warm_up_time(Duration::from_nanos(1));

    group.bench_function("read_100k", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();

            for password in &passwords {
                black_box(checker.is_breached(password).unwrap());
            }

            let elapsed = start.elapsed();
            let passwords_checked = passwords.len() as u64;
            let time_per_password_ns = elapsed.as_nanos() as f64 / passwords_checked as f64;
            let scaled_nanos = (time_per_password_ns * iters as f64) as u64;
            Duration::from_nanos(scaled_nanos)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_common_passwords,
    bench_random_passwords,
    bench_mixed_passwords,
    bench_cold_pages,
);
criterion_main!(benches);
