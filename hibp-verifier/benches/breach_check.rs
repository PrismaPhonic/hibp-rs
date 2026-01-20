use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hibp_verifier::{dataset_path_from_env, BreachChecker};

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

criterion_group!(
    benches,
    bench_common_passwords,
    bench_random_passwords,
    bench_mixed_passwords
);
criterion_main!(benches);
