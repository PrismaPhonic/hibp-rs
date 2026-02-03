# hibp-rs

[![CI](https://img.shields.io/github/actions/workflow/status/PrismaPhonic/hibp-rs/ci.yml?branch=main)](https://github.com/PrismaPhonic/hibp-rs/actions)
[![maintenance](https://img.shields.io/badge/maintenance-actively--developed-brightgreen)](https://github.com/PrismaPhonic/hibp-rs)

Rust tools for working with the Have I Been Pwned password hash database.

## Crates

| Crate                                | Description                                      | Docs                                                                                   |
|--------------------------------------|--------------------------------------------------|----------------------------------------------------------------------------------------|
| [hibp-bin-fetch](./hibp-bin-fetch/)  | Download and convert HIBP data to binary format  | [![docs.rs](https://docs.rs/hibp-bin-fetch/badge.svg)](https://docs.rs/hibp-bin-fetch) |
| [hibp-verifier](./hibp-verifier/)    | Check passwords against the breach database      | [![docs.rs](https://docs.rs/hibp-verifier/badge.svg)](https://docs.rs/hibp-verifier)   |

## Quick Start

Download the dataset:

```sh
cargo install hibp-bin-fetch
hibp-bin-fetch --output ./hibp-data
```

Check a password:

```rust
use hibp_verifier::BreachChecker;
use std::path::Path;

let checker = BreachChecker::new(Path::new("./hibp-data"));
let is_breached = checker.is_breached("password123").unwrap();
```

## Storage Format

Both tools use sha1t48, a compact format that truncates SHA1 hashes to 48 bits.
This reduces storage from 77 GB (original text) to 13 GB while maintaining
negligible collision probability.

See the individual crate READMEs for detailed documentation.

## License

MIT
