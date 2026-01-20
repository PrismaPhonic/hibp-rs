/// Convert hex ASCII character to nibble value (0-15)
#[inline]
pub fn hex_to_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'A'..=b'F' => c - b'A' + 10,
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("invalid hex char: {}", c as char),
    }
}

/// Convert prefix (u32) + suffix line to sha1t64 (8 bytes)
///
/// The prefix is a 20-bit value (5 hex chars), and the suffix line starts with
/// 35 hex chars. Together, the first 64 bits (8 bytes) form the sha1t64.
///
/// Layout:
/// - Prefix: 5 hex chars = 20 bits = bytes 0-1 and high nibble of byte 2
/// - Suffix: first 11 hex chars = 44 bits = low nibble of byte 2 and bytes 3-7
#[inline]
pub fn line_to_sha1t64(prefix: u32, suffix_line: &[u8], out: &mut [u8; 8]) {
    let p0 = ((prefix >> 16) & 0xF) as u8;
    let p1 = ((prefix >> 12) & 0xF) as u8;
    let p2 = ((prefix >> 8) & 0xF) as u8;
    let p3 = ((prefix >> 4) & 0xF) as u8;
    let p4 = (prefix & 0xF) as u8;

    out[0] = (p0 << 4) | p1;
    out[1] = (p2 << 4) | p3;
    out[2] = (p4 << 4) | hex_to_nibble(suffix_line[0]);
    out[3] = (hex_to_nibble(suffix_line[1]) << 4) | hex_to_nibble(suffix_line[2]);
    out[4] = (hex_to_nibble(suffix_line[3]) << 4) | hex_to_nibble(suffix_line[4]);
    out[5] = (hex_to_nibble(suffix_line[5]) << 4) | hex_to_nibble(suffix_line[6]);
    out[6] = (hex_to_nibble(suffix_line[7]) << 4) | hex_to_nibble(suffix_line[8]);
    out[7] = (hex_to_nibble(suffix_line[9]) << 4) | hex_to_nibble(suffix_line[10]);
}

/// Convert prefix u32 to 5-char uppercase hex string (stack allocated)
#[inline]
pub fn prefix_to_hex(prefix: u32) -> [u8; 5] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    [
        HEX[((prefix >> 16) & 0xF) as usize],
        HEX[((prefix >> 12) & 0xF) as usize],
        HEX[((prefix >> 8) & 0xF) as usize],
        HEX[((prefix >> 4) & 0xF) as usize],
        HEX[(prefix & 0xF) as usize],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_nibble() {
        assert_eq!(hex_to_nibble(b'0'), 0);
        assert_eq!(hex_to_nibble(b'9'), 9);
        assert_eq!(hex_to_nibble(b'A'), 10);
        assert_eq!(hex_to_nibble(b'F'), 15);
        assert_eq!(hex_to_nibble(b'a'), 10);
        assert_eq!(hex_to_nibble(b'f'), 15);
    }

    #[test]
    fn test_prefix_to_hex() {
        assert_eq!(&prefix_to_hex(0x00000), b"00000");
        assert_eq!(&prefix_to_hex(0xFFFFF), b"FFFFF");
        assert_eq!(&prefix_to_hex(0xABCDE), b"ABCDE");
        assert_eq!(&prefix_to_hex(0x12345), b"12345");
    }

    #[test]
    fn test_line_to_sha1t64() {
        // Test with known password "password123"
        // Full SHA1: CBFDAC6008F9CAB4083784CBD1874F76618D2A97
        // Prefix: CBFDA (0xCBFDA)
        // Suffix line: C6008F9CAB4083784CBD1874F76618D2A97:count
        // sha1t64 should be first 8 bytes: CB FD AC 60 08 F9 CA B4
        let prefix = 0xCBFDA;
        let suffix_line = b"C6008F9CAB4083784CBD1874F76618D2A97:2254650";
        let mut out = [0u8; 8];
        line_to_sha1t64(prefix, suffix_line, &mut out);

        assert_eq!(out, [0xCB, 0xFD, 0xAC, 0x60, 0x08, 0xF9, 0xCA, 0xB4]);
    }

    #[test]
    fn test_line_to_sha1t64_all_zeros() {
        let prefix = 0x00000;
        let suffix_line = b"00000000000000000000000000000000000:1";
        let mut out = [0u8; 8];
        line_to_sha1t64(prefix, suffix_line, &mut out);

        assert_eq!(out, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_line_to_sha1t64_all_fs() {
        let prefix = 0xFFFFF;
        let suffix_line = b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1";
        let mut out = [0u8; 8];
        line_to_sha1t64(prefix, suffix_line, &mut out);

        assert_eq!(out, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }
}
