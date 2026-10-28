pub const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn decode_char(c: char) -> Option<usize> {
    match c.to_ascii_uppercase() {
        '0' | 'O' => Some(0),
        '1' | 'I' | 'L' => Some(1),
        '2' => Some(2),
        '3' => Some(3),
        '4' => Some(4),
        '5' => Some(5),
        '6' => Some(6),
        '7' => Some(7),
        '8' => Some(8),
        '9' => Some(9),
        'A' => Some(10),
        'B' => Some(11),
        'C' => Some(12),
        'D' => Some(13),
        'E' => Some(14),
        'F' => Some(15),
        'G' => Some(16),
        'H' => Some(17),
        'J' => Some(18),
        'K' => Some(19),
        'M' => Some(20),
        'N' => Some(21),
        'P' => Some(22),
        'Q' => Some(23),
        'R' => Some(24),
        'S' => Some(25),
        'T' => Some(26),
        'V' => Some(27),
        'W' => Some(28),
        'X' => Some(29),
        'Y' => Some(30),
        'Z' => Some(31),
        _ => None,
    }
}

pub fn encode_value(val: usize) -> char {
    CROCKFORD_ALPHABET[val % 32] as char
}

/// Computes a 10-bit checksum (represented as 2 Crockford Base32 characters)
/// over the 8-character payload.
pub fn calculate_checksum(payload: &str) -> (char, char) {
    let mut sum: usize = 0;
    for (i, c) in payload.chars().enumerate() {
        if let Some(val) = decode_char(c) {
            sum += (i + 1) * val;
        }
    }
    let cs_val = sum % 1024;
    let c1 = encode_value((cs_val >> 5) & 0x1F);
    let c2 = encode_value(cs_val & 0x1F);
    (c1, c2)
}

/// Verifies whether the provided code (10+ characters) has a valid checksum.
pub fn verify_checksum(code: &str) -> Result<bool, &'static str> {
    let clean: String = code
        .chars()
        .filter(|c| !matches!(*c, '-' | '_' | '%' | '$' | '#' | '@' | ' '))
        .collect();
    if clean.len() < 10 {
        return Err("Code must be at least 10 alphanumeric characters (symbols like _-%$#@ are ignored as separators)");
    }

    for c in clean.chars() {
        if decode_char(c).is_none() {
            return Err("Contains invalid characters (only 0-9 and A-Z excluding I, L, O, U)");
        }
    }

    let payload_len = clean.len() - 2;
    let payload = &clean[0..payload_len];
    let c1_given = clean.chars().nth(payload_len).unwrap().to_ascii_uppercase();
    let c2_given = clean
        .chars()
        .nth(payload_len + 1)
        .unwrap()
        .to_ascii_uppercase();

    let (c1_exp, c2_exp) = calculate_checksum(payload);
    // Normalize comparison with decode_char (O->0, I/L->1)
    let c1_norm = encode_value(decode_char(c1_given).unwrap());
    let c2_norm = encode_value(decode_char(c2_given).unwrap());

    Ok(c1_norm == c1_exp && c2_norm == c2_exp)
}
