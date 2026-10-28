use anyhow::{bail, Result};

pub const MAGIC_BYTES: [u8; 3] = [0x53, 0x44, 0x53]; // ASCII "SDS"
pub const PROTOCOL_VERSION: u8 = 0x01;
pub const HEADER_SIZE: usize = 28; // Exactly 28 bytes (7 x 32-bit aligned words)
pub const AUTH_TAG_SIZE: usize = 16;

// Flag bitmasks (1 Byte, Offset 4)
pub const FLAG_IS_DATAGRAM: u8 = 0b0000_0001; // 0 = Reliable Stream, 1 = QUIC Datagram
pub const FLAG_ENCRYPTED_E2EE: u8 = 0b0000_0010; // Payload is Double-Ratchet encrypted
pub const FLAG_AUTH_TAG: u8 = 0b0000_0100; // 16-byte Poly1305 MAC appended
pub const FLAG_COMPRESSED_ZSTD: u8 = 0b0000_1000; // Payload compressed with Zstandard
pub const FLAG_URGENT_PRIORITY: u8 = 0b0001_0000; // Urgent packet scheduling

// Standard Frame Types (2 Bytes, Big-Endian, Offset 6..8)
pub const TYPE_HANDSHAKE_INIT: u16 = 0x0001;
pub const TYPE_HANDSHAKE_RESP: u16 = 0x0002;
pub const TYPE_SESSION_TICKET: u16 = 0x0003;
pub const TYPE_PING: u16 = 0x0004;
pub const TYPE_PONG: u16 = 0x0005;
pub const TYPE_CLOSE_NOTIFY: u16 = 0x0006;

pub const TYPE_RESOLVE_PROFILE_REQ: u16 = 0x0010;
pub const TYPE_RESOLVE_PROFILE_RESP: u16 = 0x0011;
pub const TYPE_VERIFY_IDENTITY_PROOF: u16 = 0x0012;

pub const TYPE_MSG_ENVELOPE: u16 = 0x0030;
pub const TYPE_MSG_ACK: u16 = 0x0031;
pub const TYPE_MSG_OFFLINE_SYNC_REQ: u16 = 0x0032;
pub const TYPE_MSG_OFFLINE_SYNC_RESP: u16 = 0x0033;
pub const TYPE_PRESENCE_STATE: u16 = 0x0034;

pub const TYPE_CALL_INVITE: u16 = 0x0050;
pub const TYPE_CALL_RINGING: u16 = 0x0051;
pub const TYPE_CALL_ACCEPT: u16 = 0x0052;
pub const TYPE_CALL_REJECT: u16 = 0x0053;
pub const TYPE_CALL_TERMINATE: u16 = 0x0054;

pub const TYPE_MEDIA_AUDIO_OPUS: u16 = 0x0070;
pub const TYPE_MEDIA_VIDEO_KEYFRAME: u16 = 0x0071;
pub const TYPE_MEDIA_VIDEO_DELTA: u16 = 0x0072;
pub const TYPE_MEDIA_FEC_PARITY: u16 = 0x0073;
pub const TYPE_MEDIA_FEEDBACK_RTCP: u16 = 0x0074;

pub const TYPE_RELAY_BIND_REQ: u16 = 0x0090;
pub const TYPE_RELAY_BIND_RESP: u16 = 0x0091;
pub const TYPE_RELAY_PACKET_FORWARD: u16 = 0x0092;
pub const TYPE_RELAY_HOLE_PUNCH_SYNC: u16 = 0x0093;

// Canonical Protocol Error Codes (u16)
pub const ERR_OK: u16 = 0x0000;
pub const ERR_MALFORMED_FRAME: u16 = 0x0001;
pub const ERR_UNSUPPORTED_VERSION: u16 = 0x0002;
pub const ERR_ID_CHECKSUM_INVALID: u16 = 0x0003;
pub const ERR_DOMAIN_NOT_REGISTERED: u16 = 0x0004;
pub const ERR_IDENTITY_SIGNATURE_FAILED: u16 = 0x0005;
pub const ERR_REPLAY_DETECTED: u16 = 0x0006;
pub const ERR_0RTT_OPERATION_FORBIDDEN: u16 = 0x0007;
pub const ERR_DEADLINE_EXPIRED: u16 = 0x0008;
pub const ERR_DIRECT_PATH_UNAVAILABLE: u16 = 0x0009;
pub const ERR_RELAY_AUTH_FAILED: u16 = 0x000A;
pub const ERR_RATE_LIMITED: u16 = 0x000B;
pub const ERR_CALL_BUSY: u16 = 0x000C;
pub const ERR_CALL_DECLINED: u16 = 0x000D;

/// Universal SDS Binary Frame representation (RFC 28-Byte Wire Format)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdsFrame {
    pub version: u8,
    pub flags: u8,
    pub sub_type: u8,
    pub frame_type: u16,
    pub stream_id: u32,
    pub sequence_num: u64,
    pub lifetime_ms: u16,
    pub payload: Vec<u8>,
    pub auth_tag: Option<[u8; AUTH_TAG_SIZE]>,
}

impl SdsFrame {
    pub fn new(
        frame_type: u16,
        sub_type: u8,
        stream_id: u32,
        sequence_num: u64,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            flags: 0,
            sub_type,
            frame_type,
            stream_id,
            sequence_num,
            lifetime_ms: 0,
            payload,
            auth_tag: None,
        }
    }

    pub fn new_datagram(
        frame_type: u16,
        sub_type: u8,
        stream_id: u32,
        sequence_num: u64,
        lifetime_ms: u16,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            flags: FLAG_IS_DATAGRAM,
            sub_type,
            frame_type,
            stream_id,
            sequence_num,
            lifetime_ms,
            payload,
            auth_tag: None,
        }
    }

    /// Serializes the frame into network wire format (Exact 28-Byte Header + Big-Endian)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut flags = self.flags;
        if self.auth_tag.is_some() {
            flags |= FLAG_AUTH_TAG;
        }

        let mut buf = Vec::with_capacity(
            HEADER_SIZE
                + self.payload.len()
                + if self.auth_tag.is_some() {
                    AUTH_TAG_SIZE
                } else {
                    0
                },
        );

        // Word 0 (Bytes 0..3): Magic [3B] + Version [1B]
        buf.extend_from_slice(&MAGIC_BYTES); // 0..2
        buf.push(self.version); // 3

        // Word 1 (Bytes 4..7): Flags [1B] + Sub-Type [1B] + Frame Type [2B]
        buf.push(flags); // 4
        buf.push(self.sub_type); // 5
        buf.extend_from_slice(&self.frame_type.to_be_bytes()); // 6..7

        // Word 2 (Bytes 8..11): Stream ID [4B]
        buf.extend_from_slice(&self.stream_id.to_be_bytes()); // 8..11

        // Words 3 & 4 (Bytes 12..19): Sequence Number [8B]
        buf.extend_from_slice(&self.sequence_num.to_be_bytes()); // 12..19

        // Word 5 (Bytes 20..23): Payload Length [4B]
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes()); // 20..23

        // Word 6 (Bytes 24..27): Lifetime Budget ms [2B] + Reserved [2B]
        buf.extend_from_slice(&self.lifetime_ms.to_be_bytes()); // 24..25
        buf.extend_from_slice(&0u16.to_be_bytes()); // 26..27

        debug_assert_eq!(buf.len(), HEADER_SIZE, "Header must be exactly 28 bytes");

        // Payload
        buf.extend_from_slice(&self.payload);

        // Optional Auth Tag (16 Bytes)
        if let Some(tag) = self.auth_tag {
            buf.extend_from_slice(&tag);
        }

        buf
    }

    /// Parses a frame from raw wire bytes adhering to RFC 28-byte header layout
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            bail!(
                "Frame truncated: size {} < minimum header {}",
                data.len(),
                HEADER_SIZE
            );
        }

        // Validate Magic [Bytes 0..2]
        if data[0..3] != MAGIC_BYTES {
            bail!("Invalid SDS magic: {:02X?}", &data[0..3]);
        }

        // Version [Byte 3]
        let version = data[3];
        if version != PROTOCOL_VERSION {
            bail!("Unsupported SDS protocol version: 0x{:02X}", version);
        }

        // Flags [Byte 4] & Sub-Type [Byte 5]
        let flags = data[4];
        let sub_type = data[5];

        // Frame Type [Bytes 6..7]
        let frame_type = u16::from_be_bytes([data[6], data[7]]);

        // Stream ID [Bytes 8..11]
        let stream_id = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        // Sequence Number [Bytes 12..19]
        let sequence_num = u64::from_be_bytes([
            data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
        ]);

        // Payload Length [Bytes 20..23]
        let payload_len = u32::from_be_bytes([data[20], data[21], data[22], data[23]]) as usize;

        // Lifetime Budget ms [Bytes 24..25]
        let lifetime_ms = u16::from_be_bytes([data[24], data[25]]);
        // Bytes 26..27 is Reserved

        let has_auth_tag = (flags & FLAG_AUTH_TAG) != 0;
        let expected_total =
            HEADER_SIZE + payload_len + if has_auth_tag { AUTH_TAG_SIZE } else { 0 };

        if data.len() < expected_total {
            bail!(
                "Incomplete frame: expected {} bytes, received {}",
                expected_total,
                data.len()
            );
        }

        let payload = data[HEADER_SIZE..HEADER_SIZE + payload_len].to_vec();

        let auth_tag = if has_auth_tag {
            let offset = HEADER_SIZE + payload_len;
            let mut tag = [0u8; AUTH_TAG_SIZE];
            tag.copy_from_slice(&data[offset..offset + AUTH_TAG_SIZE]);
            Some(tag)
        } else {
            None
        };

        Ok(Self {
            version,
            flags,
            sub_type,
            frame_type,
            stream_id,
            sequence_num,
            lifetime_ms,
            payload,
            auth_tag,
        })
    }

    /// Evaluates if a media datagram has passed its relative lifetime budget and must be dropped.
    pub fn is_lifetime_expired(&self, elapsed_ms: u64) -> bool {
        if self.lifetime_ms == 0 {
            return false;
        }
        elapsed_ms > self.lifetime_ms as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_28_byte_header_and_roundtrip() {
        let payload = b"SDS Wire Format Exact 28-Byte Header".to_vec();
        let frame = SdsFrame::new(TYPE_MSG_ENVELOPE, 0x02, 101, 5000, payload.clone());
        let bytes = frame.to_bytes();

        // Exact header check
        assert_eq!(&bytes[0..3], &MAGIC_BYTES);
        assert_eq!(bytes[3], PROTOCOL_VERSION);
        assert_eq!(bytes[4], 0); // flags
        assert_eq!(bytes[5], 0x02); // sub_type
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), TYPE_MSG_ENVELOPE);
        assert_eq!(
            u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            101
        );
        assert_eq!(bytes.len(), HEADER_SIZE + payload.len());
        assert_eq!(HEADER_SIZE, 28);

        let parsed = SdsFrame::from_bytes(&bytes).expect("Should parse valid 28-byte header frame");
        assert_eq!(parsed.frame_type, TYPE_MSG_ENVELOPE);
        assert_eq!(parsed.sub_type, 0x02);
        assert_eq!(parsed.stream_id, 101);
        assert_eq!(parsed.sequence_num, 5000);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_datagram_with_lifetime_and_auth_tag() {
        let payload = vec![0xEE; 32];
        let mut frame =
            SdsFrame::new_datagram(TYPE_MEDIA_AUDIO_OPUS, 0x01, 2, 777, 80, payload.clone());
        frame.auth_tag = Some([0x33; 16]);

        let bytes = frame.to_bytes();
        assert_eq!(bytes.len(), 28 + 32 + 16);

        let parsed = SdsFrame::from_bytes(&bytes).expect("Should parse datagram with auth tag");
        assert_eq!(parsed.flags & FLAG_IS_DATAGRAM, FLAG_IS_DATAGRAM);
        assert_eq!(parsed.flags & FLAG_AUTH_TAG, FLAG_AUTH_TAG);
        assert_eq!(parsed.lifetime_ms, 80);
        assert_eq!(parsed.auth_tag, Some([0x33; 16]));

        assert!(!parsed.is_lifetime_expired(79));
        assert!(parsed.is_lifetime_expired(81));
    }
}
