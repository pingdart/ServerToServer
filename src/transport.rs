use anyhow::{bail, Result};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

use crate::frame::SdsFrame;
use crate::replay::ReplayStrikeRegister;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    Uninitialized,
    IdResolved,
    EndpointFound,
    DirectQuic0Rtt,
    RelayFallback,
    SessionActive,
    CidMigrating,
    Terminated,
}

#[derive(Debug, Clone, Default)]
pub struct TransportMetrics {
    pub rtt_ms: u32,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub dropped_deadline_packets: u64,
    pub migration_count: u32,
}

/// A media datagram queued with local ingestion timestamp for deadline management
#[derive(Debug, Clone)]
pub struct QueuedDatagram {
    pub frame: SdsFrame,
    pub ingested_at: Instant,
}

/// SDS Transport Session Engine
pub struct SdsTransportSession {
    pub session_id: u64,
    pub connection_id: u64, // 64-bit CID enabling zero-drop migration across IP/Port changes
    pub state: TransportState,
    pub local_addr: Option<SocketAddr>,
    pub remote_addr: Option<SocketAddr>,
    pub is_relay_path: bool,
    pub metrics: TransportMetrics,
    pub replay_register: ReplayStrikeRegister,
    incoming_media_queue: VecDeque<QueuedDatagram>,
    next_stream_seq: u64,
}

impl SdsTransportSession {
    pub fn new(session_id: u64, connection_id: u64) -> Self {
        Self {
            session_id,
            connection_id,
            state: TransportState::Uninitialized,
            local_addr: None,
            remote_addr: None,
            is_relay_path: false,
            metrics: TransportMetrics::default(),
            replay_register: ReplayStrikeRegister::new(),
            incoming_media_queue: VecDeque::new(),
            next_stream_seq: 1,
        }
    }

    /// Advance state from discovery to endpoint resolution
    pub fn set_endpoint(&mut self, remote_addr: SocketAddr) {
        self.remote_addr = Some(remote_addr);
        self.state = TransportState::EndpointFound;
    }

    /// Connect directly via QUIC 0-RTT path
    pub fn connect_direct(&mut self, local_addr: SocketAddr) {
        self.local_addr = Some(local_addr);
        self.is_relay_path = false;
        self.state = TransportState::DirectQuic0Rtt;
    }

    /// Complete handshake and transition to active session
    pub fn complete_handshake(&mut self) {
        self.state = TransportState::SessionActive;
    }

    /// Activate relay fallback when direct UDP connection fails or times out
    pub fn activate_relay_fallback(&mut self, relay_addr: SocketAddr) {
        self.remote_addr = Some(relay_addr);
        self.is_relay_path = true;
        self.state = TransportState::RelayFallback;
    }

    /// Execute seamless connection migration (e.g. WiFi -> 5G / IP change)
    pub fn migrate_connection(&mut self, new_local_addr: SocketAddr) -> Result<()> {
        if self.state != TransportState::SessionActive && self.state != TransportState::CidMigrating
        {
            bail!("Cannot migrate connection in state {:?}", self.state);
        }
        self.state = TransportState::CidMigrating;
        self.local_addr = Some(new_local_addr);
        self.metrics.migration_count += 1;
        // Migration complete under the same 64-bit connection_id
        self.state = TransportState::SessionActive;
        Ok(())
    }

    /// Send a reliable stream frame
    pub fn send_stream_frame(
        &mut self,
        frame_type: u16,
        sub_type: u8,
        stream_id: u32,
        payload: Vec<u8>,
    ) -> SdsFrame {
        let seq = self.next_stream_seq;
        self.next_stream_seq += 1;

        let frame = SdsFrame::new(frame_type, sub_type, stream_id, seq, payload);
        self.metrics.packets_sent += 1;
        self.metrics.bytes_sent += (frame.payload.len() + crate::frame::HEADER_SIZE) as u64;
        frame
    }

    /// Ingests and validates an incoming frame at the protocol transport layer.
    /// When the session is in DirectQuic0Rtt state, enforces the RFC 9001 0-RTT idempotency gate.
    pub fn handle_incoming_frame(&mut self, frame: &SdsFrame) -> Result<(), u16> {
        if self.state == TransportState::DirectQuic0Rtt {
            self.replay_register
                .validate_0rtt_operation(frame.frame_type)?;
        }
        self.metrics.packets_received += 1;
        self.metrics.bytes_received += (frame.payload.len() + crate::frame::HEADER_SIZE) as u64;
        Ok(())
    }

    /// Ingest an incoming media datagram into the jitter buffer
    pub fn ingest_media_datagram(&mut self, frame: SdsFrame) {
        self.metrics.packets_received += 1;
        self.metrics.bytes_received += (frame.payload.len() + crate::frame::HEADER_SIZE) as u64;

        self.incoming_media_queue.push_back(QueuedDatagram {
            frame,
            ingested_at: Instant::now(),
        });
    }

    /// Dequeues the next valid media datagram for audio/video playback.
    /// Strictly drops any packets that have exceeded their lifetime budget.
    pub fn dequeue_playable_media(&mut self) -> Option<SdsFrame> {
        let now = Instant::now();

        while let Some(item) = self.incoming_media_queue.pop_front() {
            let elapsed_ms = now.duration_since(item.ingested_at).as_millis() as u64;

            if item.frame.is_lifetime_expired(elapsed_ms) {
                // Drop expired packet immediately; do not forward to audio/video decoder
                self.metrics.dropped_deadline_packets += 1;
                continue;
            }

            return Some(item.frame);
        }

        None
    }

    pub fn terminate(&mut self) {
        self.state = TransportState::Terminated;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::TYPE_MEDIA_AUDIO_OPUS;
    use std::time::Duration;

    #[test]
    fn test_transport_lifecycle_and_migration() {
        let mut session = SdsTransportSession::new(1001, 0xAABBCCDDEEFF0011);
        assert_eq!(session.state, TransportState::Uninitialized);

        let endpoint: SocketAddr = "192.168.1.50:4433".parse().unwrap();
        session.set_endpoint(endpoint);
        assert_eq!(session.state, TransportState::EndpointFound);

        let local_wifi: SocketAddr = "192.168.1.10:55000".parse().unwrap();
        session.connect_direct(local_wifi);
        assert_eq!(session.state, TransportState::DirectQuic0Rtt);

        session.complete_handshake();
        assert_eq!(session.state, TransportState::SessionActive);

        // Network change from WiFi to 5G (Cellular IP handover)
        let cellular_ip: SocketAddr = "100.64.2.14:58220".parse().unwrap();
        session
            .migrate_connection(cellular_ip)
            .expect("Migration should succeed");
        assert_eq!(session.state, TransportState::SessionActive);
        assert_eq!(session.local_addr, Some(cellular_ip));
        assert_eq!(session.metrics.migration_count, 1);
    }

    #[test]
    fn test_media_playout_deadline_enforcement() {
        let mut session = SdsTransportSession::new(2002, 0x11223344);
        session.complete_handshake();

        // Datagram with 10ms deadline
        let tight_frame =
            SdsFrame::new_datagram(TYPE_MEDIA_AUDIO_OPUS, 0, 2, 1, 10, vec![0x11, 0x22]);
        // Datagram with 500ms deadline
        let relaxed_frame =
            SdsFrame::new_datagram(TYPE_MEDIA_AUDIO_OPUS, 0, 2, 2, 500, vec![0x33, 0x44]);

        session.ingest_media_datagram(tight_frame);
        session.ingest_media_datagram(relaxed_frame);

        // Sleep 15ms so the first frame expires past its 10ms deadline
        std::thread::sleep(Duration::from_millis(15));

        let popped = session
            .dequeue_playable_media()
            .expect("Should dequeue relaxed frame");
        assert_eq!(popped.sequence_num, 2); // Frame 1 was dropped due to expired deadline!
        assert_eq!(session.metrics.dropped_deadline_packets, 1);
    }

    #[test]
    fn test_relay_fallback_activation() {
        let mut session = SdsTransportSession::new(3003, 0x55667788);
        let relay_addr: SocketAddr = "198.51.100.1:8080".parse().unwrap();

        session.activate_relay_fallback(relay_addr);
        assert_eq!(session.state, TransportState::RelayFallback);
        assert!(session.is_relay_path);
        assert_eq!(session.remote_addr, Some(relay_addr));
    }

    #[test]
    fn test_0rtt_protocol_layer_enforcement() {
        use crate::frame::{
            ERR_0RTT_OPERATION_FORBIDDEN, TYPE_CALL_INVITE, TYPE_PING, TYPE_RESOLVE_PROFILE_REQ,
        };

        let mut session = SdsTransportSession::new(4004, 0x99887766);
        let client_addr: SocketAddr = "127.0.0.1:55000".parse().unwrap();
        session.connect_direct(client_addr);
        assert_eq!(session.state, TransportState::DirectQuic0Rtt);

        // 1. Safe read-only / idempotent frame is accepted in 0-RTT
        let profile_req = SdsFrame::new(TYPE_RESOLVE_PROFILE_REQ, 1, 0, 1, vec![]);
        assert!(session.handle_incoming_frame(&profile_req).is_ok());

        let ping_frame = SdsFrame::new(TYPE_PING, 1, 0, 2, vec![]);
        assert!(session.handle_incoming_frame(&ping_frame).is_ok());

        // 2. State-mutating operation (e.g. CALL_INVITE) is strictly rejected at the protocol layer
        let invite_frame = SdsFrame::new(TYPE_CALL_INVITE, 1, 1, 3, vec![0x01]);
        let err = session.handle_incoming_frame(&invite_frame);
        assert_eq!(err, Err(ERR_0RTT_OPERATION_FORBIDDEN));

        // 3. Once handshake completes, CALL_INVITE is accepted normally
        session.complete_handshake();
        assert_eq!(session.state, TransportState::SessionActive);
        assert!(session.handle_incoming_frame(&invite_frame).is_ok());
    }
}
