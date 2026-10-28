use sds_core::frame::*;
use sds_core::transport::*;

use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_live_udp_transport_handshake_and_exchange() {
    // 1. Bind live local server socket on ephemeral port
    let server_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Server bind failed");
    let server_addr = server_socket
        .local_addr()
        .expect("Failed to get server addr");

    // 2. Bind client socket
    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Client bind failed");
    let client_addr = client_socket
        .local_addr()
        .expect("Failed to get client addr");

    // 3. Client transmits TYPE_HANDSHAKE_INIT frame across network
    let payload = b"client_ephemeral_key_x25519".to_vec();
    let init_frame = SdsFrame::new(TYPE_HANDSHAKE_INIT, 0x01, 0, 1, payload.clone());
    let wire_bytes = init_frame.to_bytes();

    client_socket
        .send_to(&wire_bytes, server_addr)
        .await
        .expect("Client send failed");

    // 4. Server receives and parses binary frame over the wire
    let mut server_buf = [0u8; 1024];
    let (len, src) = server_socket
        .recv_from(&mut server_buf)
        .await
        .expect("Server recv failed");

    assert_eq!(src, client_addr);
    assert_eq!(len, HEADER_SIZE + payload.len());

    let parsed_req = SdsFrame::from_bytes(&server_buf[..len]).expect("Server parsing failed");
    assert_eq!(parsed_req.frame_type, TYPE_HANDSHAKE_INIT);
    assert_eq!(parsed_req.sub_type, 0x01);
    assert_eq!(parsed_req.payload, payload);

    // 5. Server responds with TYPE_HANDSHAKE_RESP
    let resp_payload = b"server_cert_and_session_ticket_0rtt".to_vec();
    let resp_frame = SdsFrame::new(TYPE_HANDSHAKE_RESP, 0x01, 0, 2, resp_payload.clone());
    server_socket
        .send_to(&resp_frame.to_bytes(), src)
        .await
        .expect("Server resp send failed");

    // 6. Client receives response
    let mut client_buf = [0u8; 1024];
    let (resp_len, resp_src) = client_socket
        .recv_from(&mut client_buf)
        .await
        .expect("Client recv failed");

    assert_eq!(resp_src, server_addr);
    let parsed_resp = SdsFrame::from_bytes(&client_buf[..resp_len]).expect("Client parsing failed");
    assert_eq!(parsed_resp.frame_type, TYPE_HANDSHAKE_RESP);
    assert_eq!(parsed_resp.payload, resp_payload);
}

#[tokio::test]
async fn test_live_network_datagram_lifetime_drop() {
    let server_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Server bind failed");
    let server_addr = server_socket.local_addr().unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut session = SdsTransportSession::new(5001, 0xCAFEBABE);
    session.complete_handshake();

    // Send a datagram with tight 15ms lifetime budget
    let audio_payload = vec![0x12, 0x34, 0x56, 0x78];
    let datagram =
        SdsFrame::new_datagram(TYPE_MEDIA_AUDIO_OPUS, 0, 2, 101, 15, audio_payload.clone());

    client_socket
        .send_to(&datagram.to_bytes(), server_addr)
        .await
        .unwrap();

    // Receive on server
    let mut buf = [0u8; 512];
    let (len, _) = server_socket.recv_from(&mut buf).await.unwrap();
    let received_frame = SdsFrame::from_bytes(&buf[..len]).unwrap();

    // Ingest into session jitter buffer
    session.ingest_media_datagram(received_frame);

    // Sleep 25ms to intentionally exceed the 15ms lifetime budget
    tokio::time::sleep(Duration::from_millis(25)).await;

    // Playout must drop expired frame
    let playable = session.dequeue_playable_media();
    assert!(playable.is_none(), "Expired audio datagram must be dropped");
    assert_eq!(session.metrics.dropped_deadline_packets, 1);
}

#[tokio::test]
async fn test_live_network_migration_over_real_sockets() {
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server_socket.local_addr().unwrap();

    let mut session = SdsTransportSession::new(7777, 0x9988776655443322);
    session.set_endpoint(server_addr);

    // Initial connection from Interface 1 (e.g. WiFi)
    let wifi_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let wifi_addr = wifi_socket.local_addr().unwrap();
    session.connect_direct(wifi_addr);
    session.complete_handshake();

    let ping = session.send_stream_frame(TYPE_PING, 0, 0, b"ping_wifi".to_vec());
    wifi_socket
        .send_to(&ping.to_bytes(), server_addr)
        .await
        .unwrap();

    let mut srv_buf = [0u8; 512];
    let (len, src1) = server_socket.recv_from(&mut srv_buf).await.unwrap();
    assert_eq!(src1, wifi_addr);
    let f1 = SdsFrame::from_bytes(&srv_buf[..len]).unwrap();
    assert_eq!(f1.payload, b"ping_wifi");

    // Network Handover: Mobile switches to Interface 2 (e.g. Cellular / 5G)
    let cellular_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cellular_addr = cellular_socket.local_addr().unwrap();

    // Execute migration in session engine under same 64-bit CID
    session
        .migrate_connection(cellular_addr)
        .expect("Migration should succeed");
    assert_eq!(session.local_addr, Some(cellular_addr));
    assert_eq!(session.metrics.migration_count, 1);

    // Transmit subsequent packet from new cellular socket
    let ping2 = session.send_stream_frame(TYPE_PING, 0, 0, b"ping_cellular".to_vec());
    cellular_socket
        .send_to(&ping2.to_bytes(), server_addr)
        .await
        .unwrap();

    let (len2, src2) = server_socket.recv_from(&mut srv_buf).await.unwrap();
    assert_eq!(src2, cellular_addr); // Source address migrated on live UDP socket
    let f2 = SdsFrame::from_bytes(&srv_buf[..len2]).unwrap();
    assert_eq!(f2.payload, b"ping_cellular");
}

#[tokio::test]
async fn test_live_wire_tampering_rejection() {
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let valid_frame = SdsFrame::new(TYPE_MSG_ENVELOPE, 0, 1, 10, b"Secret E2EE message".to_vec());
    let mut wire_bytes = valid_frame.to_bytes();

    // Corrupt magic bytes over the live network wire
    wire_bytes[0] = 0x00; // Corrupt "S" -> 0x00

    client_socket
        .send_to(&wire_bytes, server_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 512];
    let (len, _) = server_socket.recv_from(&mut buf).await.unwrap();

    let result = SdsFrame::from_bytes(&buf[..len]);
    assert!(result.is_err(), "Server must reject wire-tampered frames");
}
