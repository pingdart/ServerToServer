use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sds_core::frame::*;
use std::sync::Arc;
use std::time::Duration;

const SDS_ALPN: &[u8] = b"sds/1.0";

/// Helper to generate self-signed cert and Quinn server/client configurations
fn make_quic_configs() -> (ServerConfig, ClientConfig) {
    let cert = generate_simple_self_signed(vec![
        "localhost".to_string(),
        "server.example.com".to_string(),
    ])
    .unwrap();
    let cert_der = cert.cert.der().to_vec();
    let priv_key_der = cert.key_pair.serialize_der();

    let cert_chain = vec![CertificateDer::from(cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(priv_key_der));

    // Server Config
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .unwrap();
    server_crypto.alpn_protocols = vec![SDS_ALPN.to_vec()];

    let mut server_transport = TransportConfig::default();
    server_transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
    server_transport.datagram_receive_buffer_size(Some(65536));

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
    ));
    server_config.transport_config(Arc::new(server_transport));

    // Client Config with custom verifier that trusts our test self-signed cert
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(cert_der)).unwrap();

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![SDS_ALPN.to_vec()];

    let mut client_transport = TransportConfig::default();
    client_transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
    client_transport.datagram_receive_buffer_size(Some(65536));

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
    ));
    client_config.transport_config(Arc::new(client_transport));

    (server_config, client_config)
}

#[tokio::test]
async fn test_live_quic_stream_exchange_with_sds_frames() {
    let (server_config, client_config) = make_quic_configs();

    // 1. Start live Quinn QUIC Server on 127.0.0.1
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    // Spawn server accept task
    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("Incoming connection failed");
        let connection = incoming.await.expect("QUIC handshake failed");

        // Accept bi-directional stream
        let (mut send_stream, mut recv_stream) =
            connection.accept_bi().await.expect("Stream accept failed");

        // Read SDS frame
        let mut buf = vec![0u8; 1024];
        let n = recv_stream
            .read(&mut buf)
            .await
            .expect("Read failed")
            .unwrap();
        let frame = SdsFrame::from_bytes(&buf[..n]).expect("Frame decode failed");

        assert_eq!(frame.frame_type, TYPE_HANDSHAKE_INIT);
        assert_eq!(frame.payload, b"client_quic_hello");

        // Respond with TYPE_HANDSHAKE_RESP
        let resp_frame = SdsFrame::new(
            TYPE_HANDSHAKE_RESP,
            0x01,
            0,
            100,
            b"server_quic_ack".to_vec(),
        );
        send_stream
            .write_all(&resp_frame.to_bytes())
            .await
            .expect("Write failed");
        send_stream.finish().unwrap();
        // Server keeps connection alive until client completes read and closes
        connection.closed().await;
    });

    // 2. Start Quinn QUIC Client and connect
    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);

    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .expect("Client connect failed");

    // Open bidirectional stream
    let (mut send_stream, mut recv_stream) =
        connection.open_bi().await.expect("Open bi stream failed");

    // Send SDS frame
    let req_frame = SdsFrame::new(
        TYPE_HANDSHAKE_INIT,
        0x01,
        0,
        1,
        b"client_quic_hello".to_vec(),
    );
    send_stream
        .write_all(&req_frame.to_bytes())
        .await
        .expect("Send failed");
    send_stream.finish().unwrap();

    // Receive response
    let mut resp_buf = vec![0u8; 1024];
    let n = recv_stream
        .read(&mut resp_buf)
        .await
        .expect("Recv failed")
        .unwrap();
    let resp_frame = SdsFrame::from_bytes(&resp_buf[..n]).expect("Resp decode failed");

    assert_eq!(resp_frame.frame_type, TYPE_HANDSHAKE_RESP);
    assert_eq!(resp_frame.payload, b"server_quic_ack");

    connection.close(0u32.into(), b"client_done");
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_live_quic_unreliable_datagram_exchange_rfc9221() {
    let (server_config, client_config) = make_quic_configs();

    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();

        // Receive datagram over QUIC connection
        let dgram = connection
            .read_datagram()
            .await
            .expect("Read datagram failed");
        let frame = SdsFrame::from_bytes(&dgram).expect("Parse datagram failed");

        assert_eq!(frame.frame_type, TYPE_MEDIA_AUDIO_OPUS);
        assert_eq!(frame.flags & FLAG_IS_DATAGRAM, FLAG_IS_DATAGRAM);
        assert_eq!(frame.lifetime_ms, 80);
        assert_eq!(frame.payload, b"opus_audio_frame_payload_chunk");

        connection.close(0u32.into(), b"done");
    });

    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);

    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // Build SDS Datagram Frame
    let audio_frame = SdsFrame::new_datagram(
        TYPE_MEDIA_AUDIO_OPUS,
        0,
        2, // stream 2 = audio
        1001,
        80, // 80ms lifetime budget
        b"opus_audio_frame_payload_chunk".to_vec(),
    );

    let wire_bytes = audio_frame.to_bytes();
    connection
        .send_datagram(wire_bytes.into())
        .expect("Send datagram failed");

    // Allow time for reception and server verification
    tokio::time::sleep(Duration::from_millis(50)).await;
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_live_quic_connection_migration() {
    let (server_config, client_config) = make_quic_configs();

    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();

        // 1. Receive packet on initial path (simulating WiFi)
        let (_s1, mut recv_stream) = connection.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 512];
        let n = recv_stream.read(&mut buf).await.unwrap().unwrap();
        let f1 = SdsFrame::from_bytes(&buf[..n]).unwrap();
        assert_eq!(f1.payload, b"ping_on_wifi_path");

        // 2. Receive packet on migrated path (simulating cellular handover)
        let (mut send2, mut recv2) = connection.accept_bi().await.unwrap();
        let n2 = recv2.read(&mut buf).await.unwrap().unwrap();
        let f2 = SdsFrame::from_bytes(&buf[..n2]).unwrap();
        assert_eq!(f2.payload, b"ping_after_migration_cellular");

        send2.write_all(b"migration_ack").await.unwrap();
        send2.finish().unwrap();

        connection.closed().await;
    });

    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);

    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // 1. Send frame on initial path
    let (mut send_stream, _) = connection.open_bi().await.unwrap();
    let frame1 = SdsFrame::new(TYPE_PING, 0, 0, 1, b"ping_on_wifi_path".to_vec());
    send_stream.write_all(&frame1.to_bytes()).await.unwrap();
    send_stream.finish().unwrap();

    // 2. Simulate network handover: client rebinds underlying socket to new ephemeral port (simulating Wi-Fi -> 5G handover)
    let new_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    client_endpoint
        .rebind(new_socket)
        .expect("QUIC Endpoint rebind failed");

    // 3. Send second frame across migrated socket path without reconnecting!
    let (mut send2, mut recv2) = connection.open_bi().await.unwrap();
    let frame2 = SdsFrame::new(
        TYPE_PING,
        0,
        0,
        2,
        b"ping_after_migration_cellular".to_vec(),
    );
    send2.write_all(&frame2.to_bytes()).await.unwrap();
    send2.finish().unwrap();

    let mut ack_buf = vec![0u8; 64];
    let n = recv2.read(&mut ack_buf).await.unwrap().unwrap();
    assert_eq!(&ack_buf[..n], b"migration_ack");

    connection.close(0u32.into(), b"migration_test_complete");
    server_handle.await.unwrap();
}
