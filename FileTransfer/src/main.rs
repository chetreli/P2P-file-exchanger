use std::{collections::HashMap, sync::Arc, time::Duration};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use aes_gcm::aead::rand_core::RngCore;
use axum::{
    Router,
    extract::{State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::IntoResponse,
    routing::get,
};
use base64::{engine::general_purpose, Engine as _};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::{sync::{broadcast, mpsc, Mutex}, time::interval};
use uuid::Uuid;



#[derive(Clone)]
struct AppState {
    connections: Arc<Mutex<HashMap<String, broadcast::Sender<Message>>>>,
    keys: Arc<Mutex<HashMap<String, [u8; 32]>>>,
}

// ─────────────────────────────────────────────
//  Entry point
// ─────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let state = AppState {
        connections: Arc::new(Mutex::new(HashMap::new())),
        keys: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/ws", get(websocket_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    println!("Server running on ws://localhost:8000");
    axum::serve(listener, app).await.unwrap();
}

// ─────────────────────────────────────────────
//  Upgrade handler
// ─────────────────────────────────────────────

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

// ─────────────────────────────────────────────
//  Encryption helpers
// ─────────────────────────────────────────────

/// Encrypt `plaintext` with the given AES-256-GCM key.
/// Returns `nonce (12 bytes) || ciphertext` as a Vec<u8>.
fn encrypt(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Generate a random 96-bit nonce for every message
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)?;

    // Prepend nonce so the receiver can decrypt without extra signalling
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `nonce (12 bytes) || ciphertext` with the given AES-256-GCM key.
fn decrypt(key_bytes: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    if payload.len() < 12 {
        return Err(aes_gcm::Error); // payload too short
    }
    let (nonce_bytes, ciphertext) = payload.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext)
}

// ─────────────────────────────────────────────
//  Per-connection handler
// ─────────────────────────────────────────────

async fn handle_socket(socket: WebSocket, state: AppState) {
    let conn_id = Uuid::new_v4().to_string();
    let conn_id_clone = conn_id.clone();

    println!("New connection: {}", conn_id);

    // ── 1. Generate a fresh AES-256 session key for this connection ──────────
    let mut session_key = [0u8; 32];
    OsRng.fill_bytes(&mut session_key);

    // Store the key so other tasks can look it up
    {
        let mut keys = state.keys.lock().await;
        keys.insert(conn_id.clone(), session_key);
    }

    // ── 2. Register this connection ───────────────────────────────────────────
    let (tx, mut rx) = broadcast::channel(100);
    {
        let mut connections = state.connections.lock().await;
        connections.insert(conn_id.clone(), tx.clone());
    }

    let (mut sender, mut receiver) = socket.split();
    let (message_tx, mut message_rx) = mpsc::channel::<Message>(1000);

    // ── 3. Send the session key to the client right away (base64-encoded) ────
    //
    // In a real deployment you would wrap this step with RSA / ECDH so the
    // key itself is never sent in plain text. Here we send it in a JSON
    // envelope to keep the example self-contained.
    //
    // Format: { "type": "session_key", "key": "<base64>" }
    let key_msg = json!({
        "type": "session_key",
        "key": general_purpose::STANDARD.encode(session_key)
    })
    .to_string();

    if sender.send(Message::Text(key_msg)).await.is_err() {
        println!("Failed to send session key to {}", conn_id);
        return;
    }

    // ── 4. Spawn the four worker tasks ────────────────────────────────────────

    // 4a. sender_task – writes messages out to the WebSocket
    let sender_task = tokio::spawn(async move {
        while let Some(msg) = message_rx.recv().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    // 4b. ping_task – keeps the connection alive
    let ping_tx = message_tx.clone();
    let ping_task = tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            if ping_tx.send(Message::Ping(vec![])).await.is_err() {
                break;
            }
        }
    });

    // 4c. forward_task – forwards broadcast messages into the mpsc queue
    let forward_tx = message_tx.clone();
    let forward_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if forward_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // 4d. receive_task – handles incoming messages from this client
    let receive_task = tokio::spawn({
        let state = state.clone();
        let tx = tx.clone();
        let conn_id_inner = conn_id.clone();
        let mut target_map: HashMap<String, String> = HashMap::new();

        async move {
            while let Some(Ok(msg)) = receiver.next().await {
                match msg {
                    // ── Text / JSON control messages ──────────────────────
                    Message::Text(text) => {
                        if let Ok(data) = serde_json::from_str::<Value>(&text) {

                            // Register an alias connection id
                            if data["type"] == "register" {
                                if let Some(id) = data["connectionId"].as_str() {
                                    state.connections.lock().await
                                        .insert(id.to_string(), tx.clone());
                                }
                                continue;
                            }

                            // Forward JSON to a target peer
                            if let Some(target_id) = data["target_id"].as_str() {
                                target_map.insert(
                                    conn_id_inner.clone(),
                                    target_id.to_string(),
                                );
                                if let Some(target_tx) = state.connections.lock().await
                                    .get(target_id)
                                {
                                    let _ = target_tx.send(Message::Text(text));
                                }
                            }
                        }
                    }

                    // ── Binary messages (encrypted file chunks) ───────────
                    //
                    // Expected layout coming FROM the client:
                    //   nonce (12 bytes) || AES-256-GCM ciphertext
                    //
                    // The server:
                    //   1. Decrypts with the *sender's* session key.
                    //   2. Re-encrypts with the *receiver's* session key.
                    //   3. Forwards the re-encrypted bytes to the target.
                    //
                    // This keeps end-to-end encryption intact: neither peer
                    // ever sees the other's plaintext bytes on the wire.
                    Message::Binary(bin_data) => {
                        if let Some(target_id) = target_map.get(&conn_id_inner) {
                            // --- decrypt with sender's key ---
                            let sender_key = {
                                state.keys.lock().await
                                    .get(&conn_id_inner)
                                    .copied()
                            };

                            let plaintext = match sender_key {
                                Some(key) => match decrypt(&key, &bin_data) {
                                    Ok(pt) => pt,
                                    Err(_) => {
                                        println!(
                                            "Decryption failed for chunk from {}",
                                            conn_id_inner
                                        );
                                        continue;
                                    }
                                },
                                None => {
                                    println!("No key for sender {}", conn_id_inner);
                                    continue;
                                }
                            };

                            // --- re-encrypt with receiver's key ---
                            let receiver_key = {
                                state.keys.lock().await
                                    .get(target_id.as_str())
                                    .copied()
                            };

                            match receiver_key {
                                Some(key) => match encrypt(&key, &plaintext) {
                                    Ok(ciphertext) => {
                                        if let Some(target_tx) = state.connections.lock().await
                                            .get(target_id.as_str())
                                        {
                                            let _ = target_tx.send(
                                                Message::Binary(ciphertext)
                                            );
                                        }
                                    }
                                    Err(_) => println!(
                                        "Re-encryption failed for target {}",
                                        target_id
                                    ),
                                },
                                None => println!("No key for target {}", target_id),
                            }
                        } else {
                            println!(
                                "No target set for binary transfer from {}",
                                conn_id_inner
                            );
                        }
                    }

                    Message::Close(_) => break,
                    _ => continue,
                }
            }
        }
    });

    // ── 5. Run until any task exits ───────────────────────────────────────────
    tokio::select! {
        _ = sender_task  => {},
        _ = ping_task    => {},
        _ = forward_task => {},
        _ = receive_task => {},
    }

    // ── 6. Clean up ───────────────────────────────────────────────────────────
    state.connections.lock().await.remove(&conn_id_clone);
    state.keys.lock().await.remove(&conn_id_clone);
    println!("Connection closed: {}", conn_id_clone);
}