use crate::extractors::*;
use axum::{
    Json, Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::{any, get, post},
};
use cursed_core::protocol::{Frame, TomeId};
use dashmap::DashMap;
use futures::SinkExt;
use rooms::Room;
use serde::Serialize;

use axum::extract::connect_info::ConnectInfo;
use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use futures_util::stream::StreamExt;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use uuid::Uuid;

pub type Service = IntoMakeServiceWithConnectInfo<Router<()>, SocketAddr>;

#[derive(Clone)]
pub struct AppState {
    pub rooms: Arc<DashMap<TomeId, TomeRoom>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            rooms: Arc::new(DashMap::new()),
        }
    }
}

pub fn service() -> Service {
    let app = Router::new()
        .route("/room/{room_id}", any(ws_handler))
        .route("/room", post(create_room))
        .route("/rooms", get(rooms_handler))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        )
        .with_state(AppState::default());

    app.into_make_service_with_connect_info::<SocketAddr>()
}

#[derive(Serialize)]
pub struct TomesResponse {
    rooms: Vec<TomeId>,
}

#[axum_macros::debug_handler]
async fn create_room(State(state): State<AppState>) -> impl IntoResponse {
    let room_id = TomeId(Uuid::new_v4());
    state
        .rooms
        .insert(room_id.clone(), TomeRoom(Arc::new(Room::new(100))));
    Json(room_id)
}

#[axum_macros::debug_handler]
async fn rooms_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(TomesResponse {
        rooms: state
            .rooms
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>(),
    })
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    room: TomeRoom,
    primary_key: AuthPrimaryKey,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, room, primary_key, addr))
}

async fn handle_socket(
    socket: WebSocket,
    TomeRoom(room): TomeRoom,
    AuthPrimaryKey(participant_key): AuthPrimaryKey,
    _who: SocketAddr,
) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    let mut handle = room.join(participant_key, tx.clone());

    let sender_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    let tx_clone = tx.clone();
    let broadcast_task = tokio::spawn(async move {
        while let Ok(msg) = handle.recv_broadcast().await {
            if tx_clone.send(msg).is_err() {
                break;
            }
        }
    });

    while let Some(Ok(msg)) = ws_receiver.next().await {
        match msg {
            Message::Binary(data) => {
                match Frame::from_bytes(&data) {
                    Ok(Frame::Announce(_)) => {
                        // Broadcast announcement to all participants
                        room.broadcast(Message::Binary(data))
                            .inspect_err(|err| {
                                tracing::error!(err = ?err, "Failed to broadcast announcement");
                            })
                            .ok();
                    }
                    Ok(Frame::Chunk(_)) => {
                        // Broadcast chunk (everyone needs pieces)
                        room.broadcast(Message::Binary(data))
                            .inspect_err(|err| {
                                tracing::error!(err = ?err, "Failed to broadcast chunk");
                            })
                            .ok();
                    }
                    Ok(Frame::UnlockRequest(request)) => {
                        // Route to specific keeper who owns the rune
                        // You'd need to track who owns what
                        room.send_to(&request.keeper_pk_ed25519, Message::Binary(data))
                            .inspect_err(|err| {
                                tracing::error!(err = ?err, "Failed to send unlock request");
                            })
                            .ok();
                    }
                    Ok(Frame::UnlockGrant(grant)) => {
                        // Send directly to requester
                        // Need to track who requested what
                        room.send_to(&grant.requester_pk_ed25519, Message::Binary(data))
                            .inspect_err(|err| {
                                tracing::error!(err = ?err, "Failed to send unlock grant");
                            })
                            .ok();
                    }
                    Err(e) => {
                        tracing::warn!("Invalid frame: {}", e);
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    room.leave(&participant_key);
    sender_task.abort();
    broadcast_task.abort();
}
