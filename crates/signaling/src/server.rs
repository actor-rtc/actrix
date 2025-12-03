//! Actor-RTC 信令服务器 - 基于 protobuf SignalingEnvelope
//!
//! 完全基于 protobuf 协议，使用 WebSocket Binary 消息传输
//!
//! # 功能概览
//!
//! ## 已实现的核心功能
//!
//! ### 基础信令流程
//! - ✅ Actor 注册 / 注销 (`RegisterRequest`, `UnregisterRequest`)
//! - ✅ 心跳机制 (`Ping` / `Pong`)
//! - ✅ WebRTC 信令中继 (`ActrRelay` - ICE / SDP)
//!
//! ### 扩展功能
//! - ✅ 服务发现 (`DiscoveryRequest` / `DiscoveryResponse`)
//! - ✅ 负载均衡路由 (`RouteCandidatesRequest` / `RouteCandidatesResponse`)
//!   - 多因素排序：功率储备、邮箱积压、兼容性评分、地理距离、客户端粘性
//!   - 集成 GlobalCompatibilityCache 实现实时兼容性计算
//!   - 精确匹配快速路径优化
//! - ✅ Presence 订阅 (`SubscribeActrUpRequest` / `ActrUpEvent`)
//! - ✅ Credential 刷新 (`CredentialUpdateRequest` - 通过 AIS 客户端)
//! - ✅ 负载指标存储 (`handle_ping()` - 存储到 ServiceRegistry 用于负载均衡)
//!
//! ## 待完成的功能（可选增强）
//!
//! 1. **Credential 验证** (可选安全增强)
//!    - `handle_actr_to_server()` - 验证 Actor 消息中的 credential
//!    - `handle_actr_relay()` - 验证中继消息的 credential
//!
//! 2. **ServiceSpec 和 ACL 持久化** (可选访问控制)
//!    - `handle_register_request()` - 持久化服务规格和访问控制规则
//!    - 用于细粒度的服务间访问控制

use actr_protocol::{
    AIdCredential, ActrId, ActrRelay, ActrToSignaling, ActrType, ActrUpEvent, ErrorResponse,
    PeerToSignaling, Ping, Pong, Realm, RegisterRequest, RegisterResponse, RoleAssignment,
    RoleNegotiation, SignalingEnvelope, SignalingToActr, actr_relay, actr_to_signaling,
    peer_to_signaling, register_response, signaling_envelope, signaling_to_actr,
};
use actrix_common::aid::credential::validator::AIdCredentialValidator;
use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, info_span, instrument, warn};
use uuid::Uuid;

// Axum WebSocket
use axum::extract::ws::{Message as WsMessage, WebSocket};

use crate::load_balancer::LoadBalancer;
use crate::presence::PresenceManager;
use crate::service_registry::ServiceRegistry;
#[cfg(feature = "opentelemetry")]
use crate::trace::{extract_trace_context, inject_trace_context};
use tracing::Instrument;

/// 信令服务器状态
#[derive(Debug)]
pub struct SignalingServer {
    /// 已连接的客户端
    pub clients: Arc<RwLock<HashMap<String, ClientConnection>>>,
    /// 通过 ActorId 查找 client_id 的索引
    pub actor_id_index: Arc<RwLock<HashMap<ActrId, String>>>,
    /// 服务注册表
    pub service_registry: Arc<RwLock<ServiceRegistry>>,
    /// Presence 订阅管理器
    pub presence_manager: Arc<RwLock<PresenceManager>>,
    /// AIS 客户端（用于 ActorId 分配和 Credential 签发）
    pub ais_client: Option<Arc<crate::ais_client::AisClient>>,
    /// 兼容性缓存（用于 BEST_COMPATIBILITY 排序）
    pub compatibility_cache: Arc<RwLock<crate::compatibility_cache::GlobalCompatibilityCache>>,
    /// 连接速率限制器
    pub connection_rate_limiter: Option<Arc<crate::ratelimit::ConnectionRateLimiter>>,
    /// 消息速率限制器
    pub message_rate_limiter: Option<Arc<crate::ratelimit::MessageRateLimiter>>,
    /// ACL 配置
    pub acl_config: actrix_common::config::AclConfig,
}

/// 客户端连接信息
#[derive(Debug)]
pub struct ClientConnection {
    pub id: String,
    pub actor_id: Option<ActrId>,
    pub credential: Option<AIdCredential>,
    pub direct_sender: tokio::sync::mpsc::UnboundedSender<WsMessage>,
    pub client_ip: Option<std::net::IpAddr>,
}

/// 信令服务器句柄 - 用于在异步任务中操作服务器
#[derive(Debug, Clone)]
pub struct SignalingServerHandle {
    pub clients: Arc<RwLock<HashMap<String, ClientConnection>>>,
    pub actor_id_index: Arc<RwLock<HashMap<ActrId, String>>>,
    pub service_registry: Arc<RwLock<ServiceRegistry>>,
    pub presence_manager: Arc<RwLock<PresenceManager>>,
    pub ais_client: Option<Arc<crate::ais_client::AisClient>>,
    pub compatibility_cache: Arc<RwLock<crate::compatibility_cache::GlobalCompatibilityCache>>,
    pub connection_rate_limiter: Option<Arc<crate::ratelimit::ConnectionRateLimiter>>,
    pub message_rate_limiter: Option<Arc<crate::ratelimit::MessageRateLimiter>>,
    pub acl_config: actrix_common::config::AclConfig,
}

impl SignalingServerHandle {
    /// 创建 SignalingEnvelope
    #[instrument(level = "debug", skip_all, fields(reply_for))]
    fn create_envelope(
        &self,
        flow: signaling_envelope::Flow,
        reply_for: Option<&str>,
    ) -> SignalingEnvelope {
        #[allow(unused_mut)]
        let mut envelope = SignalingEnvelope {
            envelope_version: 1,
            envelope_id: Uuid::new_v4().to_string(),
            reply_for: reply_for.map(|id| id.to_string()),
            timestamp: prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            },
            traceparent: None,
            tracestate: None,
            flow: Some(flow),
        };
        debug!(
            "Created envelope: envelope_id={}, reply_for={reply_for:?}",
            envelope.envelope_id,
        );
        envelope
    }

    #[instrument(level = "debug", skip_all)]
    fn create_new_envelope(&self, flow: signaling_envelope::Flow) -> SignalingEnvelope {
        self.create_envelope(flow, None)
    }
}

impl Default for SignalingServer {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalingServer {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            actor_id_index: Arc::new(RwLock::new(HashMap::new())),
            service_registry: Arc::new(RwLock::new(ServiceRegistry::new())),
            presence_manager: Arc::new(RwLock::new(PresenceManager::new())),
            ais_client: None, // 在 axum_router 中初始化
            compatibility_cache: Arc::new(RwLock::new(
                crate::compatibility_cache::GlobalCompatibilityCache::new(),
            )),
            connection_rate_limiter: None, // 在 axum_router 中根据配置初始化
            message_rate_limiter: None,    // 在 axum_router 中根据配置初始化
            acl_config: actrix_common::config::AclConfig::default(),
        }
    }
    
    /// 设置 ACL 配置
    pub fn set_acl_config(&mut self, config: actrix_common::config::AclConfig) {
        self.acl_config = config;
    }
}

/// 处理 WebSocket 连接
pub async fn handle_websocket_connection(
    websocket: WebSocket,
    server: SignalingServerHandle,
    client_ip: Option<std::net::IpAddr>,
    url_identity: Option<(ActrId, AIdCredential)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let client_id = Uuid::new_v4().to_string();
    info!(
        "🔗 新 WebSocket 客户端连接: {} (IP: {:?})",
        client_id, client_ip
    );

    // 分离读写流
    let (mut ws_sender, mut ws_receiver) = websocket.split();

    // 创建专用的发送通道用于点对点消息
    let (direct_tx, mut direct_rx) = tokio::sync::mpsc::unbounded_channel();

    // 注册客户端（包含专用发送器）
    {
        let mut clients_guard = server.clients.write().await;

        // 如果 URL 已带 actor_id，则移除已有相同 actor 的连接（避免 stale 映射）。
        let (actor_for_entry, cred_for_entry) =
            if let Some((actor_id, credential)) = url_identity.clone() {
                let mut to_remove = Vec::new();
                for (cid, conn) in clients_guard.iter() {
                    if conn.actor_id.as_ref() == Some(&actor_id) {
                        to_remove.push(cid.clone());
                    }
                }
                for cid in to_remove {
                    clients_guard.remove(&cid);
                    info!("🧹 Removed stale client {} for actor {:?}", cid, actor_id);
                }
                (Some(actor_id), Some(credential))
            } else {
                (None, None)
            };

        clients_guard.insert(
            client_id.clone(),
            ClientConnection {
                id: client_id.clone(),
                actor_id: actor_for_entry,
                credential: cred_for_entry,
                direct_sender: direct_tx,
                client_ip,
            },
        );
    }

    // 处理客户端消息的任务
    let server_for_receive = server.clone();
    let client_id_for_receive = client_id.clone();

    let receive_task = tokio::spawn(async move {
        while let Some(msg) = ws_receiver.next().await {
            match msg {
                Ok(WsMessage::Binary(data)) => {
                    if let Err(e) =
                        handle_client_envelope(&data, &client_id_for_receive, &server_for_receive)
                            .await
                    {
                        error!("处理客户端信令错误: {}", e);
                        break;
                    }
                }
                Ok(WsMessage::Close(_)) => {
                    info!("客户端 {} 主动断开连接", client_id_for_receive);
                    break;
                }
                Err(e) => {
                    error!("WebSocket 错误: {}", e);
                    break;
                }
                _ => {
                    warn!("收到非 Binary 消息，忽略");
                }
            }
        }

        // 清理客户端
        cleanup_client(&client_id_for_receive, &server_for_receive).await;
    });

    // 处理发送消息的任务
    let send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                // 处理点对点消息
                msg = direct_rx.recv() => {
                    match msg {
                        Some(message) => {
                            if ws_sender.send(message).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    // 等待任一任务完成
    tokio::select! {
        _ = receive_task => {},
        _ = send_task => {},
    }

    // 清理客户端连接
    cleanup_client(&client_id, &server).await;
    info!("🔌 客户端 {} 已断开连接", client_id);

    Ok(())
}

/// 处理客户端发送的 SignalingEnvelope
async fn handle_client_envelope(
    data: &[u8],
    client_id: &str,
    server: &SignalingServerHandle,
) -> Result<(), Box<dyn std::error::Error>> {
    // 检查消息速率限制
    if let Some(ref limiter) = server.message_rate_limiter
        && let Err(e) = limiter.check_message(client_id).await
    {
        warn!("🚫 连接 {} 消息速率限制触发: {}", client_id, e);
        // 发送错误响应
        let error_response = ErrorResponse {
            code: 429,
            message: e,
        };
        let error_envelope =
            server.create_new_envelope(signaling_envelope::Flow::EnvelopeError(error_response));
        send_envelope_to_client(client_id, error_envelope, server).await?;
        return Ok(());
    }

    // 解码 protobuf 消息
    let envelope = SignalingEnvelope::decode(data)?;

    #[cfg(feature = "opentelemetry")]
    let remote_context = extract_trace_context(&envelope);

    let span = info_span!(
        "signaling.handle_envelope",
        envelope_id = %envelope.envelope_id,
        client_id = %client_id
    );
    #[cfg(feature = "opentelemetry")]
    {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        let _ = span.set_parent(remote_context.clone());
    }

    async move {
        debug!("📨 收到信令消息 envelope_id={}", envelope.envelope_id);

        // 根据流向处理消息
        match envelope.flow {
            Some(signaling_envelope::Flow::PeerToServer(peer_to_server)) => {
                handle_peer_to_server(peer_to_server, client_id, server, &envelope.envelope_id)
                    .await
            }
            Some(signaling_envelope::Flow::ActrToServer(actr_to_server)) => {
                handle_actr_to_server(actr_to_server, client_id, server, &envelope.envelope_id)
                    .await
            }
            Some(signaling_envelope::Flow::ActrRelay(ref relay)) => {
                #[cfg(feature = "opentelemetry")]
                {
                    handle_actr_relay(
                        relay.clone(),
                        client_id,
                        server,
                        &envelope.envelope_id,
                        remote_context,
                    )
                    .await
                }
                #[cfg(not(feature = "opentelemetry"))]
                {
                    handle_actr_relay(relay.clone(), client_id, server, &envelope.envelope_id).await
                }
            }
            Some(signaling_envelope::Flow::EnvelopeError(error)) => {
                error!(
                    "收到 envelope 错误: code={}, message={}",
                    error.code, error.message
                );
                Ok(())
            }
            _ => {
                warn!("未知的信令流向");
                Ok(())
            }
        }
    }
    .instrument(span)
    .await
}

/// 处理 PeerToSignaling 流程（注册前）
#[instrument(level = "debug", skip_all, fields(client_id, envelope_id = request_envelope_id))]
async fn handle_peer_to_server(
    peer_to_server: PeerToSignaling,
    client_id: &str,
    server: &SignalingServerHandle,
    request_envelope_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match peer_to_server.payload {
        Some(peer_to_signaling::Payload::RegisterRequest(register_request)) => {
            handle_register_request(register_request, client_id, server, request_envelope_id)
                .await?;
        }
        None => {
            warn!("PeerToSignaling 消息缺少 payload");
        }
    }
    Ok(())
}

/// 处理注册请求
#[instrument(level = "debug", skip_all, fields(client_id, envelope_id = request_envelope_id))]
async fn handle_register_request(
    request: RegisterRequest,
    client_id: &str,
    server: &SignalingServerHandle,
    request_envelope_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "🎯 处理注册请求: type={}/{}, has_service_spec={}, has_acl={}",
        request.actr_type.manufacturer,
        request.actr_type.name,
        request.service_spec.is_some(),
        request.acl.is_some()
    );

    // 记录 ServiceSpec 和 ACL 信息
    if let Some(ref service_spec) = request.service_spec {
        info!(
            "  📦 ServiceSpec: fingerprint={}, packages={}, tags={:?}",
            service_spec.fingerprint,
            service_spec.protobufs.len(),
            service_spec.tags
        );
    }

    if let Some(ref acl) = request.acl {
        info!("  🔐 ACL 规则数量: {}", acl.rules.len());
    }

    // 检查是否已经注册过
    if let Some(client) = server.clients.read().await.get(client_id)
        && client.actor_id.is_some()
    {
        send_register_error(
            client_id,
            409,
            "Already registered",
            server,
            request_envelope_id,
        )
        .await?;
        return Ok(());
    }

    // 通过 AIS 分配 ActorId 和 Credential
    let ais_client = match &server.ais_client {
        Some(client) => client,
        None => {
            error!(
                "❌ AIS 未配置，无法处理注册请求 (realm={}, type={}/{})",
                request.realm.realm_id, request.actr_type.manufacturer, request.actr_type.name
            );
            send_register_error(
                client_id,
                500,
                "AIS not configured; registration is unavailable",
                server,
                request_envelope_id,
            )
            .await?;
            return Ok(());
        }
    };

    let register_ok = match ais_client
        .refresh_credential(request.realm.realm_id, request.actr_type.clone())
        .await
    {
        Ok(ais_response) => {
            // 解析 AIS 响应
            match ais_response.result {
                Some(register_response::Result::Success(register_ok)) => {
                    info!(
                        "✅ AIS 分配 ActorId: realm={}, serial={}",
                        register_ok.actr_id.realm.realm_id, register_ok.actr_id.serial_number
                    );
                    register_ok
                }
                Some(register_response::Result::Error(err)) => {
                    error!(
                        "❌ AIS 注册失败: code={}, message={}",
                        err.code, err.message
                    );
                    send_register_error(
                        client_id,
                        err.code,
                        &err.message,
                        server,
                        request_envelope_id,
                    )
                    .await?;
                    return Ok(());
                }
                None => {
                    error!("❌ AIS 返回空响应");
                    send_register_error(
                        client_id,
                        500,
                        "AIS returned empty response",
                        server,
                        request_envelope_id,
                    )
                    .await?;
                    return Ok(());
                }
            }
        }
        Err(e) => {
            error!("❌ 调用 AIS 失败: {}", e);
            send_register_error(
                client_id,
                500,
                &format!("Failed to call AIS: {e}"),
                server,
                request_envelope_id,
            )
            .await?;
            return Ok(());
        }
    };

    // 注册服务到 ServiceRegistry（存储 ServiceSpec 和 ACL）
    {
        let mut registry = server.service_registry.write().await;

        // 从 ServiceSpec 中提取服务名称，如果没有则使用 ActrType 作为服务名
        let service_name = request
            .service_spec
            .as_ref()
            .and_then(|spec| spec.description.clone())
            .unwrap_or_else(|| {
                format!(
                    "{}/{}",
                    register_ok.actr_id.r#type.manufacturer, register_ok.actr_id.r#type.name
                )
            });

        // 从 ServiceSpec 中提取 message_types（proto packages）
        let message_types = request
            .service_spec
            .as_ref()
            .map(|spec| {
                spec.protobufs
                    .iter()
                    .map(|proto| proto.package.clone())
                    .collect()
            })
            .unwrap_or_default();

        if let Err(e) = registry.register_service_full(
            register_ok.actr_id.clone(),
            service_name,
            message_types,
            None, // capabilities 当前不使用
            request.service_spec.clone(),
            request.acl.clone(),
        ) {
            warn!("⚠️  注册服务到 ServiceRegistry 失败: {}", e);
        } else {
            info!(
                "✅ 服务已注册到 ServiceRegistry (serial={})",
                register_ok.actr_id.serial_number
            );
        }
        drop(registry);
    }

    // 持久化 ACL 规则到数据库
    if let Some(ref acl) = request.acl {
        use actrix_common::tenant::acl::ActorAcl;
        
        let tenant_id = register_ok.actr_id.realm.realm_id.to_string();
        let my_type = &register_ok.actr_id.r#type.name;
        
        for rule in &acl.rules {
            // actr_protocol::Acl 是反向设计：principals 可以访问"我"
            // 需要转换为数据库的正向设计：from_type -> to_type
            let permission = rule.permission == actr_protocol::acl_rule::Permission::Allow as i32;
            
            for principal in &rule.principals {
                // 提取 principal 的类型（如果没有则跳过）
                let from_type = match &principal.actr_type {
                    Some(actr_type) => &actr_type.name,
                    None => {
                        warn!("⚠️  ACL principal 缺少 actr_type，跳过");
                        continue;
                    }
                };
                
                // 保存规则：from_type (principal) -> to_type (me)
                let mut actor_acl = ActorAcl::new(
                    tenant_id.clone(),
                    from_type.to_string(),
                    my_type.to_string(),
                    permission,
                );
                
                match actor_acl.save().await {
                    Ok(acl_id) => {
                        info!(
                            "✅ ACL 规则已保存: {} -> {} : {} (id={})",
                            from_type,
                            my_type,
                            if permission { "ALLOW" } else { "DENY" },
                            acl_id
                        );
                    }
                    Err(e) => {
                        warn!(
                            "⚠️  保存 ACL 规则失败 ({} -> {}): {}",
                            from_type, my_type, e
                        );
                    }
                }
            }
        }
    }

    // 更新客户端信息和 ActorId 索引
    // Hold clients lock until actor_id_index update completes to prevent race condition
    // where cleanup_client removes the client between releasing clients lock and
    // acquiring actor_id_index lock, leading to stale index entries.
    {
        let mut clients_guard = server.clients.write().await;
        if let Some(client) = clients_guard.get_mut(client_id) {
            client.actor_id = Some(register_ok.actr_id.clone());
            client.credential = Some(register_ok.credential.clone());
        }
    }

    // 直接使用 AIS 返回的 register_ok（包含 psk 和 public_key）
    let response = RegisterResponse {
        result: Some(register_response::Result::Success(register_ok.clone())),
    };

    // 构造 SignalingToActr 流程
    let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
        target: register_ok.actr_id.clone(),
        payload: Some(signaling_to_actr::Payload::RegisterResponse(response)),
    });

    // 创建响应 envelope
    let response_envelope = server.create_envelope(flow, Some(request_envelope_id));

    send_envelope_to_client(client_id, response_envelope, server).await?;

    // 通知所有订阅了该 ActrType 的订阅者（带 ACL 过滤）
    let presence = server.presence_manager.read().await;
    let subscribers = presence.get_subscribers_with_acl(&register_ok.actr_id).await;

    if !subscribers.is_empty() {
        info!(
            "📢 Actor {}/{} 上线，通知 {} 个 ACL 授权的订阅者",
            register_ok.actr_id.r#type.manufacturer,
            register_ok.actr_id.r#type.name,
            subscribers.len()
        );

        // 构造 ActrUpEvent
        let actr_up_event = ActrUpEvent {
            actor_id: register_ok.actr_id.clone(),
        };

        // 为每个订阅者构造并发送通知
        for subscriber_id in subscribers {
            let subscriber_client_id =
                match resolve_client_id_by_actor_id(&subscriber_id, server).await {
                    Ok(id) => id,
                    Err(e) => {
                        warn!(
                            "⚠️  订阅者 {} 索引缺失或不一致: {}",
                            subscriber_id.serial_number, e
                        );
                        continue;
                    }
                };

            let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
                target: subscriber_id,
                payload: Some(signaling_to_actr::Payload::ActrUpEvent(
                    actr_up_event.clone(),
                )),
            });

            let event_envelope = server.create_new_envelope(flow);

            if let Err(e) =
                send_envelope_to_client(&subscriber_client_id, event_envelope, server).await
            {
                warn!(
                    "⚠️  发送 ActrUpEvent 到订阅者失败: {}",
                    e
                );
            }
        }
    }
    drop(presence);

    Ok(())
}

/// 发送注册错误响应
#[instrument(level = "debug", skip_all, fields(client_id, envelope_id = request_envelope_id))]
async fn send_register_error(
    client_id: &str,
    code: u32,
    message: &str,
    server: &SignalingServerHandle,
    request_envelope_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let error_response = ErrorResponse {
        code,
        message: message.to_string(),
    };

    let response = RegisterResponse {
        result: Some(register_response::Result::Error(error_response)),
    };

    // 创建临时 ActrId（用于响应）
    let temp_actor_id = ActrId {
        realm: Realm { realm_id: 0 },
        serial_number: 0,
        r#type: ActrType {
            manufacturer: "temp".to_string(),
            name: "temp".to_string(),
        },
    };

    let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
        target: temp_actor_id,
        payload: Some(signaling_to_actr::Payload::RegisterResponse(response)),
    });

    let response_envelope = server.create_envelope(flow, Some(request_envelope_id));

    send_envelope_to_client(client_id, response_envelope, server).await?;

    Ok(())
}

/// 处理 ActrToSignaling 流程（注册后）
#[instrument(level = "debug", skip_all, fields(client_id, envelope_id = request_envelope_id))]
async fn handle_actr_to_server(
    actr_to_server: ActrToSignaling,
    client_id: &str,
    server: &SignalingServerHandle,
    request_envelope_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = actr_to_server.source.clone();

    info!("📬 处理来自 Actor {} 的消息", source.serial_number);

    // 验证 credential
    if let Err(e) =
        AIdCredentialValidator::check(&actr_to_server.credential, source.realm.realm_id).await
    {
        warn!(
            "⚠️  Actor {} credential 验证失败: {}",
            source.serial_number, e
        );
        // 发送错误响应
        send_error_response(
            client_id,
            &source,
            401,
            &format!("Credential validation failed: {e}"),
            server,
            Some(request_envelope_id),
        )
        .await?;
        return Ok(());
    }

    match actr_to_server.payload {
        Some(actr_to_signaling::Payload::Ping(ping)) => {
            handle_ping(source, ping, client_id, server, request_envelope_id).await?;
        }
        Some(actr_to_signaling::Payload::UnregisterRequest(req)) => {
            handle_unregister(source, req, client_id, server, request_envelope_id).await?;
        }
        Some(actr_to_signaling::Payload::CredentialUpdateRequest(req)) => {
            handle_credential_update(source, req, client_id, server, request_envelope_id).await?;
        }
        Some(actr_to_signaling::Payload::DiscoveryRequest(req)) => {
            handle_discovery_request(source, req, client_id, server, request_envelope_id).await?;
        }
        Some(actr_to_signaling::Payload::RouteCandidatesRequest(req)) => {
            handle_route_candidates_request(source, req, client_id, server, request_envelope_id)
                .await?;
        }
        Some(actr_to_signaling::Payload::SubscribeActrUpRequest(req)) => {
            handle_subscribe_actr_up(source, req, client_id, server, request_envelope_id).await?;
        }
        Some(actr_to_signaling::Payload::UnsubscribeActrUpRequest(req)) => {
            handle_unsubscribe_actr_up(source, req, client_id, server, request_envelope_id).await?;
        }
        Some(actr_to_signaling::Payload::Error(error)) => {
            error!(
                "收到客户端错误报告 (Actor {}): code={}, message={}",
                source.serial_number, error.code, error.message
            );
        }
        None => {
            warn!("ActrToSignaling 消息缺少 payload");
        }
    }

    Ok(())
}

/// 处理心跳
async fn handle_ping(
    source: ActrId,
    ping: Ping,
    client_id: &str,
    server: &SignalingServerHandle,
    request_envelope_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "💓 收到 Actor {} 心跳: availability={}, power_reserve={:.2}, mailbox_backlog={:.2}, sticky_clients={}",
        source.serial_number,
        ping.availability,
        ping.power_reserve,
        ping.mailbox_backlog,
        ping.sticky_client_ids.len()
    );

    // 存储负载指标到 ServiceRegistry
    let mut registry = server.service_registry.write().await;
    if let Err(e) = registry.update_load_metrics(
        &source,
        ping.availability,
        ping.power_reserve,
        ping.mailbox_backlog,
    ) {
        warn!("更新 Actor {} 负载指标失败: {}", source.serial_number, e);
    }
    drop(registry);

    // 创建 Pong 响应
    let pong = Pong {
        seq: chrono::Utc::now().timestamp() as u64,
        suggest_interval_secs: Some(30),
    };

    let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
        target: source,
        payload: Some(signaling_to_actr::Payload::Pong(pong)),
    });

    let response_envelope = server.create_envelope(flow, Some(request_envelope_id));

    send_envelope_to_client(client_id, response_envelope, server).await?;

    Ok(())
}

/// 处理注销
#[instrument(level = "debug", skip_all, fields(client_id, envelope_id = request_envelope_id))]
async fn handle_unregister(
    source: ActrId,
    req: actr_protocol::UnregisterRequest,
    client_id: &str,
    server: &SignalingServerHandle,
    request_envelope_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "👋 Actor {} 注销: reason={:?}",
        source.serial_number,
        req.reason.as_deref().unwrap_or("未提供")
    );

    // 发送 UnregisterResponse
    let response = actr_protocol::UnregisterResponse {
        result: Some(actr_protocol::unregister_response::Result::Success(
            actr_protocol::unregister_response::UnregisterOk {},
        )),
    };

    let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
        target: source,
        payload: Some(signaling_to_actr::Payload::UnregisterResponse(response)),
    });

    let response_envelope = server.create_envelope(flow, Some(request_envelope_id));
    send_envelope_to_client(client_id, response_envelope, server).await?;

    // 清理客户端连接
    cleanup_client(client_id, server).await;

    Ok(())
}

/// 通过 actor_id_index 快速解析 client_id，保持索引与 clients 同步
async fn resolve_client_id_by_actor_id(
    actor_id: &ActrId,
    server: &SignalingServerHandle,
) -> Result<String, String> {
    let client_id = {
        let index_guard = server.actor_id_index.read().await;
        index_guard.get(actor_id).cloned()
    };

    let client_id = match client_id {
        Some(id) => id,
        None => {
            warn!(
                "⚠️  Actor {} 缺少 client_id 索引，可能尚未注册或已清理",
                format_actor_id(actor_id)
            );
            return Err("client_id not found for actor_id".into());
        }
    };

    let exists = server.clients.read().await.contains_key(&client_id);
    if !exists {
        warn!(
            "⚠️  Actor {} 索引指向不存在的客户端 {}，索引可能已过期",
            format_actor_id(actor_id),
            client_id
        );
        return Err("actor_id_index stale for actor_id".into());
    }

    Ok(client_id)
}

fn format_actor_id(actor_id: &ActrId) -> String {
    format!(
        "realm={} serial={}",
        actor_id.realm.realm_id, actor_id.serial_number
    )
}

/// 处理 ActrRelay（WebRTC 信令中继）
#[instrument(level = "debug", skip_all, fields(client_id, envelope_id = request_envelope_id))]
async fn handle_actr_relay(
    relay: ActrRelay,
    client_id: &str,
    server: &SignalingServerHandle,
    request_envelope_id: &str,
    #[cfg(feature = "opentelemetry")] remote_context: opentelemetry::Context,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = relay.source.clone();
    let target = &relay.target;

    info!(
        "🔀 中继信令: {} -> {}",
        source.serial_number, target.serial_number
    );

    tracing::debug!(?relay, "handle_actr_relay");

    // ACL check: can source relay to target?
    use actrix_common::tenant::acl::ActorAcl;
    let source_realm = source.realm.realm_id.to_string();
    let target_realm = target.realm.realm_id.to_string();
    
    // Cross-realm relay is denied by default for security
    if source_realm != target_realm {
        warn!(
            "⚠️  ACL denied cross-realm relay: realm {} -> realm {}",
            source_realm, target_realm
        );
        send_error_response(
            client_id,
            &source,
            403,
            "Cross-realm relay is not allowed",
            server,
            Some(request_envelope_id),
        )
        .await?;
        return Ok(());
    }
    
    // Same realm: check ACL rules (always enforced)
    let can_relay = ActorAcl::can_discover(
        &source_realm,
        &source.r#type.name,
        &target.r#type.name,
    )
    .await
    .unwrap_or(false);

    if !can_relay {
        warn!(
            "⚠️  ACL denied relay: {} -> {}",
            source.serial_number, target.serial_number
        );
        send_error_response(
            client_id,
            &source,
            403,
            "ACL policy denies relay to target actor",
            server,
            Some(request_envelope_id),
        )
        .await?;
        return Ok(());
    }

    // 验证 credential
    if let Err(e) = AIdCredentialValidator::check(&relay.credential, source.realm.realm_id).await {
        warn!(
            "⚠️  Actor {} credential 验证失败: {}",
            source.serial_number, e
        );
        // 发送错误响应
        send_error_response(
            client_id,
            &source,
            401,
            &format!("Credential validation failed: {e}"),
            server,
            Some(request_envelope_id),
        )
        .await?;
        return Ok(());
    }

    // Role negotiation: server decides offerer/answerer and notifies both parties
    if let Some(actr_relay::Payload::RoleNegotiation(RoleNegotiation { from, to, .. })) =
        relay.payload.clone()
    {
        let is_offerer = actor_order_key(&from) < actor_order_key(&to);

        let new_relay = ActrRelay {
            // source: peer actor (对端)，target: 该 assignment 的接收方
            source: from.clone(),
            credential: relay.credential.clone(),
            target: to.clone(),
            payload: Some(actr_relay::Payload::RoleAssignment(RoleAssignment {
                is_offerer,
            })),
        };
        send_role_assignment(&from, server, new_relay.clone()).await?;

        let new_relay = ActrRelay {
            // source: peer actor (对端)，target: 该 assignment 的接收方
            source: from.clone(),
            credential: relay.credential.clone(),
            target: to.clone(),
            payload: Some(actr_relay::Payload::RoleAssignment(RoleAssignment {
                is_offerer: !is_offerer,
            })),
        };

        send_role_assignment(&to, server, new_relay).await?;

        return Ok(());
    }

    // 查找目标客户端并转发其他中继消息
    let clients_guard = server.clients.read().await;
    let target_client = clients_guard.values().find(|client| {
        client.actor_id.as_ref().is_some_and(|id| {
            id.realm.realm_id == target.realm.realm_id && id.serial_number == target.serial_number
        })
    });

    if let Some(target_client) = target_client {
        // 重新构造 envelope 并转发
        let flow = signaling_envelope::Flow::ActrRelay(relay);
        let forward_envelope = server.create_new_envelope(flow);

        let mut buf = Vec::new();
        forward_envelope.encode(&mut buf)?;

        target_client
            .direct_sender
            .send(WsMessage::Binary(buf.into()))?;

        info!("✅ 信令中继成功");
    } else {
        warn!("⚠️ 未找到目标 Actor {}", target.serial_number);
    }

    Ok(())
}

// 计算用于排序的 ActorId key，确保角色分配可重复
fn actor_order_key(id: &ActrId) -> (u32, u64, String, String) {
    (
        id.realm.realm_id,
        id.serial_number,
        id.r#type.manufacturer.clone(),
        id.r#type.name.clone(),
    )
}

async fn send_role_assignment(
    target_actor: &ActrId,
    server: &SignalingServerHandle,
    relay: ActrRelay,
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = signaling_envelope::Flow::ActrRelay(relay);
    let envelope = server.create_new_envelope(flow);

    let mut buf = Vec::new();
    envelope.encode(&mut buf)?;

    let clients_guard = server.clients.read().await;
    if let Some(client) = clients_guard.values().find(|client| {
        client.actor_id.as_ref().is_some_and(|id| {
            id.realm.realm_id == target_actor.realm.realm_id
                && id.serial_number == target_actor.serial_number
        })
    }) {
        client
            .direct_sender
            .send(WsMessage::Binary(buf.into()))
            .map_err(|e| e.into())
    } else {
        warn!(
            "⚠️ send_role_assignment: 未找到目标 Actor {}",
            target_actor.serial_number
        );
        Ok(())
    }
}

/// 发送 SignalingEnvelope 到客户端
#[instrument(level = "debug", skip_all, fields(client_id, envelope_id = envelope.envelope_id))]
async fn send_envelope_to_client(
    client_id: &str,
    #[allow(unused_mut)] mut envelope: SignalingEnvelope,
    server: &SignalingServerHandle,
) -> Result<(), Box<dyn std::error::Error>> {
    let clients_guard = server.clients.read().await;

    if let Some(client) = clients_guard.get(client_id) {
        #[cfg(feature = "opentelemetry")]
        {
            use tracing_opentelemetry::OpenTelemetrySpanExt;
            let context = tracing::Span::current().context();
            inject_trace_context(&context, &mut envelope);
        }

        // 编码 protobuf
        let mut buf = Vec::new();
        envelope.encode(&mut buf)?;

        // 发送 Binary 消息
        match client.direct_sender.send(WsMessage::Binary(buf.into())) {
            Ok(_) => {
                info!("✅ 成功发送 envelope 到客户端 {}", client_id);
                Ok(())
            }
            Err(e) => {
                error!("❌ 发送失败: {}", e);
                Err(format!("发送失败: {e}").into())
            }
        }
    } else {
        warn!("⚠️ 未找到客户端 {}", client_id);
        Err(format!("客户端 {client_id} 未找到").into())
    }
}

/// 清理客户端连接
async fn cleanup_client(client_id: &str, server: &SignalingServerHandle) {
    let removed_client = {
        let mut clients_guard = server.clients.write().await;
        clients_guard.remove(client_id)
    };

    if let Some(client) = removed_client {
        if let Some(actor_id) = client.actor_id {
            info!("🧹 清理 Actor {} 的连接", actor_id.serial_number);

            // Remove all services for this Actor from the ServiceRegistry to avoid stale ghost instances
            server
                .service_registry
                .write()
                .await
                .unregister_actor(&actor_id);

            let mut actor_index = server.actor_id_index.write().await;
            match actor_index.remove(&actor_id) {
                Some(mapped_client) if mapped_client != client_id => warn!(
                    "⚠️  Actor {} 索引指向意外客户端 {}，已移除",
                    actor_id.serial_number, mapped_client
                ),
                None => warn!("⚠️  Actor {} 清理时未找到索引条目", actor_id.serial_number),
                _ => {}
            }
        }

        // 移除消息速率限制器
        if let Some(ref limiter) = server.message_rate_limiter {
            limiter.remove_connection(client_id).await;
        }
    }
}

/// 处理 Credential 更新请求
#[instrument(level = "debug", skip_all, fields(client_id, envelope_id = request_envelope_id))]
async fn handle_credential_update(
    source: ActrId,
    _req: actr_protocol::CredentialUpdateRequest,
    client_id: &str,
    server: &SignalingServerHandle,
    request_envelope_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "🔑 处理 Actor {} 的 Credential 更新请求",
        source.serial_number
    );

    // 检查是否配置了 AIS 客户端
    let ais_client = match &server.ais_client {
        Some(client) => client,
        None => {
            warn!("⚠️  AIS 客户端未配置，无法刷新 Credential");
            let error_response = ErrorResponse {
                code: 503,
                message: "AIS service not configured".to_string(),
            };

            let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
                target: source.clone(),
                payload: Some(signaling_to_actr::Payload::Error(error_response)),
            });

            let response_envelope = server.create_envelope(flow, Some(request_envelope_id));
            send_envelope_to_client(client_id, response_envelope, server).await?;
            return Ok(());
        }
    };

    // 调用 AIS 刷新 Credential
    match ais_client
        .refresh_credential(source.realm.realm_id, source.r#type.clone())
        .await
    {
        Ok(register_response) => {
            use actr_protocol::register_response::Result as RegisterResult;

            match register_response.result {
                Some(RegisterResult::Success(register_ok)) => {
                    let new_credential = register_ok.credential;
                    let expires_at = register_ok.credential_expires_at;

                    // 更新客户端连接中存储的 credential
                    {
                        let mut clients_guard = server.clients.write().await;
                        if let Some(client_conn) = clients_guard.get_mut(client_id) {
                            client_conn.credential = Some(new_credential.clone());
                            info!(
                                "✅ 已更新 Actor {} 的 Credential (key_id={})",
                                source.serial_number, new_credential.token_key_id
                            );
                        }
                    }

                    // 返回成功响应（使用 RegisterResponse，因为协议中没有 CredentialUpdateResponse）
                    use actr_protocol::register_response::RegisterOk;
                    let response = actr_protocol::RegisterResponse {
                        result: Some(actr_protocol::register_response::Result::Success(
                            RegisterOk {
                                actr_id: source.clone(),
                                credential: new_credential.clone(),
                                psk: None, // Credential 刷新不需要重新生成 PSK
                                credential_expires_at: expires_at,
                                signaling_heartbeat_interval_secs: 30, // 保持心跳间隔
                            },
                        )),
                    };

                    let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
                        target: source,
                        payload: Some(signaling_to_actr::Payload::RegisterResponse(response)),
                    });

                    let response_envelope = server.create_envelope(flow, Some(request_envelope_id));
                    send_envelope_to_client(client_id, response_envelope, server).await?;

                    info!("✅ Credential 更新成功");
                }
                Some(RegisterResult::Error(err)) => {
                    error!("❌ AIS 返回错误: {} - {}", err.code, err.message);

                    let error_response = ErrorResponse {
                        code: err.code,
                        message: format!("AIS error: {}", err.message),
                    };

                    let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
                        target: source,
                        payload: Some(signaling_to_actr::Payload::Error(error_response)),
                    });

                    let response_envelope = server.create_envelope(flow, Some(request_envelope_id));
                    send_envelope_to_client(client_id, response_envelope, server).await?;
                }
                None => {
                    error!("❌ AIS 返回空响应");

                    let error_response = ErrorResponse {
                        code: 500,
                        message: "AIS returned empty response".to_string(),
                    };

                    let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
                        target: source,
                        payload: Some(signaling_to_actr::Payload::Error(error_response)),
                    });

                    let response_envelope = server.create_envelope(flow, Some(request_envelope_id));
                    send_envelope_to_client(client_id, response_envelope, server).await?;
                }
            }
        }
        Err(e) => {
            error!("❌ 调用 AIS 失败: {}", e);

            let error_response = ErrorResponse {
                code: 500,
                message: format!("Failed to refresh credential: {e}"),
            };

            let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
                target: source,
                payload: Some(signaling_to_actr::Payload::Error(error_response)),
            });

            let response_envelope = server.create_envelope(flow, Some(request_envelope_id));
            send_envelope_to_client(client_id, response_envelope, server).await?;
        }
    }

    Ok(())
}

/// 处理服务发现请求
#[instrument(level = "debug", skip_all, fields(client_id, envelope_id = request_envelope_id))]
async fn handle_discovery_request(
    source: ActrId,
    req: actr_protocol::DiscoveryRequest,
    client_id: &str,
    server: &SignalingServerHandle,
    request_envelope_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "🔍 处理 Actor {} 的 Discovery 请求: manufacturer={:?}, limit={}",
        source.serial_number,
        req.manufacturer.as_deref().unwrap_or("*"),
        req.limit.unwrap_or(64)
    );

    // 从 ServiceRegistry 查询所有服务
    let registry = server.service_registry.read().await;
    let services = registry.discover_all(req.manufacturer.as_deref());
    let total_count = services.len(); // Save count before moving

    // Apply ACL filtering (if ACL is enabled)
    use actrix_common::tenant::acl::ActorAcl;
    let source_realm = source.realm.realm_id.to_string();
    let source_type = &source.r#type.name;

    let mut acl_filtered_services = Vec::new();
    
    // ACL always enabled: filter services based on ACL rules
    for service in services {
        let target_realm = service.actor_id.realm.realm_id.to_string();
        let target_type = &service.actor_id.r#type.name;

        // Only check ACL if in same realm
        if source_realm == target_realm {
            match ActorAcl::can_discover(&source_realm, source_type, target_type).await {
                Ok(true) => acl_filtered_services.push(service),
                Ok(false) => {
                    debug!(
                        "ACL denied discovery: {} cannot discover {}",
                        source.serial_number, service.actor_id.serial_number
                    );
                }
                Err(e) => {
                    warn!(
                        "ACL check failed for {} -> {}: {}",
                        source.serial_number, service.actor_id.serial_number, e
                    );
                }
            }
        } else {
            // Cross-realm discovery denied
            debug!(
                "Cross-realm discovery denied: {} -> {}",
                source_realm, target_realm
            );
        }
    }
    info!(
        "ACL filtering: {} -> {} services",
        total_count,
        acl_filtered_services.len()
    );

    // 按 ActrType 聚合服务（使用 HashMap 去重）
    use std::collections::HashMap;
    let mut type_map: HashMap<String, actr_protocol::discovery_response::TypeEntry> =
        HashMap::new();

    for service in acl_filtered_services {
        let type_key = format!(
            "{}/{}",
            service.actor_id.r#type.manufacturer, service.actor_id.r#type.name
        );

        // 如果该类型还未添加，创建新条目
        type_map.entry(type_key).or_insert_with(|| {
            let fingerprint = service
                .service_spec
                .as_ref()
                .map(|spec| spec.fingerprint.clone())
                .unwrap_or_else(|| "unknown".to_string());

            actr_protocol::discovery_response::TypeEntry {
                actr_type: service.actor_id.r#type.clone(),
                description: None,
                service_fingerprint: fingerprint,
                published_at: Some(service.last_heartbeat_time_secs as i64),
                tags: vec![],
            }
        });
    }

    // 转换为 Vec 并应用 limit
    let mut entries: Vec<_> = type_map.into_values().collect();
    let limit = req.limit.unwrap_or(64) as usize;
    entries.truncate(limit);

    drop(registry);

    info!(
        "✅ 为 Actor {} 返回 {} 个服务类型",
        source.serial_number,
        entries.len()
    );

    let response = actr_protocol::DiscoveryResponse {
        result: Some(actr_protocol::discovery_response::Result::Success(
            actr_protocol::discovery_response::DiscoveryOk { entries },
        )),
    };

    let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
        target: source,
        payload: Some(signaling_to_actr::Payload::DiscoveryResponse(response)),
    });

    let response_envelope = server.create_envelope(flow, Some(request_envelope_id));
    send_envelope_to_client(client_id, response_envelope, server).await?;

    Ok(())
}

/// 处理路由候选请求（负载均衡）
#[instrument(level = "debug", skip_all, fields(client_id, envelope_id = request_envelope_id))]
async fn handle_route_candidates_request(
    source: ActrId,
    req: actr_protocol::RouteCandidatesRequest,
    client_id: &str,
    server: &SignalingServerHandle,
    request_envelope_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "🎯 处理 Actor {} 的 RouteCandidates 请求: target_type={}/{}",
        source.serial_number, req.target_type.manufacturer, req.target_type.name
    );

    // 从 ServiceRegistry 查询所有匹配 target_type 的实例
    let registry = server.service_registry.read().await;
    let candidates = registry.find_by_actr_type(&req.target_type);
    drop(registry);

    let total_candidates = candidates.len();

    if candidates.is_empty() {
        info!(
            "⚠️  未找到 {}/{} 类型的服务实例",
            req.target_type.manufacturer, req.target_type.name
        );
    } else {
        info!(
            "📋 找到 {} 个 {}/{} 类型的候选实例",
            total_candidates,
            req.target_type.manufacturer,
            req.target_type.name
        );
    }

    // Apply ACL filtering
    use actrix_common::tenant::acl::ActorAcl;
    let source_realm = source.realm.realm_id.to_string();
    let source_type = &source.r#type.name;
    let target_type = &req.target_type.name;

    let mut acl_filtered_candidates = Vec::new();
    for candidate in candidates {
        let target_realm = candidate.actor_id.realm.realm_id.to_string();

        // Only check ACL if in same realm
        if source_realm == target_realm {
            match ActorAcl::can_discover(&source_realm, source_type, target_type).await {
                Ok(true) => acl_filtered_candidates.push(candidate),
                Ok(false) => {
                    debug!(
                        "ACL denied route candidate: {} cannot access {}",
                        source.serial_number, candidate.actor_id.serial_number
                    );
                }
                Err(e) => {
                    warn!(
                        "ACL check failed for {} -> {}: {}",
                        source.serial_number, candidate.actor_id.serial_number, e
                    );
                }
            }
        } else {
            // Cross-realm access denied
            debug!(
                "Cross-realm route candidate denied: {} -> {}",
                source_realm, target_realm
            );
        }
    }
    info!(
        "ACL filtering for route candidates: {} -> {} candidates",
        total_candidates,
        acl_filtered_candidates.len()
    );

    // 使用 LoadBalancer 进行排序和过滤
    // 从请求中提取客户端位置（如果提供）
    let client_location = req.client_location.as_ref().and_then(|loc| {
        if let (Some(lat), Some(lon)) = (loc.latitude, loc.longitude) {
            Some((lat, lon))
        } else {
            None
        }
    });

    // 从 ServiceRegistry 提取客户端的 fingerprint
    let client_fingerprint = {
        let registry = server.service_registry.read().await;
        registry
            .get_service_spec(&source)
            .map(|spec| spec.fingerprint.clone())
    };

    // 获取兼容性缓存引用
    let cache_guard = server.compatibility_cache.read().await;
    let compatibility_cache = Some(&*cache_guard);

    let ranked_actor_ids = LoadBalancer::rank_candidates(
        acl_filtered_candidates,
        req.criteria.as_ref(),
        Some(client_id),
        client_location,
        compatibility_cache,
        client_fingerprint.as_deref(),
    );

    info!(
        "✅ 为 Actor {} 返回 {} 个排序后的候选",
        source.serial_number,
        ranked_actor_ids.len()
    );

    let response = actr_protocol::RouteCandidatesResponse {
        result: Some(actr_protocol::route_candidates_response::Result::Success(
            actr_protocol::route_candidates_response::RouteCandidatesOk {
                candidates: ranked_actor_ids,
            },
        )),
    };

    let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
        target: source,
        payload: Some(signaling_to_actr::Payload::RouteCandidatesResponse(
            response,
        )),
    });

    let response_envelope = server.create_envelope(flow, Some(request_envelope_id));
    send_envelope_to_client(client_id, response_envelope, server).await?;

    Ok(())
}

/// 处理订阅 Actor 上线事件
#[instrument(level = "debug", skip_all, fields(client_id, envelope_id = request_envelope_id))]
async fn handle_subscribe_actr_up(
    source: ActrId,
    req: actr_protocol::SubscribeActrUpRequest,
    client_id: &str,
    server: &SignalingServerHandle,
    request_envelope_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "📢 Actor {} 订阅服务上线事件: target_type={}/{}",
        source.serial_number, req.target_type.manufacturer, req.target_type.name
    );

    // 添加订阅到 PresenceManager
    let mut presence = server.presence_manager.write().await;
    presence.subscribe(source.clone(), req.target_type);
    drop(presence);

    let response = actr_protocol::SubscribeActrUpResponse {
        result: Some(actr_protocol::subscribe_actr_up_response::Result::Success(
            actr_protocol::subscribe_actr_up_response::SubscribeOk {},
        )),
    };

    let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
        target: source,
        payload: Some(signaling_to_actr::Payload::SubscribeActrUpResponse(
            response,
        )),
    });

    let response_envelope = server.create_envelope(flow, Some(request_envelope_id));
    send_envelope_to_client(client_id, response_envelope, server).await?;

    Ok(())
}

/// 处理取消订阅 Actor 上线事件
#[instrument(level = "debug", skip_all, fields(client_id, envelope_id = request_envelope_id))]
async fn handle_unsubscribe_actr_up(
    source: ActrId,
    req: actr_protocol::UnsubscribeActrUpRequest,
    client_id: &str,
    server: &SignalingServerHandle,
    request_envelope_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "🔕 Actor {} 取消订阅服务上线事件: target_type={}/{}",
        source.serial_number, req.target_type.manufacturer, req.target_type.name
    );

    // 从 PresenceManager 移除订阅
    let mut presence = server.presence_manager.write().await;
    let removed = presence.unsubscribe(&source, &req.target_type);
    drop(presence);

    if !removed {
        warn!(
            "Actor {} 未订阅过 {}/{}",
            source.serial_number, req.target_type.manufacturer, req.target_type.name
        );
    }

    let response = actr_protocol::UnsubscribeActrUpResponse {
        result: Some(
            actr_protocol::unsubscribe_actr_up_response::Result::Success(
                actr_protocol::unsubscribe_actr_up_response::UnsubscribeOk {},
            ),
        ),
    };

    let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
        target: source,
        payload: Some(signaling_to_actr::Payload::UnsubscribeActrUpResponse(
            response,
        )),
    });

    let response_envelope = server.create_envelope(flow, Some(request_envelope_id));
    send_envelope_to_client(client_id, response_envelope, server).await?;

    Ok(())
}

/// 发送通用错误响应
#[instrument(level = "debug", skip_all, fields(client_id, reply_for = ?reply_for, target = ?target))]
async fn send_error_response(
    client_id: &str,
    target: &ActrId,
    code: u32,
    message: &str,
    server: &SignalingServerHandle,
    reply_for: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let error_response = ErrorResponse {
        code,
        message: message.to_string(),
    };

    let flow = signaling_envelope::Flow::ServerToActr(SignalingToActr {
        target: target.clone(),
        payload: Some(signaling_to_actr::Payload::Error(error_response)),
    });

    let response_envelope = server.create_envelope(flow, reply_for);
    send_envelope_to_client(client_id, response_envelope, server).await?;

    Ok(())
}

// Main function removed - SignalingServer can now be instantiated and started from other modules
