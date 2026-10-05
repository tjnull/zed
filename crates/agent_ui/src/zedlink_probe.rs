use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, DirBuilder, Permissions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    rc::Rc,
    sync::mpsc,
    time::Duration,
};

use acp_thread::{
    AcpThread, AcpThreadEvent, AgentThreadEntry, AuthorizationKind, SelectedPermissionOutcome,
    ThreadStatus, ToolCallStatus,
};
use agent_client_protocol::schema::v1 as acp;
use agent_settings::{AgentProfile, AgentProfileId};
use anyhow::{Context as _, Result, anyhow};
use gpui::{App, Entity, Global, Subscription, Task};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::agent_panel::{AgentPanel, CreateThreadOptions};
use crate::conversation_view::ThreadView;
use crate::{Agent, AgentThreadSource};

const MAX_REQUEST_BYTES: u64 = 4096;
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024;
const MAX_ACTIVITY_BYTES: usize = 256 * 1024;
const MAX_APPROVAL_INPUT_BYTES: usize = 8192;
const MAX_THREAD_TITLE_BYTES: usize = 128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeRequest {
    version: u8,
    request_id: String,
    method: String,
    params: Value,
}

struct ProbeCommand {
    request: ProbeRequest,
    response: mpsc::Sender<Value>,
}

struct ProbeState {
    project_root: PathBuf,
    instance_id: String,
    epoch: String,
    submissions: RefCell<HashMap<String, SubmissionRecord>>,
    creations: RefCell<HashMap<String, CreationRecord>>,
    exposed_threads: RefCell<HashSet<String>>,
    subscriptions: RefCell<HashMap<String, Subscription>>,
    events: RefCell<HashMap<String, ThreadEvents>>,
}

#[derive(Default)]
struct ThreadEvents {
    last_sequence: u64,
    records: VecDeque<Value>,
}

struct ProbeGlobal(Rc<ProbeState>);

impl Global for ProbeGlobal {}

struct SubmissionRecord {
    thread_id: String,
    text: String,
    outcome: &'static str,
}

struct CreationRecord {
    title: Option<String>,
    thread_id: Option<String>,
}

pub fn init(cx: &mut App) {
    let (Some(directory), Some(project_root)) = (
        std::env::var_os("ZEDLINK_PROBE_DIR"),
        std::env::var_os("ZEDLINK_PROBE_PROJECT_ROOT"),
    ) else {
        return;
    };

    let directory = PathBuf::from(directory);
    let project_root = PathBuf::from(project_root);
    if !directory.is_absolute() || !project_root.is_absolute() {
        log::warn!("ZedLink probe requires absolute directory and project paths");
        return;
    }

    let setup = (|| -> Result<(UnixListener, ProbeState)> {
        let project_root = fs::canonicalize(project_root).context("project root unavailable")?;
        if !project_root.is_dir() {
            return Err(anyhow!("project root is not a directory"));
        }

        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&directory)?;
                if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o077 != 0 {
                    return Err(anyhow!("existing probe directory is not private"));
                }
            }
            Err(error) => return Err(error).context("private socket directory unavailable"),
        }
        let socket = directory.join("zedlink.sock");
        if let Ok(metadata) = fs::symlink_metadata(&socket) {
            if !metadata.file_type().is_socket() || UnixStream::connect(&socket).is_ok() {
                return Err(anyhow!("probe socket path is occupied"));
            }
            fs::remove_file(&socket).context("stale probe socket unavailable")?;
        }
        let listener = UnixListener::bind(&socket).context("socket unavailable")?;
        fs::set_permissions(&socket, Permissions::from_mode(0o600))
            .context("socket permissions unavailable")?;
        Ok((
            listener,
            ProbeState {
                project_root,
                instance_id: uuid::Uuid::new_v4().to_string(),
                epoch: uuid::Uuid::new_v4().to_string(),
                submissions: RefCell::new(HashMap::new()),
                creations: RefCell::new(HashMap::new()),
                exposed_threads: RefCell::new(HashSet::new()),
                subscriptions: RefCell::new(HashMap::new()),
                events: RefCell::new(HashMap::new()),
            },
        ))
    })();

    let Ok((listener, state)) = setup else {
        log::warn!("ZedLink local probe could not start");
        return;
    };
    let state = Rc::new(state);

    let (sender, receiver) = async_channel::bounded::<ProbeCommand>(16);
    let listener_thread = std::thread::Builder::new()
        .name("zedlink-probe".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else {
                    log::warn!("ZedLink local probe listener stopped");
                    break;
                };
                if handle_stream(stream, &sender).is_err() {
                    log::debug!("ZedLink local probe request failed");
                }
            }
        });
    if listener_thread.is_err() {
        log::warn!("ZedLink local probe worker could not start");
        return;
    }
    cx.set_global(ProbeGlobal(state.clone()));

    cx.spawn(async move |cx| {
        while let Ok(command) = receiver.recv().await {
            let result = cx.update(|cx| handle_request(command.request, &state, cx));
            if command.response.send(result).is_err() {
                continue;
            }
        }
    })
    .detach();
}

pub(crate) fn toggle_thread_exposure(thread: &Entity<AcpThread>, cx: &mut App) -> Option<bool> {
    let state = cx.try_global::<ProbeGlobal>()?.0.clone();
    if !thread_belongs_to_project(thread, &state.project_root, cx) {
        return None;
    }
    let id = thread.read(cx).session_id().to_string();
    let was_exposed = state.exposed_threads.borrow_mut().remove(&id);
    if was_exposed {
        state.subscriptions.borrow_mut().remove(&id);
        Some(false)
    } else {
        expose_thread(&state, thread, cx);
        Some(true)
    }
}

fn expose_thread(state: &Rc<ProbeState>, thread: &Entity<AcpThread>, cx: &mut App) {
    let id = thread.read(cx).session_id().to_string();
    if state.exposed_threads.borrow().contains(&id) {
        return;
    }
    let subscription = cx.subscribe(thread, {
        let state = state.clone();
        let id = id.clone();
        move |_thread, event: &AcpThreadEvent, _cx| {
            let mut events = state.events.borrow_mut();
            let record = events.entry(id.clone()).or_default();
            let Some(sequence) = record.last_sequence.checked_add(1) else {
                return;
            };
            record.last_sequence = sequence;
            record.records.push_back(json!({
                "sequence": sequence,
                "kind": event_kind(event),
            }));
            if record.records.len() > 256 {
                record.records.pop_front();
            }
        }
    });
    state.events.borrow_mut().entry(id.clone()).or_default();
    state
        .subscriptions
        .borrow_mut()
        .insert(id.clone(), subscription);
    state.exposed_threads.borrow_mut().insert(id);
}

fn event_kind(event: &AcpThreadEvent) -> &'static str {
    match event {
        AcpThreadEvent::NewEntry => "entry.added",
        AcpThreadEvent::EntryUpdated(_) => "entry.updated",
        AcpThreadEvent::EntriesRemoved(_) => "entry.removed",
        AcpThreadEvent::StatusChanged => "status.changed",
        AcpThreadEvent::ToolAuthorizationRequested(_) => "approval.requested",
        AcpThreadEvent::ToolAuthorizationReceived(_) => "approval.resolved",
        AcpThreadEvent::Stopped(_) => "turn.stopped",
        AcpThreadEvent::Error => "turn.error",
        _ => "metadata.changed",
    }
}

pub(crate) fn is_available(cx: &App) -> bool {
    cx.has_global::<ProbeGlobal>()
}

fn handle_stream(
    mut stream: UnixStream,
    sender: &async_channel::Sender<ProbeCommand>,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    let mut bytes = Vec::new();
    let mut reader = BufReader::new((&mut stream).take(MAX_REQUEST_BYTES + 1));
    reader.read_until(b'\n', &mut bytes)?;
    let response = if bytes.len() as u64 > MAX_REQUEST_BYTES {
        error("", "PAYLOAD_TOO_LARGE")
    } else {
        match serde_json::from_slice::<ProbeRequest>(&bytes) {
            Ok(request)
                if request.version == 1
                    && !request.request_id.is_empty()
                    && request.request_id.len() <= 128
                    && request.params.is_object() =>
            {
                let request_id = request.request_id.clone();
                let (response_sender, response_receiver) = mpsc::channel();
                match sender.try_send(ProbeCommand {
                    request,
                    response: response_sender,
                }) {
                    Ok(()) => response_receiver
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap_or_else(|_| error(&request_id, "INSTANCE_UNAVAILABLE")),
                    Err(async_channel::TrySendError::Full(_)) => error(&request_id, "RATE_LIMITED"),
                    Err(async_channel::TrySendError::Closed(_)) => {
                        error(&request_id, "INSTANCE_UNAVAILABLE")
                    }
                }
            }
            _ => error("", "INVALID_REQUEST"),
        }
    };
    serde_json::to_writer(&mut stream, &response)?;
    stream.write_all(b"\n")?;
    Ok(())
}

fn handle_request(request: ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    match request.method.as_str() {
        "instance.info" => success(
            &request.request_id,
            json!({
                "instance_id": state.instance_id,
                "epoch": state.epoch,
                "capabilities": ["thread.list", "thread.create", "thread.snapshot", "thread.events", "thread.commands", "thread.settings", "thread.settings.update", "thread.send", "thread.cancel", "request.status"],
                "provisional": true,
            }),
        ),
        "request.status" => {
            if request.params.get("instance_id").and_then(Value::as_str)
                != Some(state.instance_id.as_str())
                || request.params.get("epoch").and_then(Value::as_str) != Some(state.epoch.as_str())
            {
                return error(&request.request_id, "INSTANCE_UNAVAILABLE");
            }
            let Some(original_request_id) = request
                .params
                .get("original_request_id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
            else {
                return error(&request.request_id, "INVALID_REQUEST");
            };
            let submissions = state.submissions.borrow();
            let Some(record) = submissions.get(original_request_id) else {
                return success(
                    &request.request_id,
                    json!({"known": false, "outcome": "unknown", "provisional": true}),
                );
            };
            if !state.exposed_threads.borrow().contains(&record.thread_id) {
                return error(&request.request_id, "THREAD_NOT_EXPOSED");
            }
            success(
                &request.request_id,
                json!({"known": true, "outcome": record.outcome, "provisional": true}),
            )
        }
        "thread.list" => {
            let mut seen = HashSet::new();
            let threads = loaded_threads(&state.project_root, cx)
                .into_iter()
                .filter_map(|thread| {
                    let thread = thread.read(cx);
                    let id = thread.session_id().to_string();
                    (state.exposed_threads.borrow().contains(&id) && seen.insert(id.clone())).then(
                        || {
                            json!({
                                "thread_id": id,
                            "title": thread.title().map(|title| title.to_string()),
                            "status": format!("{:?}", thread.status()),
                            "current_turn_id": thread.current_turn_id(),
                            })
                        },
                    )
                })
                .collect::<Vec<_>>();
            success(
                &request.request_id,
                json!({
                    "instance_id": state.instance_id,
                    "epoch": state.epoch,
                    "threads": threads,
                }),
            )
        }
        "thread.create" => create_thread(&request, state, cx),
        "thread.snapshot" => {
            let Some(id) = request.params.get("thread_id").and_then(Value::as_str) else {
                return error(&request.request_id, "INVALID_REQUEST");
            };
            if !state.exposed_threads.borrow().contains(id) {
                return error(&request.request_id, "THREAD_NOT_EXPOSED");
            }
            let Some(thread) = loaded_threads(&state.project_root, cx)
                .into_iter()
                .find(|thread| thread.read(cx).session_id().to_string() == id)
            else {
                return error(&request.request_id, "THREAD_NOT_EXPOSED");
            };
            let thread = thread.read(cx);
            let mut used = 0;
            let mut entries = Vec::new();
            let mut truncated = false;
            for entry in thread.entries() {
                let markdown = entry.to_markdown(cx);
                if used + markdown.len() > MAX_SNAPSHOT_BYTES {
                    truncated = true;
                    break;
                }
                used += markdown.len();
                entries.push(markdown);
            }
            // Keep a separate bounded tail for live activity. The compatible transcript
            // projection above is prefix-capped, so a long thread would otherwise hide
            // the currently streaming assistant thought or tool update.
            let mut activity_used = 0;
            let mut activity_entries = Vec::new();
            let mut activity_truncated = false;
            for entry in thread.entries().iter().rev() {
                let markdown = entry.to_markdown(cx);
                if activity_used + markdown.len() > MAX_ACTIVITY_BYTES {
                    activity_truncated = true;
                    if activity_entries.is_empty() {
                        let mut end = MAX_ACTIVITY_BYTES.min(markdown.len());
                        while !markdown.is_char_boundary(end) {
                            end -= 1;
                        }
                        activity_entries.push(markdown[..end].to_string());
                    }
                    break;
                }
                activity_used += markdown.len();
                activity_entries.push(markdown);
            }
            activity_entries.reverse();
            success(
                &request.request_id,
                json!({
                    "instance_id": state.instance_id,
                    "epoch": state.epoch,
                    "thread_id": id,
                    "title": thread.title().map(|title| title.to_string()),
                    "status": format!("{:?}", thread.status()),
                    "current_turn_id": thread.current_turn_id(),
                    "pending_approvals": pending_approvals(thread, cx),
                    "entries_markdown": entries,
                    "truncated": truncated,
                    "activity_entries_markdown": activity_entries,
                    "activity_truncated": activity_truncated,
                    "provisional": true,
                    "last_sequence": state.events.borrow().get(id).map_or(0, |events| events.last_sequence),
                }),
            )
        }
        "thread.events" => {
            let Some(id) = request.params.get("thread_id").and_then(Value::as_str) else {
                return error(&request.request_id, "INVALID_REQUEST");
            };
            let Some(after_sequence) = request.params.get("after_sequence").and_then(Value::as_u64)
            else {
                return error(&request.request_id, "INVALID_REQUEST");
            };
            if !state.exposed_threads.borrow().contains(id)
                || !loaded_threads(&state.project_root, cx)
                    .into_iter()
                    .any(|thread| thread.read(cx).session_id().to_string() == id)
            {
                return error(&request.request_id, "THREAD_NOT_EXPOSED");
            }
            let events = state.events.borrow();
            let Some(events) = events.get(id) else {
                return error(&request.request_id, "RESYNC_REQUIRED");
            };
            if after_sequence > events.last_sequence
                || events.records.front().is_some_and(|record| {
                    after_sequence.saturating_add(1) < record["sequence"].as_u64().unwrap_or(0)
                })
            {
                return error(&request.request_id, "RESYNC_REQUIRED");
            }
            let records = events
                .records
                .iter()
                .filter(|record| {
                    record["sequence"]
                        .as_u64()
                        .is_some_and(|seq| seq > after_sequence)
                })
                .cloned()
                .collect::<Vec<_>>();
            success(
                &request.request_id,
                json!({
                    "instance_id": state.instance_id,
                    "epoch": state.epoch,
                    "thread_id": id,
                    "last_sequence": events.last_sequence,
                    "events": records,
                    "provisional": true,
                }),
            )
        }
        "thread.commands" => command_list(&request, state, cx),
        "thread.settings" => thread_settings(&request, state, cx),
        "thread.settings.update" => update_thread_settings(&request, state, cx),
        "thread.send" => send_request(&request, state, cx),
        "thread.cancel" => cancel_request(&request, state, cx),
        "thread.approvals" => approval_list(&request, state, cx),
        "approval.respond" => approval_response(&request, state, cx),
        _ => error(&request.request_id, "UNSUPPORTED_CAPABILITY"),
    }
}

fn create_thread(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    if request.params.get("instance_id").and_then(Value::as_str) != Some(state.instance_id.as_str())
        || request.params.get("epoch").and_then(Value::as_str) != Some(state.epoch.as_str())
    {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    let title = match request.params.get("title") {
        None | Some(Value::Null) => None,
        Some(Value::String(title)) => {
            let title = title.trim();
            if title.is_empty() {
                None
            } else if title.len() > MAX_THREAD_TITLE_BYTES {
                return error(&request.request_id, "INVALID_REQUEST");
            } else {
                Some(title.to_string())
            }
        }
        _ => return error(&request.request_id, "INVALID_REQUEST"),
    };

    {
        let creations = state.creations.borrow();
        if let Some(previous) = creations.get(&request.request_id) {
            if previous.title != title {
                return error(&request.request_id, "REQUEST_CONFLICT");
            }
            return creation_result(&request.request_id, previous);
        }
        if creations.len() >= 64 {
            return error(&request.request_id, "RATE_LIMITED");
        }
    }

    let panel = workspace::AppState::global(cx)
        .workspace_store
        .read(cx)
        .workspaces()
        .filter_map(|workspace| workspace.upgrade())
        .find_map(|workspace| {
            let matches_project = workspace
                .read(cx)
                .project()
                .read(cx)
                .visible_worktrees(cx)
                .any(|worktree| worktree.read(cx).abs_path().as_ref() == state.project_root);
            matches_project
                .then(|| workspace.read(cx).panel::<AgentPanel>(cx))
                .flatten()
        });
    let Some(panel) = panel else {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    };

    let created = cx.with_window(panel.entity_id(), |window, cx| {
        panel.update(cx, |panel, cx| {
            let thread_id = panel.create_thread_with_options(
                CreateThreadOptions {
                    title: title.clone().map(Into::into),
                    agent: Some(Agent::NativeAgent),
                    ..Default::default()
                },
                AgentThreadSource::AgentPanel,
                window,
                cx,
            );
            let conversation = panel
                .conversation_views()
                .into_iter()
                .find(|conversation| conversation.read(cx).thread_id == thread_id);
            (thread_id, conversation)
        })
    });
    let Some((_thread_id, Some(conversation))) = created else {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    };

    state.creations.borrow_mut().insert(
        request.request_id.clone(),
        CreationRecord {
            title,
            thread_id: None,
        },
    );
    let probe_state = cx.global::<ProbeGlobal>().0.clone();
    if let Some(thread) = conversation.read(cx).root_thread(cx) {
        finish_thread_creation(&request.request_id, &probe_state, &thread, cx);
    } else {
        let request_id = request.request_id.clone();
        cx.observe(&conversation, move |conversation, cx| {
            let Some(thread) = conversation.read(cx).root_thread(cx) else {
                return;
            };
            finish_thread_creation(&request_id, &probe_state, &thread, cx);
        })
        .detach();
    }

    let creations = state.creations.borrow();
    creation_result(
        &request.request_id,
        creations
            .get(&request.request_id)
            .expect("creation record inserted"),
    )
}

fn finish_thread_creation(
    request_id: &str,
    state: &Rc<ProbeState>,
    thread: &Entity<AcpThread>,
    cx: &mut App,
) {
    if !thread_belongs_to_project(thread, &state.project_root, cx) {
        return;
    }
    let thread_id = thread.read(cx).session_id().to_string();
    let creation = state.creations.borrow();
    let Some(record) = creation.get(request_id) else {
        return;
    };
    let should_expose = record.thread_id.is_none();
    let title = record.title.clone();
    drop(creation);
    if !should_expose {
        return;
    }
    if let Some(title) = title {
        thread
            .update(cx, |thread, cx| thread.set_title(title.into(), cx))
            .detach();
    }
    expose_thread(state, thread, cx);
    if let Some(record) = state.creations.borrow_mut().get_mut(request_id) {
        record.thread_id = Some(thread_id);
    }
}

fn creation_result(request_id: &str, record: &CreationRecord) -> Value {
    match &record.thread_id {
        Some(thread_id) => success(
            request_id,
            json!({"outcome": "ready", "thread_id": thread_id, "provisional": true}),
        ),
        None => success(
            request_id,
            json!({"outcome": "creating", "provisional": true}),
        ),
    }
}

fn pending_approvals(thread: &AcpThread, cx: &App) -> Vec<Value> {
    let turn_id = thread.current_turn_id();
    thread
        .entries()
        .iter()
        .filter_map(|entry| {
            let AgentThreadEntry::ToolCall(tool_call) = entry else {
                return None;
            };
            let ToolCallStatus::WaitingForConfirmation { options, kind, .. } = &tool_call.status
            else {
                return None;
            };
            if !matches!(kind, AuthorizationKind::PermissionGrant) {
                return None;
            }
            let raw_input = tool_call
                .raw_input
                .as_ref()
                .filter(|input| input.to_string().len() <= MAX_APPROVAL_INPUT_BYTES);
            let tool_name = tool_call.tool_name.as_ref().map(|name| name.to_string());
            let details_available = raw_input.is_some() && tool_name.is_some();
            Some(json!({
                "approval_id": tool_call.id.0.as_ref(),
                "turn_id": turn_id,
                "tool_name": tool_name,
                "display": tool_call.label.read(cx).source().chars().take(256).collect::<String>(),
                "raw_input": raw_input,
                "details_truncated": !details_available,
                "can_approve_once": details_available && options.allow_once_option_id().is_some(),
                "can_deny_once": options.deny_once_option_id().is_some(),
            }))
        })
        .collect()
}

fn approval_list(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    let Some(thread_id) = request.params.get("thread_id").and_then(Value::as_str) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    if !state.exposed_threads.borrow().contains(thread_id) {
        return error(&request.request_id, "THREAD_NOT_EXPOSED");
    }
    let Some(thread) = loaded_threads(&state.project_root, cx)
        .into_iter()
        .find(|thread| thread.read(cx).session_id().to_string() == thread_id)
    else {
        return error(&request.request_id, "THREAD_NOT_EXPOSED");
    };
    success(
        &request.request_id,
        json!({"thread_id": thread_id, "approvals": pending_approvals(thread.read(cx), cx), "provisional": true}),
    )
}

fn approval_response(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    let Some(thread_id) = request.params.get("thread_id").and_then(Value::as_str) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    let Some(approval_id) = request.params.get("approval_id").and_then(Value::as_str) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    let Some(turn_id) = request
        .params
        .get("turn_id")
        .and_then(Value::as_u64)
        .and_then(|id| u32::try_from(id).ok())
    else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    let kind = match request.params.get("decision").and_then(Value::as_str) {
        Some("approve_once") => acp::PermissionOptionKind::AllowOnce,
        Some("deny_once") => acp::PermissionOptionKind::RejectOnce,
        _ => return error(&request.request_id, "INVALID_REQUEST"),
    };
    if request.params.get("instance_id").and_then(Value::as_str) != Some(state.instance_id.as_str())
        || request.params.get("epoch").and_then(Value::as_str) != Some(state.epoch.as_str())
    {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    if !state.exposed_threads.borrow().contains(thread_id) {
        return error(&request.request_id, "THREAD_NOT_EXPOSED");
    }
    let Some(thread) = loaded_threads(&state.project_root, cx)
        .into_iter()
        .find(|thread| thread.read(cx).session_id().to_string() == thread_id)
    else {
        return error(&request.request_id, "THREAD_NOT_EXPOSED");
    };
    if thread.read(cx).current_turn_id() != Some(turn_id) {
        return error(&request.request_id, "STALE_TURN");
    }
    let tool_call_id = acp::ToolCallId::new(approval_id);
    let outcome = {
        let thread = thread.read(cx);
        let Some((_, tool_call)) = thread.tool_call(&tool_call_id) else {
            return error(&request.request_id, "APPROVAL_EXPIRED");
        };
        let ToolCallStatus::WaitingForConfirmation {
            options,
            kind: authorization_kind,
            ..
        } = &tool_call.status
        else {
            return error(&request.request_id, "APPROVAL_ALREADY_RESOLVED");
        };
        if !matches!(authorization_kind, AuthorizationKind::PermissionGrant) {
            return error(&request.request_id, "UNSUPPORTED_CAPABILITY");
        }
        if kind == acp::PermissionOptionKind::AllowOnce
            && (tool_call.tool_name.is_none()
                || !tool_call
                    .raw_input
                    .as_ref()
                    .is_some_and(|input| input.to_string().len() <= MAX_APPROVAL_INPUT_BYTES))
        {
            return error(&request.request_id, "UNSUPPORTED_CAPABILITY");
        }
        let Some(option) = options.first_option_of_kind(kind) else {
            return error(&request.request_id, "UNSUPPORTED_CAPABILITY");
        };
        SelectedPermissionOutcome::new(option.option_id.clone(), option.kind)
    };
    thread.update(cx, |thread, cx| {
        thread.authorize_tool_call(tool_call_id, outcome, cx)
    });
    success(
        &request.request_id,
        json!({"outcome": "resolved", "provisional": true}),
    )
}

fn cancel_request(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    let Some(thread_id) = request.params.get("thread_id").and_then(Value::as_str) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    let Some(turn_id) = request
        .params
        .get("turn_id")
        .and_then(Value::as_u64)
        .and_then(|id| u32::try_from(id).ok())
    else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    if request.params.get("instance_id").and_then(Value::as_str) != Some(state.instance_id.as_str())
        || request.params.get("epoch").and_then(Value::as_str) != Some(state.epoch.as_str())
    {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    if !state.exposed_threads.borrow().contains(thread_id) {
        return error(&request.request_id, "THREAD_NOT_EXPOSED");
    }
    let Some((thread, view)) = loaded_thread_views(&state.project_root, cx)
        .into_iter()
        .find(|(thread, _)| thread.read(cx).session_id().to_string() == thread_id)
    else {
        return error(&request.request_id, "THREAD_NOT_EXPOSED");
    };
    if thread.read(cx).current_turn_id() != Some(turn_id) {
        return error(&request.request_id, "STALE_TURN");
    }
    view.update(cx, |view, cx| view.cancel_generation(cx));
    success(
        &request.request_id,
        json!({"outcome": "requested", "turn_id": turn_id, "provisional": true}),
    )
}

fn command_list(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    let Some(thread_id) = request.params.get("thread_id").and_then(Value::as_str) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    if request.params.get("instance_id").and_then(Value::as_str) != Some(state.instance_id.as_str())
        || request.params.get("epoch").and_then(Value::as_str) != Some(state.epoch.as_str())
    {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    if !state.exposed_threads.borrow().contains(thread_id) {
        return error(&request.request_id, "THREAD_NOT_EXPOSED");
    }
    let Some((thread, _)) = loaded_thread_views(&state.project_root, cx)
        .into_iter()
        .find(|(thread, _)| thread.read(cx).session_id().to_string() == thread_id)
    else {
        return error(&request.request_id, "THREAD_NOT_EXPOSED");
    };
    let commands = thread
        .read(cx)
        .available_commands()
        .iter()
        .map(|command| {
            json!({
                "name": command.name,
                "description": command.description,
                "category": match acp_thread::command_category_from_meta(&command.meta) {
                    Some(acp_thread::CommandCategory::Native) => "native",
                    Some(acp_thread::CommandCategory::Mcp) => "mcp",
                    None => "agent",
                },
                "requires_argument": command.input.is_some(),
            })
        })
        .collect::<Vec<_>>();
    success(
        &request.request_id,
        json!({"thread_id": thread_id, "commands": commands}),
    )
}

fn thread_settings(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    let Some(thread_id) = request.params.get("thread_id").and_then(Value::as_str) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    if request.params.get("instance_id").and_then(Value::as_str) != Some(state.instance_id.as_str())
        || request.params.get("epoch").and_then(Value::as_str) != Some(state.epoch.as_str())
    {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    let Some((thread, native_thread)) = exposed_native_thread(thread_id, state, cx) else {
        return error(&request.request_id, "THREAD_NOT_EXPOSED");
    };
    success(
        &request.request_id,
        thread_settings_value(thread_id, &thread, &native_thread, cx),
    )
}

fn update_thread_settings(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    let Some(thread_id) = request.params.get("thread_id").and_then(Value::as_str) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    if request.params.get("instance_id").and_then(Value::as_str) != Some(state.instance_id.as_str())
        || request.params.get("epoch").and_then(Value::as_str) != Some(state.epoch.as_str())
    {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    let Some(parameters) = request.params.as_object() else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    if parameters.keys().any(|key| {
        !matches!(
            key.as_str(),
            "instance_id" | "epoch" | "thread_id" | "profile_id" | "thinking_enabled"
        )
    }) {
        return error(&request.request_id, "INVALID_REQUEST");
    }
    let profile_id = match parameters.get("profile_id") {
        None => None,
        Some(Value::String(profile_id)) if !profile_id.is_empty() && profile_id.len() <= 128 => {
            Some(AgentProfileId(profile_id.as_str().into()))
        }
        _ => return error(&request.request_id, "INVALID_REQUEST"),
    };
    let thinking_enabled = match parameters.get("thinking_enabled") {
        None => None,
        Some(Value::Bool(enabled)) => Some(*enabled),
        _ => return error(&request.request_id, "INVALID_REQUEST"),
    };
    if profile_id.is_none() && thinking_enabled.is_none() {
        return error(&request.request_id, "INVALID_REQUEST");
    }
    let Some((thread, native_thread)) = exposed_native_thread(thread_id, state, cx) else {
        return error(&request.request_id, "THREAD_NOT_EXPOSED");
    };
    if thread.read(cx).status() != ThreadStatus::Idle {
        return error(&request.request_id, "THREAD_BUSY");
    }
    if let Some(profile_id) = profile_id.as_ref()
        && !AgentProfile::available_profiles(cx).contains_key(profile_id)
    {
        return error(&request.request_id, "INVALID_REQUEST");
    }
    if let Some(enabled) = thinking_enabled {
        let native = native_thread.read(cx);
        let Some(model) = native.model() else {
            return error(&request.request_id, "UNSUPPORTED_CAPABILITY");
        };
        if !model.supports_thinking() || (!enabled && !model.supports_disabling_thinking()) {
            return error(&request.request_id, "UNSUPPORTED_CAPABILITY");
        }
    }
    native_thread.update(cx, |thread, cx| {
        if let Some(profile_id) = profile_id {
            thread.set_profile(profile_id, cx);
        }
        if let Some(enabled) = thinking_enabled {
            thread.set_thinking_enabled(enabled, cx);
        }
    });
    success(
        &request.request_id,
        thread_settings_value(thread_id, &thread, &native_thread, cx),
    )
}

fn exposed_native_thread(
    thread_id: &str,
    state: &ProbeState,
    cx: &App,
) -> Option<(Entity<AcpThread>, Entity<agent::Thread>)> {
    if !state.exposed_threads.borrow().contains(thread_id) {
        return None;
    }
    let (thread, view) = loaded_thread_views(&state.project_root, cx)
        .into_iter()
        .find(|(thread, _)| thread.read(cx).session_id().to_string() == thread_id)?;
    let native_thread = view.read(cx).as_native_thread(cx)?;
    Some((thread, native_thread))
}

fn thread_settings_value(
    thread_id: &str,
    thread: &Entity<AcpThread>,
    native_thread: &Entity<agent::Thread>,
    cx: &App,
) -> Value {
    let native = native_thread.read(cx);
    let model = native.model();
    let profiles = AgentProfile::available_profiles(cx)
        .iter()
        .map(|(id, name)| json!({"id": id.as_str(), "name": name.to_string()}))
        .collect::<Vec<_>>();
    json!({
        "thread_id": thread_id,
        "status": format!("{:?}", thread.read(cx).status()),
        "model": model.map(|model| json!({
            "id": model.id().0.to_string(),
            "name": model.name().0.to_string(),
            "provider_id": model.provider_id().0.to_string(),
        })),
        "profile_id": native.profile().as_str(),
        "profiles": profiles,
        "thinking_enabled": native.thinking_enabled(),
        "thinking_supported": model.is_some_and(|model| model.supports_thinking()),
        "thinking_can_disable": model.is_some_and(|model| model.supports_disabling_thinking()),
        "provisional": true,
    })
}

fn send_request(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    let Some(thread_id) = request.params.get("thread_id").and_then(Value::as_str) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    let Some(text) = request.params.get("text").and_then(Value::as_str) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    if text.trim().is_empty() || text.len() > 3000 {
        return error(&request.request_id, "INVALID_REQUEST");
    }
    if request.params.get("instance_id").and_then(Value::as_str) != Some(state.instance_id.as_str())
        || request.params.get("epoch").and_then(Value::as_str) != Some(state.epoch.as_str())
    {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    if !state.exposed_threads.borrow().contains(thread_id) {
        return error(&request.request_id, "THREAD_NOT_EXPOSED");
    }

    let submissions = state.submissions.borrow();
    if let Some(previous) = submissions.get(&request.request_id) {
        if previous.thread_id != thread_id || previous.text != text {
            return error(&request.request_id, "REQUEST_CONFLICT");
        }
        return send_result(&request.request_id, previous.outcome);
    }
    if submissions.len() >= 256 {
        return error(&request.request_id, "RATE_LIMITED");
    }
    drop(submissions);

    let Some((thread, view)) = loaded_thread_views(&state.project_root, cx)
        .into_iter()
        .find(|(thread, _)| thread.read(cx).session_id().to_string() == thread_id)
    else {
        return error(&request.request_id, "THREAD_NOT_EXPOSED");
    };
    let slash_name = text
        .trim_start()
        .strip_prefix('/')
        .map(|rest| rest.split_whitespace().next().unwrap_or(""));
    let native_command = if let Some(name) = slash_name {
        let thread = thread.read(cx);
        let Some(command) = thread
            .available_commands()
            .iter()
            .find(|command| command.name == name)
        else {
            return error(&request.request_id, "UNSUPPORTED_CAPABILITY");
        };
        acp_thread::command_category_from_meta(&command.meta)
            == Some(acp_thread::CommandCategory::Native)
    } else {
        false
    };
    if view.read(cx).is_loading_message_contents() {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }

    let content = vec![acp::ContentBlock::Text(acp::TextContent::new(text))];
    let can_send_now =
        thread.read(cx).status() == ThreadStatus::Idle && !view.read(cx).has_queued_messages();
    let sent = cx.with_window(view.entity_id(), |window, cx| {
        view.update(cx, |view, cx| {
            if can_send_now {
                if native_command {
                    let name = slash_name.unwrap_or("");
                    let remainder = text
                        .trim_start()
                        .strip_prefix('/')
                        .unwrap_or("")
                        .strip_prefix(name)
                        .unwrap_or("")
                        .trim_start();
                    if !remainder.is_empty() {
                        view.add_to_queue(
                            vec![acp::ContentBlock::Text(acp::TextContent::new(remainder))],
                            Vec::new(),
                            window,
                            cx,
                        );
                    }
                    view.send_content(
                        Task::ready(Ok(Some((
                            vec![acp::ContentBlock::Text(acp::TextContent::new(format!(
                                "/{name}"
                            )))],
                            Vec::new(),
                        )))),
                        true,
                        window,
                        cx,
                    );
                } else {
                    view.send_content(
                        Task::ready(Ok(Some((content, Vec::new())))),
                        false,
                        window,
                        cx,
                    );
                }
                "unknown"
            } else {
                view.add_to_queue(content, Vec::new(), window, cx);
                "queued"
            }
        })
    });
    let Some(outcome) = sent else {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    };
    state.submissions.borrow_mut().insert(
        request.request_id.clone(),
        SubmissionRecord {
            thread_id: thread_id.to_string(),
            text: text.to_string(),
            outcome,
        },
    );
    send_result(&request.request_id, outcome)
}

fn send_result(request_id: &str, outcome: &str) -> Value {
    success(request_id, json!({"outcome": outcome, "provisional": true}))
}

fn loaded_threads(project_root: &Path, cx: &App) -> Vec<Entity<AcpThread>> {
    loaded_thread_views(project_root, cx)
        .into_iter()
        .map(|(thread, _)| thread)
        .collect()
}

fn loaded_thread_views(
    project_root: &Path,
    cx: &App,
) -> Vec<(Entity<AcpThread>, Entity<ThreadView>)> {
    let workspaces = workspace::AppState::global(cx)
        .workspace_store
        .read(cx)
        .workspaces()
        .cloned()
        .collect::<Vec<_>>();
    let mut threads = Vec::new();
    for workspace in workspaces {
        let Some(workspace) = workspace.upgrade() else {
            continue;
        };
        let Some(panel) = workspace.read(cx).panel::<AgentPanel>(cx) else {
            continue;
        };
        for conversation in panel.read(cx).conversation_views() {
            let conversation = conversation.read(cx);
            if conversation.as_native_thread(cx).is_none() {
                continue;
            }
            let Some(view) = conversation.root_thread_view() else {
                continue;
            };
            let thread = view.read(cx).thread.clone();
            if thread_belongs_to_project(&thread, project_root, cx) {
                threads.push((thread, view));
            }
        }
    }
    threads
}

fn thread_belongs_to_project(thread: &Entity<AcpThread>, project_root: &Path, cx: &App) -> bool {
    let project = thread.read(cx).project().clone();
    project
        .read(cx)
        .visible_worktrees(cx)
        .any(|worktree| worktree.read(cx).abs_path().as_ref() == project_root)
}

fn success(request_id: &str, result: Value) -> Value {
    json!({"version": 1, "request_id": request_id, "result": result})
}

fn error(request_id: &str, code: &str) -> Value {
    json!({"version": 1, "request_id": request_id, "error": {"code": code}})
}
