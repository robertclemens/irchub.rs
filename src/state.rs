//! The hub's state (hub_state_t and the records it holds), the per-client
//! connection struct with its outbound lanes, and the small inline rules from
//! hub.h (LWW acceptance, name validation, strict integer parsing).
//!
//! Where the C code used fixed arrays with a companion count, this uses a
//! `Vec` bounded by the same constant: the caps are enforced at every insert
//! exactly as the C `< MAX_*` guards did, and the sizing argument behind the
//! bulk-payload ceilings in `consts` is unchanged.  The ring buffers
//! (`recent_purges`, `seen_forwards`, `pending`) keep their ring indices.
//!
//! `HubClient::fd` is the raw descriptor number, kept only as an identity
//! token: peers record `fd` to say which connection they are on, forwarded
//! requests carry an `origin_fd` to route a reply home, and broadcasts
//! exclude one.  It is never used to do I/O — that goes through the owned
//! `TcpStream` — so the number is as safe to hold as an index, and reusing
//! the C semantics keeps the routing identical.

use std::collections::VecDeque;
use std::fs::File;
use std::net::{TcpListener, TcpStream};

use zeroize::Zeroizing;

use crate::consts::*;
use crate::crypto::Key32;
use crate::cstr::now;
use crate::secret::Locked;

// ---------------------------------------------------------------------------
// Small shared rules (the static inline block of hub.h)
// ---------------------------------------------------------------------------

/// Timestamp for changing an EXISTING replicated record: now, but always past
/// its previous stamp.  Peers and bots accept only a strictly newer
/// timestamp, so an add and a remove in the same second would tie and the
/// remove would never replicate (a removed admin staying active elsewhere).
pub fn lww_next_ts(prev: i64) -> i64 {
    let n = now();
    if n > prev { n } else { prev + 1 }
}

/// LWW acceptance for a replicated add/del record: a strictly newer stamp
/// wins, and on an exact tie a delete beats an add.  `lww_next_ts` only
/// separates writes made on ONE node; two nodes stamping the same second (a
/// bot's part reaching one hub while another hub still holds the add) tie,
/// and with a plain "newer wins" each side keeps its own copy and refuses the
/// other's forever.  Delete-over-add is deterministic, so every node
/// converges.  Mirrored in ircbot (lww_accepts) — the rule must match on both.
pub fn lww_accepts(in_ts: i64, in_active: bool, cur_ts: i64, cur_active: bool) -> bool {
    in_ts > cur_ts || (in_ts == cur_ts && cur_active && !in_active)
}

/// LWW acceptance for the network opt flags (one value, no add/del).  Newer
/// stamp wins; on a tie the byte-wise greater flag string wins, so every node
/// picks the same side -- and a set ("h") beats a clear (""), the stricter
/// policy.  Mirrored in ircbot (opt_accepts).
pub fn opt_accepts(in_ts: i64, in_flags: &str, cur_ts: i64, cur_flags: &str) -> bool {
    in_ts > cur_ts || (in_ts == cur_ts && in_flags > cur_flags)
}

/// Whether a stored c/m/o global value ("...|add" / "...|del") is live: its
/// op is the last '|' field.
pub fn global_value_active(value: &str) -> bool {
    match value.rfind('|') {
        Some(i) => &value[i + 1..] != "del",
        None => true,
    }
}

/// A hub friendly name: 1-63 bytes of [A-Za-z0-9._-].  The name travels
/// inside '|'-separated config lines and handshakes, ':'/','-separated mesh
/// gossip and the ':'-separated ADD_PEER payload, so any other byte could
/// forge a field or a whole record ("x|203.0.113.77|0" after a newline).
pub fn name_valid(name: &str) -> bool {
    let b = name.as_bytes();
    // strnlen(name, 64): a longer name is refused, not truncated.
    if b.is_empty() || b.len() > 63 {
        return false;
    }
    b.iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-')
}

/// Strict unsigned decimal for admin numeric fields (indices, days, ports):
/// 1-10 ASCII digits, nothing else -- no sign, space, suffix or empty string
/// -- and value <= max.  atoi() read "7d" as 7, "c3cd..." as 0 and "" as 0;
/// in DEL_PEER a UUID starting with digits deleted the peer at that index,
/// and in PURGE_TOMBSTONES a typo meant "purge every tombstone now".
pub fn parse_uint(s: &str, max: u64) -> Option<u64> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 10 {
        return None;
    }
    let mut v: u64 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        let d = u64::from(c - b'0');
        if v > (max - d) / 10 {
            return None; // v*10 + d would pass max
        }
        v = v * 10 + d;
    }
    Some(v)
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct ConfigEntry {
    pub key: String,
    pub value: String,
    pub timestamp: i64,
}

/// An admin ('a') or oper ('o') record.
#[derive(Clone, Debug, Default)]
pub struct UserRecord {
    pub uuid: String,
    pub name: String,
    /// Per-user Curve25519 combined pubkey (Ed25519 + X25519), base64-encoded
    /// — the user's only credential: hub_admin logins and bot ~A2 commands
    /// verify against it.  Empty (`has_pubkey` false) for a legacy record not
    /// yet given a key; such a user can authenticate nowhere.  The matching
    /// private key lives only on the user's machine.
    pub pubkey_b64: String,
    pub has_pubkey: bool,
    pub typ: char,
    pub is_active: bool,
    pub last_seen: i64,
    pub timestamp: i64,
}

#[derive(Clone, Debug, Default)]
pub struct MaskRecord {
    pub uuid: String,
    pub mask: String,
    pub is_active: bool,
    /// 0 = never used.
    pub last_used: i64,
    pub timestamp: i64,
}

#[derive(Clone, Debug, Default)]
pub struct BotConfig {
    pub uuid: String,
    pub entries: Vec<ConfigEntry>,
    pub is_active: bool,
    pub last_sync_time: i64,
}

impl BotConfig {
    /// Value of one stored key, or None.
    pub fn entry(&self, key: &str) -> Option<&ConfigEntry> {
        self.entries.iter().find(|e| e.key == key)
    }
}

#[derive(Clone, Debug, Default)]
pub struct PendingBot {
    pub uuid: String,
    pub nick: String,
    pub ip: String,
    pub last_attempt: i64,
}

#[derive(Clone, Debug, Default)]
pub struct PendingOpRequest {
    pub request_id: String,
    pub requester_uuid: String,
    pub target_uuid: String,
    pub channel: String,
    /// FD to send the response back to (-1 if a local bot).
    pub origin_fd: i32,
    pub timestamp: i64,
    pub active: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PendingChanRequest {
    pub request_id: String,
    /// Bot that is locked out.
    pub requester_uuid: String,
    /// "unban" | "invite" | "key"
    pub kind: String,
    pub channel: String,
    /// Peer fd the request came from, -1 if a local bot.
    pub origin_fd: i32,
    pub timestamp: i64,
    pub active: bool,
}

#[derive(Clone, Debug, Default)]
pub struct IpRateLimit {
    pub ip: String,
    pub active_connections: i32,
    pub failed_auth_count: i32,
    pub last_failed_auth: i64,
    /// Temporary block expiration (0 if not blocked).
    pub blocked_until: i64,
    /// For cleanup of old entries.
    pub first_seen: i64,
    /// D1: start of the current connect-rate window.
    pub churn_window_start: i64,
    /// D1: new connections counted in the current window.
    pub churn_count: i32,
}

/// IP allow/deny list entry (hub_admin 0x38-0x3D).  The lists are local to
/// this hub: never replicated to peers, never pushed to bots; config lines
/// `w|<pattern>|<ts>` (allow) and `x|<pattern>|<ts>` (deny).  IPv4 only (the
/// hub listens on AF_INET).  `pattern` is canonical: a bare address, or
/// network/N with the host bits cleared; net/mask are its parsed form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpAcl {
    pub pattern: [u8; IP_ACL_PATTERN_MAX],
    pub pattern_len: usize,
    /// Host byte order.
    pub net: u32,
    /// Host byte order.
    pub mask: u32,
    pub added: i64,
}

impl IpAcl {
    pub fn pattern(&self) -> &str {
        std::str::from_utf8(&self.pattern[..self.pattern_len]).unwrap_or("")
    }

    pub fn set_pattern(&mut self, s: &str) -> bool {
        let b = s.as_bytes();
        if b.len() >= IP_ACL_PATTERN_MAX {
            return false;
        }
        self.pattern = [0; IP_ACL_PATTERN_MAX];
        self.pattern[..b.len()].copy_from_slice(b);
        self.pattern_len = b.len();
        true
    }

    /// Same network and prefix — how add refuses a duplicate and remove finds
    /// its target.
    pub fn same_net(&self, other: &IpAcl) -> bool {
        self.net == other.net && self.mask == other.mask
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpAclAdd {
    Added,
    Duplicate,
    Full,
    BadList,
}

#[derive(Clone, Debug)]
pub struct PeerConfig {
    /// Configured/advertised IP.
    pub ip: String,
    pub port: i32,
    /// Remote peer's UUID.
    pub uuid: String,
    pub friendly_name: String,
    /// Actual connection IP (from the socket).
    pub remote_ip: String,
    pub connected: bool,
    pub fd: i32,
    pub remote_connected_count: i32,
    pub remote_total_peers: i32,
    pub last_mesh_report: i64,
    /// What the remote hub reported in its CMD_BOT_ROSTER header.  Volatile
    /// and never serialized: these only feed the bots tree's uptime/version
    /// columns.
    pub remote_started: i64,
    pub remote_version: String,
    /// Its code base ("c" / "rs"), from the roster's v| line; empty until a
    /// hub that sends one reports in.
    pub remote_variant: String,
    pub last_gossip: String,
    /// Peer auth (HUBv3): per-peer Curve25519 public keys.  `has_pubkey` is
    /// required — a peer without one is refused (there is no shared secret).
    pub ed_pub: [u8; ED25519_KEY_LEN],
    pub x25519_pub: [u8; X25519_KEY_LEN],
    pub has_pubkey: bool,
}

impl Default for PeerConfig {
    fn default() -> Self {
        PeerConfig {
            ip: String::new(),
            port: 0,
            uuid: String::new(),
            friendly_name: String::new(),
            remote_ip: String::new(),
            connected: false,
            fd: -1,
            remote_connected_count: 0,
            remote_total_peers: 0,
            last_mesh_report: 0,
            remote_started: 0,
            remote_version: String::new(),
            remote_variant: String::new(),
            last_gossip: String::new(),
            ed_pub: [0; ED25519_KEY_LEN],
            x25519_pub: [0; X25519_KEY_LEN],
            has_pubkey: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Network upgrade orchestration
// ---------------------------------------------------------------------------

/// Where one node stands in a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum UpgradeNodeState {
    /// PREPARE sent, no answer yet.
    #[default]
    Pending,
    /// Answered ready; waiting for its turn.
    Ready,
    /// Answered not-ready (`reason` says why).
    Unable,
    /// COMMIT sent; waiting for the restart.
    Committed,
    /// Back on the target version.
    Done,
    /// Said fail, or never came back in time.
    Failed,
}

impl UpgradeNodeState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Unable => "unable",
            Self::Committed => "committing",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }
}

/// Which kind of node a row describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum UpgradeNodeKind {
    #[default]
    Bot,
    PeerHub,
    /// This hub, which upgrades last.
    SelfHub,
}

impl UpgradeNodeKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Bot => "bot",
            Self::PeerHub => "hub",
            Self::SelfHub => "self",
        }
    }
}

/// The plan a completed run left behind, and the one node being walked up to
/// it right now.  The plan is persisted in this hub's own `.irchub.cnf` (a
/// `rollup|` line, hub-local and never replicated — its base may be a test
/// hook's file:// URL) so a restart does not forget what the network is
/// supposed to be running; the attempt in flight and the retry ledger stay
/// volatile.  The roll-up is a convenience, never the record of what the
/// network runs (that is each node's own presence), and it only ever chases a
/// target some other bot is demonstrably running (`rollup_target_proven`).
#[derive(Clone, Debug, Default)]
pub struct PendingRollup {
    pub have_plan: bool,
    pub target: String,
    pub variant: String,
    pub kind: String,
    pub min_from: String,
    pub base: String,
    /// The run's hub target, "" = hubs were not moved.
    pub hub_target: String,
    pub hub_base: String,
    pub plan_set: i64,

    /// The attempt in flight, if any.
    pub active: bool,
    /// Its own run id, distinct from any real run.
    pub id: String,
    /// The node being rolled up.
    pub uuid: String,
    pub node_kind: UpgradeNodeKind,
    /// The version THIS attempt installs.
    pub step: String,
    pub started: i64,
    pub committed: bool,
}

#[derive(Clone, Debug, Default)]
pub struct RollupTry {
    pub uuid: String,
    pub last_try: i64,
    pub tries: i32,
}

/// One downstream node a FOLLOWER relays for.  A run reaches every hub in the
/// mesh, whatever shape it is wired in: each follower re-broadcasts PREPARE to
/// its own peers and forwards the answers back toward the driver, so a node
/// several hops away is still a node of the run.  COMMIT and ABORT travel the
/// same path in reverse, hop by hop, and this is the hop: "the peer I heard
/// `uuid` from is where a frame for `uuid` goes next".
#[derive(Clone, Debug, Default)]
pub struct UpgradeRoute {
    /// The node the driver is addressing.
    pub uuid: String,
    /// Hub uuid of the peer it was learned from (the next hop).
    pub via: String,
}

#[derive(Clone, Debug, Default)]
pub struct UpgradeNode {
    /// Bot uuid, or a peer hub's OWN hub uuid.
    pub uuid: String,
    /// Display label: a peer hub is known to the mesh by its friendly name,
    /// while every upgrade frame it sends is keyed by its uuid, so the table
    /// is keyed by uuid and prints this.  Empty for a bot.
    pub name: String,
    pub kind: UpgradeNodeKind,
    /// Peer hub a remote bot is reached through, else empty.
    pub via: String,
    /// The connection it was reached on, -1 once gone.
    pub fd: i32,
    pub cur_version: String,
    /// "c" / "rs".
    pub variant: String,
    pub arch: String,
    pub libc: String,
    pub state: UpgradeNodeState,
    pub reason: String,
    pub committed_at: i64,
    /// A hub node's READY says how many of ITS local bots it relayed PREPARE
    /// to; the driver holds PREPARE open until that many relayed READYs are
    /// in, so a peer's bots are never missed for answering a moment after it.
    pub relayed: usize,
    /// Order its READY reached the driver in (1, 2, ...; 0 = none yet).  A
    /// follower answers before it relays anything from below it, and every
    /// answer travels the same FIFO peer links up, so a hub's READY always
    /// lands ahead of any hub it routes for: descending `ready_seq` is
    /// deepest-first along the COMMIT routes (see `upgrade::tick`).
    pub ready_seq: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum UpgradePhase {
    #[default]
    Idle,
    /// PREPARE fanned out, collecting READY/UNABLE.
    Prepare,
    /// Committing nodes wave by wave.
    Rolling,
    Done,
    Failed,
    Aborted,
}

impl UpgradePhase {
    pub fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Prepare => "preparing",
            Self::Rolling => "rolling",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Aborted => "aborted",
        }
    }
}

/// `pending_upgrade_t`: the network upgrade this hub is driving, if any.
///
/// Modeled on [`PendingOpRequest`]: a run carries its own id, routes its
/// status back down `origin_fd`, and every node it touches gets a row.
/// Volatile on purpose — a hub that restarts mid-run has no business
/// resuming someone else's plan; it comes back with the freeze flag still set
/// in the replicated opt record, and an admin clears it explicitly.
#[derive(Clone, Debug, Default)]
pub struct PendingUpgrade {
    pub active: bool,
    /// `opflow::generate_request_id()`.
    pub id: String,
    pub target_ver: String,
    /// "" = keep each node's own variant.
    pub variant: String,
    /// "" = let each node pick bin/src.
    pub kind: String,
    /// "*" = any.
    pub min_from: String,
    /// Release base override, "" = compiled-in.
    pub base: String,
    /// The hubs' own target.  ircbot and irchub are separate products with
    /// separate version lines and separate release trees, so a hub node is
    /// never checked against `target_ver`/`base` — those are the bots'.  An
    /// empty `hub_ver` leaves every hub on the build it runs.
    pub hub_ver: String,
    /// irchub-releases override, "" = compiled-in.
    pub hub_base: String,
    /// Admin connection that started it, or -1.
    pub origin_fd: i32,
    pub started: i64,
    pub phase_started: i64,
    pub phase: UpgradePhase,
    pub nodes: Vec<UpgradeNode>,
    /// When the node table last grew.
    pub last_added: i64,
    /// Last `UpgradeNode::ready_seq` handed out.
    pub ready_seq_next: usize,
    /// Why it ended, shown by CMD_ADMIN_UPGRADE_STATUS.
    pub summary: String,
}

/// Track recently processed PURGE messages to prevent feedback loops.
#[derive(Clone, Debug, Default)]
pub struct RecentPurge {
    pub cutoff: i64,
    /// The origin's purge id ("" from pre-id hubs).
    pub id: String,
    pub received_at: i64,
}

/// Track recently seen OP_FORWARD_REQUEST ids to prevent packet storms.
#[derive(Clone, Debug, Default)]
pub struct SeenForward {
    pub request_id: String,
    pub seen_at: i64,
}

/// One peer link a hub reports in its roster gossip (an l| line): a peer it is
/// configured with and whether that link is up right now.
#[derive(Clone, Debug, Default)]
pub struct MeshLink {
    pub uuid: String,
    pub name: String,
    pub online: bool,
}

/// What this hub knows about another hub anywhere in the mesh, from that
/// hub's own roster gossip — direct or relayed.  Volatile like the roster:
/// dropped once nothing refreshed it within BOT_ROSTER_TTL.  `round` and
/// `chunks_seen` suppress relay loops: a hub applies and passes on a given
/// frame (origin, generation, chunk) exactly once.
#[derive(Clone, Debug, Default)]
pub struct MeshHub {
    pub uuid: String,
    pub name: String,
    pub started: i64,
    pub version: String,
    pub variant: String,
    pub links: Vec<MeshLink>,
    /// It has sent an l| list (a hub that relays).
    pub have_links: bool,
    /// Newest gossip generation (round) seen from it.
    pub round: i64,
    /// Chunks of `gen` already applied (bit n).
    pub chunks_seen: u64,
    /// Local clock: drives the TTL.
    pub reported_at: i64,
}

/// One bot's live presence, as reported by the hub it is connected to.
/// Purely in-memory: never written to the config, never tombstoned, never
/// purged.  An entry whose `reported_at` falls behind BOT_ROSTER_TTL is
/// dropped, so a bot that disconnects — or a whole hub that dies — ages out
/// on its own.
#[derive(Clone, Debug, Default)]
pub struct BotRoster {
    /// Hub that reported this bot.
    pub hub_uuid: String,
    /// Its friendly name, for display.
    pub hub_name: String,
    pub bot_uuid: String,
    pub nick: String,
    pub version: String,
    /// Code base: "c" / "rs" / "".
    pub variant: String,
    /// The bot's IRC link.
    pub server: String,
    /// bot -> hub, for uptime.
    pub connected_at: i64,
    /// Local clock: drives the TTL.
    pub reported_at: i64,
}

/// Loop-prevention seen-set: highest lamport_seq observed per (origin, bot).
#[derive(Clone, Debug, Default)]
pub struct DeltaSeen {
    pub origin_hub_uuid: String,
    pub bot_uuid: String,
    pub max_seq_seen: u64,
    pub last_seen_at: i64,
}

// ---------------------------------------------------------------------------
// Mesh transport: per-peer outbound queue
// ---------------------------------------------------------------------------

/// Lane indices (lower = higher priority).  `Urgent` must be 0 so the drain
/// loop can rely on numeric ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Lane {
    /// CMD_OP_REQUEST/GRANT/FAILED, CMD_OP_FORWARD_*
    Urgent = 0,
    /// Small per-key deltas (b|uuid|h|...), global add/del
    Delta = 1,
    /// CMD_PEER_SYNC, CMD_MESH_STATE, CMD_CONFIG_DATA
    Bulk = 2,
}

impl Lane {
    pub fn index(self) -> usize {
        self as usize
    }

    pub fn name(self) -> &'static str {
        match self {
            Lane::Urgent => "URGENT",
            Lane::Delta => "DELTA",
            Lane::Bulk => "BULK",
        }
    }
}

/// Queued outbound message — pre-encryption.  The payload is zeroized on
/// drop: it can carry hostmask and op-flow material.
pub struct QueuedMsg {
    /// Protocol opcode (CMD_*).
    pub cmd: u8,
    pub lane: Lane,
    /// Coalesce key: typically "<origin_hub_uuid>|<key>|<bot_uuid>".  Empty
    /// means "never coalesce".
    pub coalesce_key: String,
    /// Monotonic per origin_hub_uuid.
    pub lamport_seq: u64,
    pub origin_hub_uuid: String,
    pub payload: Zeroizing<Vec<u8>>,
}

impl QueuedMsg {
    /// queued_msg_new(): None when the payload exceeds the bulk ceiling.
    pub fn new(cmd: u8, lane: Lane, payload: &[u8]) -> Option<QueuedMsg> {
        if payload.len() > MAX_BULK_PAYLOAD {
            return None;
        }
        Some(QueuedMsg {
            cmd,
            lane,
            coalesce_key: String::new(),
            lamport_seq: 0,
            origin_hub_uuid: String::new(),
            payload: Zeroizing::new(payload.to_vec()),
        })
    }

    /// queued_msg_set_coalesce().
    pub fn set_coalesce(&mut self, origin_hub_uuid: &str, lamport_seq: u64, coalesce_key: &str) {
        self.origin_hub_uuid = origin_hub_uuid.to_string();
        self.lamport_seq = lamport_seq;
        self.coalesce_key = coalesce_key.to_string();
    }

    pub fn len(&self) -> usize {
        self.payload.len()
    }

    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

#[derive(Default)]
pub struct QueueLane {
    pub msgs: VecDeque<QueuedMsg>,
    /// Sum of payload lengths in this lane.
    pub bytes: usize,
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ClientType {
    /// calloc() left client_type_t at 0 — a fresh connection is a bot until
    /// its handshake says otherwise, and the pre-auth reaper relies on it.
    #[default]
    Bot,
    Admin,
    Hub,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BotAuthState {
    #[default]
    Idle,
    UuidReceived,
    ChallengeSent,
    SignatureReceived,
    Complete,
}

pub struct HubClient {
    /// The connection.  `None` once the socket is closed.
    pub sock: Option<TcpStream>,
    /// Identity token only — see the module comment.  -1 once closed.
    pub fd: i32,
    pub ip: String,
    pub id: String,
    pub session_key: Key32,
    pub authenticated: bool,
    pub typ: ClientType,
    pub last_seen: i64,
    pub last_pong_sent: i64,
    /// D4: when the socket was accepted/created.
    pub connected_at: i64,
    /// Accepted on the listener (subject to the IP lists).
    pub inbound: bool,
    /// D4b: sent ADMIN-HELLO → longer pre-auth grace.
    pub admin_hello_seen: bool,
    /// Admin login v2: the one-time challenge handed out in HUB-PUBKEY2.  Set
    /// on ADMIN-HELLO, consumed (wiped) by the first ADMIN2 attempt either
    /// way.
    pub admin_nonce: [u8; 32],
    pub admin_nonce_set: bool,
    /// Protocol version this bot connection advertised ("v|N" in its config
    /// push): 0 = not known yet, 1 = its push carried no v| (a
    /// pre-passwordless build), >= 2 = advertised.  Per connection on
    /// purpose: a downgraded binary reconnecting is never mistaken for a
    /// passwordless one.
    pub bot_proto: i32,
    /// D2: PREAUTH_BUF_SIZE, then the per-type bulk size on auth.  `len()` is
    /// the C `recv_len`.
    pub recv_buf: Vec<u8>,
    pub recv_cap: usize,
    pub bot_auth_state: BotAuthState,
    pub challenge: [u8; 32],
    pub bot_eph_x25519_priv: Key32,
    pub bot_eph_x25519_pub: [u8; 32],
    pub bot_eph_priv_set: bool,
    /// IP that hub_admin used to connect.
    pub admin_connect_ip: String,
    /// Port that hub_admin used to connect.
    pub admin_connect_port: i32,

    // ---- Outbound queue (per-lane FIFOs, drained on POLLOUT) ----
    pub out_lanes: [QueueLane; LANE_COUNT],
    pub out_total_bytes: usize,

    /// In-flight cipher buffer for partial writes.  While `writing_offset <
    /// writing_buf.len()` the FD must be watched for writability, before any
    /// new message is encrypted.
    pub writing_buf: Zeroizing<Vec<u8>>,
    pub writing_cap: usize,
    pub writing_offset: usize,

    /// Per-peer/client byte-rate accounting (1-second window).
    pub bw_window_start: i64,
    pub bw_bytes_in_window: i64,

    /// Presence this bot reported via CMD_BOT_PRESENCE.  Per connection, and
    /// volatile on purpose: a bot that reconnects re-reports, and a bot that
    /// never reports simply shows blank fields in the tree.  Never persisted.
    pub bot_version: String,
    pub bot_server: String,
    /// "c" / "rs", empty = unreported.
    pub bot_variant: String,
    /// The bot's own start time, 0 = unreported.
    pub bot_started: i64,
    /// SHA-256 of the last full config queued to this bot (CMD_CONFIG_DATA),
    /// so a broadcast push that would repeat it is skipped.  Only set while
    /// that push is known to be on its way: cleared when a queued config is
    /// dropped on overflow and whenever the bot sends a config push of its
    /// own.
    pub cfg_sent_hash: Option<[u8; 32]>,
}

impl HubClient {
    /// calloc(1, sizeof(hub_client_t)) + hub_client_alloc_buffers(size).
    pub fn new(sock: TcpStream, fd: i32, ip: &str, size: usize) -> HubClient {
        let t = now();
        HubClient {
            sock: Some(sock),
            fd,
            ip: ip.to_string(),
            id: String::new(),
            session_key: Zeroizing::new([0u8; 32]),
            authenticated: false,
            typ: ClientType::Bot,
            last_seen: t,
            last_pong_sent: 0,
            connected_at: t,
            inbound: false,
            admin_hello_seen: false,
            admin_nonce: [0; 32],
            admin_nonce_set: false,
            bot_proto: 0,
            recv_buf: Vec::with_capacity(size.min(PREAUTH_BUF_SIZE)),
            recv_cap: size,
            bot_auth_state: BotAuthState::Idle,
            challenge: [0; 32],
            bot_eph_x25519_priv: Zeroizing::new([0u8; 32]),
            bot_eph_x25519_pub: [0; 32],
            bot_eph_priv_set: false,
            admin_connect_ip: String::new(),
            admin_connect_port: 0,
            out_lanes: Default::default(),
            out_total_bytes: 0,
            writing_buf: Zeroizing::new(Vec::new()),
            writing_cap: size + 64,
            writing_offset: 0,
            bw_window_start: 0,
            bw_bytes_in_window: 0,
            bot_version: String::new(),
            bot_server: String::new(),
            bot_variant: String::new(),
            bot_started: 0,
            cfg_sent_hash: None,
        }
    }

    /// D2: grow a client's buffers on successful authentication.  Idempotent.
    ///
    /// Change 5: size by client type so bulk lanes never truncate.  Peers
    /// exchange full-state anti-entropy sync both directions
    /// (MAX_SYNC_PAYLOAD); a bot receives its full config on the hub->bot
    /// (writing) side (MAX_CONFIG_PAYLOAD) but only ever pushes small
    /// config/deltas up (recv stays MAX_BUFFER).  Must be called after
    /// `typ` is set.
    pub fn promote_buffers(&mut self) {
        let (recv_target, write_target) = match self.typ {
            ClientType::Hub => (MAX_SYNC_PAYLOAD, MAX_SYNC_PAYLOAD),
            // bot->hub pushes are small; hub->bot carries the full config.
            ClientType::Bot => (MAX_BUFFER, MAX_CONFIG_PAYLOAD),
            ClientType::Admin => (MAX_BUFFER, MAX_BUFFER),
        };
        if self.recv_cap < recv_target {
            self.recv_cap = recv_target;
        }
        if self.writing_cap < write_target + 64 {
            self.writing_cap = write_target + 64;
        }
    }

    /// peer_has_pending_writes(): a partial in-flight write, or any non-empty
    /// lane.  The main loop uses it to decide whether to watch for POLLOUT.
    pub fn has_pending_writes(&self) -> bool {
        self.writing_offset < self.writing_buf.len()
            || self.out_lanes.iter().any(|l| !l.msgs.is_empty())
    }

    /// hub_client_has_buffered_frame(): recv_buf already holds a whole frame
    /// (or a length prefix the pump will refuse).  `handle_client_data` takes
    /// at most 8 frames per call for fairness; the main loop must come back
    /// for the rest without waiting for new bytes, or they sit unread until
    /// the sender's next packet.
    pub fn has_buffered_frame(&self) -> bool {
        if self.fd <= 0 || self.recv_buf.len() < 4 {
            return false;
        }
        let packet_len = u32::from_be_bytes([
            self.recv_buf[0],
            self.recv_buf[1],
            self.recv_buf[2],
            self.recv_buf[3],
        ]) as i64;
        // An out-of-range prefix counts: the pump refuses it and drops the
        // client rather than leaving it parked on a length that can never
        // complete.
        if packet_len < 0 || packet_len > (self.recv_cap as i64 - 4) {
            return true;
        }
        self.recv_buf.len() as i64 >= 4 + packet_len
    }

    /// peer_queue_destroy(): free all queued messages and wipe any
    /// partially-written ciphertext.
    pub fn queue_destroy(&mut self) {
        for l in &mut self.out_lanes {
            l.msgs.clear();
            l.bytes = 0;
        }
        self.out_total_bytes = 0;
        self.writing_buf.clear();
        self.writing_offset = 0;
    }
}

// ---------------------------------------------------------------------------
// Hub state
// ---------------------------------------------------------------------------

/// The function-local `static time_t` timers of hub_maintenance() and
/// hub_check_peers(), made explicit.
#[derive(Debug, Default)]
pub struct MaintTimers {
    pub last_anti_entropy: i64,
    pub last_mesh_gossip: i64,
    pub last_client_scan: i64,
    pub last_ip_cleanup: i64,
    pub last_purge: i64,
    pub last_status_dump: i64,
    pub last_peer_check: i64,
}

pub struct HubState {
    pub listener: Option<TcpListener>,
    pub port: i32,
    /// IP this hub advertises itself as in the mesh.
    pub bind_ip: String,
    pub hub_uuid: String,
    /// `realpath(argv[0])` — the binary an upgrade replaces, and the one
    /// `<exe>.prev` sits beside.  Empty when it could not be resolved, which
    /// disables self-upgrade rather than guessing.
    pub executable_path: String,
    pub hub_friendly_name: String,
    /// The plaintext AES-GCM config-file password, held for the lifetime of
    /// the process (needed on every config write) in an mlock'd buffer.  See
    /// the threat model in `secret`.
    pub config_pass: Locked<MAX_PASS>,

    pub hub_ed25519_priv: Locked<32>,
    pub hub_x25519_priv: Locked<32>,
    pub hub_ed25519_pub: [u8; 32],
    pub hub_x25519_pub: [u8; 32],
    pub hub_keys_loaded: bool,

    pub clients: Vec<HubClient>,
    pub bots: Vec<BotConfig>,

    /// GLOBAL CONFIG STORE (shared by all bots).
    pub global_entries: Vec<ConfigEntry>,

    /// Named admin/oper records and their usermasks.
    pub user_records: Vec<UserRecord>,
    pub mask_records: Vec<MaskRecord>,

    pub peers: Vec<PeerConfig>,

    pub pending: Vec<PendingBot>,
    pub pending_head: usize,

    pub pending_op_requests: Vec<PendingOpRequest>,
    pub pending_chan_requests: Vec<PendingChanRequest>,

    /// The network upgrade this hub is driving, if any (one at a time).
    pub upgrade: PendingUpgrade,

    /// The upgrade this hub has agreed to take from ANOTHER hub, if any.  The
    /// mesh is flat, so a hub is a follower and a driver at the same time and
    /// the two must not share state: `upgrade` above is the run this hub
    /// drives, these are a run someone else drives.  CMD_UPGRADE_COMMIT
    /// carries only the id and the version, so the release base the driver
    /// named at PREPARE time is remembered here.  Volatile — the upgrade
    /// itself hands over through HUB_UPGRADE_MARKER_FILE.
    pub follow_id: String,
    /// uuid of the hub driving the followed run.
    pub follow_origin: String,
    /// The bots' target (relayed COMMITs).
    pub follow_target: String,
    /// This hub's own target, "" = stay put.
    pub follow_hub_target: String,
    pub follow_variant: String,
    /// irchub-releases base for this hub.
    pub follow_hub_base: String,
    /// Whether this hub itself can take the followed run.
    pub follow_self_ready: bool,
    pub follow_prepared: i64,
    /// Nodes below this hub in the followed run's fan-out tree (its own
    /// peers' subtrees).  Rebuilt for every run; see [`UpgradeRoute`].
    pub follow_routes: Vec<UpgradeRoute>,
    /// Offline roll-up; see [`PendingRollup`].
    pub rollup: PendingRollup,
    pub rollup_tries: Vec<RollupTry>,

    pub ip_limits: Vec<IpRateLimit>,

    /// IP allow/deny lists (local only).  `ip_acl_changed` makes
    /// `maintenance` close inbound connections the lists no longer permit.
    pub ip_allow: Vec<IpAcl>,
    pub ip_deny: Vec<IpAcl>,
    pub ip_acl_changed: bool,

    /// Days threshold for the tombstone purge (0 = disabled).
    pub purge_days_setting: i32,
    /// D3: if true, 127.0.0.1/::1 bypass rate limiting (default false —
    /// secure by default).
    pub trust_loopback: bool,
    /// Held for its flock, which is what says "this hub is running".
    pub pid_file: Option<File>,
    pub running: bool,

    /// PURGE deduplication: prevent feedback loops in the peer mesh.
    pub recent_purges: Vec<RecentPurge>,
    /// Timestamp of the last scheduled purge this hub initiated.
    pub last_scheduled_purge: i64,

    /// OP_FORWARD_REQUEST deduplication: an LRU ring of MAX_SEEN_FORWARD_IDS
    /// slots prevents infinite re-broadcast storms.
    pub seen_forwards: Vec<SeenForward>,
    /// Next slot to write (ring index).
    pub seen_forward_head: usize,

    pub log_level: i32,
    pub log_max_size: i64,

    /// Network options pushed to bots/peers via the 'opt|' record.  Each
    /// letter is an enabled flag (see OPT_* in `consts`).
    pub opt_flags: String,
    pub opt_flags_ts: i64,

    /// Debounced config write: set the dirty flag instead of writing
    /// immediately.  `maintenance` flushes at most once every
    /// CONFIG_WRITE_DEBOUNCE_S seconds.  This prevents N PBKDF2(100k) calls
    /// when N peer syncs arrive in a burst.
    pub config_dirty: bool,
    /// A full config push to every local bot is owed
    /// (`client::flush_bot_config`, at most once per BOT_CONFIG_PUSH_COALESCE).
    pub bot_config_pending: bool,
    pub last_bot_config_push: i64,
    pub last_config_write: i64,
    /// Set on peer connect/disconnect; clears after gossip.
    pub mesh_state_dirty: bool,
    /// Set to force anti-entropy on the next maintenance tick.
    pub anti_entropy_due: bool,

    /// Mesh transport: monotonic Lamport sequence stamped onto outgoing
    /// deltas.  On load from disk this is bumped past any plausibly recent
    /// value to keep monotonicity even if the system clock or the stored
    /// value lags.
    pub next_lamport_seq: u64,

    /// Loop prevention: deltas already observed per (origin_hub_uuid,
    /// bot_uuid).  LRU-evicted past MAX_DELTA_SEEN.
    pub delta_seen: Vec<DeltaSeen>,

    // ---- Bot presence (volatile; never serialized) ----
    pub roster: Vec<BotRoster>,
    /// This hub's own uptime base.
    pub hub_started: i64,
    pub last_presence_gossip: i64,
    pub last_tree_push: i64,
    /// Roster changed: push to bots on the next tick.
    pub tree_dirty: bool,
    /// Every hub heard from, any hop (see `MeshHub`).
    pub mesh_hubs: Vec<MeshHub>,
    /// Last generation this hub gossiped.
    pub roster_gen: i64,
    /// Peers linked at the last gossip (bit p).
    pub gossip_link_mask: u32,
    /// Ask peers for a sync then (0 = none).
    pub resync_due_at: i64,

    pub timers: MaintTimers,
}

impl Default for HubState {
    fn default() -> Self {
        HubState::new()
    }
}

impl HubState {
    pub fn new() -> HubState {
        HubState {
            listener: None,
            port: 0,
            bind_ip: String::new(),
            hub_uuid: String::new(),
            executable_path: String::new(),
            hub_friendly_name: String::new(),
            config_pass: Locked::new(),
            hub_ed25519_priv: Locked::new(),
            hub_x25519_priv: Locked::new(),
            hub_ed25519_pub: [0; 32],
            hub_x25519_pub: [0; 32],
            hub_keys_loaded: false,
            clients: Vec::new(),
            bots: Vec::new(),
            global_entries: Vec::new(),
            user_records: Vec::new(),
            mask_records: Vec::new(),
            peers: Vec::new(),
            pending: Vec::new(),
            pending_head: 0,
            pending_op_requests: vec![PendingOpRequest::default(); MAX_PENDING_OP_REQUESTS],
            pending_chan_requests: vec![PendingChanRequest::default(); MAX_PENDING_CHAN_REQUESTS],
            upgrade: PendingUpgrade::default(),
            follow_id: String::new(),
            follow_origin: String::new(),
            follow_target: String::new(),
            follow_variant: String::new(),
            follow_hub_target: String::new(),
            follow_hub_base: String::new(),
            follow_self_ready: false,
            follow_prepared: 0,
            follow_routes: Vec::new(),
            rollup: PendingRollup::default(),
            rollup_tries: Vec::new(),
            ip_limits: Vec::new(),
            ip_allow: Vec::new(),
            ip_deny: Vec::new(),
            ip_acl_changed: false,
            purge_days_setting: 0,
            trust_loopback: false,
            pid_file: None,
            running: true,
            recent_purges: Vec::new(),
            last_scheduled_purge: 0,
            seen_forwards: vec![SeenForward::default(); MAX_SEEN_FORWARD_IDS],
            seen_forward_head: 0,
            log_level: HUB_DEFAULT_LOG_LEVEL,
            log_max_size: HUB_LOG_FILE_SIZE,
            opt_flags: String::new(),
            opt_flags_ts: 0,
            config_dirty: false,
            bot_config_pending: false,
            last_bot_config_push: 0,
            last_config_write: 0,
            mesh_state_dirty: false,
            anti_entropy_due: false,
            next_lamport_seq: 0,
            delta_seen: Vec::new(),
            roster: Vec::new(),
            hub_started: 0,
            last_presence_gossip: 0,
            last_tree_push: 0,
            tree_dirty: false,
            mesh_hubs: Vec::new(),
            roster_gen: 0,
            gossip_link_mask: 0,
            resync_due_at: 0,
            timers: MaintTimers::default(),
        }
    }

    /// hub_set_config_pass().
    pub fn set_config_pass(&mut self, pass: &str) {
        self.config_pass.set_str(pass);
    }

    /// hub_get_config_pass().
    pub fn get_config_pass(&self) -> Zeroizing<String> {
        self.config_pass.get_str()
    }

    /// The combined 64-byte private key (ed_priv || x_priv).
    pub fn hub_priv_combined(&self) -> Zeroizing<[u8; COMBINED_KEY_LEN]> {
        let mut out = Zeroizing::new([0u8; COMBINED_KEY_LEN]);
        out[..32].copy_from_slice(self.hub_ed25519_priv.get());
        out[32..].copy_from_slice(self.hub_x25519_priv.get());
        out
    }

    /// The combined 64-byte public key (ed_pub || x_pub).
    pub fn hub_pub_combined(&self) -> [u8; COMBINED_KEY_LEN] {
        let mut out = [0u8; COMBINED_KEY_LEN];
        out[..32].copy_from_slice(&self.hub_ed25519_pub);
        out[32..].copy_from_slice(&self.hub_x25519_pub);
        out
    }

    /// Split a combined private key into the two locked halves.
    pub fn set_hub_priv(&mut self, combined: &[u8; COMBINED_KEY_LEN]) {
        let mut ed = [0u8; 32];
        let mut x = [0u8; 32];
        ed.copy_from_slice(&combined[..32]);
        x.copy_from_slice(&combined[32..]);
        self.hub_ed25519_priv.set(&ed);
        self.hub_x25519_priv.set(&x);
        crate::crypto::wipe(&mut ed);
        crate::crypto::wipe(&mut x);
    }

    pub fn set_hub_pub(&mut self, combined: &[u8; COMBINED_KEY_LEN]) {
        self.hub_ed25519_pub.copy_from_slice(&combined[..32]);
        self.hub_x25519_pub.copy_from_slice(&combined[32..]);
    }

    /// hub_next_lamport_seq(): bump-then-return, so the first issued seq is
    /// 1, not 0.
    pub fn next_lamport_seq(&mut self) -> u64 {
        self.next_lamport_seq = self.next_lamport_seq.wrapping_add(1);
        self.next_lamport_seq
    }

    /// Index of the client on `fd`, or None.
    pub fn client_by_fd(&self, fd: i32) -> Option<usize> {
        if fd < 0 {
            return None;
        }
        self.clients.iter().position(|c| c.fd == fd)
    }

    /// Index of the authenticated bot with this UUID, or None.
    pub fn bot_client(&self, uuid: &str) -> Option<usize> {
        self.clients
            .iter()
            .position(|c| c.typ == ClientType::Bot && c.authenticated && c.id == uuid)
    }

    /// Indices of every authenticated peer hub.
    pub fn peer_clients(&self) -> Vec<usize> {
        self.clients
            .iter()
            .enumerate()
            .filter(|(_, c)| c.typ == ClientType::Hub && c.authenticated)
            .map(|(i, _)| i)
            .collect()
    }

    /// Indices of every authenticated bot.
    pub fn bot_clients(&self) -> Vec<usize> {
        self.clients
            .iter()
            .enumerate()
            .filter(|(_, c)| c.typ == ClientType::Bot && c.authenticated)
            .map(|(i, _)| i)
            .collect()
    }

    /// Look up one `key` of a stored bot record (e.g. "h" hostmask, "n"
    /// nick).  None when the bot or the key is unknown or the value is empty.
    pub fn bot_entry(&self, uuid: &str, key: &str) -> Option<&str> {
        let b = self.bots.iter().find(|b| b.uuid == uuid)?;
        let e = b.entry(key)?;
        if e.value.is_empty() {
            None
        } else {
            Some(e.value.as_str())
        }
    }

    /// Whether the network opt flag is set.
    pub fn opt(&self, flag: char) -> bool {
        self.opt_flags.contains(flag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lww_tie_prefers_delete() {
        assert!(lww_accepts(10, true, 5, true));
        assert!(!lww_accepts(5, true, 10, true));
        // Same second: a delete beats a live record, an add does not.
        assert!(lww_accepts(10, false, 10, true));
        assert!(!lww_accepts(10, true, 10, false));
        assert!(!lww_accepts(10, true, 10, true));
    }

    #[test]
    fn opt_tie_prefers_greater_string() {
        assert!(opt_accepts(10, "", 5, "h"));
        // A set beats a clear on a tie, the stricter policy.
        assert!(opt_accepts(10, "h", 10, ""));
        assert!(!opt_accepts(10, "", 10, "h"));
    }

    #[test]
    fn lww_next_ts_never_ties() {
        let n = now();
        assert!(lww_next_ts(n + 500) > n + 500);
        assert_eq!(lww_next_ts(0), n);
    }

    #[test]
    fn global_value_active_reads_last_field() {
        assert!(global_value_active("#chan|key|0|add"));
        assert!(!global_value_active("#chan|key|0|del"));
        assert!(global_value_active("bare"));
    }

    #[test]
    fn names_and_uints_are_strict() {
        assert!(name_valid("hub-1.eu_west"));
        assert!(!name_valid(""));
        assert!(!name_valid("has space"));
        assert!(!name_valid("pipe|name"));
        assert!(!name_valid(&"x".repeat(64)));
        assert_eq!(parse_uint("7000", 65535), Some(7000));
        assert_eq!(parse_uint("7d", 65535), None);
        assert_eq!(parse_uint("", 65535), None);
        assert_eq!(parse_uint("-3", 65535), None);
        assert_eq!(parse_uint("70000", 65535), None);
        assert_eq!(parse_uint("12345678901", 99), None);
    }
}
