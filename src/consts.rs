//! Compile-time settings, limits and the wire contract shared with ircbot.
//! Mirrors hub.h: every `CMD_*` opcode, label and size here must match
//! ircbot/bot.h byte for byte.

pub const HUB_CONFIG_FILE: &str = ".irchub.cnf";
pub const MAX_CLIENTS: usize = 100;
pub const MAX_BOTS: usize = 100;
pub const MAX_PEERS: usize = 10;
pub const MAX_OPT_FLAGS: usize = 32;

/// Network option flag letter: refuse bot-originated mutations of
/// hub-authoritative records (the active set lives in `HubState::opt_flags`).
pub const OPT_HUB_ONLY_MUTATIONS: char = 'h';
/// Set for the duration of a network upgrade window: config mutations
/// (admin commands + bot deltas/pushes) are refused until every node
/// reports success, or the run aborts.
pub const OPT_CONFIG_FROZEN: char = 'F';

pub const MAX_CHAN: usize = 65;
pub const MAX_NICK: usize = 32;
pub const MAX_KEY: usize = 31;
pub const MAX_MASK_LEN: usize = 256;
pub const MAX_PASS: usize = 128;
pub const MAX_BUFFER: usize = 16384;
pub const SALT_SIZE: usize = 16;
pub const GCM_IV_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;
pub const HEADER_SIZE: usize = 4;
pub const MAX_PENDING_BOTS: usize = 10;
pub const MAX_PENDING_OP_REQUESTS: usize = 500;
pub const PBKDF2_ITERATIONS: u32 = 100_000;
/// Passwordless (docs/passwordless.md): a bot advertises this as "v|2" in its
/// CMD_CONFIG_PUSH; until it has, it is sent legacy record shapes with an
/// empty password slot (old bots then fail closed).
pub const BOT_PROTO_PASSWORDLESS: i32 = 2;
pub const KEY_FP_LEN: usize = 19; // "ab12:cd34:ef56:7890"
pub const HUB_PID_FILE: &str = ".irchub.pid";
pub const HUB_PASS_FILE: &str = ".irchub.pass";
pub const HUB_LOG_FILE: &str = ".irchub.log";
pub const HUB_LOG_FILE_SIZE: i64 = 10 * 1024 * 1024;
/// CMD_ADMIN_SET_LOG_SIZE / log_size| bounds (ircbot's L| takes the same).
pub const HUB_LOG_SIZE_MIN: i64 = 1024;
pub const HUB_LOG_SIZE_MAX: i64 = 1024 * 1024 * 1024;

// Curve25519 key constants
pub const ED25519_KEY_LEN: usize = 32;
pub const X25519_KEY_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const COMBINED_KEY_LEN: usize = 64;
pub const COMBINED_KEY_B64: usize = 88;

// Log levels
pub const LOG_NONE: i32 = 0;
pub const LOG_ERROR: i32 = 1;
pub const LOG_WARNING: i32 = 2;
pub const LOG_INFO: i32 = 3;
pub const LOG_DEBUG: i32 = 4;

pub const HUB_DEFAULT_LOG_LEVEL: i32 = LOG_DEBUG;

// Rate limiting
pub const MAX_IP_RATE_LIMITS: usize = 500;
pub const MAX_CONNECTIONS_PER_IP: i32 = 5;
pub const MAX_FAILED_AUTH_ATTEMPTS: i32 = 3;
pub const FAILED_AUTH_BLOCK_DURATION: i64 = 300; // 5 minutes
pub const FAILED_AUTH_RESET_TIME: i64 = 3600; // 1 hour

/// D1 — churn-based (connect/close flood) throttle.  Concurrency and
/// failed-auth limits don't catch a rapid connect/close flood; this sliding
/// window does.
pub const CHURN_WINDOW_SEC: i64 = 10;
pub const CHURN_MAX_CONNS: i32 = 30;
pub const CHURN_BLOCK_SEC: i64 = 30;

/// PURGE loop suppression.  A purge is flooded to every peer and forwarded
/// on, so on a big mesh each hub sees many copies, some of them minutes late
/// when peer queues back up.  An id is random and never reused, so it is
/// remembered long and in quantity: with 5 ids for 60 s, a late copy or one
/// pushed out by newer purges was taken as new, re-applied and re-flooded,
/// and a 10-hub mesh kept a dozen purges circulating for good.  An id-less
/// purge (a hub that predates the id) can only be told apart by time, so it
/// keeps the short window — a longer one would swallow a second, deliberate
/// purge now.
pub const MAX_RECENT_PURGES: usize = 64;
/// The full config push to bots is coalesced: however many updates land in a
/// burst, the bots get one push per this many seconds, with the latest state.
pub const BOT_CONFIG_PUSH_COALESCE: i64 = 1;
pub const PURGE_DEDUP_WINDOW: i64 = 3600;
pub const PURGE_DEDUP_WINDOW_LEGACY: i64 = 60;
pub const PURGE_ID_HEX: usize = 16;

// OP_FORWARD_REQUEST deduplication — prevents packet storms
pub const OP_FORWARD_TTL_SECONDS: i64 = 60;
pub const MAX_SEEN_FORWARD_IDS: usize = 256;

/// Keepalive traffic (CMD_PING and the PONG it draws) is pure noise in the
/// hub log; true = never log it.  Mirrors HIDEPINGPONG in ircbot/bot.h.
pub const HIDEPINGPONG: bool = true;

/// This hub's version, reported in the bots tree beside each hub node.
/// Overridable at build time (`IRCHUB_VERSION=2.1 cargo build --release`) so a
/// release build can stamp its own version without editing the tree.  Mirrors
/// the `#ifndef HUB_VERSION` guard in hub.h.  This is the version reported in
/// the bots tree and the one every upgrade comparison is made against.
pub const HUB_VERSION: &str = match option_env!("IRCHUB_VERSION") {
    Some(v) => v,
    None => "2.4.1",
};

/// Signed-release channel for the hub (irchub-releases).  Same Ed25519 key
/// as ircbot's BOT_UPDATE_PUBKEY_B64: one key signs both repos.  An empty
/// pubkey DISABLES hub updates (fail-closed).  Mirrors hub.h.
///
/// `HUB_UPDATE_BASE` is the tree ROOT; one variant subdirectory below it holds
/// that build's manifest.  Keeping the root separate is what lets a
/// hub-orchestrated upgrade flip a hub between the C and Rust builds:
/// `update::commit` appends the variant it was told to install.
pub const HUB_UPDATE_BASE: &str =
    "https://raw.githubusercontent.com/robertclemens/irchub-releases/main/irchub";
/// The variant THIS build is.  The C hub answers "c".
pub const HUB_UPDATE_VARIANT: &str = "rs";
pub const HUB_UPDATE_URL: &str =
    "https://raw.githubusercontent.com/robertclemens/irchub-releases/main/irchub/rs/releases.txt";
pub const HUB_UPDATE_SIG_URL: &str =
    "https://raw.githubusercontent.com/robertclemens/irchub-releases/main/irchub/rs/releases.sig";
pub const HUB_UPDATE_PUBKEY_B64: &str = "qkXMh/F8TC+cnKuIwrP5TJIynfrLBD+MDUwvkyh9lBU=";
/// Hand-off note written just before an upgrade execs the new binary: the
/// restarted process reads the upgrade id from here and answers
/// CMD_UPGRADE_RESULT.
pub const HUB_UPGRADE_MARKER_FILE: &str = ".irchub.upgrade";
/// Retained previous binary/config, kept (not deleted) after an upgrade so
/// CMD_UPGRADE_ABORT can put this hub back.
pub const HUB_UPGRADE_PREV_SUFFIX: &str = ".prev";
/// The generated installer, written 0700 and exec'd once the old process has
/// let go of its pid lock.
pub const HUB_UPGRADE_SCRIPT: &str = "hub_upgrade.sh";
/// Ceilings on what the updater will pull down.
pub const HUB_UPDATE_MAX_MANIFEST: u64 = 1024 * 1024;
pub const HUB_UPDATE_MAX_ARCHIVE: u64 = 256 * 1024 * 1024;
pub const HUB_UPDATE_FETCH_TIMEOUT: u64 = 300;

// Timeouts (seconds)
pub const PING_INTERVAL: i64 = 60;
pub const CLIENT_TIMEOUT: i64 = 180;
pub const CONNECT_TIMEOUT: u64 = 5;

/// D4 — pre-authentication handshake timeout.
pub const PREAUTH_TIMEOUT_SEC: i64 = 10;
/// D4b — extended pre-auth grace for interactive admin logins.
pub const PREAUTH_ADMIN_TIMEOUT_SEC: i64 = 120;

/// D2 — two-tier client buffers: unauthenticated clients get a small buffer,
/// grown to the per-type bulk size on successful auth.
pub const PREAUTH_BUF_SIZE: usize = 4096;
pub const PEER_RECONNECT_INTERVAL: i64 = 120;

// ---- Protocol commands (must match ircbot/bot.h) ---------------------------
pub const CMD_PING: u8 = 0x01;
pub const CMD_CONFIG_PUSH: u8 = 0x02;
pub const CMD_CONFIG_PULL: u8 = 0x03;
pub const CMD_CONFIG_DATA: u8 = 0x04;
pub const CMD_UPDATE_PUBKEY: u8 = 0x05;
pub const CMD_PEER_SYNC: u8 = 0x06;
pub const CMD_MESH_STATE: u8 = 0x07;
pub const CMD_SYNC_REQUEST: u8 = 0x08;
pub const CMD_INVITE_REQUEST: u8 = 0x09;

pub const CMD_ADMIN_AUTH: u8 = 0x10;
pub const CMD_ADMIN_LIST_FULL: u8 = 0x11;
pub const CMD_ADMIN_ADD: u8 = 0x12;
pub const CMD_ADMIN_DEL: u8 = 0x13;
pub const CMD_ADMIN_REGEN_KEYS: u8 = 0x14;
pub const CMD_ADMIN_LIST_SUMMARY: u8 = 0x15;
pub const CMD_ADMIN_GET_PENDING: u8 = 0x16;
pub const CMD_ADMIN_APPROVE: u8 = 0x17;
pub const CMD_ADMIN_ADD_PEER: u8 = 0x18;
pub const CMD_ADMIN_LIST_PEERS: u8 = 0x19;
pub const CMD_ADMIN_DEL_PEER: u8 = 0x1A;
pub const CMD_ADMIN_GET_PUBKEY: u8 = 0x1B;
pub const CMD_ADMIN_SET_PRIVKEY: u8 = 0x1C;
pub const CMD_ADMIN_GET_PRIVKEY: u8 = 0x1D;
pub const CMD_ADMIN_SET_PUBKEY: u8 = 0x1E;
pub const CMD_ADMIN_SYNC_MESH: u8 = 0x1F;
pub const CMD_ADMIN_CREATE_BOT: u8 = 0x32; // 50 decimal
pub const CMD_ADMIN_REKEY_BOT: u8 = 0x20;
pub const CMD_ADMIN_DISCONNECT_BOT: u8 = 0x21;
pub const CMD_ADMIN_BOT_STATUS: u8 = 0x22;
pub const CMD_BOT_KEY_UPDATE: u8 = 0x40;

// Global config management
pub const CMD_ADMIN_LIST_CHANNELS: u8 = 0x23;
pub const CMD_ADMIN_ADD_CHANNEL: u8 = 0x24;
pub const CMD_ADMIN_DEL_CHANNEL: u8 = 0x25;
pub const CMD_ADMIN_LIST_MASKS: u8 = 0x26;
pub const CMD_ADMIN_ADD_MASK: u8 = 0x27;
pub const CMD_ADMIN_DEL_MASK: u8 = 0x2B;
pub const CMD_ADMIN_LIST_OPERS: u8 = 0x2C;
pub const CMD_ADMIN_ADD_OPER: u8 = 0x2D;
pub const CMD_ADMIN_DEL_OPER: u8 = 0x2E;
/// 0x2F and 0x30 are retired — passwordless.  Kept as names so the hub can
/// answer "retired"; never reuse the values.
pub const CMD_ADMIN_SET_ADMIN_PASS: u8 = 0x2F; // RETIRED
pub const CMD_ADMIN_SET_BOT_PASS: u8 = 0x30; // RETIRED
pub const CMD_ADMIN_OP_USER: u8 = 0x31;

// Bot-to-bot op commands (via hub)
pub const CMD_OP_REQUEST: u8 = 0x28;
pub const CMD_OP_GRANT: u8 = 0x29;
pub const CMD_OP_FAILED: u8 = 0x2A;
pub const CMD_OP_FORWARD_REQUEST: u8 = 0x33;
pub const CMD_OP_FORWARD_GRANT: u8 = 0x34;
pub const CMD_OP_FORWARD_FAILED: u8 = 0x35;
pub const CMD_PEER_REKEY_BOT: u8 = 0x42;
pub const CMD_BOT_RELAY: u8 = 0x50;
pub const CMD_BOT_MSG: u8 = 0x51;

// Tombstone purge
pub const CMD_ADMIN_PURGE_TOMBSTONES: u8 = 0x36;
pub const CMD_ADMIN_SET_PURGE_DAYS: u8 = 0x41;

// Bind IP and IP access control
pub const CMD_ADMIN_SET_BIND_IP: u8 = 0x37;
pub const CMD_ADMIN_LIST_ALLOWLIST: u8 = 0x38;
pub const CMD_ADMIN_ADD_ALLOWLIST: u8 = 0x39;
pub const CMD_ADMIN_DEL_ALLOWLIST: u8 = 0x3A;
pub const CMD_ADMIN_LIST_DENYLIST: u8 = 0x3B;
pub const CMD_ADMIN_ADD_DENYLIST: u8 = 0x3C;
pub const CMD_ADMIN_DEL_DENYLIST: u8 = 0x3D;
pub const CMD_ADMIN_SET_HUB_NAME: u8 = 0x3E;
pub const CMD_ADMIN_SET_BIND_PORT: u8 = 0x3F;
pub const CMD_ADMIN_SET_LOG_LEVEL: u8 = 0x43;
pub const CMD_ADMIN_SET_LOG_SIZE: u8 = 0x44;
pub const CMD_BOT_DELTA: u8 = 0x45;

// Named admin/oper/usermask commands (v2)
pub const CMD_ADMIN_ADD_ADMIN: u8 = 0x46;
pub const CMD_ADMIN_DEL_ADMIN: u8 = 0x47;
pub const CMD_ADMIN_ADD_OPER_RECORD: u8 = 0x48;
pub const CMD_ADMIN_DEL_OPER_RECORD: u8 = 0x49;
pub const CMD_ADMIN_ADD_USERMASK: u8 = 0x4A;
pub const CMD_ADMIN_DEL_USERMASK: u8 = 0x4B;
pub const CMD_ADMIN_SET_USERPASS: u8 = 0x4C; // RETIRED
pub const CMD_ADMIN_MATCH: u8 = 0x4D;
pub const CMD_ADMIN_LIST_ADMINS: u8 = 0x4E;
pub const CMD_ADMIN_LIST_OPERS_V2: u8 = 0x4F;
pub const CMD_ADMIN_SET_PEER_PUBKEY: u8 = 0x52;
pub const CMD_ADMIN_SET_OPT_FLAGS: u8 = 0x53;
pub const CMD_ADMIN_GET_OPT_FLAGS: u8 = 0x54;
pub const CMD_ADMIN_SET_USERKEY: u8 = 0x55;

/// ---- Bot presence (the 'bots' tree) ---------------------------------------
/// Deliberately OUTSIDE the config store.  Version / IRC server / uptime are
/// volatile runtime facts: parking them in the LWW config would persist them
/// to disk, replicate them with tombstones, drag them through the purge
/// policy and leave a dead hub's bots reading "online, uptime 40d" forever.
/// They also do not belong in the per-bot ingest whitelist {t,n,h,pub,seen,d}
/// -- that bound is what makes the payload ceilings below provable.
///
/// So presence rides its own gossip: every hub reports the bots currently
/// connected to IT, peers hold that in memory only, and an entry nobody has
/// refreshed within BOT_ROSTER_TTL is simply dropped.
pub const CMD_BOT_PRESENCE: u8 = 0x56;
pub const CMD_BOT_ROSTER: u8 = 0x57;
pub const CMD_BOT_TREE: u8 = 0x58;

/// ---- Channel-access requests (unban / invite / key) -----------------------
/// A bot locked out of a managed channel (474 banned, 473 invite-only, 475
/// bad key) asks the mesh to let it back in.  The requesting bot supplies only
/// `kind|channel`; the hub fills in the requester's nick and hostmask from its
/// own `n`/`h` records for that authenticated UUID.  Mirrors ircbot/bot.h.
pub const CMD_CHAN_REQUEST: u8 = 0x59;
pub const CMD_CHAN_ACTION: u8 = 0x5A;
pub const CMD_CHAN_REPLY: u8 = 0x5B;
pub const CMD_CHAN_FWD_REQUEST: u8 = 0x5C;
pub const CMD_CHAN_FWD_REPLY: u8 = 0x5D;

// Network-wide upgrade coordination (mirrors irchub/hub.h).
pub const CMD_UPGRADE_PREPARE: u8 = 0x5E;
pub const CMD_UPGRADE_READY: u8 = 0x5F;
pub const CMD_UPGRADE_COMMIT: u8 = 0x60;
pub const CMD_UPGRADE_RESULT: u8 = 0x61;
pub const CMD_UPGRADE_ABORT: u8 = 0x62;
pub const CMD_ADMIN_UPGRADE_NET: u8 = 0x63;
pub const CMD_ADMIN_UPGRADE_STATUS: u8 = 0x64;

/// Sealed bot-to-bot relay across hubs (mirrors irchub/hub.h).  A
/// CMD_BOT_RELAY whose target is not connected here is stamped with a request
/// id and flooded to the peers; each delivers it as CMD_BOT_MSG to its own bot
/// or passes it on minus the link it came in on.  Loop-suppressed by the
/// shared seen-forwards ring; the target bot still checks the sealed payload
/// against the sender's key, so a peer cannot forge a command.  Hub <-> hub
/// only.  Payload: `id|origin_ts|sender_uuid|target_uuid|<sealed frame>`.
pub const CMD_BOT_RELAY_FWD: u8 = 0x65;
/// Seconds a forwarded relay stays deliverable.
pub const BOT_RELAY_FWD_TTL: i64 = 30;

/// Drop the roll-up plan mesh-wide (mirrors irchub/hub.h).  Every hub that
/// followed a run keeps that run's plan in its own .irchub.cnf and walks any
/// bot that comes back behind it up to the target; an admin's
/// CMD_ADMIN_UPGRADE_STATUS "forget" drops it on the hub it is logged into
/// and floods this frame so every other hub drops its copy too.
/// Loop-suppressed by the seen-forwards ring, refused while the config
/// freeze (a run in flight) is up.  Hub <-> hub only.  Payload: `id|origin_ts`.
pub const CMD_UPGRADE_FORGET: u8 = 0x66;
/// Seconds a forwarded forget stays valid.
pub const UPGRADE_FORGET_TTL: i64 = 60;

/// A config broadcast (mirrors irchub/hub.h): the payload of CMD_PEER_SYNC,
/// sent by a hub to EVERY peer it is linked to (minus the one it forwards
/// for).  The receiver may rely on that when it forwards what it accepted: a
/// peer the sender is linked to right now already has the frame first hand,
/// so the forwarder skips it (the split horizon in `mesh`).  Point-to-point
/// syncs (the reply to CMD_SYNC_REQUEST, the sync a new link opens with) stay
/// CMD_PEER_SYNC.  Sent only to a peer whose roster gossip carries l| lines;
/// an older peer gets CMD_PEER_SYNC as before.
pub const CMD_PEER_BCAST: u8 = 0x67;

/// Admin -> Hub: this hub's traffic counters since it started (read-only,
/// empty payload).  Reply lines, zero rows left out:
///   stats|up=<s>
///   cfg|sent=<n>|same=<n>|lost=<n>        full config pushes to bots
///   sync|frames=<n>|noop=<n>|records=<n>|applied=<n>   PEER_SYNC/BCAST in
///   op|0x<cc>|rx=<frames>/<bytes>|tx=<frames>/<bytes>
/// "same" = a push skipped because that bot was already sent the identical
/// config; "lost" = a queued push dropped on overflow (that bot is re-sent
/// the next one in full).  rx counts every authenticated frame this hub
/// decrypted, tx every frame it sent from its outbound queues (the ping/pong
/// keepalive and direct admin/bot replies are not queued and not counted).
pub const CMD_ADMIN_STATS: u8 = 0x68;
/// After a peer link drops, ask the remaining peers for a full sync this many
/// seconds later: a forwarder may have skipped us on the strength of that
/// link in the moment before the drop reached its gossip.
pub const SYNC_RESYNC_AFTER_LINK_LOSS: i64 = 5;

pub const MAX_PENDING_CHAN_REQUESTS: usize = 200;
pub const CHAN_REQUEST_TIMEOUT: i64 = 45;

// ---- Network upgrade run (CMD_UPGRADE_*, CMD_ADMIN_UPGRADE_NET) -----------
// One run at a time per hub: the whole point is that exactly one plan drives
// the mesh while the config is frozen.
/// Every client, plus this hub.
pub const MAX_UPGRADE_NODES: usize = MAX_CLIENTS + 1;
/// Downstream routes a follower remembers for a run it is only relaying: one
/// per node it forwarded an answer for.  See `state::UpgradeRoute`.
pub const MAX_UPGRADE_ROUTES: usize = MAX_UPGRADE_NODES;

// ---- Offline roll-up (upgrade plan, Task 7) -------------------------------
// A node that was down, or homed elsewhere, when a run went through comes back
// on the old build.  The hub brings it up to the last completed run's target
// by itself, ONE node at a time and WITHOUT freezing the config: a single late
// bot is not a reason to hold the whole network's config still.  Bounded on
// purpose — a node that keeps failing must not be re-committed on every
// reconnect.
/// Attempts per node, per hub lifetime.
pub const ROLLUP_MAX_TRIES: i32 = 3;
/// Seconds between attempts on one node.
pub const ROLLUP_COOLDOWN: i64 = 900;
/// Seconds after a run completes before late nodes are chased.
pub const ROLLUP_SETTLE: i64 = 20;
/// Give up on one attempt after this many seconds.
pub const ROLLUP_TIMEOUT: i64 = 300;
/// Nodes remembered in the attempt ledger.
pub const MAX_ROLLUP_TRIES: usize = 64;
/// Stop waiting for READY acks.
pub const UPGRADE_PREPARE_TIMEOUT: i64 = 45;
/// PREPARE also stays open this long after the node table last grew: a hub
/// several hops out is unknown to the driver until its first READY arrives.
pub const UPGRADE_PREPARE_SETTLE: i64 = 3;
/// A committed node must be back, upgraded, by now.
pub const UPGRADE_COMMIT_TIMEOUT: i64 = 420;
/// Bots go in waves so a channel never loses every bot at once.
pub const UPGRADE_BOT_WAVE_MAX: usize = 4;
/// Never commit more than 1/N of the bots at once.
pub const UPGRADE_BOT_WAVE_DIVISOR: usize = 4;
/// How long a CMD_UPGRADE_PREPARE this hub acknowledged stays commitable.  A
/// driver that stalls mid-roll has to ask again rather than commit against a
/// stale plan.
pub const UPGRADE_PREPARE_TTL: i64 = 900;

pub const MESH_ANTI_ENTROPY_INTERVAL: i64 = 300;
pub const MAX_BOT_ENTRIES: usize = 64;

pub const MAX_HUB_USER_RECORDS: usize = 40;
pub const MAX_HUB_USER_MASKS: usize = 200;

// ---- Bulk-payload ceilings (Change 5) --------------------------------------
// Hard upper bounds on generated config / sync payloads, derived entirely
// from the record-count constants above so they auto-track whatever an
// operator sets.  These bound the *allocation cap*, not the bytes actually
// sent (payloads carry only real records at real sizes).
//
// They are true hard bounds because ingest is bounded: per-bot state is
// restricted to the whitelist {t,n,h,pub,seen,d} with per-key value caps in
// storage::update_entry, so a bot has at most BOT_SYNC_FIELDS entries whose
// lines never approach value[1024].  Keep this shared contract identical with
// ircbot/bot.h (MAX_CONFIG_PAYLOAD).
pub const BOT_SYNC_FIELDS: usize = 8;
pub const GLOBAL_LINE_MAX: usize = 1088;
pub const BOT_FIELD_LINE: usize = 320;
pub const USER_LINE_MAX: usize = 384;
pub const MASK_LINE_MAX: usize = 352;
pub const BLINE_MAX: usize = 448;
pub const PEER_LINE_MAX: usize = 256;
pub const PAYLOAD_SLACK: usize = 8192;

/// Bot config payload (`storage::generate_bot_payload`): globals + users +
/// masks + this bot's own fields + one b| line per other bot.
pub const MAX_CONFIG_PAYLOAD: usize = MAX_BOT_ENTRIES * GLOBAL_LINE_MAX
    + MAX_HUB_USER_RECORDS * USER_LINE_MAX
    + MAX_HUB_USER_MASKS * MASK_LINE_MAX
    + BOT_SYNC_FIELDS * BOT_FIELD_LINE
    + MAX_BOTS * BLINE_MAX
    + PAYLOAD_SLACK;

/// Hub<->hub full-state sync (`mesh::generate_sync_packet`): globals + users +
/// masks + every bot's fields + peer/opt lines.
pub const MAX_SYNC_PAYLOAD: usize = MAX_BOT_ENTRIES * GLOBAL_LINE_MAX
    + MAX_HUB_USER_RECORDS * USER_LINE_MAX
    + MAX_HUB_USER_MASKS * MASK_LINE_MAX
    + MAX_BOTS * BOT_SYNC_FIELDS * BOT_FIELD_LINE
    + MAX_PEERS * PEER_LINE_MAX
    + PAYLOAD_SLACK;

/// `config::write()` buffer: every serialized section at its bound, with the
/// per-bot term scaled by the bots actually present.  A config that does not
/// fit is NOT written (the old file is kept) — never a truncated one.
/// The persisted roll-up plan (see `PendingRollup`): `rollup|` + target,
/// variant, kind, min_from, hub_target, plan_set and both 512-byte bases.
pub const ROLLUP_LINE_MAX: usize = 1536;
pub const HUB_CONFIG_FIXED_MAX: usize = 8192
    + ROLLUP_LINE_MAX
    + MAX_BOT_ENTRIES * GLOBAL_LINE_MAX
    + MAX_HUB_USER_RECORDS * USER_LINE_MAX
    + MAX_HUB_USER_MASKS * MASK_LINE_MAX
    + 2 * MAX_IP_ACL_ENTRIES * IP_ACL_LINE_MAX
    + MAX_PEERS * 512;
pub const HUB_CONFIG_PER_BOT_MAX: usize = MAX_BOT_ENTRIES * 1100;

/// Largest bulk lane payload — buffers on the config/sync paths size to this.
pub const MAX_BULK_PAYLOAD: usize = if MAX_CONFIG_PAYLOAD > MAX_SYNC_PAYLOAD {
    MAX_CONFIG_PAYLOAD
} else {
    MAX_SYNC_PAYLOAD
};

// ---- Bot-presence gossip sizing (the 'bots' tree) --------------------------
// Same macro-derived discipline as the ceilings above: every bound below
// follows from MAX_BOTS / MAX_PEERS, so raising either retracks the buffers
// automatically.  None of this touches the config store.
pub const BOT_PRESENCE_INTERVAL: i64 = 60;
pub const BOT_TREE_REFRESH: i64 = 300;
pub const BOT_ROSTER_TTL: i64 = 240;
pub const ROSTER_VERSION_MAX: usize = 15;
/// Code base: "c" / "rs".
pub const ROSTER_VARIANT_MAX: usize = 7;
pub const ROSTER_SERVER_MAX: usize = 63;
pub const ROSTER_FRAME_BUDGET: usize = 8192;
pub const TREE_ROW_MAX: usize = 256;
/// One entry per (reporting hub, bot).  A hub only ever reports bots
/// connected to itself, so the mesh-wide worst case is every hub carrying
/// MAX_BOTS.
pub const MAX_BOT_ROSTER: usize = (MAX_PEERS + 1) * MAX_BOTS;
/// Tree rows: every hub node, every bot beneath one, plus the disconnected
/// tail (bounded by the bots the config knows about).
/// Hubs the tree can know mesh-wide, direct peers or not.  Each hub's roster
/// gossip is relayed hop by hop (see CMD_BOT_ROSTER), so a chain or a star
/// still draws every hub; this bounds the per-origin relay bookkeeping.
pub const MAX_MESH_HUBS: usize = 64;
/// Hops a relayed roster frame may still travel when its origin sends it.
pub const ROSTER_RELAY_HOPS: i32 = 16;
/// Hub rows are hung no deeper than this; the bots render up to depth 32.
pub const MAX_TREE_DEPTH: i32 = 30;
/// A forwarder trusts a sender's reported links (for the sync split horizon)
/// only while the report is this fresh: past one missed gossip round it
/// forwards to everyone, as a hub that never reported links is.
pub const SYNC_SPLIT_HORIZON_FRESH: i64 = 2 * BOT_PRESENCE_INTERVAL + 10;
pub const MAX_TREE_ROWS: usize = MAX_MESH_HUBS + MAX_PEERS + 1 + MAX_BOT_ROSTER + MAX_BOTS;
pub const MAX_TREE_PAYLOAD: usize = MAX_TREE_ROWS * TREE_ROW_MAX + PAYLOAD_SLACK;

// ---- Mesh transport tuning (see docs/mesh.md) ------------------------------
pub const LANE_COUNT: usize = 3;
pub const MAX_QUEUE_PER_LANE: usize = 256;
/// Must hold one full bulk payload plus concurrent small-lane traffic
/// (deltas, op grants) on a connection.  Enforced cap, not a reservation, so
/// a large value costs nothing until actually queued.
pub const MAX_QUEUED_BYTES_PER_PEER: usize = 3 * MAX_BULK_PAYLOAD;

/// Change 5 guard: a single bulk payload must fit within a connection's queue
/// byte budget, else a full config/sync could never be enqueued.  Const-eval
/// so a future change that breaks the relationship fails the build rather
/// than silently dropping payloads at runtime.
const _: () = assert!(
    MAX_QUEUED_BYTES_PER_PEER >= MAX_BULK_PAYLOAD,
    "per-peer queue budget must hold at least one bulk payload"
);

pub const MAX_DELTA_SEEN: usize = 8192;
pub const BULK_SOFT_BUDGET_BPS: i64 = 32 * 1024;
pub const DELTA_HARD_BUDGET_BPS: i64 = 64 * 1024;
pub const BOT_DELTA_RATE_LIMIT: i64 = 10;
pub const BOT_DELTA_RATE_WINDOW: i64 = 30;

// ---- IP allow/deny list entries --------------------------------------------
pub const MAX_IP_ACL_ENTRIES: usize = 64;
pub const IP_ACL_PATTERN_MAX: usize = 19; // "255.255.255.255/32" + NUL
pub const IP_ACL_LINE_MAX: usize = 48; // w|<pattern>|<ts>\n

pub const CONFIG_WRITE_DEBOUNCE_S: i64 = 5;
