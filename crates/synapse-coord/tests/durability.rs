//! Durability boundaries of the board and the coordination store (review findings B6, B7,
//! B8 of aien-dev/aien-sovereign-core-mv#928):
//!
//! - B6: a refused recovery leaves `journal.log` and `journal.idx` byte for byte as they
//!   were, so a retry refuses again instead of cutting acknowledged events as a torn tail
//!   (same boot, after a reboot, and with a partly written final table entry).
//! - B7: a failed directory sync never yields a durable-success result (post receipt,
//!   compaction report, cursor ack, coordination record), and the next writer flushes a
//!   created-but-unsynced root entry again before it acknowledges; `EINVAL` (a file system
//!   that cannot sync directories) is the one tolerated answer.
//! - B8: a cursor directory that cannot be listed refuses compaction; nothing is dropped.
//!
//! Round 11 review findings of the same pull request:
//!
//! - R4: a reboot rebuild refuses (twice, bytes unchanged) when `journal.idx` proves a
//!   frame committed that the journal no longer verifies: a partly written final entry
//!   over a corrupt frame, and a journal that ends on a frame boundary before a committed
//!   frame (also the same-boot partial-entry case).
//! - R5: an "already applied" retry (an ack at or below the cursor, a repeated
//!   subscription, a compaction whose cursors were already expired) syncs its directory
//!   again and fails while that sync still fails; compaction never publishes over cursor
//!   state it could not flush.
//! - R6: `dirsync.pending` is reconciled by every durable mutator, not only journal
//!   writers: a registration or a first read retried while the root sync still fails is an
//!   error; after the repair it succeeds and the marker is gone.
//!
//! Round 12 review findings of the same pull request:
//!
//! - N3: an empty or missing `journal.log` under a `journal.idx` that names committed
//!   events is refused (twice, both files unchanged, no id reused), same boot and after a
//!   reboot; a generation-mismatch rebuild must reach the table's last committed id. A
//!   compaction cut between its renames still recovers (controls).
//! - N4: a first delivery retried while its cursor's directory sync still fails is an
//!   error; after the repair it succeeds, and a delivery with nothing pending needs no
//!   directory sync.
//! - N5: a root sync that succeeded earlier never clears the `dirsync.pending` of a later
//!   publication whose own sync failed (a deterministic two-process interleaving through
//!   the `pause-after-root-sync` barrier), plus a serial retry control.
//!
//! Round 14 review findings of the same pull request (a lookup or listing whose error was
//! read as absence), driven by the `stat-eio:<name>`, `readdir-eio:<name>` and
//! `readdirent-eio:<name>` fault points of `SYNAPSE_COORD_FAULT`:
//!
//! - B1: `init` on an existing board of an old boot whose `journal.log` lookup fails is an
//!   error with `boot` unchanged, so the next read of the new boot still rebuilds a lost
//!   inbox entry (fresh-board and existing-board controls).
//! - B2: a coordination-store discriminator (`dirs`, `STORE_ID`) that cannot be looked up
//!   is an error, never a board: no `BOARD_ID` is created.
//! - The audit: a lost journal whose lookups fail creates no journal; the reboot rebuild,
//!   the torn-tail index cleanup, the compaction trim and `check` refuse (or report) an
//!   index directory they cannot list; an unlistable `agents/` is no second tag; an
//!   unlistable coordination `dirs/` keeps an agent's presence and locks; an unanswerable
//!   target lookup refuses the key instead of keying the file differently.
//!
//! Permission-based cases make a directory unreadable (mode 0300: entries can still be
//! created, renamed and opened by name, but the directory cannot be opened or listed). The
//! superuser bypasses that, so those cases print `NOT_RUN` and return when run as uid 0.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use synapse_coord::board::{Board, BoardError, Kind, Post, Resume, Sub};
use synapse_coord::json::{self, J};
use synapse_coord::{ClaimOutcome, CoordError, CoordStore, Holder, Workspace};

const BIN: &str = env!("CARGO_BIN_EXE_synapse-coord");
static N: AtomicU32 = AtomicU32::new(0);

struct Fx {
    root: PathBuf,
}
impl Drop for Fx {
    fn drop(&mut self) {
        // Restore every mode a test changed so the tree can be removed.
        for d in [
            self.root.clone(),
            self.root.join("cursors"),
            self.root.join("subs"),
            self.root.join("store/crumb/v1/dirs"),
        ] {
            let _ = fs::set_permissions(&d, fs::Permissions::from_mode(0o755));
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn scratch(name: &str) -> Fx {
    let root = std::env::temp_dir().join(format!(
        "sb-dur-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&root);
    Fx { root }
}

fn fx(name: &str) -> (Fx, Board) {
    let f = scratch(name);
    let b = Board::init(&f.root).unwrap();
    (f, b)
}

/// True (after printing NOT_RUN) when permission bits do not bind this process.
fn is_superuser(name: &str, probe: &Path) -> bool {
    if fs::metadata(probe).unwrap().uid() == 0 {
        println!("NOT_RUN {name}: running as uid 0, directory permissions are not enforced");
        return true;
    }
    false
}

fn chmod(p: &Path, mode: u32) {
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

fn post(b: &Board, session: &str, to: &[&str], text: &str) -> Result<u64, BoardError> {
    let mut p = Post::new(&b.whoami(session)?, "t", "lane/test", Kind::Finding, text);
    p.to = to.iter().map(|s| s.to_string()).collect();
    b.post(&p).map(|r| r.id)
}

fn bytes(root: &Path) -> (Vec<u8>, Vec<u8>) {
    (
        fs::read(root.join("journal.log")).unwrap(),
        fs::read(root.join("journal.idx")).unwrap(),
    )
}

/// Offsets of the frames in `journal.log` (4-byte length, 4-byte CRC-32C, body).
fn frame_offsets(j: &[u8]) -> Vec<usize> {
    let mut v = Vec::new();
    let mut pos = 0;
    while pos + 8 <= j.len() {
        v.push(pos);
        let len = u32::from_le_bytes(j[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 8 + len;
    }
    v
}

/// Flip one body byte of the frame at `off` (its CRC no longer verifies).
fn corrupt_frame_at(root: &Path, off: usize) {
    let p = root.join("journal.log");
    let mut j = fs::read(&p).unwrap();
    j[off + 8 + 3] ^= 0x5a;
    fs::write(&p, &j).unwrap();
}

fn is_corrupt<T: std::fmt::Debug>(r: &Result<T, BoardError>) -> bool {
    matches!(r, Err(BoardError::Corrupt { .. }))
}

fn is_io<T: std::fmt::Debug>(r: &Result<T, BoardError>) -> bool {
    matches!(r, Err(BoardError::Io { .. }))
}

// ---------------------------------------------------------------------------------------
// B6: a failed recovery keeps its evidence.

#[test]
fn b6_corrupt_first_frame_refused_twice_with_bytes_unchanged() {
    let (f, b) = fx("b6-first");
    b.register("sa", "alpha", None).unwrap();
    for i in 1..=3 {
        assert_eq!(post(&b, "sa", &[], &format!("event {i}")).unwrap(), i);
    }
    corrupt_frame_at(&f.root, 0);
    let before = bytes(&f.root);
    // Small enough that the old code took the remainder for one torn frame.
    assert!(before.0.len() < 1 << 16);
    for attempt in 1..=2 {
        let r = b.recover();
        assert!(
            is_corrupt(&r),
            "attempt {attempt}: expected Corrupt, got {r:?}"
        );
        assert_eq!(
            bytes(&f.root),
            before,
            "attempt {attempt}: journal.log and journal.idx must be unchanged"
        );
    }
    // A post goes through the same recovery: refused, nothing written, no id reused.
    let r = post(&b, "sa", &[], "after the damage");
    assert!(is_corrupt(&r), "post: expected Corrupt, got {r:?}");
    assert_eq!(bytes(&f.root), before, "post must not touch the files");
    let r = b.recover();
    assert!(
        is_corrupt(&r),
        "third recovery: expected Corrupt, got {r:?}"
    );
    assert_eq!(bytes(&f.root), before);
}

#[test]
fn b6_partly_written_final_entry_never_licenses_cutting_its_frame() {
    let (f, b) = fx("b6-partial");
    b.register("sa", "alpha", None).unwrap();
    post(&b, "sa", &[], "one").unwrap();
    post(&b, "sa", &[], "two").unwrap();
    // journal.idx loses its last whole entry and ends in a partial one (the commit of
    // event 2), and event 2's frame (synced before that entry was written) is damaged.
    let ip = f.root.join("journal.idx");
    let mut t = fs::read(&ip).unwrap();
    t.truncate(64);
    t.extend_from_slice(&[0xab; 20]);
    fs::write(&ip, &t).unwrap();
    let j = fs::read(f.root.join("journal.log")).unwrap();
    corrupt_frame_at(&f.root, frame_offsets(&j)[1]);
    let before = bytes(&f.root);
    for attempt in 1..=2 {
        let r = b.recover();
        assert!(
            is_corrupt(&r),
            "attempt {attempt}: expected Corrupt, got {r:?}"
        );
        assert_eq!(bytes(&f.root), before, "attempt {attempt}: unchanged");
    }
}

#[test]
fn b6_partly_written_final_entry_is_still_dropped_when_its_frame_verifies() {
    let (f, b) = fx("b6-partial-ok");
    b.register("sa", "alpha", None).unwrap();
    post(&b, "sa", &[], "one").unwrap();
    post(&b, "sa", &[], "two").unwrap();
    let ip = f.root.join("journal.idx");
    let mut t = fs::read(&ip).unwrap();
    t.truncate(64);
    t.extend_from_slice(&[0xab; 20]);
    fs::write(&ip, &t).unwrap();
    let r = b.recover().unwrap();
    assert!(r.dropped_table_entry, "{r:?}");
    assert_eq!(r.adopted, vec![2], "{r:?}");
    assert_eq!(b.bounds().unwrap(), (1, 2));
    assert_eq!(fs::metadata(&ip).unwrap().len(), 128);
    assert!(b.check().unwrap().ok());
}

/// The board CLI with an overridden boot id (a "reboot" for the test).
fn board_cli(root: &Path, session: Option<&str>, args: &[&str], boot: &str) -> Output {
    let mut c = Command::new(BIN);
    c.arg("board").arg("--board-root").arg(root);
    if let Some(s) = session {
        c.arg("--session").arg(s);
    }
    c.args(args)
        .env_remove("SYNAPSE_COORD_FAULT")
        .env_remove("SYNAPSE_BOARD_ID")
        .env_remove("SYNAPSE_BOARD_SESSION")
        .env_remove("CRUMB_SESSION")
        .env("SYNAPSE_BOARD_BOOT_ID", boot)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c.output().unwrap()
}

fn summary(o: &Output) -> J {
    let out = String::from_utf8_lossy(&o.stdout);
    let last = out.lines().last().unwrap_or_else(|| {
        panic!(
            "no summary line; stderr: {}",
            String::from_utf8_lossy(&o.stderr)
        )
    });
    json::parse(last.as_bytes()).unwrap_or_else(|| panic!("not JSON: {last}"))
}

fn ok_cli(o: &Output) -> J {
    assert!(
        o.status.success(),
        "exit {:?}: {} {}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    summary(o)
}

fn reboot_fixture(name: &str) -> Fx {
    let f = scratch(name);
    ok_cli(&board_cli(&f.root, None, &["init"], "test-boot-one"));
    ok_cli(&board_cli(
        &f.root,
        Some("sa"),
        &["register", "alpha"],
        "test-boot-one",
    ));
    for i in 1..=3 {
        let text = format!("event {i}");
        ok_cli(&board_cli(
            &f.root,
            Some("sa"),
            &[
                "post", "--thread", "t", "--topic", "lane/x", "--text", &text,
            ],
            "test-boot-one",
        ));
    }
    f
}

fn assert_boot_rebuild_refuses_twice(f: &Fx) {
    let before = bytes(&f.root);
    for attempt in 1..=2 {
        let o = board_cli(&f.root, None, &["recover"], "test-boot-two");
        assert_eq!(
            o.status.code(),
            Some(2),
            "attempt {attempt}: {} {}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        assert_eq!(
            summary(&o).str_of("error").as_deref(),
            Some("Corrupt"),
            "attempt {attempt}"
        );
        assert_eq!(bytes(&f.root), before, "attempt {attempt}: unchanged");
    }
}

#[test]
fn b6_boot_rebuild_never_cuts_a_corrupt_first_committed_frame() {
    let f = reboot_fixture("b6-boot-first");
    corrupt_frame_at(&f.root, 0);
    assert_boot_rebuild_refuses_twice(&f);
}

#[test]
fn b6_boot_rebuild_never_cuts_a_corrupt_last_committed_frame() {
    let f = reboot_fixture("b6-boot-last");
    let j = fs::read(f.root.join("journal.log")).unwrap();
    corrupt_frame_at(&f.root, *frame_offsets(&j).last().unwrap());
    assert_boot_rebuild_refuses_twice(&f);
}

// ---------------------------------------------------------------------------------------
// B7: a failed directory sync is a failure.

#[test]
fn b7_root_sync_failure_gives_no_receipt_and_is_retried() {
    let (f, b) = fx("b7-root");
    if is_superuser(
        "b7_root_sync_failure_gives_no_receipt_and_is_retried",
        &f.root,
    ) {
        return;
    }
    b.register("sa", "alpha", None).unwrap();
    let pending = f.root.join("dirsync.pending");
    chmod(&f.root, 0o300);
    // Each writer open creates what is missing (the subdirectories, then journal.log and
    // journal.idx) and fails on the root sync that would make it durable.
    let mut opens = 0;
    while fs::symlink_metadata(f.root.join("journal.log")).is_err() {
        let r = b.recover();
        assert!(is_io(&r), "writer open {opens}: expected Io, got {r:?}");
        opens += 1;
        assert!(opens < 10, "journal.log never created");
    }
    let r = b.recover();
    assert!(
        is_io(&r),
        "created-but-unsynced journal: expected Io, got {r:?}"
    );
    // The files exist now; a post must still not be acknowledged over their unsynced
    // entries.
    let r = post(&b, "sa", &[], "never acknowledged");
    assert!(is_io(&r), "post: expected Io (no receipt), got {r:?}");
    assert!(fs::symlink_metadata(&pending).is_ok(), "retry marker kept");
    chmod(&f.root, 0o755);
    assert_eq!(post(&b, "sa", &[], "durable").unwrap(), 1, "no id was used");
    assert!(
        fs::symlink_metadata(&pending).is_err(),
        "the successful root sync clears the marker"
    );
    assert_eq!(b.bounds().unwrap(), (1, 1));
    assert!(b.check().unwrap().ok());
}

#[test]
fn b7_compaction_root_sync_failure_is_refused_and_flushed_before_the_next_ack() {
    let (f, b) = fx("b7-compact");
    if is_superuser("b7_compaction_root_sync_failure", &f.root) {
        return;
    }
    b.register("sa", "alpha", None).unwrap();
    for i in 1..=4 {
        post(&b, "sa", &[], &format!("e{i}")).unwrap();
    }
    chmod(&f.root, 0o300);
    let r = b.compact(3, false);
    assert!(is_io(&r), "compact: expected Io, got {r:?}");
    assert!(fs::symlink_metadata(f.root.join("dirsync.pending")).is_ok());
    // The renamed generation is not durable yet: no post into it is acknowledged.
    let r = post(&b, "sa", &[], "into the unsynced generation");
    assert!(is_io(&r), "post: expected Io (no receipt), got {r:?}");
    chmod(&f.root, 0o755);
    assert_eq!(post(&b, "sa", &[], "e5").unwrap(), 5);
    assert!(fs::symlink_metadata(f.root.join("dirsync.pending")).is_err());
    assert_eq!(b.bounds().unwrap(), (3, 5));
}

#[test]
fn b7_cursor_dir_sync_failure_is_not_an_ack() {
    let (f, b) = fx("b7-cursor");
    if is_superuser("b7_cursor_dir_sync_failure_is_not_an_ack", &f.root) {
        return;
    }
    b.register("sa", "alpha", None).unwrap();
    b.register("sb", "beta", None).unwrap();
    let id = post(&b, "sa", &["beta"], "for beta").unwrap();
    assert_eq!(b.deliver("sb", 10, Resume::Acked).unwrap().events.len(), 1);
    chmod(&f.root.join("cursors"), 0o300);
    let r = b.ack("sb", id);
    assert!(is_io(&r), "ack: expected Io, got {r:?}");
    chmod(&f.root.join("cursors"), 0o755);
    b.ack("sb", id).unwrap();
    assert_eq!(b.acked("sb").unwrap(), id);
}

#[test]
fn b7_coord_record_dir_sync_failure_is_an_error() {
    let f = scratch("b7-coord");
    let top = f.root.join("wa");
    fs::create_dir_all(top.join("src")).unwrap();
    fs::write(top.join("src/a.c"), "a").unwrap();
    fs::write(top.join("src/b.c"), "b").unwrap();
    let store = f.root.join("store/crumb/v1");
    let cs = CoordStore::open(&store);
    let mut h = Holder::git("A", "0123456789ab", "ba9876543210");
    h.session = Some("A-session".into());
    let ws = Workspace::worktree(top.to_str().unwrap(), h);
    match cs
        .claim(&ws, "agent-a", "src", "a.c", "first", None)
        .unwrap()
    {
        ClaimOutcome::Claimed { .. } => {}
        o => panic!("expected a claim, got {o:?}"),
    }
    if is_superuser("b7_coord_record_dir_sync_failure_is_an_error", &store) {
        return;
    }
    let dirs = store.join("dirs");
    chmod(&dirs, 0o300);
    let r = cs.claim(&ws, "agent-a", "src", "b.c", "second", None);
    chmod(&dirs, 0o755);
    assert!(
        matches!(r, Err(CoordError::Io { .. })),
        "claim over a failed directory sync: expected Io, got {r:?}"
    );
}

fn post_cli(root: &Path, text: &str, fault: Option<&str>) -> Output {
    let mut c = Command::new(BIN);
    c.arg("board")
        .arg("--board-root")
        .arg(root)
        .arg("--session")
        .arg("sa")
        .args(["post", "--thread", "t", "--topic", "lane/x", "--text", text])
        .env_remove("SYNAPSE_COORD_FAULT")
        .env_remove("SYNAPSE_BOARD_ID")
        .env_remove("SYNAPSE_BOARD_SESSION")
        .env_remove("CRUMB_SESSION")
        .env_remove("SYNAPSE_BOARD_BOOT_ID")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(p) = fault {
        c.env("SYNAPSE_COORD_FAULT", p);
    }
    c.output().unwrap()
}

#[test]
fn b7_injected_eio_refuses_the_receipt_and_einval_is_tolerated() {
    let (f, b) = fx("b7-inject");
    b.register("sa", "alpha", None).unwrap();
    // EIO on the directory sync of the first post (it creates the journal): exit 1, a
    // failure summary, no id.
    let o = post_cli(&f.root, "lost", Some("dir-sync-eio"));
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    let s = summary(&o);
    assert_eq!(s.get("ok"), Some(&J::False), "{s:?}");
    assert_eq!(s.str_of("error").as_deref(), Some("Io"), "{s:?}");
    assert!(s.get("id").is_none(), "no receipt: {s:?}");
    // The created-but-unsynced journal is flushed again by the next post: still EIO.
    let o = post_cli(&f.root, "lost again", Some("dir-sync-eio"));
    assert_eq!(o.status.code(), Some(1), "retry must sync the root again");
    // EINVAL (a file system that cannot sync directories) is the documented exception.
    let o = post_cli(&f.root, "kept", Some("dir-sync-einval"));
    let s = ok_cli(&o);
    let id = match s.get("id") {
        Some(J::Num(t)) => String::from_utf8_lossy(t).into_owned(),
        other => panic!("no id in {s:?}: {other:?}"),
    };
    assert_eq!(id, "1", "{s:?}");
    assert_eq!(b.bounds().unwrap(), (1, 1), "exactly one event, id 1");
}

// ---------------------------------------------------------------------------------------
// B8: compaction refuses unless the cursor enumeration is complete.

#[test]
fn b8_unlistable_cursor_dir_refuses_compaction() {
    let (f, b) = fx("b8");
    if is_superuser("b8_unlistable_cursor_dir_refuses_compaction", &f.root) {
        return;
    }
    b.register("sa", "alpha", None).unwrap();
    b.register("sb", "beta", None).unwrap();
    let first = post(&b, "sa", &["beta"], "e1").unwrap();
    assert_eq!(b.deliver("sb", 1, Resume::Acked).unwrap().events.len(), 1);
    b.ack("sb", first).unwrap();
    for i in 2..=4 {
        post(&b, "sa", &["beta"], &format!("e{i}")).unwrap();
    }
    // beta's cursor (acked 1) lags behind keep_since 3.
    let cursors = f.root.join("cursors");
    assert!(fs::symlink_metadata(cursors.join("beta.json")).is_ok());
    let before = bytes(&f.root);
    chmod(&cursors, 0o300);
    for expire in [false, true] {
        let r = b.compact(3, expire);
        assert!(
            is_io(&r),
            "compact(expire={expire}) over an unlistable cursors/: expected Io, got {r:?}"
        );
        assert_eq!(bytes(&f.root), before, "expire={expire}: nothing dropped");
    }
    chmod(&cursors, 0o755);
    assert_eq!(b.acked("sb").unwrap(), first, "the cursor was not expired");
    // Control: with the directory listable, the lagging cursor is found and named.
    match b.compact(3, false) {
        Err(BoardError::CompactRefused { tags, .. }) => {
            assert!(tags.iter().any(|t| t == "beta"), "{tags:?}")
        }
        other => panic!("expected CompactRefused, got {other:?}"),
    }
    assert_eq!(bytes(&f.root), before);
}

// ---------------------------------------------------------------------------------------
// R4: a reboot rebuild keeps every committed boundary journal.idx proves.

/// `journal.idx` keeps its first two entries and ends in a partly written third one.
fn partial_third_entry(root: &Path) {
    let ip = root.join("journal.idx");
    let mut t = fs::read(&ip).unwrap();
    assert_eq!(t.len(), 192, "three whole entries");
    t.truncate(128);
    t.extend_from_slice(&[0xab; 20]);
    fs::write(&ip, &t).unwrap();
}

fn truncate_journal_before_frame(root: &Path, n: usize) {
    let jp = root.join("journal.log");
    let mut j = fs::read(&jp).unwrap();
    let off = frame_offsets(&j)[n];
    j.truncate(off);
    fs::write(&jp, &j).unwrap();
}

#[test]
fn r4_boot_rebuild_refuses_a_partly_written_final_entry_over_a_corrupt_frame() {
    // The reviewer's variant A: the old rebuild cut 236 bytes at offset 472 (event 3,
    // whose partly written entry proves it was durable) and reported success.
    let f = reboot_fixture("r4-partial");
    partial_third_entry(&f.root);
    let j = fs::read(f.root.join("journal.log")).unwrap();
    corrupt_frame_at(&f.root, frame_offsets(&j)[2]);
    assert_boot_rebuild_refuses_twice(&f);
}

#[test]
fn r4_boot_rebuild_refuses_a_journal_that_ends_before_a_committed_frame() {
    // The reviewer's variant B: an intact three-entry table, the journal cut exactly
    // before the third frame. The old rebuild reached EOF on a frame boundary, never
    // compared it with the table's floor, and replaced the table with two entries.
    let f = reboot_fixture("r4-eof");
    truncate_journal_before_frame(&f.root, 2);
    assert_boot_rebuild_refuses_twice(&f);
}

#[test]
fn r4_boot_rebuild_refuses_a_partly_written_entry_whose_frame_is_gone() {
    // Both at once: the partly written third entry is the only evidence of event 3, and
    // the journal ends on the boundary before it.
    let f = reboot_fixture("r4-partial-eof");
    partial_third_entry(&f.root);
    truncate_journal_before_frame(&f.root, 2);
    assert_boot_rebuild_refuses_twice(&f);
}

#[test]
fn r4_same_boot_partly_written_entry_refuses_a_journal_that_ends_at_its_frame() {
    let (f, b) = fx("r4-same-boot-eof");
    b.register("sa", "alpha", None).unwrap();
    for i in 1..=3 {
        post(&b, "sa", &[], &format!("event {i}")).unwrap();
    }
    partial_third_entry(&f.root);
    truncate_journal_before_frame(&f.root, 2);
    let before = bytes(&f.root);
    for attempt in 1..=2 {
        let r = b.recover();
        assert!(
            is_corrupt(&r),
            "attempt {attempt}: expected Corrupt, got {r:?}"
        );
        assert_eq!(bytes(&f.root), before, "attempt {attempt}: unchanged");
    }
}

#[test]
fn r4_boot_rebuild_adopts_a_partly_written_final_entry_whose_frame_verifies() {
    // Control: the evidence only refuses what does not verify. The frame the partial
    // entry names is intact, so the rebuild succeeds with all three events.
    let f = reboot_fixture("r4-partial-ok");
    partial_third_entry(&f.root);
    let s = ok_cli(&board_cli(&f.root, None, &["recover"], "test-boot-two"));
    assert_eq!(s.get("rebuilt_after_boot"), Some(&J::True), "{s:?}");
    assert_eq!(s.get("torn_tail_at"), Some(&J::Null), "nothing cut: {s:?}");
    assert_eq!(
        fs::metadata(f.root.join("journal.idx")).unwrap().len(),
        192,
        "all three events committed again"
    );
    // `check` exits 0 only when journal.idx and every index agree with the journal.
    ok_cli(&board_cli(&f.root, None, &["check"], "test-boot-two"));
}

// ---------------------------------------------------------------------------------------
// R5: an already-applied retry is not durable until its directory is synced.

#[test]
fn r5_ack_retry_with_the_cursor_dir_sync_still_failing_is_not_an_ack() {
    let (f, b) = fx("r5-ack");
    if is_superuser("r5_ack_retry", &f.root) {
        return;
    }
    b.register("sa", "alpha", None).unwrap();
    b.register("sb", "beta", None).unwrap();
    let id = post(&b, "sa", &["beta"], "message").unwrap();
    assert_eq!(b.deliver("sb", 10, Resume::Acked).unwrap().events.len(), 1);
    chmod(&f.root.join("cursors"), 0o300);
    // The first ack renames the cursor into place, then fails its directory sync. The
    // retry finds the cursor already at `id`: it must sync again, and that still fails.
    let first = b.ack("sb", id);
    let retry = b.ack("sb", id);
    chmod(&f.root.join("cursors"), 0o755);
    assert!(is_io(&first), "first: expected Io, got {first:?}");
    assert!(
        is_io(&retry),
        "retry with the sync still failing: expected Io, got {retry:?}"
    );
    // Repaired: the same retry is now a durable success.
    let c = b.ack("sb", id).unwrap();
    assert_eq!((c.acked, c.delivered, c.exists), (id, id, true));
}

#[test]
fn r5_subscribe_retry_with_the_subs_dir_sync_still_failing_is_an_error() {
    let (f, b) = fx("r5-subs");
    if is_superuser("r5_subscribe_retry", &f.root) {
        return;
    }
    b.register("sa", "alpha", None).unwrap();
    b.subscribe("sa", &Sub::Topic("lane/a".into())).unwrap();
    chmod(&f.root.join("subs"), 0o300);
    let sub = Sub::Topic("lane/b".into());
    let first = b.subscribe("sa", &sub);
    let retry = b.subscribe("sa", &sub);
    chmod(&f.root.join("subs"), 0o755);
    assert!(is_io(&first), "first: expected Io, got {first:?}");
    assert!(is_io(&retry), "retry: expected Io, got {retry:?}");
    let s = b.subscribe("sa", &sub).unwrap();
    assert_eq!(s.topics, vec!["lane/a".to_string(), "lane/b".to_string()]);
}

/// `board compact --keep-since <keep> --expire-cursors`, optionally with an injected fault.
fn compact_cli(root: &Path, keep: u64, fault: Option<&str>) -> Output {
    let mut c = Command::new(BIN);
    c.arg("board")
        .arg("--board-root")
        .arg(root)
        .args([
            "compact",
            "--keep-since",
            &keep.to_string(),
            "--expire-cursors",
        ])
        .env_remove("SYNAPSE_COORD_FAULT")
        .env_remove("SYNAPSE_BOARD_ID")
        .env_remove("SYNAPSE_BOARD_SESSION")
        .env_remove("CRUMB_SESSION")
        .env_remove("SYNAPSE_BOARD_BOOT_ID")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(p) = fault {
        c.env("SYNAPSE_COORD_FAULT", p);
    }
    c.output().unwrap()
}

#[test]
fn r5_compaction_retry_after_a_failed_expiration_sync_refuses_with_the_journal_unchanged() {
    let (f, b) = fx("r5-compact");
    b.register("sa", "alpha", None).unwrap();
    b.register("sb", "beta", None).unwrap();
    let first = post(&b, "sa", &["beta"], "e1").unwrap();
    assert_eq!(b.deliver("sb", 1, Resume::Acked).unwrap().events.len(), 1);
    b.ack("sb", first).unwrap();
    for i in 2..=4 {
        post(&b, "sa", &["beta"], &format!("e{i}")).unwrap();
    }
    // beta (acked 1) lags behind keep_since 3. Every directory sync fails (EIO): the first
    // attempt writes `expired: true` and fails its sync; the retry finds beta already
    // expired, so it writes no cursor, and must still not publish over that unsynced
    // expiration.
    let before = bytes(&f.root);
    for attempt in 1..=2 {
        let o = compact_cli(&f.root, 3, Some("dir-sync-eio"));
        assert_eq!(
            o.status.code(),
            Some(1),
            "attempt {attempt}: {} {}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        assert_eq!(
            summary(&o).str_of("error").as_deref(),
            Some("Io"),
            "attempt {attempt}"
        );
        assert_eq!(
            bytes(&f.root),
            before,
            "attempt {attempt}: journal.log and journal.idx must be unchanged"
        );
    }
    // Control: with the fault gone, the compaction runs. beta's expiration was written by
    // the first attempt (so this run expires nobody new) and is flushed before publishing.
    let s = ok_cli(&compact_cli(&f.root, 3, None));
    assert_eq!(s.get("expired"), Some(&J::Arr(vec![])), "{s:?}");
    assert_eq!(b.bounds().unwrap(), (3, 4));
    assert!(b.cursor("beta").unwrap().expired);
}

// ---------------------------------------------------------------------------------------
// R6: every durable mutator reconciles a pending root sync.

#[test]
fn r6_register_retry_with_the_root_sync_still_failing_is_an_error() {
    let (f, b) = fx("r6-register");
    if is_superuser("r6_register_retry", &f.root) {
        return;
    }
    let pending = f.root.join("dirsync.pending");
    chmod(&f.root, 0o300);
    // The first call creates agents/ and fails the root sync; the retry finds agents/
    // there and must flush the root again (still failing) before writing a binding.
    let first = b.register("sa", "alpha", None);
    let retry = b.register("sa", "alpha", None);
    let marked = fs::symlink_metadata(&pending).is_ok();
    chmod(&f.root, 0o755);
    assert!(is_io(&first), "first: expected Io, got {first:?}");
    assert!(
        is_io(&retry),
        "retry with the root sync still failing: expected Io, got {retry:?}"
    );
    assert!(marked, "the retry marker is kept while the sync fails");
    let r = b.register("sa", "alpha", None).unwrap();
    assert_eq!(r.me.tag, "alpha");
    assert!(
        fs::symlink_metadata(&pending).is_err(),
        "the successful root sync clears the marker"
    );
    assert_eq!(b.whoami("sa").unwrap().tag, "alpha");
}

#[test]
fn r6_first_read_with_a_pending_root_sync_still_failing_is_an_error() {
    let (f, b) = fx("r6-cursor");
    if is_superuser("r6_first_read", &f.root) {
        return;
    }
    b.register("sa", "alpha", None).unwrap();
    b.register("sb", "beta", None).unwrap();
    post(&b, "sa", &["beta"], "for beta").unwrap();
    // An earlier root change whose sync failed (the marker is what that failure leaves).
    let pending = f.root.join("dirsync.pending");
    fs::write(&pending, b"").unwrap();
    chmod(&f.root, 0o300);
    // beta's first read creates its durable cursor under cursors/, which exists: the root
    // must be flushed first, and that still fails.
    let first = b.deliver("sb", 10, Resume::Acked);
    let retry = b.deliver("sb", 10, Resume::Acked);
    chmod(&f.root, 0o755);
    assert!(is_io(&first), "first: expected Io, got {first:?}");
    assert!(is_io(&retry), "retry: expected Io, got {retry:?}");
    assert!(!b.cursor("beta").unwrap().exists, "no cursor was created");
    assert_eq!(b.deliver("sb", 10, Resume::Acked).unwrap().events.len(), 1);
    assert!(fs::symlink_metadata(&pending).is_err());
    assert!(b.cursor("beta").unwrap().exists);
}

// ---------------------------------------------------------------------------------------
// Round 12 helpers.

/// The board CLI with the inherited test variables removed and `env` applied (no boot id
/// override unless `env` sets one).
fn cli_cmd(root: &Path, session: Option<&str>, args: &[&str], env: &[(&str, &str)]) -> Command {
    let mut c = Command::new(BIN);
    c.arg("board").arg("--board-root").arg(root);
    if let Some(s) = session {
        c.arg("--session").arg(s);
    }
    c.args(args)
        .env_remove("SYNAPSE_COORD_FAULT")
        .env_remove("SYNAPSE_COORD_PAUSE_DIR")
        .env_remove("SYNAPSE_BOARD_ID")
        .env_remove("SYNAPSE_BOARD_SESSION")
        .env_remove("CRUMB_SESSION")
        .env_remove("SYNAPSE_BOARD_BOOT_ID")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        c.env(k, v);
    }
    c
}

fn cli(root: &Path, session: Option<&str>, args: &[&str], env: &[(&str, &str)]) -> Output {
    cli_cmd(root, session, args, env).output().unwrap()
}

fn show(o: &Output) -> String {
    format!(
        "exit {:?}: {} {}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// Exit status 1 with an `Io` failure summary (no receipt).
fn assert_io_cli(o: &Output, what: &str) {
    assert_eq!(o.status.code(), Some(1), "{what}: {}", show(o));
    assert_eq!(
        summary(o).str_of("error").as_deref(),
        Some("Io"),
        "{what}: {}",
        show(o)
    );
}

// ---------------------------------------------------------------------------------------
// N3: an empty or missing journal never erases what journal.idx proves committed.

/// `journal.log` cut to zero bytes (`empty`) or removed; `journal.idx` left intact.
fn lose_journal(root: &Path, empty: bool) {
    let jp = root.join("journal.log");
    if empty {
        fs::write(&jp, b"").unwrap();
    } else {
        fs::remove_file(&jp).unwrap();
    }
}

/// The journal (None when missing), the table and the boot record, byte for byte.
type BoardFiles = (Option<Vec<u8>>, Vec<u8>, Option<Vec<u8>>);

fn files(root: &Path) -> BoardFiles {
    (
        fs::read(root.join("journal.log")).ok(),
        fs::read(root.join("journal.idx")).unwrap(),
        fs::read(root.join("boot")).ok(),
    )
}

#[test]
fn n3_same_boot_empty_or_missing_journal_is_refused_with_the_table_kept() {
    for empty in [true, false] {
        let (f, b) = fx(if empty { "n3-empty" } else { "n3-missing" });
        b.register("sa", "alpha", None).unwrap();
        for i in 1..=3 {
            assert_eq!(post(&b, "sa", &[], &format!("event {i}")).unwrap(), i);
        }
        lose_journal(&f.root, empty);
        let before = files(&f.root);
        assert_eq!(before.1.len(), 192, "the intact three-entry table");
        for attempt in 1..=2 {
            let r = b.recover();
            assert!(
                is_corrupt(&r),
                "empty={empty} attempt {attempt}: expected Corrupt, got {r:?}"
            );
            assert_eq!(
                files(&f.root),
                before,
                "empty={empty} attempt {attempt}: both files unchanged"
            );
        }
        // A post runs the same recovery: refused, so id 1 is never handed out again.
        let r = post(&b, "sa", &[], "would reuse id 1");
        assert!(
            is_corrupt(&r),
            "empty={empty} post: expected Corrupt, got {r:?}"
        );
        assert_eq!(
            files(&f.root),
            before,
            "empty={empty}: the post wrote nothing"
        );
    }
}

#[test]
fn n3_boot_rebuild_refuses_an_empty_or_missing_journal_with_the_table_kept() {
    for empty in [true, false] {
        let f = reboot_fixture(if empty {
            "n3-boot-empty"
        } else {
            "n3-boot-missing"
        });
        lose_journal(&f.root, empty);
        let before = files(&f.root);
        assert_eq!(before.1.len(), 192, "the intact three-entry table");
        for attempt in 1..=2 {
            let o = board_cli(&f.root, None, &["recover"], "test-boot-two");
            assert_eq!(
                o.status.code(),
                Some(2),
                "empty={empty} attempt {attempt}: {}",
                show(&o)
            );
            assert_eq!(
                summary(&o).str_of("error").as_deref(),
                Some("Corrupt"),
                "empty={empty} attempt {attempt}"
            );
            assert_eq!(
                files(&f.root),
                before,
                "empty={empty} attempt {attempt}: journal, table and boot record unchanged"
            );
        }
        let o = board_cli(
            &f.root,
            Some("sa"),
            &[
                "post",
                "--thread",
                "t",
                "--topic",
                "lane/x",
                "--text",
                "would reuse id 1",
            ],
            "test-boot-two",
        );
        assert_eq!(o.status.code(), Some(2), "empty={empty} post: {}", show(&o));
        assert_eq!(
            files(&f.root),
            before,
            "empty={empty}: the post wrote nothing"
        );
    }
}

/// `board compact --keep-since <keep>` killed between its two renames: the new journal
/// generation is in place, `journal.idx` is still the old one.
fn compact_cut_between_renames(root: &Path, keep: u64, boot: Option<&str>) {
    let keep = keep.to_string();
    let mut env = vec![("SYNAPSE_COORD_FAULT", "compact-between-renames")];
    if let Some(b) = boot {
        env.push(("SYNAPSE_BOARD_BOOT_ID", b));
    }
    let o = cli(root, None, &["compact", "--keep-since", &keep], &env);
    assert_eq!(o.status.code(), Some(86), "{}", show(&o));
}

#[test]
fn n3_control_a_compaction_cut_between_its_renames_still_recovers() {
    // Same boot: the table of the old generation is rebuilt from the new journal.
    let (f, b) = fx("n3-cut");
    b.register("sa", "alpha", None).unwrap();
    for i in 1..=3 {
        post(&b, "sa", &[], &format!("event {i}")).unwrap();
    }
    compact_cut_between_renames(&f.root, 2, None);
    let r = b.recover().unwrap();
    assert!(r.table_rebuilt, "{r:?}");
    assert_eq!(r.torn_tail_at, None, "nothing cut: {r:?}");
    assert_eq!(b.bounds().unwrap(), (2, 3));
    assert!(b.check().unwrap().ok());
    assert_eq!(post(&b, "sa", &[], "event 4").unwrap(), 4, "no id reused");
    // After a reboot: the rebuild from offset 0 accepts the new generation too.
    let g = reboot_fixture("n3-cut-boot");
    compact_cut_between_renames(&g.root, 2, Some("test-boot-one"));
    let s = ok_cli(&board_cli(&g.root, None, &["recover"], "test-boot-two"));
    assert_eq!(s.get("rebuilt_after_boot"), Some(&J::True), "{s:?}");
    assert_eq!(s.get("torn_tail_at"), Some(&J::Null), "nothing cut: {s:?}");
    assert_eq!(
        fs::metadata(g.root.join("journal.idx")).unwrap().len(),
        128,
        "events 2 and 3 committed"
    );
    ok_cli(&board_cli(&g.root, None, &["check"], "test-boot-two"));
}

#[test]
fn n3_a_generation_mismatch_rebuild_must_reach_the_tables_last_committed_id() {
    // A cut compaction leaves the new journal (events 2 and 3) under the old table, which
    // names event 3 committed. A journal that then ends on the boundary before event 3 has
    // lost it: the rebuild must not accept that boundary (and hand id 3 out again).
    let (f, b) = fx("n3-cut-short");
    b.register("sa", "alpha", None).unwrap();
    for i in 1..=3 {
        post(&b, "sa", &[], &format!("event {i}")).unwrap();
    }
    compact_cut_between_renames(&f.root, 2, None);
    truncate_journal_before_frame(&f.root, 1);
    let before = files(&f.root);
    for attempt in 1..=2 {
        let r = b.recover();
        assert!(
            is_corrupt(&r),
            "attempt {attempt}: expected Corrupt, got {r:?}"
        );
        assert_eq!(files(&f.root), before, "attempt {attempt}: unchanged");
    }
    let r = post(&b, "sa", &[], "would reuse id 3");
    assert!(is_corrupt(&r), "post: expected Corrupt, got {r:?}");
    assert_eq!(files(&f.root), before);
}

// ---------------------------------------------------------------------------------------
// N4: a first delivery is not a success over an unsynced durable cursor.

#[test]
fn n4_first_delivery_retry_with_the_cursor_dir_sync_still_failing_is_an_error() {
    let (f, b) = fx("n4-first");
    if is_superuser("n4_first_delivery_retry", &f.root) {
        return;
    }
    b.register("sa", "alpha", None).unwrap();
    b.register("sb", "beta", None).unwrap();
    post(&b, "sa", &["beta"], "one").unwrap();
    // The writer created cursors/; beta never read, so it has no durable cursor yet.
    assert!(fs::symlink_metadata(f.root.join("cursors/beta.json")).is_err());
    chmod(&f.root.join("cursors"), 0o300);
    // The first delivery renames beta's cursor into place, then fails its directory sync.
    // The retry finds the cursor there: it must flush it again, and that still fails.
    let first = b.deliver("sb", 10, Resume::Acked);
    let retry = b.deliver("sb", 10, Resume::Acked);
    chmod(&f.root.join("cursors"), 0o755);
    assert!(is_io(&first), "first: expected Io, got {first:?}");
    assert!(
        is_io(&retry),
        "retry with the sync still failing: expected Io, got {retry:?}"
    );
    // Repaired: the same retry flushes the cursor and delivers.
    let r = b.deliver("sb", 10, Resume::Acked).unwrap();
    assert_eq!(r.events.len(), 1, "{r:?}");
    let c = b.cursor("beta").unwrap();
    assert!(c.exists && c.acked == 0, "{c:?}");
}

#[test]
fn n4_control_a_delivery_with_nothing_pending_needs_no_cursor_dir_sync() {
    let (f, b) = fx("n4-clean");
    if is_superuser("n4_control_clean_delivery", &f.root) {
        return;
    }
    b.register("sa", "alpha", None).unwrap();
    b.register("sb", "beta", None).unwrap();
    post(&b, "sa", &["beta"], "one").unwrap();
    assert_eq!(b.deliver("sb", 10, Resume::Acked).unwrap().events.len(), 1);
    let two = post(&b, "sa", &["beta"], "two").unwrap();
    // beta's cursor was flushed by its first delivery: a later delivery owes no directory
    // sync, so an unreadable cursors/ does not fail it.
    chmod(&f.root.join("cursors"), 0o300);
    let r = b.deliver("sb", 10, Resume::Delivered);
    chmod(&f.root.join("cursors"), 0o755);
    let ids: Vec<u64> = r.unwrap().events.iter().map(|d| d.event.id).collect();
    assert_eq!(ids, vec![two]);
}

// ---------------------------------------------------------------------------------------
// N5: an earlier root sync never clears a later publication's dirsync.pending.

/// alpha posts three events to beta, beta reads and acknowledges them all.
fn n5_board(name: &str) -> (Fx, Board) {
    let (f, b) = fx(name);
    b.register("sa", "alpha", None).unwrap();
    b.register("sb", "beta", None).unwrap();
    for i in 1..=3 {
        post(&b, "sa", &["beta"], &format!("e{i}")).unwrap();
    }
    assert_eq!(b.deliver("sb", 10, Resume::Acked).unwrap().events.len(), 3);
    b.ack("sb", 3).unwrap();
    (f, b)
}

fn wait_for(p: &Path, child: &mut std::process::Child, what: &str) {
    let t0 = std::time::Instant::now();
    while fs::symlink_metadata(p).is_err() {
        if let Some(st) = child.try_wait().unwrap() {
            panic!("{what}: exited ({st}) before reaching the barrier");
        }
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(30),
            "{what}: never reached the barrier"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn n5_a_paused_root_sync_never_clears_a_later_failed_publication() {
    // The reviewer's interleaving, deterministic through the test barrier:
    //  A (beta's read) reconciles a pending marker: its root fsync succeeds and it pauses
    //    before clearing the marker;
    //  B (a compaction) publishes a new generation and its root sync fails (EIO), so its
    //    marker must stay;
    //  A resumes;
    //  C (a post with every directory sync failing) must then sync the root and fail.
    let (f, b) = n5_board("n5-race");
    let sig = scratch("n5-race-sig");
    fs::create_dir_all(&sig.root).unwrap();
    let pending = f.root.join("dirsync.pending");
    // An earlier root change whose sync failed.
    fs::write(&pending, b"").unwrap();
    let sigdir = sig.root.to_str().unwrap().to_string();
    let mut a = cli_cmd(
        &f.root,
        Some("sb"),
        &["read"],
        &[
            ("SYNAPSE_COORD_FAULT", "pause-after-root-sync"),
            ("SYNAPSE_COORD_PAUSE_DIR", &sigdir),
        ],
    )
    .spawn()
    .unwrap();
    wait_for(&sig.root.join("ready"), &mut a, "reader A");
    let mut bp = cli_cmd(
        &f.root,
        None,
        &["compact", "--keep-since", "2"],
        &[("SYNAPSE_COORD_FAULT", "compact-root-sync-eio")],
    )
    .spawn()
    .unwrap();
    // B must not get through its publication while A is between its sync and its clear.
    let t0 = std::time::Instant::now();
    let mut b_done_while_a_paused = false;
    while t0.elapsed() < std::time::Duration::from_secs(3) {
        if bp.try_wait().unwrap().is_some() {
            b_done_while_a_paused = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    fs::write(sig.root.join("go"), b"").unwrap();
    let ao = a.wait_with_output().unwrap();
    let bo = bp.wait_with_output().unwrap();
    assert!(ao.status.success(), "reader A: {}", show(&ao));
    assert_io_cli(&bo, "compaction B");
    let marked = fs::symlink_metadata(&pending).is_ok();
    let co = cli(
        &f.root,
        Some("sa"),
        &["post", "--thread", "t", "--topic", "lane/x", "--text", "C"],
        &[("SYNAPSE_COORD_FAULT", "dir-sync-eio")],
    );
    println!(
        "B finished while A paused: {b_done_while_a_paused}; marker after A and B: {marked}; C: {}",
        show(&co)
    );
    assert_io_cli(&co, "post C over B's unsynced publication");
    assert!(marked, "B's failed publication keeps dirsync.pending");
    assert!(
        !b_done_while_a_paused,
        "B published while A was between its root sync and its marker removal"
    );
    // Control: with the root sync working, the next post flushes and is acknowledged.
    assert_eq!(b.bounds().unwrap(), (2, 3), "B's generation is in place");
    let s = ok_cli(&post_cli(&f.root, "after the repair", None));
    assert_eq!(s.get("id"), Some(&J::Num(b"4".to_vec())), "{s:?}");
    assert!(fs::symlink_metadata(&pending).is_err());
}

#[test]
fn n5_control_a_failed_publication_is_cleared_only_by_a_successful_root_sync() {
    let (f, b) = n5_board("n5-serial");
    let pending = f.root.join("dirsync.pending");
    let o = cli(
        &f.root,
        None,
        &["compact", "--keep-since", "2"],
        &[("SYNAPSE_COORD_FAULT", "compact-root-sync-eio")],
    );
    assert_io_cli(&o, "compaction");
    assert!(fs::symlink_metadata(&pending).is_ok());
    // A reader and a post whose root sync fails: each is an error and the marker stays.
    for attempt in 1..=2 {
        let o = cli(
            &f.root,
            Some("sb"),
            &["read"],
            &[("SYNAPSE_COORD_FAULT", "dir-sync-eio")],
        );
        assert_io_cli(&o, &format!("read attempt {attempt}"));
        assert!(fs::symlink_metadata(&pending).is_ok(), "attempt {attempt}");
        let o = post_cli(&f.root, "not acknowledged", Some("dir-sync-eio"));
        assert_io_cli(&o, &format!("post attempt {attempt}"));
        assert!(fs::symlink_metadata(&pending).is_ok(), "attempt {attempt}");
    }
    // A reader whose root sync succeeds discharges the marker; the next post needs none.
    let o = cli(&f.root, Some("sb"), &["read"], &[]);
    assert!(o.status.success(), "{}", show(&o));
    assert!(fs::symlink_metadata(&pending).is_err());
    let s = ok_cli(&post_cli(&f.root, "e4", None));
    assert_eq!(s.get("id"), Some(&J::Num(b"4".to_vec())), "{s:?}");
    assert_eq!(b.bounds().unwrap(), (2, 4));
}

// Round 13 (#928 review P1): a durability marker whose lookup fails (anything but
// NotFound) still owes its flush; a failed lookup must never read as "nothing pending".

fn cli_with_fault(root: &Path, session: &str, args: &[&str], fault: Option<&str>) -> Output {
    let mut c = Command::new(BIN);
    c.arg("board")
        .arg("--board-root")
        .arg(root)
        .arg("--session")
        .arg(session)
        .args(args)
        .env_remove("SYNAPSE_COORD_FAULT")
        .env_remove("SYNAPSE_BOARD_ID")
        .env_remove("SYNAPSE_BOARD_SESSION")
        .env_remove("CRUMB_SESSION")
        .env_remove("SYNAPSE_BOARD_BOOT_ID")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(p) = fault {
        c.env("SYNAPSE_COORD_FAULT", p);
    }
    c.output().unwrap()
}

#[test]
fn r13_unobservable_cursor_marker_is_not_a_flushed_cursor() {
    let (f, b) = fx("r13-cursor");
    if is_superuser("r13_unobservable_cursor_marker", &f.root) {
        return;
    }
    b.register("sa", "alpha", None).unwrap();
    b.register("sb", "beta", None).unwrap();
    post(&b, "sa", &["beta"], "one").unwrap();
    let marker = f.root.join("cursors/beta.unsynced");
    chmod(&f.root.join("cursors"), 0o300);
    // First delivery: beta's cursor is renamed into place, its directory sync fails, the
    // marker stays (positive control for the obligation).
    let first = cli_with_fault(&f.root, "sb", &["read", "--limit", "10"], None);
    // The marker cannot be looked up (EIO on that one stat) while the sync still fails.
    let blind = cli_with_fault(
        &f.root,
        "sb",
        &["read", "--limit", "10"],
        Some("marker-stat-eio:beta.unsynced"),
    );
    chmod(&f.root.join("cursors"), 0o755);
    assert!(
        !first.status.success(),
        "first delivery must fail: {first:?}"
    );
    assert!(
        !blind.status.success(),
        "a delivery that cannot see its cursor marker returned success: {} {}",
        String::from_utf8_lossy(&blind.stdout),
        String::from_utf8_lossy(&blind.stderr)
    );
    assert!(fs::symlink_metadata(&marker).is_ok(), "marker must be kept");
    // Repaired directory, no injection: the retry flushes and clears the marker.
    let ok = cli_with_fault(&f.root, "sb", &["read", "--limit", "10"], None);
    assert!(ok.status.success(), "repaired retry: {ok:?}");
    assert!(
        fs::symlink_metadata(&marker).is_err(),
        "marker cleared after the flush"
    );
}

#[test]
fn r13_unobservable_root_marker_gives_no_receipt() {
    let (f, b) = fx("r13-root");
    b.register("sa", "alpha", None).unwrap();
    for i in 1..=4 {
        post(&b, "sa", &[], &format!("e{i}")).unwrap();
    }
    // A compaction whose final root sync fails leaves dirsync.pending.
    let o = compact_cli(&f.root, 3, Some("compact-root-sync-eio"));
    assert!(
        !o.status.success(),
        "compaction with a failed root sync: {o:?}"
    );
    let pending = f.root.join("dirsync.pending");
    assert!(fs::symlink_metadata(&pending).is_ok());
    // A post that cannot look the marker up must not acknowledge anything.
    let blind = cli_with_fault(
        &f.root,
        "sa",
        &[
            "post", "--thread", "t", "--topic", "lane/x", "--text", "blind",
        ],
        Some("marker-stat-eio:dirsync.pending"),
    );
    assert!(
        !blind.status.success(),
        "a post that cannot see dirsync.pending returned a receipt: {}",
        String::from_utf8_lossy(&blind.stdout)
    );
    assert!(
        fs::symlink_metadata(&pending).is_ok(),
        "marker must be kept"
    );
    // Control: without the injection the post flushes the root and clears the marker.
    let ok = cli_with_fault(
        &f.root,
        "sa",
        &[
            "post", "--thread", "t", "--topic", "lane/x", "--text", "seen",
        ],
        None,
    );
    assert!(ok.status.success(), "control post: {ok:?}");
    assert!(fs::symlink_metadata(&pending).is_err(), "marker cleared");
}

// ---------------------------------------------------------------------------------------
// Round 14 (#928 review): a lookup or listing that fails is never "absent" or "empty".

const BOOT_ONE: (&str, &str) = ("SYNAPSE_BOARD_BOOT_ID", "boot-one");
const BOOT_TWO: (&str, &str) = ("SYNAPSE_BOARD_BOOT_ID", "boot-two");

fn fault(spec: &str) -> (&str, &str) {
    ("SYNAPSE_COORD_FAULT", spec)
}

/// Board of boot `boot-one`: alpha (session sa) posted events 1, 2, 3 to beta (sb).
fn r14_beta_board(name: &str) -> Fx {
    let f = scratch(name);
    ok_cli(&cli(&f.root, None, &["init"], &[BOOT_ONE]));
    ok_cli(&cli(
        &f.root,
        Some("sa"),
        &["register", "alpha"],
        &[BOOT_ONE],
    ));
    ok_cli(&cli(
        &f.root,
        Some("sb"),
        &["register", "beta"],
        &[BOOT_ONE],
    ));
    for i in 1..=3 {
        let text = format!("e{i}");
        ok_cli(&cli(
            &f.root,
            Some("sa"),
            &[
                "post", "--thread", "t", "--topic", "lane/x", "--to", "beta", "--text", &text,
            ],
            &[BOOT_ONE],
        ));
    }
    f
}

/// Derived-index loss as after a power loss: beta's inbox index loses its last id (the
/// journal and `journal.idx` are intact), the model of tests/board_cli.rs.
fn lose_last_inbox_id(root: &Path) {
    let ip = root.join("inbox/beta.idx");
    let b = fs::read(&ip).unwrap();
    assert_eq!(b.len(), 24, "three ids");
    fs::write(&ip, &b[..16]).unwrap();
}

/// The event ids `read --mine --peek` returns to beta.
fn beta_reads(root: &Path, env: &[(&str, &str)]) -> Vec<i64> {
    let o = cli(
        root,
        Some("sb"),
        &["read", "--mine", "--peek", "--limit", "100"],
        env,
    );
    ok_cli(&o);
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| json::parse(l.as_bytes()))
        .filter(|j| j.get("v").is_some())
        .map(|j| j.long_of("id", -1))
        .collect()
}

fn boot_record(root: &Path) -> Option<Vec<u8>> {
    fs::read(root.join("boot")).ok()
}

fn assert_cli_error(o: &Output, code: i32, error: &str, what: &str) {
    assert_eq!(o.status.code(), Some(code), "{what}: {}", show(o));
    assert_eq!(
        summary(o).str_of("error").as_deref(),
        Some(error),
        "{what}: {}",
        show(o)
    );
}

#[test]
fn r14_b1_journal_lookup_error_on_init_keeps_the_old_boot_and_the_rebuild() {
    let f = r14_beta_board("r14-b1");
    lose_last_inbox_id(&f.root);
    assert_eq!(boot_record(&f.root).as_deref(), Some(&b"boot-one\n"[..]));
    // A new boot; init cannot look the journal up. That is not a fresh board.
    let o = cli(
        &f.root,
        None,
        &["init"],
        &[BOOT_TWO, fault("stat-eio:journal.log")],
    );
    assert_io_cli(&o, "init with an unobservable journal");
    assert_eq!(
        boot_record(&f.root).as_deref(),
        Some(&b"boot-one\n"[..]),
        "boot must not be marked verified"
    );
    // The next uninjected read of the new boot rebuilds: the acknowledged event 3 is back.
    assert_eq!(beta_reads(&f.root, &[BOOT_TWO]), vec![1, 2, 3]);
    assert_eq!(boot_record(&f.root).as_deref(), Some(&b"boot-two\n"[..]));
}

#[test]
fn r14_b1_controls_fresh_and_existing_board_init() {
    // Fresh board: no journal (NotFound), so init records its boot.
    let fresh = scratch("r14-b1-fresh");
    ok_cli(&cli(&fresh.root, None, &["init"], &[BOOT_ONE]));
    assert_eq!(
        boot_record(&fresh.root).as_deref(),
        Some(&b"boot-one\n"[..])
    );
    // Existing board, new boot, ordinary init: the old boot is kept, the next read
    // rebuilds the lost inbox id and records the new boot.
    let f = r14_beta_board("r14-b1-existing");
    lose_last_inbox_id(&f.root);
    ok_cli(&cli(&f.root, None, &["init"], &[BOOT_TWO]));
    assert_eq!(boot_record(&f.root).as_deref(), Some(&b"boot-one\n"[..]));
    assert_eq!(beta_reads(&f.root, &[BOOT_TWO]), vec![1, 2, 3]);
    assert_eq!(boot_record(&f.root).as_deref(), Some(&b"boot-two\n"[..]));
}

#[test]
fn r14_b2_unobservable_store_discriminator_never_becomes_a_board() {
    let f = scratch("r14-b2");
    let board_id = |r: &Path| fs::symlink_metadata(r.join("BOARD_ID")).is_ok();
    // Clean root: a board.
    let clean = f.root.join("clean");
    ok_cli(&cli(&clean, None, &["init"], &[]));
    assert!(board_id(&clean));
    // Legacy coordination root (dirs/, no STORE_ID): refused, then refused while dirs
    // cannot be looked up.
    let legacy = f.root.join("legacy");
    fs::create_dir_all(legacy.join("dirs")).unwrap();
    let o = cli(&legacy, None, &["init"], &[]);
    assert_cli_error(&o, 2, "NotABoard", "legacy root");
    let o = cli(&legacy, None, &["init"], &[fault("stat-eio:dirs")]);
    assert_io_cli(&o, "legacy root, dirs unobservable");
    assert!(!board_id(&legacy), "no BOARD_ID in a coordination root");
    // Marked store (STORE_ID): the same for its marker, and for both at once.
    let marked = f.root.join("marked");
    fs::create_dir_all(marked.join("dirs")).unwrap();
    fs::write(marked.join("STORE_ID"), b"crumb-coord-store-id/1 x\n").unwrap();
    let o = cli(&marked, None, &["init"], &[]);
    assert_cli_error(&o, 2, "NotABoard", "marked store");
    let o = cli(&marked, None, &["init"], &[fault("stat-eio:STORE_ID")]);
    assert_cli_error(&o, 2, "NotABoard", "marked store, STORE_ID unobservable");
    let o = cli(
        &marked,
        None,
        &["init"],
        &[fault("stat-eio:STORE_ID,stat-eio:dirs")],
    );
    assert_io_cli(&o, "marked store, both discriminators unobservable");
    assert!(!board_id(&marked), "no BOARD_ID in a coordination root");
    let only_id = f.root.join("only-id");
    fs::create_dir_all(&only_id).unwrap();
    fs::write(only_id.join("STORE_ID"), b"crumb-coord-store-id/1 x\n").unwrap();
    let o = cli(&only_id, None, &["init"], &[fault("stat-eio:STORE_ID")]);
    assert_io_cli(&o, "store marker only, unobservable");
    assert!(!board_id(&only_id), "no BOARD_ID in a coordination root");
    // An uninspectable root is not adopted either, and opening a board refuses the same.
    let blind = f.root.join("blind");
    let o = cli(&blind, None, &["init"], &[fault("stat-eio:dirs")]);
    assert_io_cli(&o, "clean root, dirs unobservable");
    assert!(!board_id(&blind));
    let o = cli(&clean, None, &["agents"], &[fault("stat-eio:STORE_ID")]);
    assert_io_cli(&o, "open with STORE_ID unobservable");
}

#[test]
fn r14_lost_journal_whose_lookups_fail_creates_no_journal() {
    let (f, b) = fx("r14-lost");
    b.register("sa", "alpha", None).unwrap();
    for i in 1..=3 {
        post(&b, "sa", &[], &format!("e{i}")).unwrap();
    }
    lose_journal(&f.root, false);
    let before = files(&f.root);
    for spec in ["stat-eio:journal.log", "stat-eio:journal.idx"] {
        let o = cli(
            &f.root,
            Some("sa"),
            &[
                "post", "--thread", "t", "--topic", "lane/x", "--text", "late",
            ],
            &[fault(spec)],
        );
        assert_io_cli(&o, spec);
        assert_eq!(files(&f.root), before, "{spec}: no journal created");
    }
    // Control: observable, the lost journal is refused as in N3, still with nothing created.
    let o = cli(
        &f.root,
        Some("sa"),
        &[
            "post", "--thread", "t", "--topic", "lane/x", "--text", "late",
        ],
        &[],
    );
    assert_cli_error(&o, 2, "Corrupt", "lost journal");
    assert_eq!(files(&f.root), before);
}

#[test]
fn r14_reboot_rebuild_that_cannot_list_an_index_dir_keeps_the_old_boot() {
    let f = r14_beta_board("r14-rebuild");
    // A derived index no event names (gamma never received anything): the rebuild must
    // reach it, so it must list inbox/.
    let stale = f.root.join("inbox/gamma.idx");
    fs::write(&stale, 2u64.to_le_bytes()).unwrap();
    for spec in [
        "readdir-eio:inbox",
        "readdirent-eio:inbox",
        "readdir-eio:topics",
        "readdirent-eio:topics",
    ] {
        let o = cli(&f.root, None, &["recover"], &[BOOT_TWO, fault(spec)]);
        assert_io_cli(&o, spec);
        assert_eq!(
            boot_record(&f.root).as_deref(),
            Some(&b"boot-one\n"[..]),
            "{spec}: boot must not be marked verified"
        );
    }
    let r = ok_cli(&cli(&f.root, None, &["recover"], &[BOOT_TWO]));
    assert_eq!(r.get("rebuilt_after_boot"), Some(&J::True), "{r:?}");
    assert_eq!(fs::read(&stale).unwrap(), b"", "stale index rewritten");
    ok_cli(&cli(&f.root, None, &["check"], &[BOOT_TWO]));
    assert_eq!(beta_reads(&f.root, &[BOOT_TWO]), vec![1, 2, 3]);
}

#[test]
fn r14_torn_tail_cleanup_that_cannot_list_keeps_the_tail_and_reuses_no_stale_id() {
    let (f, b) = fx("r14-torn");
    b.register("sa", "alpha", None).unwrap();
    b.register("sb", "beta", None).unwrap();
    for i in 1..=3 {
        post(&b, "sa", &["beta"], &format!("e{i}")).unwrap();
    }
    // A writer died after listing id 4 in beta's inbox and before committing it; its frame
    // is a torn tail (a 32-byte frame header with 4 body bytes).
    let ip = f.root.join("inbox/beta.idx");
    let mut ids = fs::read(&ip).unwrap();
    ids.extend_from_slice(&4u64.to_le_bytes());
    fs::write(&ip, &ids).unwrap();
    let jp = f.root.join("journal.log");
    let mut j = fs::read(&jp).unwrap();
    j.extend_from_slice(&[32, 0, 0, 0, 1, 2, 3, 4, b'{', b'"', b'v', b'"']);
    fs::write(&jp, &j).unwrap();
    let args = [
        "post", "--thread", "t", "--topic", "lane/y", "--text", "next",
    ];
    for spec in ["readdir-eio:inbox", "readdirent-eio:inbox"] {
        let o = cli(&f.root, Some("sa"), &args, &[fault(spec)]);
        assert_io_cli(&o, spec);
        assert_eq!(
            fs::read(&jp).unwrap(),
            j,
            "{spec}: torn tail kept for the retry"
        );
    }
    // The retry cleans the stale id, cuts the tail and hands id 4 to a post beta is not
    // addressed by: beta must not receive it.
    let s = ok_cli(&cli(&f.root, Some("sa"), &args, &[]));
    assert_eq!(s.long_of("id", -1), 4, "{s:?}");
    assert_eq!(beta_reads(&f.root, &[]), vec![1, 2, 3]);
    assert!(b.check().unwrap().ok(), "{:?}", b.check().unwrap().problems);
}

#[test]
fn r14_trim_that_cannot_list_is_not_a_successful_compaction() {
    let (f, b) = fx("r14-trim");
    b.register("sa", "alpha", None).unwrap();
    for i in 1..=4 {
        post(&b, "sa", &[], &format!("e{i}")).unwrap();
    }
    let o = compact_cli(&f.root, 3, Some("readdir-eio:topics"));
    assert_io_cli(&o, "compaction whose trim cannot list topics/");
    // The new generation was published (durable) before the trim; readers skip the ids
    // below the base that the topic index still holds.
    assert_eq!(b.bounds().unwrap(), (3, 4));
    assert!(b.check().unwrap().ok(), "{:?}", b.check().unwrap().problems);
    let topic_ids = |root: &Path| -> Vec<u64> {
        let mut v = Vec::new();
        for e in fs::read_dir(root.join("topics")).unwrap() {
            let p = e.unwrap().path();
            if p.extension().and_then(|x| x.to_str()) == Some("idx") {
                for c in fs::read(&p).unwrap().chunks(8) {
                    v.push(u64::from_le_bytes(c.try_into().unwrap()));
                }
            }
        }
        v
    };
    assert_eq!(topic_ids(&f.root), vec![1, 2, 3, 4], "untrimmed");
    // A later compaction trims everything below its base.
    for i in 5..=6 {
        post(&b, "sa", &[], &format!("e{i}")).unwrap();
    }
    let o = compact_cli(&f.root, 5, None);
    assert!(o.status.success(), "{}", show(&o));
    assert_eq!(topic_ids(&f.root), vec![5, 6]);
}

#[test]
fn r14_check_that_cannot_list_does_not_pass() {
    let (f, b) = fx("r14-check");
    b.register("sa", "alpha", None).unwrap();
    b.register("sb", "beta", None).unwrap();
    post(&b, "sa", &["beta"], "one").unwrap();
    ok_cli(&cli(&f.root, None, &["check"], &[]));
    for spec in [
        "readdirent-eio:inbox",
        "readdir-eio:inbox",
        "readdirent-eio:topics",
        "readdir-eio:topics",
    ] {
        let o = cli(&f.root, None, &["check"], &[fault(spec)]);
        assert_cli_error(&o, 2, "CheckFailed", spec);
        assert!(
            String::from_utf8_lossy(&o.stdout).contains("cannot list"),
            "{spec}: {}",
            show(&o)
        );
    }
}

#[test]
fn r14_unlistable_agents_dir_is_no_second_tag() {
    let (f, b) = fx("r14-agents");
    b.register("sa", "alpha", None).unwrap();
    let gamma = f.root.join("agents/gamma.json");
    for spec in ["readdir-eio:agents", "readdirent-eio:agents"] {
        let o = cli(&f.root, Some("sa"), &["register", "gamma"], &[fault(spec)]);
        assert_io_cli(&o, spec);
        assert!(fs::symlink_metadata(&gamma).is_err(), "{spec}: no binding");
        let o = cli(&f.root, Some("sa"), &["whoami"], &[fault(spec)]);
        assert_io_cli(&o, spec);
    }
    // Control: the session already holds alpha.
    let o = cli(&f.root, Some("sa"), &["register", "gamma"], &[]);
    assert_cli_error(&o, 2, "SessionTagged", "second tag");
    assert!(fs::symlink_metadata(&gamma).is_err());
    assert_eq!(b.whoami("sa").unwrap().tag, "alpha");
}

fn store_cli(store: &Path, top: &Path, args: &[&str], spec: Option<&str>) -> Output {
    let mut c = Command::new(BIN);
    c.arg("--store")
        .arg(store)
        .arg("--top")
        .arg(top)
        .args(args)
        .env_remove("SYNAPSE_COORD_FAULT")
        .env_remove("CRUMB_SESSION")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(s) = spec {
        c.env("SYNAPSE_COORD_FAULT", s);
    }
    c.output().unwrap()
}

#[test]
fn r14_unlistable_store_dirs_keeps_presence_and_locks() {
    let f = scratch("r14-store");
    let top = f.root.join("wa");
    fs::create_dir_all(top.join("src")).unwrap();
    fs::create_dir_all(top.join("lib")).unwrap();
    fs::write(top.join("src/a.c"), "a").unwrap();
    fs::write(top.join("lib/b.c"), "b").unwrap();
    let store = f.root.join("store/crumb/v1");
    let cs = CoordStore::open(&store);
    let ws = Workspace::worktree(top.to_str().unwrap(), Holder::default());
    for (dir, t) in [("src", "a.c"), ("lib", "b.c")] {
        match cs.claim(&ws, "agent-a", dir, t, "work", None).unwrap() {
            ClaimOutcome::Claimed { .. } => {}
            o => panic!("expected a claim, got {o:?}"),
        }
    }
    let presence = store.join("agents/agent-a.json");
    assert!(fs::symlink_metadata(&presence).is_ok());
    let close = ["close", "agent-a", "src", "a.c", "modify"];
    for spec in ["readdir-eio:dirs", "readdirent-eio:dirs"] {
        // Closing a.c must see that agent-a still holds lib/b.c in another record.
        let o = store_cli(&store, &top, &close, Some(spec));
        assert!(!o.status.success(), "{spec}: {}", show(&o));
        assert!(
            fs::symlink_metadata(&presence).is_ok(),
            "{spec}: presence kept"
        );
        let o = store_cli(&store, &top, &["sniff", "agent-a", "."], Some(spec));
        assert!(!o.status.success(), "{spec}: sniff {}", show(&o));
    }
    let o = store_cli(
        &store,
        &top,
        &["sniff", "agent-a", "."],
        Some("readdir-eio:agents"),
    );
    assert!(!o.status.success(), "sniff without agents/: {}", show(&o));
    let s = cs.sniff(&ws, "agent-a", ".").unwrap();
    assert_eq!(s.locks.len(), 2, "both locks still held");
    // Control: the uninjected close releases a.c and keeps the presence (b.c is held).
    let o = store_cli(&store, &top, &close, None);
    assert!(o.status.success(), "{}", show(&o));
    assert!(
        fs::symlink_metadata(&presence).is_ok(),
        "agent-a still holds lib/b.c"
    );
    assert_eq!(cs.sniff(&ws, "agent-a", ".").unwrap().locks.len(), 1);
}

#[test]
fn r14_unanswerable_target_lookup_refuses_the_key() {
    let f = scratch("r14-key");
    let top = f.root.join("wa");
    fs::create_dir_all(top.join("src/x")).unwrap();
    fs::write(top.join("src/x/a.c"), "a").unwrap();
    let ws = Workspace::worktree(top.to_str().unwrap(), Holder::default());
    // Controls: an existing file keys from its directory; a path through a regular file
    // (ENOTDIR) is absent for every process and keys as written.
    assert_eq!(ws.target_key("x/a.c", "src").unwrap(), "src/x/a.c");
    assert_eq!(ws.target_key("a.c/z", "src/x").unwrap(), "a.c/z");
    // EIO on the lookup: keying it as "x/a.c" would let a second agent, which sees the
    // file, hold "src/x/a.c" at the same time.
    let store = f.root.join("store/crumb/v1");
    let o = store_cli(
        &store,
        &top,
        &["claim", "agent-a", "src", "x/a.c", "work"],
        Some("stat-eio:a.c"),
    );
    assert!(!o.status.success(), "{}", show(&o));
    assert!(
        !String::from_utf8_lossy(&o.stdout).contains("CLAIMED"),
        "{}",
        show(&o)
    );
    let o = store_cli(
        &store,
        &top,
        &["claim", "agent-a", "src", "x/a.c", "work"],
        None,
    );
    assert!(
        String::from_utf8_lossy(&o.stdout).contains("CLAIMED src/x/a.c"),
        "{}",
        show(&o)
    );
}
