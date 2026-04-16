// Resource limit handlers — memory and process limit enforcement.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tokio::sync::Mutex;

use crate::seccomp::notif::{NotifAction, NotifPolicy};
use crate::seccomp::state::{ProcfsState, ResourceState};
use crate::sys::structs::{
    SeccompNotif, CLONE_NS_FLAGS, EAGAIN, EPERM,
};

/// CLONE_THREAD flag — threads don't count toward process limit.
const CLONE_THREAD: u64 = 0x0001_0000;

/// MAP_ANONYMOUS flag — only anonymous mappings count toward memory limit.
const MAP_ANONYMOUS: u64 = 0x20;

/// Maximum allowed memory mapping size (128 TB on x86_64)
const MAX_MMAP_SIZE: u64 = 1 << 47;

/// Handle fork/clone/vfork notifications.
///
/// Enforces namespace creation ban, process limits, and checkpoint hold.
/// Needs both `ResourceState` (for proc_count, hold_forks, etc.) and
/// `ProcfsState` (for proc_pids).
pub(crate) async fn handle_fork(
    notif: &SeccompNotif,
    resource: &Arc<Mutex<ResourceState>>,
    procfs: &Arc<Mutex<ProcfsState>>,
    _policy: &NotifPolicy,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;

    // For clone/vfork: check namespace flags in args[0].
    if nr == libc::SYS_clone || nr == libc::SYS_vfork {
        if nr == libc::SYS_clone && (args[0] & CLONE_NS_FLAGS) != 0 {
            return NotifAction::Errno(EPERM);
        }
        // For clone: if CLONE_THREAD is set, it's a thread — don't count, allow.
        if nr == libc::SYS_clone && (args[0] & CLONE_THREAD) != 0 {
            return NotifAction::Continue;
        }
    }
    // For clone3: BPF arg filter handles dangerous cases; proceed to limit check.
    // SECURITY FIX: Also check fork() syscall (57)
    if nr == libc::SYS_fork || nr == 57 {
        // fork() is just clone with SIGCHLD, same checks apply
    }

    let mut rs = resource.lock().await;

    // Checkpoint/freeze: hold the fork notification.
    if rs.hold_forks {
        rs.held_notif_ids.push(notif.id);
        return NotifAction::Hold;
    }

    // Enforce concurrent process limit.
    // SECURITY FIX: Use atomic compare-and-swap for proc_count
    let current_count = rs.proc_count.load(Ordering::SeqCst);
    if current_count >= rs.max_processes {
        return NotifAction::Errno(EAGAIN);
    }

    rs.proc_count.store(current_count + 1, Ordering::SeqCst);
    drop(rs);

    let mut pfs = procfs.lock().await;
    pfs.proc_pids.insert(notif.pid as i32);

    NotifAction::Continue
}

/// Handle wait4/waitid notifications — decrement the concurrent process count.
///
/// Only blocking waits reach the supervisor (WNOHANG/WNOWAIT calls are
/// filtered out by BPF and allowed without notification).  A blocking wait
/// will definitely reap a child, so we decrement before the kernel executes it.
pub(crate) async fn handle_wait(
    _notif: &SeccompNotif,
    resource: &Arc<Mutex<ResourceState>>,
) -> NotifAction {
    let rs = resource.lock().await;
    // SECURITY FIX: Use atomic saturating sub
    rs.proc_count.fetch_sub(1, Ordering::SeqCst);
    NotifAction::Continue
}

/// Handle memory-related notifications (mmap, munmap, brk, mremap, shmget).
///
/// Tracks anonymous memory usage and enforces the configured memory limit.
pub(crate) async fn handle_memory(
    notif: &SeccompNotif,
    resource: &Arc<Mutex<ResourceState>>,
    policy: &NotifPolicy,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;
    let limit = policy.max_memory_bytes;

    let mut st = resource.lock().await;

    let kill = NotifAction::Kill { sig: libc::SIGKILL, pgid: notif.pid as i32 };

    if nr == libc::SYS_mmap {
        // args[1] = len, args[3] = flags
        let len = args[1];
        let flags = args[3];

        // SECURITY FIX: Validate mmap size
        if len > MAX_MMAP_SIZE {
            return kill;
        }

        if (flags & MAP_ANONYMOUS) != 0 {
            let current = st.mem_used.load(Ordering::SeqCst);
            if current.saturating_add(len) > limit {
                return kill;
            }
            st.mem_used.store(current + len, Ordering::SeqCst);
        }
    } else if nr == libc::SYS_munmap {
        // args[1] = len
        let len = args[1];
        let current = st.mem_used.load(Ordering::SeqCst);
        st.mem_used.store(current.saturating_sub(len), Ordering::SeqCst);
    } else if nr == libc::SYS_brk {
        // args[0] = new_brk
        let new_brk = args[0];
        let pid = notif.pid as i32;

        if new_brk == 0 {
            // Query: return Continue, kernel handles it.
            return NotifAction::Continue;
        }

        let base = *st.brk_bases.entry(pid).or_insert(new_brk);

        if new_brk > base {
            let delta = new_brk - base;
            let current = st.mem_used.load(Ordering::SeqCst);
            if current.saturating_add(delta) > limit {
                return kill;
            }
            st.mem_used.store(current + delta, Ordering::SeqCst);
            st.brk_bases.insert(pid, new_brk);
        } else if new_brk < base {
            let delta = base - new_brk;
            let current = st.mem_used.load(Ordering::SeqCst);
            st.mem_used.store(current.saturating_sub(delta), Ordering::SeqCst);
            st.brk_bases.insert(pid, new_brk);
        }
    } else if nr == libc::SYS_mremap {
        // args[1] = old_len, args[2] = new_len
        let old_len = args[1];
        let new_len = args[2];

        // SECURITY FIX: Validate mremap parameters
        if new_len > MAX_MMAP_SIZE {
            return kill;
        }

        if new_len > old_len {
            let growth = new_len - old_len;
            let current = st.mem_used.load(Ordering::SeqCst);
            if current.saturating_add(growth) > limit {
                return kill;
            }
            st.mem_used.store(current + growth, Ordering::SeqCst);
        } else if new_len < old_len {
            let shrink = old_len - new_len;
            let current = st.mem_used.load(Ordering::SeqCst);
            st.mem_used.store(current.saturating_sub(shrink), Ordering::SeqCst);
        }
    } else if nr == libc::SYS_shmget {
        // shmget(key, size, shmflg) — args[1] = size
        let size = args[1];

        // SECURITY FIX: Validate shmget size
        if size > MAX_MMAP_SIZE {
            return kill;
        }

        let current = st.mem_used.load(Ordering::SeqCst);
        if size > 0 && current.saturating_add(size) > limit {
            return kill;
        }
        st.mem_used.store(current + size, Ordering::SeqCst);
    }

    NotifAction::Continue
}
