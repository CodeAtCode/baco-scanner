//! Keep crash artefacts out of the working directory.

/// Zero `RLIMIT_CORE` for this process and, by inheritance, for every child it
/// spawns.
///
/// The limit survives fork and exec, so one call at startup covers all of the
/// external tools the scanner drives: semgrep, joern, git, rustc, node, python3
/// and docker. Without it, any of them segfaulting while handling untrusted
/// input leaves a multi-megabyte core file in the directory the user ran from.
///
/// This is deliberately a limit rather than a flag on each `Command`: the spawn
/// sites are spread over nine modules, and a guard repeated at every call is a
/// guard the next contributor forgets.
pub fn suppress_core_dumps() {
    let rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: glibc's setrlimit is a bare syscall wrapper -- it takes no lock,
    // allocates nothing and touches no global state, so it is safe both here at
    // startup and in a child's pre_exec between fork and exec. The result is
    // discarded on purpose: a leftover core file is not worth aborting a scan.
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
}

/// Apply [`suppress_core_dumps`] in a child, for use as `Command::pre_exec`.
///
/// Kept separate from the startup call because it also holds when baco runs as
/// a library, where `main` never executed and the limit was never lowered.
pub fn disable_core_dumps() -> std::io::Result<()> {
    suppress_core_dumps();
    Ok(())
}
