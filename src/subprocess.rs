//! Bounded subprocess execution.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Run `program` with `args`, killing it once it exceeds `timeout`.
///
/// `Command::output()` waits forever. Every tool driven here parses input the
/// scanner did not author — `rustc`, `node`, `python3` — so a pathological input
/// would otherwise hang the scan until the process is killed by hand.
///
/// stdout and stderr are redirected to temporary files rather than pipes. A pipe
/// holds only 64 KiB; a child that fills one blocks until someone drains it, so a
/// large amount of compiler diagnostics would be misread as a hang.
pub fn run_with_timeout<I, S>(
    program: impl AsRef<OsStr>,
    args: I,
    timeout: Duration,
) -> io::Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let program = program.as_ref();
    let (out_path, err_path) = temp_paths();
    let out_file = File::create(&out_path)?;
    let err_file = File::create(&err_path)?;

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file))
        .spawn()?;

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().ok();
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let status = child.wait()?;

    let stdout = std::fs::read(&out_path)?;
    let stderr = std::fs::read(&err_path)?;
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&err_path);

    if timed_out {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{} exceeded its {}s timeout",
                program.to_string_lossy(),
                timeout.as_secs()
            ),
        ));
    }

    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn temp_paths() -> (std::path::PathBuf, std::path::PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let id = format!(
        "{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let dir = std::env::temp_dir();
    (
        dir.join(format!("baco-subprocess-{id}.out")),
        dir.join(format!("baco-subprocess-{id}.err")),
    )
}
