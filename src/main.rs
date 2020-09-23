use bstr::io::BufReadExt;
use bstr::{BStr, BString, ByteSlice};
use nix::unistd::{getegid, geteuid, getgid, getuid, setresgid, setresuid, Gid, Pid, Uid, ROOT};
use std::env::consts::OS;
use std::ffi::OsString;
use std::fs::{self, read_dir, read_link, File};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};
use structopt::StructOpt;
use thiserror::Error;

mod config;

#[derive(Debug, Clone, StructOpt)]
#[structopt(
    name = "genie",
    about = r#"Handles transitions to the "bottle" namespace for systemd under WSL."#
)]
struct Opt {
    /// Display verbose progress messages
    #[structopt(short, long)]
    verbose: bool,

    /// Initialize the bottle (if necessary) only.
    #[structopt(short, long)]
    initialize: bool,

    /// Initialize the bottle (if necessary), and run a shell in it.
    #[structopt(short, long, conflicts_with_all(&["initialize"]))]
    shell: bool,

    /// Initialize the bottle (if necessary), and run the specified command in it.
    #[structopt(short, long, conflicts_with_all(&["initialize", "shell"]))]
    command: Option<OsString>,

    /// Shut down systemd and exit the bottle.
    #[structopt(short = "u", long, conflicts_with_all(&["initialize", "command", "command"]))]
    shutdown: bool,

    #[structopt(skip)]
    prefix: String,
}

fn main() {
    if let Err(e) = main2() {
        eprintln!("genie: {}", e);
        exit(1);
    }
}

fn main2() -> Result<(), CommandError> {
    let mut opt = Opt::from_args();
    if !opt.initialize && !opt.shell && opt.command.is_none() && !opt.shutdown {
        return Err(CommandError::NoCommand);
    }
    opt.prefix = infer_prefix();
    let opt = opt;

    if OS != "linux" {
        return Err(CommandError::NotLinux);
    }
    if is_wsl1().unwrap_or(false) {
        return Err(CommandError::IsWsl1);
    }
    if !is_wsl2() {
        return Err(CommandError::NotWsl2);
    }
    if geteuid() != ROOT {
        return Err(CommandError::NotRoot);
    }
    let config = crate::config::Configuration::read_from_file("/etc/genie.ini")?;
    log::debug!("config = {:?}", config);

    // Set up secure path.
    std::env::set_var("PATH", &config.secure_path);
    if opt.initialize {
        initialize(&opt, &config)
    } else if opt.shell {
        todo!("--shell")
    } else if let Some(_command) = &opt.command {
        todo!("--command")
    } else if opt.shutdown {
        shutdown(&opt, &config)
    } else {
        unreachable!();
    }
}

fn initialize(opt: &Opt, config: &crate::config::Configuration) -> Result<(), CommandError> {
    let systemd_pid: Option<Pid> = systemd_pid();

    if systemd_pid.is_some() {
        return Ok(());
    }

    rootify(|| -> Result<(), CommandError> {
        // Dump the envvars
        let dump_cmd = format!("{}/libexec/genie/dumpwslenv.sh", opt.prefix);
        let result = Command::new(&dump_cmd)
            .output()
            .map_err(|e| CommandError::CommandFailed(dump_cmd.clone(), e))?;
        if !result.status.success() {
            return Err(CommandError::CommandStatus(dump_cmd.clone(), result.status));
        }

        // TODO: updateHostname

        // Run systemd in a container.
        let result = Command::new("daemonize")
            .arg(&config.unshare)
            .args(&["-fp", "--propagation", "shared", "--mount-proc", "systemd"])
            .output()
            .map_err(|e| CommandError::CommandFailed("daemonize".into(), e))?;
        if !result.status.success() {
            return Err(CommandError::CommandStatus(
                "daemonize".into(),
                result.status,
            ));
        }

        wait_for_systemd_up(Instant::now() + Duration::from_secs(16));

        Ok(())
    })
}

fn shutdown(_opt: &Opt, _config: &crate::config::Configuration) -> Result<(), CommandError> {
    let systemd_pid: Option<Pid> = systemd_pid();

    let systemd_pid = systemd_pid.unwrap_or_else(|| todo!("error handling"));
    if systemd_pid.as_raw() == 1 {
        todo!("error handling");
    }

    rootify(|| -> Result<(), CommandError> {
        // Call systemctl to trigger shutdown.
        let result = Command::new("nsenter")
            .args(&[
                "-t",
                &systemd_pid.to_string(),
                "-m",
                "-p",
                "systemctl",
                "poweroff",
            ])
            .output()
            .map_err(|e| CommandError::CommandFailed("nsenter".into(), e))?;
        if !result.status.success() {
            return Err(CommandError::CommandStatus("nsenter".into(), result.status));
        }

        wait_for_exit(systemd_pid, Instant::now() + Duration::from_secs(16));

        // TODO: updateHostname

        Ok(())
    })
}

fn rootify<R>(f: impl FnOnce() -> R) -> R {
    struct UserRootifyGuard {
        ruid: Uid,
        euid: Uid,
    }
    impl Drop for UserRootifyGuard {
        fn drop(&mut self) {
            setresuid(self.ruid, self.euid, Uid::from_raw(!0)).ok();
        }
    }
    struct GroupRootifyGuard {
        rgid: Gid,
        egid: Gid,
    }
    impl Drop for GroupRootifyGuard {
        fn drop(&mut self) {
            setresgid(self.rgid, self.egid, Gid::from_raw(!0)).ok();
        }
    }

    let _user_guard = UserRootifyGuard {
        ruid: getuid(),
        euid: geteuid(),
    };
    setresuid(ROOT, ROOT, Uid::from_raw(!0)).expect("setresuid failed");
    let _group_guard = GroupRootifyGuard {
        rgid: getgid(),
        egid: getegid(),
    };
    setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(!0)).expect("setresgid failed");

    f()
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("one of the commands -i, -s, or -c must be supplied.")]
    NoCommand,
    #[error("not executing on the Linux platform - how did we get here?")]
    NotLinux,
    #[error("systemd is not supported under WSL 1.")]
    IsWsl1,
    #[error("not executing under WSL 2 - how did we get here?")]
    NotWsl2,
    #[error("must execute as root - has the setuid bit gone astray?")]
    NotRoot,
    #[error("genie.ini: {0}")]
    GenieIni(#[from] crate::config::ConfigurationError),
    #[error("command failed: {0}: {1}")]
    CommandFailed(String, #[source] io::Error),
    #[error("command failed with status {1:?}: {0}")]
    CommandStatus(String, std::process::ExitStatus),
}

fn systemd_pid() -> Option<Pid> {
    fn systemd_pid_of(entry: &std::fs::DirEntry) -> Option<Pid> {
        // Return None if filename is not an integer
        let filename = entry.file_name();
        let filename = filename.to_str()?;
        let pid = filename.parse::<nix::libc::pid_t>().ok()?;

        let cmdline_path = {
            let mut path = entry.path();
            path.push("cmdline");
            // Ignore errors, such as EPERM
            fs::read(path).ok()?
        };
        if cmdline_path == b"systemd\0" {
            Some(Pid::from_raw(pid))
        } else {
            None
        }
    }

    let proc = read_dir("/proc").expect("failed to read /proc");
    for entry in proc {
        // Ignore errors, such as EPERM
        if let Ok(entry) = entry {
            if let Some(pid) = systemd_pid_of(&entry) {
                return Some(pid);
            }
        }
    }

    None
}

fn wait_for_systemd_up(deadline: Instant) {
    loop {
        if systemd_pid().is_some() {
            return;
        }
        if Instant::now() > deadline {
            return;
        }
        sleep(Duration::from_millis(30));
    }
}

fn wait_for_exit(pid: Pid, deadline: Instant) {
    let path = PathBuf::from(format!("/proc/{}", pid));
    loop {
        if !path.exists() {
            return;
        }
        if Instant::now() > deadline {
            return;
        }
        sleep(Duration::from_millis(10));
    }
}

fn infer_prefix() -> String {
    fn infer_prefix_impl() -> Option<String> {
        let exec_path = read_link("/proc/self/exe").ok()?;
        let exec_dir = exec_path.parent()?;
        if exec_dir == Path::new("/usr/bin") {
            return Some("/usr".into());
        } else if exec_dir == Path::new("/usr/local/bin") {
            return Some("/usr/local".into());
        }
        None
    }

    infer_prefix_impl().unwrap_or_else(|| "/usr/local".into())
}

fn is_wsl1() -> io::Result<bool> {
    let f = BufReader::new(File::open("/proc/self/mounts")?);
    for mnt in f.byte_lines() {
        let mnt = BString::from(mnt?);
        let deets = mnt.split_str(" ").map(<&BStr>::from).collect::<Vec<_>>();
        if let [_, mount_point, fs, ..] = deets[..] {
            if mount_point == "/" {
                return Ok(fs == "lxfs" || fs == "wslfs");
            }
        }
    }

    Ok(false)
}

fn is_wsl2() -> bool {
    Path::new("/run/WSL").exists()
}
