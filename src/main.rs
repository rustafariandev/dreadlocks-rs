use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::sync::atomic::{AtomicIsize, Ordering};

mod data_reader;
mod dsa_key;
mod ecdsa_key;
mod ed25519_key;
mod error;
mod message_builder;
mod rsa_key;
mod ssh_agent;
mod ssh_agent_types;
mod utils;
use clap::{Parser, ValueEnum};
use message_builder::*;

use libc::{accept4, sockaddr_un};
use nix::libc::{prctl, PR_SET_PDEATHSIG};
use nix::sys::signal::{self, kill, SigHandler, SIGHUP, SIGINT, SIGPIPE, SIGTERM};
use nix::sys::stat::{umask, Mode};
use nix::unistd::Pid;
use nix::unistd::{dup2, setpgid};
use ssh_agent::*;
use std::fs::File;
use std::io;
use std::mem;
use std::os::fd::IntoRawFd;
use std::os::fd::RawFd;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net;
use std::path::PathBuf;
use tempdir::TempDir;

trait RawAccept {
    fn raw_accept(&self) -> std::io::Result<UnixStream>;
}

impl RawAccept for UnixListener {
    fn raw_accept(&self) -> std::io::Result<UnixStream> {
        let fd = self.as_raw_fd();
        let mut storage: sockaddr_un = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&storage) as libc::socklen_t;
        let sock = unsafe {
            accept4(
                fd,
                &mut storage as *mut _ as *mut _,
                &mut len,
                libc::SOCK_CLOEXEC,
            )
        };
        if sock < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let stream = unsafe { UnixStream::from_raw_fd(sock) };
        Ok(stream)
    }
}

fn stdio_to_dev_null() {
    if let Ok(file) = File::open("/dev/null") {
        let fd = file.as_raw_fd();
        let _ = dup2(fd, 0).expect("dup stdin  failed");
        let _ = dup2(fd, 1).expect("dup stdout failed");
        let _ = dup2(fd, 2).expect("dup stderr failed");
        if fd <= 2 {
            let _ = file.into_raw_fd();
        }
    }
}

fn read_packet(stream: &UnixStream) -> Result<Vec<u8>, std::io::Error> {
    use std::io::{BufReader, IoSliceMut, Read};
    let mut reader = BufReader::new(stream);
    let mut len = [0_u8; 4];
    let mut in_data = [0_u8; 4096];
    let mut bytes_read =
        reader.read_vectored(&mut [IoSliceMut::new(&mut len), IoSliceMut::new(&mut in_data)])?;
    if bytes_read == 0 {
        return Ok(Vec::new());
    }

    if bytes_read < 4 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }

    let len = (((len[0] as u32) << 24)
        | ((len[1] as u32) << 16)
        | ((len[2] as u32) << 8)
        | (len[3] as u32)) as usize;

    bytes_read -= 4;
    let mut data: Vec<u8> = Vec::with_capacity(len);
    data.extend_from_slice(&in_data[0..bytes_read]);
    data.resize(len, 0);
    let mut bytes_needed = len - bytes_read;
    while bytes_needed > 0 {
        let got = reader.read(&mut data.as_mut_slice()[bytes_read..])?;
        bytes_needed -= got;
        bytes_read += got;
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    fn u32_to_byte_be(n: u32) -> [u8; 4] {
        [
            ((n & 0xFF000000) >> 24) as u8,
            ((n & 0x00FF0000) >> 16) as u8,
            ((n & 0x0000FF00) >> 8) as u8,
            (n & 0x000000FF) as u8,
        ]
    }
    use super::*;
    #[test]
    fn test_read_packet() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let (mut sock1, sock2) = match UnixStream::pair() {
            Ok((sock1, sock2)) => (sock1, sock2),
            Err(e) => {
                panic!("Couldn't create a pair of sockets: {e:?}");
            }
        };
        let data = [1_u8; 8192];
        let len = u32_to_byte_be(data.len() as u32);
        let _ = sock1.write(&len).unwrap();
        let _ = sock1.write(&data).unwrap();
        let vec = read_packet(&sock2).unwrap();
        assert_eq!(&vec, &data);
    }
}

const FAILURE_MSG: [u8; 5] = [0, 0, 0, 1, 5];

fn handle_client(agent: &mut SshAgent, mut stream: UnixStream) -> Result<(), std::io::Error> {
    use std::io::Write;
    loop {
        let data = read_packet(&stream)?;
        if data.is_empty() {
            return Ok(());
        }
        let mut msg: MessageBuilder;
        let out = match agent.handle_msg(&data) {
            Err(_e) => &FAILURE_MSG,
            Ok(msg_build) => {
                msg = msg_build;
                msg.build()
            }
        };
        stream.write_all(out)?;
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug, Default)]
enum Fingerprint {
    #[default]
    MD5,
    Sha256,
}

#[derive(Parser, Default, Debug)]
struct Cli {
    /// Bind Address
    #[arg(short = 'a')]
    bind_address: Option<String>,

    /// C-shell commands
    #[arg(short = 'c', required = false)]
    c_shell: bool,

    /// Debug
    #[arg(short = 'd', required = false)]
    debug: bool,

    /// Foreground
    #[arg(short = 'D', required = false)]
    foreground: bool,

    /// Fingerprint hash
    #[arg(short='E', value_enum, default_value_t = Fingerprint::MD5)]
    fingerprint: Fingerprint,

    /// Kill current agent
    #[arg(short = 'k', required = false)]
    kill: bool,

    /// bourne-shell commands
    #[arg(short = 's', required = false)]
    bourne_shell: bool,

    /// Lifetime
    #[arg(short='t', default_value_t = String::from("0"))]
    life_time: String,

    commands: Vec<String>,
}

const DREADLOCKS_AGENT_PID_ENV_NAME: &str = "DREADLOCKS_AGENT_PID";
const DREADLOCKS_SOCK_ENV_NAME: &str = "SSH_AUTH_SOCK";

struct SocketPathInfo {
    dir: Option<tempdir::TempDir>,
    sock_path: PathBuf,
}

impl SocketPathInfo {
    fn keep(&mut self) -> Option<PathBuf> {
        match self.dir.take() {
            None => None,
            Some(dir) => {
                let path = dir.into_path();
                Some(path)
            }
        }
    }
}

impl Cli {
    fn check_c_shell(&mut self) {
        if self.c_shell || self.bourne_shell {
            return;
        }

        if let Ok(pid_str) = std::env::var("SHELL") {
            self.c_shell = pid_str.ends_with("csh");
        }
    }

    fn get_sock_path(&self) -> Result<SocketPathInfo, std::io::Error> {
        Ok(match &self.bind_address {
            Some(sock_path) => SocketPathInfo {
                sock_path: sock_path.clone().into(),
                dir: None,
            },
            None => {
                let dir = TempDir::new("dreadlocks")?;
                let sock_path = dir.path().join("agent.sock");
                SocketPathInfo {
                    dir: Some(dir),
                    sock_path,
                }
            }
        })
    }
}

static RUNNING: AtomicIsize = AtomicIsize::new(1);

fn run(listener: UnixListener) -> Result<(), Box<dyn std::error::Error>> {
    let mut agent = SshAgent::new();
    while RUNNING.load(Ordering::Relaxed) == 1 {
        match listener.raw_accept() {
            Ok(socket) => {
                if let Err(e) = handle_client(&mut agent, socket) {
                    eprintln!("Error {}", e)
                }
            },
            Err(e) => match e.kind() {
                std::io::ErrorKind::Interrupted => {
                    eprintln!("Interrupted");
                    continue;
                }
                _ => {
                    eprintln!("Accept error: {e}");
                    return Err(Box::new(e));
                }
            },
        }
    }
    Ok(())
}

extern "C" fn stop_handler(_: nix::libc::c_int) {
    RUNNING.store(0, Ordering::Relaxed);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cli = Cli::parse();
    cli.check_c_shell();
    if cli.kill {
        let pid = std::env::var(DREADLOCKS_AGENT_PID_ENV_NAME)
            .map_err(|_| format!("{DREADLOCKS_AGENT_PID_ENV_NAME} not set, cannot kill agent"))?;
        let pid: i32 = pid
            .parse::<i32>()
            .map_err(|_| format!("{DREADLOCKS_AGENT_PID_ENV_NAME}=\"{pid}\", not a valid pid"))?;
        kill(Pid::from_raw(pid), SIGTERM)?;
        let unset = if cli.c_shell { "unsetenv" } else { "unset" };
        println!("{unset} {DREADLOCKS_AGENT_PID_ENV_NAME};");
        println!("{unset} {DREADLOCKS_SOCK_ENV_NAME};");
        println!("echo Agent pid {pid} killed;");
        return Ok(());
    }

    let prev_mask = umask(Mode::from_bits(0o0177).ok_or("")?);
    let mut sock_path_info = cli.get_sock_path()?;
    umask(prev_mask);
    let ppid = nix::unistd::getpid();
    let listener = UnixListener::bind(&sock_path_info.sock_path)?;
    if cli.debug || cli.foreground {
        if cli.c_shell {
            println!(
                "setenv {DREADLOCKS_SOCK_ENV_NAME} {};",
                sock_path_info.sock_path.display()
            );
        } else {
            println!(
                "{DREADLOCKS_SOCK_ENV_NAME}=\"{}\"; export {DREADLOCKS_SOCK_ENV_NAME};",
                sock_path_info.sock_path.display()
            );
        }

        println!("echo Agent pid {};", ppid);
    } else {
        match unsafe { nix::unistd::fork() } {
            Ok(nix::unistd::ForkResult::Parent { child }) => {
                if cli.commands.is_empty() {
                    if cli.c_shell {
                        println!(
                            "setenv {DREADLOCKS_SOCK_ENV_NAME} {};",
                            sock_path_info.sock_path.display()
                        );
                        println!("setenv {DREADLOCKS_AGENT_PID_ENV_NAME} {};", child);
                    } else {
                        println!(
                            "{DREADLOCKS_SOCK_ENV_NAME}={}; export {DREADLOCKS_SOCK_ENV_NAME};",
                            sock_path_info.sock_path.display()
                        );
                        println!("{DREADLOCKS_AGENT_PID_ENV_NAME}={};export {DREADLOCKS_AGENT_PID_ENV_NAME};", child);
                    }
                    println!("echo Agent pid {};", child);
                    return Ok(());
                }
                let _ = sock_path_info.keep();
                std::env::set_var(DREADLOCKS_SOCK_ENV_NAME, &sock_path_info.sock_path);
                let pid_str = format!("{}", child);
                std::env::set_var(DREADLOCKS_AGENT_PID_ENV_NAME, pid_str);
                let process = std::ffi::CString::new(cli.commands[0].clone())
                    .map_err(|_| "Cannot convert")?;
                let commands = cli
                    .commands
                    .iter()
                    .map(|s| std::ffi::CString::new(s.clone()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| "Cannot convert")?;
                let _ = nix::unistd::execvp(&process, &commands);
                return Err(format!("Cannot call {}", cli.commands[0]).as_str().into());
            }
            Ok(nix::unistd::ForkResult::Child) => {
                if !cli.commands.is_empty() {
                    unsafe {
                        prctl(PR_SET_PDEATHSIG, SIGTERM);
                    }
                    kill(ppid, None).map_err(|_| "Parent died")?;
                } else {
                    let _ = nix::unistd::setsid();
                }
                stdio_to_dev_null();
            }
            Err(e) => return Err(Box::new(e)),
        }
    }

    unsafe {
        let handler = SigHandler::Handler(stop_handler);
        signal::signal(SIGPIPE, SigHandler::SigIgn).unwrap();
        let action = nix::sys::signal::SigAction::new(
            handler,
            nix::sys::signal::SaFlags::empty(),
            nix::sys::signal::SigSet::empty(),
        );
        if cli.debug || cli.foreground {
            let _ = nix::sys::signal::sigaction(SIGINT, &action);
        } else {
            signal::signal(SIGINT, SigHandler::SigIgn).unwrap();
        }

        let _ = nix::sys::signal::sigaction(SIGHUP, &action);
        let _ = nix::sys::signal::sigaction(SIGTERM, &action);
    }

    return run(listener);
}
