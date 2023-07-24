use std::os::unix::net::{UnixStream, UnixListener, SocketAddr};

mod ssh_agent;
mod ssh_agent_types;
mod message_builder;
mod data_reader;
use ssh_agent::*;

fn handle_client(agent: &mut SshAgent, mut stream: UnixStream, _: SocketAddr) {
    use std::io::{Write, BufReader, BufRead};
    let mut buf_reader = BufReader::new(&stream);
    if let Ok(data) = buf_reader.fill_buf() {
        println!("in: {:?}", data);
        if data.len() >= 5 {
            let mut data = agent.handle_msg(data);
            println!("out: {:?}", data);
            let _ = stream.write_all(data.build());
        }
    }
}

fn main() {
    let listener = UnixListener::bind("/tmp/rust-uds.sock").unwrap();
    let mut agent = SshAgent::new();

    loop {
        match listener.accept() {
            Ok((socket, addr)) => {
                handle_client(&mut agent, socket, addr);
            },
            Err(_e) => return,
        }
    }

}
