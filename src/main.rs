use std::os::unix::net::{UnixStream, UnixListener, SocketAddr};

mod ssh_agent;
mod ssh_agent_types;
mod message_builder;
mod data_reader;
use ssh_agent::*;

fn read_packet(stream: &UnixStream) -> Result<Vec<u8>,std::io::Error> {
    use std::io::{Read, BufReader, IoSliceMut};
    let mut reader = BufReader::new(stream);
    let mut len: [u8;4] = [0;4];
    let mut in_data: [u8;4096] = [0;4096];
    let mut bytes_read = reader.read_vectored(&mut [IoSliceMut::new(&mut len), IoSliceMut::new(&mut in_data)])?;
    if bytes_read < 4 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }

    let len = (
        ((len[0] as u32) << 24) |
        ((len[1] as u32) << 16) |
        ((len[2] as u32) << 8) |
        (len[3] as u32)
    ) as usize;

    bytes_read -= 4;
    let mut data: Vec<u8> = Vec::with_capacity(len);
    data.extend_from_slice(&in_data[0..bytes_read]);
    data.resize(len, 0);
    let mut bytes_needed = len - bytes_read;
    while bytes_needed > 0 {
        let got = reader.read(&mut data.as_mut_slice()[ bytes_read..])?;
        bytes_needed -= got;
        bytes_read += got;
    }

    Ok(data)
}


mod tests {
    fn u32_to_byte_be(n: u32) -> [u8;4] {
        [
            ((n & 0xFF000000) >> 24) as u8,
            ((n & 0x00FF0000) >> 16) as u8,
            ((n & 0x0000FF00) >> 8) as u8,
            (n & 0x000000FF) as u8
        ]
    }
    use super::*;
    #[test]
    fn test_read_packet() {
        use std::os::unix::net::{UnixStream, UnixListener, SocketAddr};
        use std::io::Write;
        let (mut sock1, mut sock2) = match UnixStream::pair() {
            Ok((sock1, sock2)) => (sock1, sock2),
            Err(e) => {
                panic!("Couldn't create a pair of sockets: {e:?}");
            }
        };
        let mut data: [u8;8192] = [1;8192];
        let mut len = u32_to_byte_be(data.len() as u32);
        let bytes = sock1.write(&len).unwrap();
        let bytes = sock1.write(&data).unwrap();
        let vec = read_packet(&sock2).unwrap();
        println!("vec {:?}", vec);
        assert_eq!(&vec, &data);
    }
}

fn handle_client(agent: &mut SshAgent, mut stream: UnixStream, _: SocketAddr) -> Result<(), std::io::Error> {
    use std::io::Write;
    if let Ok(data) = read_packet(&stream) {
        println!("in: {:?}", data);
        if data.len() >= 1 {
            let mut data = agent.handle_msg(&data);
            println!("out: {:?}", data);
            match stream.write_all(data.build()) {
                Err(e) => {},
                Ok(_) => {},
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = UnixListener::bind("/tmp/rust-uds.sock")?;
    let mut agent = SshAgent::new();

    loop {
        match listener.accept() {
            Ok((socket, addr)) => {
                match handle_client(&mut agent, socket, addr) {
                    Err(_e) => { todo!() },
                    Ok(_) => {},
                }
            },
            Err(e) => return Err(Box::new(e)),
        }
    }
}
