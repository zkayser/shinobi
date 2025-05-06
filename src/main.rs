use std::error::Error;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("127.0.0.1:8080").await?;
    println!("Listening on 127.0.0.1:8080");

    let dest = "127.0.0.1:8081";

    let bytes_sent = socket.send_to(b"Hello, QUIC!", dest).await?;
    println!("Send {} bytes", bytes_sent);

    let mut buf = [0u8; 1024];

    let (len, addr) = socket.recv_from(&mut buf).await?;
    println!("Received {} bytes from {}", len, addr);

    Ok(())
}
