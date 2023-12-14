mod packet;

use std::net::UdpSocket;

use packet::*;

fn main() {
    if let Err(err) = run() {
        println!("Error: {}", err);
    }
}

fn run() -> Result<()> {
    let qname = "yahoo.com";
    let qtype = QueryType::MX;

    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 22222))?;

    let mut req_packet = DnsPacket::new();

    req_packet.header.id = 9999;
    req_packet.header.questions = 1;
    req_packet.header.recursion_desired = true;
    req_packet.questions.push(DnsQuestion::new(qname, qtype));

    let mut req_buffer = BytePacketBuffer::new();
    req_packet.write(&mut req_buffer)?;

    socket.send_to(&req_buffer.buf[..req_buffer.pos], server)?;

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;
    println!("{}", res_packet);

    Ok(())
}
