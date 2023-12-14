mod packet;

use std::{env, net::UdpSocket, process};

use packet::*;
use rand::Rng;

fn main() {
    let mut args = env::args();
    if args.len() < 3 {
        println!("Usage: rdns <domain> <query-type>");
        println!();
        println!("    <query-type> is one of:");
        println!("        - a");
        println!("        - ns");
        println!("        - cname");
        println!("        - mx");
        println!("        - aaaa");
        process::exit(1);
    }

    let qname = args.nth(1).unwrap();
    let qtype = match args.next().unwrap().to_lowercase().as_str() {
        "a" => QueryType::A,
        "ns" => QueryType::NS,
        "cname" => QueryType::CNAME,
        "mx" => QueryType::MX,
        "aaaa" => QueryType::AAAA,
        _ => QueryType::UNKNOWN(0),
    };

    if let Err(err) = run(qname.as_str(), qtype) {
        println!("Error: {}", err);
    }
}

fn run(qname: &str, qtype: QueryType) -> Result<()> {
    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 22222))?;

    let mut req_packet = DnsPacket::new();

    req_packet.header.id = rand::thread_rng().gen();
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
