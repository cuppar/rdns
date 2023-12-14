mod packet;

use packet::*;
use rand::Rng;
use std::net::{Ipv4Addr, UdpSocket};

fn main() {
    // let mut args = env::args();
    // if args.len() < 3 {
    //     println!("Usage: rdns <domain> <query-type>");
    //     println!();
    //     println!("    <query-type> is one of:");
    //     println!("        - a");
    //     println!("        - ns");
    //     println!("        - cname");
    //     println!("        - mx");
    //     println!("        - aaaa");
    //     process::exit(0);
    // }

    // let qname = args.nth(1).unwrap();
    // let qtype = match args.next().unwrap().to_lowercase().as_str() {
    //     "a" => QueryType::A,
    //     "ns" => QueryType::NS,
    //     "cname" => QueryType::CNAME,
    //     "mx" => QueryType::MX,
    //     "aaaa" => QueryType::AAAA,
    //     _ => QueryType::UNKNOWN(0),
    // };

    if let Err(err) = server_run() {
        println!("Error: {}", err);
    }
}

fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket> {
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

    DnsPacket::from_buffer(&mut res_buffer)
}

fn handle_query(socket: &UdpSocket) -> Result<()> {
    let mut req_buffer = BytePacketBuffer::new();

    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    let request = DnsPacket::from_buffer(&mut req_buffer)?;

    let mut response = DnsPacket::new();
    response.header.id = request.header.id;
    response.header.recursion_desired = true;
    response.header.recursion_available = true;
    response.header.response = true;

    if let Some(question) = request.questions.iter().next() {
        println!("Received query: {:?}", question);

        if let Ok(result) = recursion_lookup(&question.name, question.qtype) {
            response.questions.push(question.clone());
            response.header.rescode = result.header.rescode;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                response.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                response.authorities.push(rec);
            }
            for rec in result.resources {
                println!("Resource: {:?}", rec);
                response.resources.push(rec);
            }
        } else {
            response.header.rescode = ResultCode::SERVFAIL;
        }
    } else {
        response.header.rescode = ResultCode::FORMERR;
    }

    let mut res_buffer = BytePacketBuffer::new();
    response.write(&mut res_buffer)?;

    let len = res_buffer.pos;
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}

fn server_run() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;
    loop {
        match handle_query(&socket) {
            Ok(_) => {}
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}

fn recursion_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    let mut ns = "192.33.4.12".parse::<Ipv4Addr>().unwrap();

    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        let server = (ns, 53);

        // lookup
        let response = lookup(qname, qtype, server)?;

        // if has answer, then down
        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response);
        }
        // else if response report has not the qname, then done
        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }
        // else if has new ns ip, continue lookup
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        // else if has new ns name, recursion lookup the new_ns's ip
        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            // else return response
            None => return Ok(response),
        };

        let recursion_response = recursion_lookup(new_ns_name, QueryType::A)?;
        // if the new_ns has ip, then continue lookup
        if let Some(new_ns) = recursion_response.get_random_a() {
            ns = new_ns;
        }
        // else return response
        else {
            return Ok(response);
        }
    }
}
