use std::net::UdpSocket;

/// DNS Header structure (12 bytes)
#[derive(Debug)]
struct DnsHeader {
    id: u16,              // Packet Identifier
    qr: u8,               // Query/Response Indicator (1 bit)
    opcode: u8,           // Operation Code (4 bits)
    aa: u8,               // Authoritative Answer (1 bit)
    tc: u8,               // Truncation (1 bit)
    rd: u8,               // Recursion Desired (1 bit)
    ra: u8,               // Recursion Available (1 bit)
    z: u8,                // Reserved (3 bits)
    rcode: u8,            // Response Code (4 bits)
    qdcount: u16,         // Question Count
    ancount: u16,         // Answer Record Count
    nscount: u16,         // Authority Record Count
    arcount: u16,         // Additional Record Count
}

impl DnsHeader {
    /// Parse header from incoming DNS query
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);

        Some(DnsHeader {
            id,
            qr: ((flags >> 15) & 0x1) as u8,
            opcode: ((flags >> 11) & 0xF) as u8,
            aa: ((flags >> 10) & 0x1) as u8,
            tc: ((flags >> 9) & 0x1) as u8,
            rd: ((flags >> 8) & 0x1) as u8,
            ra: ((flags >> 7) & 0x1) as u8,
            z: ((flags >> 4) & 0x7) as u8,
            rcode: (flags & 0xF) as u8,
            qdcount: u16::from_be_bytes([data[4], data[5]]),
            ancount: u16::from_be_bytes([data[6], data[7]]),
            nscount: u16::from_be_bytes([data[8], data[9]]),
            arcount: u16::from_be_bytes([data[10], data[11]]),
        })
    }

    /// Build response header bytes (12 bytes, big-endian)
    fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];

        // ID (16 bits)
        bytes[0..2].copy_from_slice(&self.id.to_be_bytes());

        // Flags (16 bits)
        let flags: u16 = ((self.qr as u16) << 15)
            | ((self.opcode as u16) << 11)
            | ((self.aa as u16) << 10)
            | ((self.tc as u16) << 9)
            | ((self.rd as u16) << 8)
            | ((self.ra as u16) << 7)
            | ((self.z as u16) << 4)
            | (self.rcode as u16);
        bytes[2..4].copy_from_slice(&flags.to_be_bytes());

        // Counts (16 bits each)
        bytes[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.arcount.to_be_bytes());

        bytes
    }
}

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                // Parse the incoming DNS query header
                if let Some(query_header) = DnsHeader::from_bytes(&buf[..size]) {
                    println!("Query header: {:?}", query_header);

                    // Build response header with required values
                    let response_header = DnsHeader {
                        id: query_header.id, // Echo the same ID
                        qr: 1,               // Response
                        opcode: 0,           // Standard query
                        aa: 0,               // Not authoritative
                        tc: 0,               // Not truncated
                        rd: 0,               // Recursion not desired
                        ra: 0,               // Recursion not available
                        z: 0,                // Reserved
                        rcode: 0,            // No error
                        qdcount: 0,          // No questions in response
                        ancount: 0,          // No answers
                        nscount: 0,          // No authority records
                        arcount: 0,          // No additional records
                    };

                    let response = response_header.to_bytes();
                    udp_socket
                        .send_to(&response, source)
                        .expect("Failed to send response");
                    println!("Sent {} byte response", response.len());
                }
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
