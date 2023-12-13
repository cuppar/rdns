use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

const BUF_SIZE: usize = 512;

pub struct BytePacketBuffer {
    pub buf: [u8; BUF_SIZE],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> Self {
        BytePacketBuffer {
            buf: [0; BUF_SIZE],
            pos: 0,
        }
    }
    fn pos(&self) -> usize {
        self.pos
    }
    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
    }
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }
    fn read(&mut self) -> Result<u8> {
        self.not_end_of_buf(self.pos)?;
        let res = self.buf[self.pos];
        self.step(1)?;
        Ok(res)
    }
    fn not_end_of_buf(&self, pos: usize) -> Result<()> {
        if pos > BUF_SIZE {
            return Err("End of buffer".into());
        }
        Ok(())
    }
    fn get(&self, pos: usize) -> Result<u8> {
        self.not_end_of_buf(pos)?;
        Ok(self.buf[pos])
    }
    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        self.not_end_of_buf(start + len)?;
        Ok(&self.buf[start..start + len])
    }
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32);
        Ok(res)
    }
    
}

#[test]
fn t() {
    assert_eq!(1 + 2..3 + 4, 3..7);
}
