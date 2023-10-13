use std::io::{self};
use byteorder::{LittleEndian, WriteBytesExt};

pub struct Buffer {
    pub buffer: Vec<u8>,
}

impl Buffer {
    pub fn new() -> Buffer {
        Buffer { buffer: Vec::new() }
    }

    pub fn write(&mut self, value: Vec<u8>) -> io::Result<()> {
        self.buffer.extend(value);
        Ok(())
    }

    pub fn write_usize(&mut self, value: usize) -> io::Result<()> {
        self.buffer.write_u8(value.try_into().unwrap())?;
        Ok(())
    }

    pub fn write_uint64(&mut self, value: u64) -> io::Result<()> {
        self.buffer.write_u64::<LittleEndian>(value)?;
        Ok(())
    }

    pub fn write_uint32(&mut self, value: u32) -> io::Result<()> {
        self.buffer.write_u32::<LittleEndian>(value)?;
        Ok(())
    }

    pub fn write_uint16(&mut self, value: u16) -> io::Result<()> {
        self.buffer.write_u16::<LittleEndian>(value)?;
        Ok(())
    }

    pub fn write_uint8(&mut self, value: u8) -> io::Result<()> {
        self.buffer.push(value);
        Ok(())
    }

    pub fn write_float64(&mut self, value: f64) -> io::Result<()> {
        self.buffer.write_f64::<LittleEndian>(value)?;
        Ok(())
    }

    pub fn write_float32(&mut self, value: f32) -> io::Result<()> {
        self.buffer.write_f32::<LittleEndian>(value)?;
        Ok(())
    }
}



pub struct PacketRead {
    buffer: Vec<u8>,
}

impl PacketRead {
    pub fn new(buffer: Vec<u8>) -> PacketRead {
        PacketRead {buffer}
    }

    pub fn read_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buffer[0..8]);
        self.buffer.drain(0..8);
        u64::from_le_bytes(bytes)
    }

    pub fn read_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.buffer[0..4]);
        self.buffer.drain(0..4);
        u32::from_le_bytes(bytes)
    }

    pub fn read_u16(&mut self) -> u16 {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(&self.buffer[0..2]);
        self.buffer.drain(0..2);
        u16::from_le_bytes(bytes)
    }

    pub fn read_u8(&mut self) -> u8 {
        let mut bytes = [0u8; 1];
        bytes.copy_from_slice(&self.buffer[0..1]);
        self.buffer.drain(0..1);
        u8::from_le_bytes(bytes)
    }

    

}