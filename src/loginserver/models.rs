use log::{info, error};
use tokio::{net::TcpStream, io::AsyncReadExt};

use crate::{loginserver::crypt::{blowfish_decrypt, checksum}, packet};

pub struct Account {
    id: u64,
    user_name: String,
    password: String,
    access_level: u8,
}

pub struct Client {
    pub account: Option<Account>,
    pub session_id: Vec<u8>,
    pub socket: Option<TcpStream>,
}

pub struct GameServer {
    pub id: u8,
    pub socket: Option<TcpStream>
}

impl GameServer {
    pub fn new() -> GameServer {
        GameServer { id: 0, socket: None }
    }

    pub async fn receive(&mut self) -> Result<(u8, Vec<u8>), String> {

        if let Some(sock) = self.socket.as_mut() {
            let mut header = [0; 2];
            let n = sock.read_exact(&mut header).await.unwrap();

            if n < 2 {
                return Err("An error occured while reading the packet header.".to_string());
            }
            
            //calculate the size of the packet
            let mut size = header[0] as usize;
            //sum the second byte shifted 8 bits to the left 
            size += (header[1] as usize) << 8;

            let mut data = vec![0; size - 2];

                //Read the encrypted part of the packet
            let res = sock.read_exact(&mut data).await.unwrap();

            if res < size - 2 {
                return Err("An error occured while reading the packet data.".to_string());
            }

            info!("Raw packet: {:?} {:?}", header, data);

            return Ok((data[0], data[1..].to_vec()));
        }

        return Err("Client socket is not set".to_string());
    }

    pub fn send(&mut self, data: Vec<u8>) -> Result<(), String> {
        //calculate len
        let length = data.len() + 2;


        // put everything together
        let mut buffer = packet::packet::Buffer::new();

        buffer.write_usize(length);
        buffer.write(data);

        if let Some(socket) = self.socket.as_mut() {
            match socket.try_write(buffer.buffer.as_slice()) {
                Ok(_) => {
                    info!("Sent packet to gameserver");
                },
                Err(e) => {
                    error!("Error sending packet to gameserver: {}", e);

                    return Err("Error sending packet to gameserver.".to_string());
                }
            }
        }

        Err("Can't send packet to gameserver...".to_string())
    }

}

impl Client {
    pub fn new() -> Client {
        let rand_vec: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
        Client{
            session_id: rand_vec,
            account: None,
            socket: None,
        }
    }

    pub async fn receive(&mut self) -> Result<(u8, Vec<u8>), String> {

        if let Some(sock) = self.socket.as_mut() {
            let mut header = [0; 2];
            let n = sock.read_exact(&mut header).await.unwrap();

            if n < 2 {
                return Err("An error occured while reading the packet header.".to_string());
            }
            
            //calculate the size of the packet
            let mut size = header[0] as usize;
            //sum the second byte shifted 8 bits to the left 
            size += (header[1] as usize) << 8;

            //Allocate the appropriate size for our data (size - 2 bytes used for the length)
            let mut data = vec![0; size - 2];

            //Read the encrypted part of the packet
            let res = sock.read_exact(&mut data).await.unwrap();

            if res < size - 2 {
                return Err("An error occured while reading the packet data.".to_string());
            }

            //Print raw packet
            info!("Received packet: {:?} {:?}", header, data);
            
            let res = blowfish_decrypt(data, vec!["[;'.]94-31==-%&@!^+]\000".as_bytes().to_vec()].concat());

            if let Err(e) = res {
                return Err(e);
            } else {
                data = res.unwrap();
                if checksum(&mut data) {
                    info!("Decrypted packet content: {:?}", data);
                    info!("Packet checksum OK!");
                } else {
                    return Err("The packet checksum doesn't look right...".to_string());
                }
                return Ok((data[0], data[1..].to_vec()))
            }
        }

        return Err("Client socket is not set".to_string());
    }
}