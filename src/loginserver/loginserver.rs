use log::info;
use tokio::net::TcpListener;

use crate::{packet::packet, loginserver::client::client, config::config};

use super::models;

pub struct LoginServer {
    clients: Vec<models::Client>,
    game_servers: Vec<models::GameServer>,
    database: String,
    internal_server_list: Vec<u8>,
    external_server_list: Vec<u8>,
    status: LoginServerStatus,
    client_listener: TcpListener,
    game_server_listener: TcpListener,
    conf: config::LoginServer
}

struct LoginServerStatus {
    successful_account_creation: u32,
    failed_account_creation: u32,
    successful_logins: u32,
    failed_logins: u32,
    hack_attempts: u32
}


impl LoginServer {
    pub async fn new(conf: config::LoginServer) -> Result<LoginServer, String> {
        let client_listener = match TcpListener::bind(format!("{}:2106", conf.host)).await {
            Ok(listener) => {
                info!("Listening for clients on port 2106");
                listener
            },
            Err(e) => return Err(format!("Error binding client listener: {}", e))
        };
        let game_server_listener = match TcpListener::bind(format!("{}:9413", conf.host)).await {
            Ok(listener) => {
                info!("Listening for game servers on port 9413");
                listener
            },
            Err(e) => return Err(format!("Error binding game server listener: {}", e))
        };
        Ok(LoginServer { clients: Vec::new(), 
            game_servers: Vec::new(), 
            database: "".to_string(), 
            internal_server_list: Vec::new(), 
            external_server_list: Vec::new(), 
            status: LoginServerStatus { successful_account_creation: 0, failed_account_creation: 0, successful_logins: 0, failed_logins: 0, hack_attempts: 0 },
            client_listener: client_listener, 
            game_server_listener: game_server_listener,
            conf: conf
        })
    }

    pub async fn start(&mut self) {
        self.client_listener().await;
    }

    async fn client_listener(&mut self) {
        //infinite loop
        loop {
            let (socket, _) = match self.client_listener.accept().await {
                Ok((socket, addr)) => (socket, addr),
                Err(e) => {
                    println!("Couldn't accept the incoming connection: {}", e);
                    continue;
                }
            };
            let mut client = models::Client::new();
            client.socket = Some(socket);
            //process client packets in other thread

            self.handle_client_packets(client);
        }
    }
    
    async fn handle_client_packets(&mut self, mut client: models::Client) {
        info!("A client is trying to connect..");

        let buffer = packet::Buffer::new();

        loop {
            let (packet_id, data) = match client.receive().await {
                Ok((packet_id, data)) => (packet_id, data),
                Err(e) => {
                    println!("Error receiving packet: {}", e);
                    continue;
                }
            };
            match packet_id {
                0x00 => {
                    //login packet
                    let (username, password) = match client::new_request_auth_login(data) {
                        Ok((username, password)) => (username, password),
                        Err(e) => {
                            println!("Error parsing login packet: {}", e);
                            continue;
                        }
                    };

                    info!("Username: {} - password: {}", username, password);
                },
                _ => {
                    println!("Unknown packet id: {}", packet_id);
                    continue;
                }
            }
        }
    }

    async fn game_server_listener(&mut self) {
        let gs = models::GameServer::new();
        self.game_servers.push(gs);
        
    }
}