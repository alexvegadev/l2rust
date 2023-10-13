use tokio::net::TcpListener;

pub struct GameServer {
    login_listener: TcpListener
}

impl GameServer {
    pub fn new(){
        println!("Creating game server");
    }
}