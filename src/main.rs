mod gameserver;
mod loginserver;
mod blowfish;
mod config;
mod packet;

use log::info;
use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::Config;
use tokio::task;

use crate::loginserver::loginserver::LoginServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = ConsoleAppender::builder().build();
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Trace))
        .unwrap();
    let _handle = log4rs::init_config(config).unwrap();

    let game_server_task = async {
        info!("hello world from non blocking task");
    };

    let login_server_task = async {

        match config::config::new_config() {
            Ok(conf) => {
                info!("Starting Lineage ][ Server");
                info!("Config loaded");
    
                let login_server = LoginServer::new(conf.loginserver).await;
    
                match login_server {
                    Ok(mut lg) => {
                        lg.start().await;
                    },
                    Err(e) => {
                        info!("Error starting Login Server: {}", e);
                    }
                }
            
            },
            Err(e) => {
                info!("Error reading config.toml: {}", e);
            }
        }
    };


    tokio::join!(login_server_task, game_server_task);

    Ok(())
}