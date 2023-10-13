
use std::fs::File;
use std::io::Read;
use toml;

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub gameserver: GameServer,
    pub loginserver: LoginServer,
}

#[derive(Deserialize)]
pub struct GameServer {
    pub name: String,
    pub secret: String,
    pub internal_ip: String,
    pub external_ip: String,
    pub port: u32,
    pub database: Database,
}

#[derive(Deserialize)]
pub struct Database {
    pub name: String,
    pub host: String,
    pub port: u32,
    pub user: String,
    pub password: String
}

#[derive(Deserialize)]
pub struct LoginServer {
    pub host: String,
    pub auto_create: bool,
    pub database: Database
}


pub fn new_config() -> Result<Config, String> {
    // Open the file.
    match File::open("./config/network.toml") {
        Ok(mut file) => {
            // Read the file into a string.
            let mut contents = String::new();
            match file.read_to_string(&mut contents) {
                Ok(_) => {
                    // Parse the string of data into serde_json::Value.
                    match toml::from_str(&contents) {
                        Ok(config) => Ok(config),
                        Err(e) => panic!("Error parsing config.toml: {}", e),
                    }
                }
                Err(e) => Err(format!("Error reading config.toml: {}", e)),
            }
        }
        Err(e) => Err(format!("Error reading config.toml: {}", e)),
    } 
}