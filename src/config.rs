use serde_derive::{Serialize, Deserialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct General {
    pub mode: String,
    pub interface: String,
    pub file: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Whatsapp {
    pub debug: bool,
    pub file: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub general: General,
    pub whatsapp: Whatsapp
}

impl ::std::default::Default for Config {
    fn default() -> Self {
        Self {
            general: General {
                mode: "interface".to_string(),
                interface: "enx58ef68b4b1a5".to_string(),
                file: "".to_string(),
            },
            whatsapp: Whatsapp {
                debug: true,
                file: "whatsapp".to_string()
            }
        }
    }
}

pub fn load_config() -> Config {
    let cfg: Config = confy::load("/stuff/perso/config").unwrap();
    cfg
}
