use ini::ini::Ini;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub struct Configuration {
    pub secure_path: String,
    pub unshare: String,
    pub update_hostname: bool,
}

#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("ini parse error: {0}")]
    ParseError(#[from] ini::ini::ParseError),
    #[error("invalid genie.ini: [genie] section missing")]
    MissingGenie,
    #[error("invalid genie.ini: genie.secure-path missing")]
    MissingSecurePath,
    #[error("invalid genie.ini: genie.unshare missing")]
    MissingUnshare,
    #[error("invalid genie.ini: genie.update-hostname missing")]
    MissingUpdateHostname,
    #[error("invalid genie.ini: genie.update-hostname must be true or false")]
    InvalidUpdateHostname,
}

impl From<ini::ini::Error> for ConfigurationError {
    fn from(e: ini::ini::Error) -> Self {
        match e {
            ini::ini::Error::Io(e) => e.into(),
            ini::ini::Error::Parse(e) => e.into(),
        }
    }
}

impl Configuration {
    pub fn read_from_file(path: &str) -> Result<Self, ConfigurationError> {
        let f = BufReader::new(File::open(path)?);
        Self::read(f)
    }
    pub fn read<R: BufRead>(mut r: R) -> Result<Self, ConfigurationError> {
        use ConfigurationError::{
            InvalidUpdateHostname, MissingGenie, MissingSecurePath, MissingUnshare,
            MissingUpdateHostname,
        };

        let ini = Ini::read_from(&mut r)?;
        let genie = ini.section(Some("genie")).ok_or(MissingGenie)?;
        let secure_path = genie.get("secure-path").ok_or(MissingSecurePath)?;
        let unshare = genie.get("unshare").ok_or(MissingUnshare)?;
        let update_hostname = genie.get("update-hostname").ok_or(MissingUpdateHostname)?;
        let update_hostname = update_hostname
            .parse::<bool>()
            .map_err(|_| InvalidUpdateHostname)?;
        Ok(Self {
            secure_path: secure_path.into(),
            unshare: unshare.into(),
            update_hostname,
        })
    }
}
