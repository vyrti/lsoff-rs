pub const VERSION: &str = "0.1.3";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    pub tcp: bool,
    pub udp: bool,
    pub json: bool,
    pub kill: bool,
    pub yes: bool,
    pub help: bool,
    pub version: bool,
    pub port: Option<u16>,
    pub query: String,
}

/// Parses CLI arguments following lsoff conventions.
///
/// # Errors
/// Returns error message formatted with usage instructions if arguments are invalid.
pub fn parse_args<I, S>(args: I) -> Result<Config, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut cfg = Config::default();
    let mut positional = Vec::new();
    let args_vec: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();

    let mut i = 0;
    while i < args_vec.len() {
        let a = &args_vec[i];
        match a.as_str() {
            "-h" | "--help" => {
                cfg.help = true;
                return Ok(cfg);
            }
            "-v" | "--version" => {
                cfg.version = true;
                return Ok(cfg);
            }
            "-t" | "--tcp" => {
                cfg.tcp = true;
            }
            "-u" | "--udp" => {
                cfg.udp = true;
            }
            "-j" | "--json" => {
                cfg.json = true;
            }
            "-k" | "--kill" => {
                cfg.kill = true;
            }
            "-y" | "--yes" => {
                cfg.yes = true;
            }
            "-q" | "--query" => {
                if i + 1 >= args_vec.len() {
                    return Err(format!("{a} requires a value\n\n{}", usage()));
                }
                i += 1;
                cfg.query = args_vec[i].clone();
            }
            _ if a.starts_with("--query=") => {
                cfg.query = a["--query=".len()..].to_string();
            }
            _ if a.starts_with("-q=") => {
                cfg.query = a["-q=".len()..].to_string();
            }
            _ if a.starts_with('-') => {
                return Err(format!("unknown flag {a}\n\n{}", usage()));
            }
            _ => {
                positional.push(a.clone());
            }
        }
        i += 1;
    }

    if positional.len() > 1 {
        return Err(format!("too many arguments\n\n{}", usage()));
    }

    if positional.len() == 1 {
        let arg = &positional[0];
        match arg.parse::<u16>() {
            Ok(p) => {
                cfg.port = Some(p);
            }
            Err(_) => {
                if !cfg.query.is_empty() {
                    return Err(format!(
                        "too many search terms (use quotes: \"{} {}\")",
                        cfg.query, arg
                    ));
                }
                cfg.query = arg.clone();
            }
        }
    }

    if cfg.kill && cfg.port.is_none() {
        return Err(format!("-k requires a port\n\n{}", usage()));
    }
    if cfg.kill && cfg.json {
        return Err("cannot combine -k and --json".to_string());
    }
    if cfg.yes && !cfg.kill {
        return Err("-y can only be used with -k".to_string());
    }

    Ok(cfg)
}

#[must_use]
pub fn usage() -> &'static str {
    "lsoff-rs - list listening TCP/UDP ports\n\n\
Usage:\n  \
  lsoff-rs              interactive TUI (table if stdout is not a TTY)\n  \
  lsoff-rs <port>       show processes listening on port\n  \
  lsoff-rs <query>      search by name, project, path, pid, or port substring\n  \
  lsoff-rs -k <port>    kill those processes (asks for confirmation)\n  \
  lsoff-rs -h           help\n  \
  lsoff-rs -v           version\n\n\
Flags:\n  \
  -t, --tcp          TCP only\n  \
  -u, --udp          UDP only\n  \
  -q, --query <str>  search (name, project, path, pid, port); words are AND\n  \
  -j, --json         JSON output\n  \
  -k, --kill         kill processes on <port>\n  \
  -y, --yes          do not ask before -k (required if stdin is not a TTY)\n\n\
TUI:\n  \
  / or click Search      filter as you type\n  \
  ↑/↓ / j/k / wheel      move\n  \
  click header           sort by column\n  \
  y                      copy addr:port\n  \
  a                      auto-refresh\n  \
  s / S                  sort / reverse\n  \
  enter / space          expand or collapse a process\n  \
  h / l                  collapse / expand\n  \
  esc / ctrl+c           clear search\n  \
  r                      refresh\n  \
  x                      kill selected process (asks for confirmation)\n  \
  q                      quit\n"
}
