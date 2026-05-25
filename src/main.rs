//! keep — an encrypted secrets/notes vault synced over Swarm.
//!
//! The vault is a key/value map, encrypted **client-side** with
//! ChaCha20-Poly1305 (only ciphertext ever reaches Swarm) and made
//! mutable behind a feed. The local config (`~/.keep/keep.json`) holds
//! the feed key, topic, and handle — copy it to use the vault elsewhere.
//! Built on the [scout](https://github.com/ethswarm-tools/scout) library.
//!
//!   keep init [--topic <t>] --stamp <batch>
//!   keep set <key> <value> --stamp <batch>
//!   keep get <key>     |     keep list     |     keep rm <key> --stamp <batch>

use std::collections::BTreeMap;
use std::path::PathBuf;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use clap::{Parser, Subcommand};
use scout::LiteClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
struct Config {
    key: String,
    topic: String,
    handle: String,
}

type Vault = BTreeMap<String, String>;

#[derive(Parser)]
#[command(name = "keep", version, about = "An encrypted secrets vault synced over Swarm")]
struct Cli {
    #[arg(long, env = "BEE_GATEWAY", default_value = "http://localhost:1633", global = true)]
    gateway: String,
    #[arg(long, env = "BEE_NODE", global = true)]
    node: Option<String>,
    #[arg(long, env = "BEE_STAMP", global = true)]
    stamp: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault (generates a key, writes ~/.keep/keep.json). Needs --stamp.
    Init {
        #[arg(long, short, default_value = "keep")]
        topic: String,
    },
    /// Set a key. Needs --stamp.
    Set { key: String, value: String },
    /// Print a key's value.
    Get { key: String },
    /// List the keys in the vault.
    List,
    /// Remove a key. Needs --stamp.
    Rm { key: String },
}

fn client(cli: &Cli) -> anyhow::Result<LiteClient> {
    let mut c = LiteClient::read(&cli.gateway)?;
    if let Some(stamp) = &cli.stamp {
        let node = cli.node.clone().unwrap_or_else(|| cli.gateway.clone());
        c = c.with_write(&node, stamp)?;
    }
    Ok(c)
}

fn config_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set"))?;
    let dir = PathBuf::from(home).join(".keep");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("keep.json"))
}

fn load_config() -> anyhow::Result<Config> {
    let p = config_path()?;
    let b = std::fs::read(&p).map_err(|_| anyhow::anyhow!("no vault — run `keep init` first"))?;
    Ok(serde_json::from_slice(&b)?)
}

fn cipher(key_hex: &str) -> ChaCha20Poly1305 {
    let digest = Sha256::digest(key_hex.as_bytes());
    ChaCha20Poly1305::new(Key::from_slice(digest.as_slice()))
}

fn encrypt(key_hex: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
    let ct = cipher(key_hex)
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(key_hex: &str, blob: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(blob.len() > 12, "ciphertext too short");
    cipher(key_hex)
        .decrypt(Nonce::from_slice(&blob[..12]), &blob[12..])
        .map_err(|_| anyhow::anyhow!("decryption failed (wrong key?)"))
}

async fn load_vault(c: &LiteClient, cfg: &Config) -> anyhow::Result<Vault> {
    let blob = c.cat(&cfg.handle).await?;
    let plain = decrypt(&cfg.key, &blob)?;
    Ok(serde_json::from_slice(&plain)?)
}

async fn save_vault(c: &LiteClient, cfg: &Config, vault: &Vault) -> anyhow::Result<String> {
    let plain = serde_json::to_vec(vault)?;
    let blob = encrypt(&cfg.key, &plain)?;
    // Upload as a /bzz file so the feed handle is resolvable via `cat`
    // (a feed pointing at a raw /bytes ref isn't /bzz-resolvable).
    let reference = c.up_file("vault", "application/octet-stream", blob).await?;
    c.publish(&cfg.key, &cfg.topic, &reference).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let c = client(&cli)?;

    match &cli.cmd {
        Cmd::Init { topic } => {
            anyhow::ensure!(
                std::fs::metadata(config_path()?).is_err(),
                "already initialized — config at {}",
                config_path()?.display()
            );
            let (key, owner, _pubkey) = scout::generate_key()?;
            let mut cfg = Config { key, topic: topic.clone(), handle: String::new() };
            let empty: Vault = BTreeMap::new();
            cfg.handle = save_vault(&c, &cfg, &empty).await?;
            let p = config_path()?;
            std::fs::write(&p, serde_json::to_vec_pretty(&cfg)?)?;
            println!("vault created (owner {owner})");
            println!("config: {}", p.display());
        }
        Cmd::Set { key, value } => {
            let cfg = load_config()?;
            let mut vault = load_vault(&c, &cfg).await?;
            vault.insert(key.clone(), value.clone());
            save_vault(&c, &cfg, &vault).await?;
            eprintln!("set {key}");
        }
        Cmd::Get { key } => {
            let cfg = load_config()?;
            let vault = load_vault(&c, &cfg).await?;
            match vault.get(key) {
                Some(v) => println!("{v}"),
                None => std::process::exit(1),
            }
        }
        Cmd::List => {
            let cfg = load_config()?;
            let vault = load_vault(&c, &cfg).await?;
            for k in vault.keys() {
                println!("{k}");
            }
        }
        Cmd::Rm { key } => {
            let cfg = load_config()?;
            let mut vault = load_vault(&c, &cfg).await?;
            anyhow::ensure!(vault.remove(key).is_some(), "no such key: {key}");
            save_vault(&c, &cfg, &vault).await?;
            eprintln!("removed {key}");
        }
    }
    Ok(())
}
