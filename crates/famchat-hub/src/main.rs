//! FamChat Hub binary — thin entry point. See the library crate for the server.
//!
//! Config (env, overridable by CLI flags):
//!   FAMCHAT_HUB_WORD  the family word clients authenticate with   (required)
//!   FAMCHAT_HUB_BIND  address to listen on          (default 0.0.0.0:9000)
//!   FAMCHAT_HUB_DATA  path to the state file    (default per-user data dir)
//! CLI: `famchat-hub --word <w> [--bind <addr>] [--data <path>]`
#![forbid(unsafe_code)]

#[tokio::main]
async fn main() {
    let cfg = famchat_hub::Config::from_env_and_args();
    let word = match cfg.word {
        Some(w) if !w.trim().is_empty() => w,
        _ => {
            eprintln!(
                "famchat-hub: no family word set.\n  \
                 set FAMCHAT_HUB_WORD=<the word your family uses> (or pass --word <w>)."
            );
            std::process::exit(2);
        }
    };
    famchat_hub::run(&cfg.bind, word, cfg.data).await;
}
