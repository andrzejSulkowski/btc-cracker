use std::{
    str::FromStr,
    time::{Duration, Instant},
};

use bdk_wallet::{
    bip39::Mnemonic,
    bitcoin::{
        address::NetworkChecked,
        bip32::{DerivationPath, Xpriv, Xpub},
        key::Secp256k1,
        Address, Network,
    },
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use console::{style, Emoji};
use indicatif::{ProgressBar, ProgressStyle};

static LOOKING_GLASS: Emoji<'_, '_> = Emoji("🔍", "");
static SKULL_AND_CROSSBONES: Emoji<'_, '_> = Emoji("☠️", "");


pub struct BtcWalletCracker {
    target_address: Address<NetworkChecked>,
    max_entropy: BigUint,
    chunk_size: u64,
}

impl BtcWalletCracker {
    pub fn new(target_address: &str) -> Result<Self, &'static str> {
        let checked_address = Address::from_str(target_address)
            .map_err(|_| "Unparsable Address")?
            .require_network(Network::Bitcoin)
            .map_err(|_| "Wrong Network")?;

        // 2^256 - 1 is the max for a 24-word BIP39 mnemonic space
        let max_entropy = (BigUint::one() << 256) - BigUint::one();

        Ok(Self {
            target_address: checked_address,
            max_entropy,
            chunk_size: 100,
        })
    }

    pub fn crack(&self) {
        let pb = self.setup_spinner();
        let mut chunk_start_time = Instant::now();
        let mut attempts = BigUint::zero();

        while attempts <= self.max_entropy {
            let mnemonic = self.mnemonic_from_attempts(&attempts);

            match self.check_mnemonic_address(&mnemonic) {
                Ok(found_match) => {
                    if found_match {
                        pb.finish_with_message(style("Match found!").green().bold().to_string());
                        println!(
                            "{} {} Found matching mnemonic at attempts = {}!",
                            style("✔").green().bold(),
                            LOOKING_GLASS,
                            style(&attempts).yellow()
                        );
                        println!("Mnemonic: {}", style(&mnemonic).yellow());
                        break;
                    }
                }
                Err(_) => {
                    pb.set_message("Error occurred while checking mnemonic");
                }
            }
            attempts += 1u32;

            // Once every `chunk_size` attempts, update the second line with speed stats
            if &attempts % self.chunk_size == BigUint::zero() {
                let now = Instant::now();
                let elapsed = now.duration_since(chunk_start_time).as_secs_f64();
                let average_speed = self.chunk_size as f64 / (elapsed + f64::EPSILON);

                pb.set_message(format!(
                    "Checked {} seeds total (~{:.2} seeds/s)",
                    &attempts, average_speed
                ));

                chunk_start_time = now;
            }
        }

        // Finished or reached max_entropy
        println!("{} Finished. Total attempts: {}", LOOKING_GLASS, attempts);
    }

    /// Derives a 24-word BIP39 mnemonic from a big-integer `attempts` index.
    fn mnemonic_from_attempts(&self, attempts: &BigUint) -> Mnemonic {
        // Convert the attempts counter to a 32-byte array (Big-Endian)
        let mut entropy = [0u8; 32];
        let bytes = attempts.to_bytes_be();
        let offset = 32 - bytes.len();
        entropy[offset..].copy_from_slice(&bytes);

        // A 24-word mnemonic must be derived from 32 bytes of entropy
        Mnemonic::from_entropy(&entropy)
            .expect("Failed to create mnemonic from 32 bytes of entropy")
    }

    /// For a given mnemonic, derives the first 24 addresses (m/84'/0'/0'/0/i)
    /// and checks if any of them match the target address.
    fn check_mnemonic_address(&self, mnemonic: &Mnemonic) -> Result<bool, &'static str> {
        let wallet_seed = mnemonic.to_seed("");
        let xpriv = Xpriv::new_master(Network::Bitcoin, &wallet_seed)
            .map_err(|_| "Failed to create master Xpriv")?;

        let secp = Secp256k1::new();

        for i in 0..24 {
            // Derivation path for BIP84, receiving addresses:
            let path_str = format!("m/84'/0'/0'/0/{}", i);
            let derivation_path =
                DerivationPath::from_str(&path_str).map_err(|_| "Invalid path")?;

            // Derive child private key and convert to public
            let child_xpriv = xpriv
                .derive_priv(&secp, &derivation_path)
                .map_err(|_| "Failed deriving child xpriv")?;
            let child_xpub = Xpub::from_priv(&secp, &child_xpriv);

            // BIP84: P2WPKH
            let derived_address = Address::p2wpkh(&child_xpub.to_pub(), Network::Bitcoin);

            // Compare to the target
            if derived_address == self.target_address {
                println!("Found a match at index {}!", i);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Sets up the `indicatif` spinner with a two-line display:
    /// 1) A prefix line that remains mostly static
    /// 2) A dynamically-updated message line
    fn setup_spinner(&self) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(Duration::from_millis(120));

        pb.set_style(
            ProgressStyle::with_template("{prefix}\n{spinner:.red} {msg}")
                .unwrap()
                .tick_strings(&[
                    "▹▹▹▹▹",
                    "▸▹▹▹▹",
                    "▹▸▹▹▹",
                    "▹▹▸▹▹",
                    "▹▹▹▸▹",
                    "▹▹▹▹▸",
                    "▪▪▪▪▪",
                ]),
        );

        // The top line prefix remains static
        pb.set_prefix(format!("{} BTC WALLET CRACKER {}\n-> cracking address: {}", SKULL_AND_CROSSBONES, SKULL_AND_CROSSBONES, self.target_address));

        // The second line (msg) is set here, updated later
        pb.set_message("Starting up...");

        pb
    }
}
