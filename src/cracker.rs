use std::{str::FromStr, time::Instant};

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

pub struct BtcWalletCracker {
    target_address: Address<NetworkChecked>,
    /// The upper bound of the search (2^256 - 1 for 24-word BIP39)
    max_entropy: BigUint,
    /// How many attempts are processed before we update the display
    chunk_size: u64,
}

//2048^24 mnemonic (+ passphrase combinations) = 2^264 but this includes a lot of invalid mnemonics
impl BtcWalletCracker {
    pub fn new(target_address: &str) -> Result<Self, &'static str> {
        let checked_address = Address::from_str(target_address)
            .map_err(|_| "Unparsable Address")?
            .require_network(Network::Bitcoin)
            .map_err(|_| "Wrong Network")?;

        // 2^256 - 1 is the max for a 24-word BIP39 mnemonic space (because 0 is included)
        let max_entropy = (BigUint::one() << 256) - BigUint::one();

        Ok(Self {
            target_address: checked_address,
            max_entropy,
            chunk_size: 100,
        })
    }

    pub fn crack(&self) {
        let mut chunk_start_time = Instant::now();
        let mut attempts = BigUint::zero();

        while attempts <= self.max_entropy {
            let mnemonic = self.mnemonic_from_attempts(&attempts);

            match self.check_mnemonic_address(&mnemonic) {
                Ok(found_match) => {
                    if found_match {
                        println!("Match found!");
                        println!("✔ Found matching mnemonic at attempts = {}!", attempts);
                        println!("Mnemonic: {}", &mnemonic);
                        break;
                    }
                }
                Err(_) => {
                    println!("Error occurred while checking mnemonic")
                }
            }
            attempts += 1u32;

            let maybe_new_chunk_start_time = self.maybe_log(&attempts, &mut chunk_start_time);
            if let Some(new_chunk_start_time) = maybe_new_chunk_start_time {
                chunk_start_time = new_chunk_start_time;
            }
        }
        println!("Finished. Total attempts: {}", attempts);
    }

    /// Derives a 24-word BIP39 mnemonic from a big-integer `attempts` index.
    fn mnemonic_from_attempts(&self, attempts: &BigUint) -> Mnemonic {
        let mut entropy = [0u8; 32];
        let bytes = attempts.to_bytes_be();
        /*
               We compute offset = 32 - bytes.len() so we know where to start copying into the array.
            If attempts only produces, say, 3 bytes, they end up in the rightmost 3 positions, with leading zeros in the rest.
            For example, if attempts = 1, it’s [0x01]; we place that at entropy[31], leaving zeros in entropy[0..31].

            [offset..]
            if bytes.len() is, for example, 3, offset would be 29, and entropy[29..] is the slice containing indices 29, 30, 31. That’s exactly where we place those three bytes from bytes.
        */
        let offset = 32 - bytes.len();
        entropy[offset..].copy_from_slice(&bytes);

        Mnemonic::from_entropy(&entropy)
            .expect("Failed to create mnemonic from 32 bytes of entropy")
    }

    fn check_mnemonic_address(&self, mnemonic: &Mnemonic) -> Result<bool, &'static str> {
        let wallet_seed = mnemonic.to_seed("");
        let xpriv = Xpriv::new_master(Network::Bitcoin, &wallet_seed)
            .map_err(|_| "Failed to create master Xpriv")?;

        let secp = Secp256k1::new();

        for i in 0..24 {
            let path_str = format!("m/84'/0'/0'/0/{}", i);
            let derivation_path =
                DerivationPath::from_str(&path_str).map_err(|_| "Invalid path")?;

            let child_xpriv = xpriv
                .derive_priv(&secp, &derivation_path)
                .map_err(|_| "Failed deriving child xpriv")?;
            let child_xpub = Xpub::from_priv(&secp, &child_xpriv);

            // BIP84: P2WPKH
            let derived_address = Address::p2wpkh(&child_xpub.to_pub(), Network::Bitcoin);

            if derived_address == self.target_address {
                println!("Found a match at index {}!", i);
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn maybe_log(&self, i: &BigUint, chunk_start_time: &Instant) -> Option<Instant> {
        if i % self.chunk_size == BigUint::zero() {
            let now = Instant::now();
            let elapsed = now.duration_since(*chunk_start_time).as_secs_f64();
            let average_speed = self.chunk_size as f64 / (elapsed + f64::EPSILON);

            println!("Checked {} seeds total (~{:.2} seeds/s)", &i, average_speed);
            return Some(now);
        }
        None
    }
}
