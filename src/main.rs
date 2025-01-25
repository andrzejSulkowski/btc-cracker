use clap::Parser;
use cracker::BtcWalletCracker;
mod cracker;

//https://bitinfocharts.com/top-100-richest-bitcoin-addresses.html
// 34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo is the address with most btc
//
// limitations:
//  let path_str = format!("m/84'/0'/0'/0/{}", i);

/// Command-line arguments, parsed with `clap`.
#[derive(Parser, Debug)]
#[command(name = "btc-cracker", about = "A demo BIP39 brute-force CLI in Rust.")]
struct CliArgs {
    /// The target Bitcoin address (mainnet) you want to find
    #[arg(short, long)]
    address: String,
}

fn main() {
    let args = CliArgs::parse();

    let cracker = BtcWalletCracker::new(&args.address).unwrap();
    cracker.crack();
}
