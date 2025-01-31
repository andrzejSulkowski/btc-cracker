# BTC Cracker: A Demo BIP39 Brute-Force CLI in Rust
This repository demonstrates a **theoretical** brute-force approach to finding a BIP39 mnemonic that corresponds to a given Bitcoin address. It is intended for **educational and illustrative** purposes only.

**Important**
- This code is not meant to be a practical tool for recovering lost mnemonics or hacking addresses.

<br>

1.	BIP39 Mnemonic Generation
	- Converts a big-integer counter (attempts) into a 32-byte entropy, producing a **24-word** BIP39 mnemonic.
2.	Address Derivation (BIP84)
	- For each generated mnemonic, the code derives **24 addresses** at path m/84'/0'/0'/0/i and checks if any match the target address.
3.	Progress Display
	- Uses [indicatif](https://crates.io/crates/indicatif) to show a **spinner** and regularly update the total attempts and attempt rate.
	- Uses [console](https://crates.io/crates/console) for console styling and emoji support.
4.	Command-Line Interface
	- Uses [clap](https://crates.io/crates/clap) to parse a --address parameter from the user.

<br>

## How It Works

1. Setup
	- The code reads a --address parameter (or -a) from the command line.
	- Creates a BtcWalletCracker with that address.
2.	Brute-Force Loop
	- Starts at 0, counting upward in BigUint (up to 2^{256}-1).
	•	For each value of “attempts,” it:
	1.	Creates a 32-byte entropy array from that counter.
	2.	Builds a BIP39 mnemonic.
	3.	Derives addresses for indices 0..24 at path m/84'/0'/0'/0/<i>.
	4.	Compares each address to the target address.
3.	Progress Updates
	-	Every chunk_size attempts (default 100), it displays how many seeds have been checked and the approximate seeds per second.
4.	Early Termination
	-	The loop terminates if a match is found or if it exhausts the entire space (which is practically impossible) or you stop the program manually (ctrl + c).


<br>
## Usage
1. Clone & Build
```bash
git clone https://github.com/yourusername/btc-cracker-demo.git
cd btc-cracker-demo
cargo build --release
```
2.
```bash
./target/release/btc-wallet-cracker --address 34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo
```
