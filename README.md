# CAT2 Issuance and Melt Tool

This tool helps you issue and melt CATs by connecting to a full node peer and using your wallet keys to find and spend XCH and CAT coins.

## Installation

You'll first need to [install Rust](https://rustup.rs).

Then, run the following command:

```bash
cargo install --git https://github.com/Rigidity/cat-tool
```

## Usage

You can run `cat2 --help` to see a full list of commands and options.

For example, to issue a CAT on testnet with your local full node:

```bash
cat2 issue --amount 1 --uri localhost:58444
```

You can specify an issuance secret key to make it multi-issuance, otherwise it will use the coin id of the XCH coin spent as the genesis coin for the single-issuance CAT.

You can later melt multi-issuance CATs with:

```bash
cat2 melt --amount 1 --uri localhost:58444
```
