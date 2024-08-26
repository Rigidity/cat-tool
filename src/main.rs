#![allow(clippy::too_many_arguments)]

use std::{
    collections::HashMap,
    fs,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use bip39::Mnemonic;
use chia::{
    bls::{master_to_wallet_unhardened_intermediate, DerivableKey, SecretKey},
    clvm_utils::CurriedProgram,
    protocol::{Bytes32, Coin, CoinState, CoinStateFilters, SpendBundle},
    puzzles::{
        cat::{CatArgs, EverythingWithSignatureTailArgs},
        standard::StandardArgs,
        DeriveSynthetic,
    },
};
use chia_wallet_sdk::{
    announcement_id, connect_peer, create_tls_connector, decode_address, decode_puzzle_hash,
    encode_address, load_ssl_cert, select_coins, sign_transaction, Cat, CatSpend, Condition,
    Conditions, Network, NetworkId, Peer, Primitive, Puzzle, RunTail, SpendContext, StandardLayer,
    MAINNET_CONSTANTS, TESTNET11_CONSTANTS,
};
use clap::Parser;
use colored::Colorize;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tokio::time::timeout;

/// Tool for issuing and melting CATs.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    subcommand: Subcommand,

    /// A network override, by default it's testnet11 or implied by the port of the full node.
    #[arg(global = true, short, long)]
    network: Option<String>,

    /// The URI of the full node to use. Defaults to localhost at the network's default port.
    #[arg(global = true, short, long)]
    uri: Option<String>,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Issues a CAT.
    Issue {
        /// The amount of the CAT to issue.
        #[arg(short, long)]
        amount: f64,

        /// The target address for the CAT, defaults to the address that issued it.
        #[arg(short, long)]
        target: Option<String>,

        /// The fee to use, in XCH. Defaults to 0.00005.
        #[arg(short, long)]
        fee: Option<f64>,
    },
    /// Melts a CAT back into XCH.
    Melt {
        /// The amount of the CAT to melt.
        #[arg(short, long)]
        amount: f64,

        /// The fee to use, in XCH. Defaults to 0.00005.
        #[arg(short, long)]
        fee: Option<f64>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let homedir = homedir::my_home()?.expect("could not find home directory");
    let dir = homedir.join(".cat2");
    fs::create_dir_all(dir.as_path()).ok();

    let cert = load_ssl_cert(
        dir.join("wallet.crt").to_str().unwrap(),
        dir.join("wallet.key").to_str().unwrap(),
    )?;
    let tls_connector = create_tls_connector(&cert)?;

    let specified_network_id = match args.network.as_deref() {
        Some("mainnet") => Some(NetworkId::Mainnet),
        Some("testnet11") => Some(NetworkId::Testnet11),
        None => None,
        _ => panic!("Invalid network id, expected mainnet or testnet11"),
    };
    let specified_socket_addr = args.uri.map(|uri| {
        if let Ok(socket_addr) = uri.parse::<SocketAddr>() {
            return socket_addr;
        }
        let ip_addr = uri.parse::<IpAddr>().expect("Invalid IP address");
        SocketAddr::new(
            ip_addr,
            match specified_network_id {
                Some(NetworkId::Mainnet) => 8444,
                Some(NetworkId::Testnet11) => 58444,
                _ => 58444,
            },
        )
    });

    if specified_socket_addr.is_none() {
        println!("{}", "No URI specified, falling back to localhost. If this is not what you want, consider specifying --uri".yellow());
    }

    let network_id = specified_network_id.unwrap_or_else(|| {
        specified_socket_addr.map_or_else(
            || NetworkId::Testnet11,
            |socket_addr| match socket_addr.port() {
                8444 => NetworkId::Mainnet,
                58444 => NetworkId::Testnet11,
                _ => panic!("Unspecified network id for port {}", socket_addr.port()),
            },
        )
    });
    let socket_addr = specified_socket_addr.unwrap_or_else(|| {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            match network_id {
                NetworkId::Mainnet => 8444,
                NetworkId::Testnet11 => 58444,
                _ => unreachable!(),
            },
        )
    });

    println!(
        "{}",
        format!("Connecting to peer at {}", socket_addr).blue()
    );

    let (peer, mut receiver) = timeout(
        Duration::from_secs(5),
        connect_peer(network_id.clone(), tls_connector, socket_addr),
    )
    .await??;

    println!("{}", "Successfully handshaked with peer".green());

    // Ignore messages for now
    tokio::spawn(async move { while let Some(_message) = receiver.recv().await {} });

    let mnemonic = Mnemonic::parse(
        ask("Enter your mnemonic (it is required to issue and melt CATs): ")?.trim(),
    )?;
    let root_sk = SecretKey::from_seed(&mnemonic.to_seed(""));
    let intermediate_sk = master_to_wallet_unhardened_intermediate(&root_sk);

    let puzzle_hashes: HashMap<Bytes32, SecretKey> = (0..10000)
        .into_par_iter()
        .map(|i| {
            let sk = intermediate_sk.derive_unhardened(i).derive_synthetic();
            let pk = sk.public_key();
            let puzzle_hash = StandardArgs::curry_tree_hash(pk).into();
            (puzzle_hash, sk)
        })
        .collect();

    let network = match network_id {
        NetworkId::Mainnet => Network::default_mainnet(),
        NetworkId::Testnet11 => Network::default_testnet11(),
        _ => unreachable!(),
    };

    let (mut ctx, sks) = match args.subcommand {
        Subcommand::Issue {
            amount,
            target,
            fee,
        } => {
            let key = ask("Enter the issuance secret key (or hit enter for single issuance): ")?;
            let key = key.trim();

            let target = parse_target(target, &network_id)?;
            let amount = (amount * 1000.0) as u64;
            let fee = fee.map(|fee| (fee * 1.0e12) as u64).unwrap_or(50_000_000);
            let key = if !key.is_empty() {
                Some(SecretKey::from_bytes(&decode_puzzle_hash(key)?)?)
            } else {
                None
            };
            issue(
                &peer,
                &network_id,
                &network,
                amount,
                fee,
                target,
                &puzzle_hashes,
                key,
            )
            .await?
        }
        Subcommand::Melt { amount, fee } => {
            let key = ask("Enter the issuance secret key: ")?;

            let amount = (amount * 1000.0) as u64;
            let fee = fee.map(|fee| (fee * 1.0e12) as u64).unwrap_or(50_000_000);
            let key = SecretKey::from_bytes(&decode_puzzle_hash(key.trim())?)?;

            melt(&peer, &network, amount, fee, &puzzle_hashes, key).await?
        }
    };

    let coin_spends = ctx.take();
    let signature = sign_transaction(
        &coin_spends,
        &sks,
        match network_id {
            NetworkId::Mainnet => &MAINNET_CONSTANTS,
            NetworkId::Testnet11 => &TESTNET11_CONSTANTS,
            _ => unreachable!(),
        },
    )?;

    let spend_bundle = SpendBundle::new(coin_spends, signature);
    let ack = peer.send_transaction(spend_bundle).await?;

    println!("{}", format!("Transaction ID: {}", ack.txid).green());
    if let Some(error) = ack.error {
        println!("{}", format!("Error: {}", error).red());
    }

    Ok(())
}

async fn issue(
    peer: &Peer,
    network_id: &NetworkId,
    network: &Network,
    amount: u64,
    fee: u64,
    target: Option<Bytes32>,
    puzzle_hashes: &HashMap<Bytes32, SecretKey>,
    key: Option<SecretKey>,
) -> anyhow::Result<(SpendContext, Vec<SecretKey>)> {
    let mut ctx = SpendContext::new();
    let mut sks = Vec::new();

    let coins = request_coins(
        peer,
        network,
        puzzle_hashes.keys().cloned().collect(),
        amount + fee,
        "XCH",
    )
    .await?;
    let selected = coins.iter().fold(0, |acc, coin| acc + coin.amount);
    let change = selected - amount - fee;

    let origin = coins[0];
    let target = target.unwrap_or(origin.puzzle_hash);

    for (i, &coin) in coins.iter().enumerate() {
        let mut conditions = Conditions::new();

        if i == 0 {
            let (issue_cat, eve) = if let Some(key) = key.clone() {
                let issuance_pk = key.public_key();
                sks.push(key);
                Cat::multi_issuance_eve(
                    &mut ctx,
                    coin.coin_id(),
                    issuance_pk,
                    amount,
                    Conditions::new().create_coin(target, amount, vec![target.into()]),
                )?
            } else {
                Cat::single_issuance_eve(
                    &mut ctx,
                    coin.coin_id(),
                    amount,
                    Conditions::new().create_coin(target, amount, vec![target.into()]),
                )?
            };

            conditions = conditions.extend(issue_cat).reserve_fee(fee);

            if change > 0 {
                conditions = conditions.create_coin(origin.puzzle_hash, change, Vec::new());
            }

            if coins.len() > 1 {
                conditions = conditions.create_coin_announcement(b"$".to_vec().into());
            }

            let cat = eve.wrapped_child(target, amount);
            println!("{}", format!("Asset ID: {}", cat.asset_id).green());
            println!("{}", format!("Coin ID: {}", cat.coin.coin_id()).green());
            println!(
                "{}",
                format!(
                    "Address: {}",
                    encode_address(
                        cat.p2_puzzle_hash.to_bytes(),
                        match network_id {
                            NetworkId::Mainnet => "xch",
                            NetworkId::Testnet11 => "txch",
                            _ => unreachable!(),
                        }
                    )?
                )
                .green()
            );
        } else {
            conditions =
                conditions.assert_coin_announcement(announcement_id(origin.coin_id(), b"$"));
        }

        let sk = puzzle_hashes.get(&coin.puzzle_hash).unwrap().clone();
        ctx.spend_p2_coin(coin, sk.public_key(), conditions)?;
        sks.push(sk);
    }

    Ok((ctx, sks))
}

async fn melt(
    peer: &Peer,
    network: &Network,
    amount: u64,
    fee: u64,
    puzzle_hashes: &HashMap<Bytes32, SecretKey>,
    key: SecretKey,
) -> anyhow::Result<(SpendContext, Vec<SecretKey>)> {
    let mut ctx = SpendContext::new();
    let mut sks = vec![key.clone()];

    let tail_mod = ctx.everything_with_signature_tail_puzzle()?;
    let tail = ctx.alloc(&CurriedProgram {
        program: tail_mod,
        args: EverythingWithSignatureTailArgs::new(key.public_key()),
    })?;
    let asset_id = Bytes32::from(ctx.tree_hash(tail));

    let fee_coins = request_coins(
        peer,
        network,
        puzzle_hashes.keys().cloned().collect(),
        fee.saturating_sub(amount),
        "XCH",
    )
    .await?;
    let selected_fee = fee_coins.iter().fold(0, |acc, coin| acc + coin.amount);
    let fee_change = selected_fee - fee + amount;

    let cat_coins = request_coin_states(
        peer,
        network,
        puzzle_hashes
            .keys()
            .map(|p2_puzzle_hash| {
                CatArgs::curry_tree_hash(asset_id, (*p2_puzzle_hash).into()).into()
            })
            .collect(),
        amount,
        "CAT",
    )
    .await?;
    let selected_cat = cat_coins.iter().fold(0, |acc, cs| acc + cs.coin.amount);
    let cat_change = selected_cat - amount;

    for (i, &fee_coin) in fee_coins.iter().enumerate() {
        let mut conditions = Conditions::new();

        if i == 0 {
            conditions = conditions
                .reserve_fee(fee)
                .create_coin_announcement(b"$".to_vec().into());

            if fee_change > 0 {
                conditions =
                    conditions.create_coin(fee_coins[0].puzzle_hash, fee_change, Vec::new());
            }
        } else {
            conditions =
                conditions.assert_coin_announcement(announcement_id(fee_coins[0].coin_id(), b"$"));
        }

        let sk = puzzle_hashes.get(&fee_coin.puzzle_hash).unwrap().clone();
        ctx.spend_p2_coin(fee_coin, sk.public_key(), conditions)?;
        sks.push(sk);
    }

    let mut cat_spends = Vec::new();

    for (i, &cat_cs) in cat_coins.iter().enumerate() {
        let mut parent_coin_state = peer
            .request_coin_state(
                vec![cat_cs.coin.parent_coin_info],
                None,
                network.genesis_challenge,
                false,
            )
            .await?
            .expect("rejection");

        let puzzle_and_solution = peer
            .request_puzzle_and_solution(
                cat_cs.coin.parent_coin_info,
                cat_cs.created_height.unwrap(),
            )
            .await?
            .expect("rejection");

        let puzzle = ctx.alloc(&puzzle_and_solution.puzzle)?;
        let puzzle = Puzzle::parse(&ctx.allocator, puzzle);
        let solution = ctx.alloc(&puzzle_and_solution.solution)?;

        let cat = Cat::from_parent_spend(
            &mut ctx.allocator,
            parent_coin_state.coin_states.remove(0).coin,
            puzzle,
            solution,
            cat_cs.coin,
        )?
        .expect("invalid CAT coin");

        let mut conditions = Conditions::new();

        let extra_delta = if i == 0 {
            if !fee_coins.is_empty() {
                conditions = conditions
                    .assert_coin_announcement(announcement_id(fee_coins[0].coin_id(), b"$"));
            }

            if cat_change > 0 {
                conditions = conditions.create_coin(
                    cat.p2_puzzle_hash,
                    cat_change,
                    vec![cat.p2_puzzle_hash.into()],
                );
            }

            conditions = conditions.with(Condition::other(ctx.alloc(&RunTail::new(tail, ()))?));

            -(amount as i64)
        } else {
            0
        };

        let sk = puzzle_hashes.get(&cat.p2_puzzle_hash).unwrap().clone();
        cat_spends.push(CatSpend::with_extra_delta(
            cat,
            StandardLayer::new(sk.public_key()).spend(&mut ctx, conditions)?,
            extra_delta,
        ));
        sks.push(sk);
    }

    for coin_spend in Cat::spend_all(&mut ctx, &cat_spends)? {
        ctx.insert(coin_spend);
    }

    Ok((ctx, sks))
}

fn parse_target(target: Option<String>, network_id: &NetworkId) -> anyhow::Result<Option<Bytes32>> {
    Ok(target
        .map(|address| decode_address(&address))
        .transpose()?
        .map(
            |(puzzle_hash, prefix)| match (prefix.as_str(), network_id) {
                ("xch", NetworkId::Mainnet) | ("txch", NetworkId::Testnet11) => {
                    Bytes32::from(puzzle_hash)
                }
                _ => panic!("Invalid address prefix {prefix} for network {network_id:?}"),
            },
        ))
}

async fn request_coin_states(
    peer: &Peer,
    network: &Network,
    puzzle_hashes: Vec<Bytes32>,
    select_total: u64,
    kind: &str,
) -> anyhow::Result<Vec<CoinState>> {
    let coin_states = peer
        .request_puzzle_state(
            puzzle_hashes,
            None,
            network.genesis_challenge,
            CoinStateFilters::new(false, true, false, 0),
            false,
        )
        .await?
        .unwrap()
        .coin_states;

    println!(
        "{}",
        format!(
            "Current {kind} balance: {} mojos",
            coin_states
                .iter()
                .fold(0u128, |acc, cs| acc + cs.coin.amount as u128)
        )
        .green()
    );

    let coin_states: HashMap<Bytes32, CoinState> =
        HashMap::from_iter(coin_states.into_iter().map(|cs| (cs.coin.coin_id(), cs)));

    Ok(select_coins(
        coin_states.values().map(|cs| cs.coin).collect(),
        select_total as u128,
    )?
    .into_iter()
    .map(|coin| coin_states[&coin.coin_id()])
    .collect())
}

async fn request_coins(
    peer: &Peer,
    network: &Network,
    puzzle_hashes: Vec<Bytes32>,
    select_total: u64,
    kind: &str,
) -> anyhow::Result<Vec<Coin>> {
    let coin_states = request_coin_states(peer, network, puzzle_hashes, select_total, kind).await?;
    Ok(coin_states.into_iter().map(|cs| cs.coin).collect())
}

fn ask(message: &str) -> anyhow::Result<String> {
    print!("{}", message.purple());
    io::stdout().flush()?;
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    Ok(response)
}
