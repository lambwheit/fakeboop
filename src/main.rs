use std::fs::File;
use std::io::Write;
use std::str::FromStr;
use std::cmp::Ordering;
use sha2::{Digest};
use anchor_client::{
    solana_client::rpc_client::RpcClient,
    solana_sdk::{
        commitment_config::CommitmentConfig,
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
        signature::{Keypair, Signer},
        transaction::Transaction,
    },
};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use rayon::prelude::*;
use serde_json::json;
use std::error::Error;
use std::time::{Instant, Duration};

static EXIT: AtomicBool = AtomicBool::new(false);
const BOOP_PROGRAM_ID: &str = "boop8hVGQGqehUK2iVEMEnMrL5RbjywRzHKBmBE7ry4";
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_METADATA_PROGRAM: &str = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";
const RENT_SYSVAR: &str = "SysvarRent111111111111111111111111111111111";
const ASSOCIATED_TOKEN_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";
const RPC_URL: &str = "https://api.mainnet-beta.solana.com";
//const RPC_URL: &str = "https://api.devnet.solana.com/";

type ThreadSafeError = Box<dyn Error + Send + Sync + 'static>;

fn main() -> Result<(), ThreadSafeError> { // Adjusted main error type for consistency
    rayon::ThreadPoolBuilder::new().build_global().unwrap(); // Added for parallel CPU iteration
    let payer = generate_or_load_keypair("payer_keypair.json")?;
    println!("Payer Private Key: {}", payer.to_base58_string());
    println!("Payer Public Key: {}", payer.pubkey());
    let client = RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed());
    let balance = client.get_balance(&payer.pubkey()).map_err(|e| Box::new(e) as ThreadSafeError)?;
    println!("Payer balance: {} SOL", balance as f64 / 1_000_000_000.0);
    if balance < 1 {
        println!("Warning: Payer account has insufficient funds. Please fund your account first.");
        println!("You can get devnet SOL from https://solfaucet.com");
        return Ok(());
    }
    let token_name = "dont buy airdrop farming";
    let token_symbol = "dontbuy";
    let token_uri = "https://paste.ee/r/NxH25GFa/0";
    //let desired_suffix: Option<String> = None;
    let desired_suffix: Option<String> = Some("boop".to_string());
    let start_time = Instant::now();

    let (mint_pubkey, salt) = find_valid_mint(
        &payer.pubkey(),
        desired_suffix,
       0,
        0,
        false,
    )?;

    //let mint_pubkey = Pubkey::from_str("N8owudNz4eLiJx6X7uPJsfWboExmQYrVjQTFeaHboop").unwrap();
    //let salt = 12071595097173847286;
    let elapsed = start_time.elapsed();
    println!("Found valid mint: {} with salt: {}", mint_pubkey, salt);
    println!("Time taken to find valid mint: {:.2?}", elapsed);
    print_elapsed_time(elapsed);
    // create token
    let boop_program_id = Pubkey::from_str(BOOP_PROGRAM_ID).map_err(|e| Box::new(e) as ThreadSafeError)?;
    let (config_pubkey, _) = Pubkey::find_program_address(&[b"config"], &boop_program_id);
    let metadata_program_id = Pubkey::from_str(TOKEN_METADATA_PROGRAM).map_err(|e| Box::new(e) as ThreadSafeError)?;
    let metadata_seeds = &[
        b"metadata",
        metadata_program_id.as_ref(),
        mint_pubkey.as_ref(),
    ];
    let (metadata_pubkey, _) = Pubkey::find_program_address(metadata_seeds, &metadata_program_id);
    let create_token_ix = create_token_instruction(
        &boop_program_id,
        &config_pubkey,
        &metadata_pubkey,
        &mint_pubkey,
        &payer.pubkey(),
        salt,
        token_name,
        token_symbol,
        token_uri,
    )?;
    println!("1. Create token instruction generated.");
    let (vault_authority_pubkey, _) = Pubkey::find_program_address(&[b"vault_authority"], &boop_program_id);
    let (bonding_curve_pubkey, _) = Pubkey::find_program_address(&[b"bonding_curve", mint_pubkey.as_ref()], &boop_program_id);
    let (bonding_curve_sol_vault_pubkey, _) = Pubkey::find_program_address(&[b"bonding_curve_sol_vault", mint_pubkey.as_ref()], &boop_program_id);
    let (bonding_curve_vault_pubkey, _) = Pubkey::find_program_address(&[b"bonding_curve_vault", mint_pubkey.as_ref()], &boop_program_id);
    let token_program_id_for_ata = Pubkey::from_str(TOKEN_PROGRAM)?;
    let associated_token_program_id_for_ata = Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM)?;
    let (payer_ata_pubkey, _) = Pubkey::find_program_address(
        &[
            &payer.pubkey().as_ref(),
            &token_program_id_for_ata.as_ref(),
            &mint_pubkey.as_ref(),
        ],
        &associated_token_program_id_for_ata,
    );
    let deploy_bonding_curve_ix = deploy_bonding_curve_instruction(
        &boop_program_id,
        &mint_pubkey,
        &vault_authority_pubkey,
        &bonding_curve_pubkey,
        &bonding_curve_sol_vault_pubkey,
        &bonding_curve_vault_pubkey,
        &config_pubkey,
        &payer.pubkey(),
        salt,
    )?;
    println!("2. Deploy bonding curve instruction generated.");
    let create_ata_ix = create_associated_token_account(
        &payer.pubkey(),
        &payer.pubkey(),
        &mint_pubkey,
    )?;
    println!("3. Create ATA instruction generated.");
    let amount_in_sol: f64 = 0.1; // Amount of SOL to spend
    let amount_in_lamports: u64 = (amount_in_sol * 1_000_000_000.0) as u64;
    let min_amount_out_tokens: u64 = 1; // Expect at least 1 token

    let buy_token_ix = buy_token_instruction(
        &mint_pubkey,
        &payer.pubkey(),
        &payer_ata_pubkey,
        amount_in_lamports,
        min_amount_out_tokens,
    )?;
    println!("4. Buy token instruction generated (spending {} SOL for min {} tokens).", amount_in_sol, min_amount_out_tokens);

    let all_instructions = vec![
        create_token_ix,
        deploy_bonding_curve_ix,
        create_ata_ix,
        buy_token_ix
    ];
    let recent_blockhash = client.get_latest_blockhash().map_err(|e| Box::new(e) as ThreadSafeError)?;
    let transaction = Transaction::new_signed_with_payer(
        &all_instructions,
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    println!("Sending combined transaction (create token and deploy bonding curve)...");
    let signature = client.send_and_confirm_transaction(&transaction).map_err(|e| Box::new(e) as ThreadSafeError)?;
    println!("Combined transaction successful! Signature: {}", signature);
    let token_info = json!({
        "tokenName": token_name,
        "tokenSymbol": token_symbol,
        "tokenUri": token_uri,
        "mintAddress": mint_pubkey.to_string(),
        "salt": salt,
        "payerPublicKey": payer.pubkey().to_string(),
        "transactionSignature": signature.to_string(),
        "configAccount": config_pubkey.to_string(),
        "metadataAccount": metadata_pubkey.to_string(),
        "vaultAuthorityAccount": vault_authority_pubkey.to_string(),
        "bondingCurveAccount": bonding_curve_pubkey.to_string(),
        "bondingCurveSolVaultAccount": bonding_curve_sol_vault_pubkey.to_string(),
        "bondingCurveVaultAccount": bonding_curve_vault_pubkey.to_string(),
    });

    let mut file = File::create("token_and_bonding_curve_info.json").map_err(|e| Box::new(e) as ThreadSafeError)?;
    file.write_all(serde_json::to_string_pretty(&token_info)?.as_bytes()).map_err(|e| Box::new(e) as ThreadSafeError)?;
    println!("Token and bonding curve information saved to token_and_bonding_curve_info.json");

    Ok(())
}
fn print_elapsed_time(elapsed: Duration) {
    let total_seconds = elapsed.as_secs_f64();

    if total_seconds < 1.0 {
        println!("Time breakdown: {:.2} milliseconds", elapsed.as_millis());
    } else if total_seconds < 60.0 {
        println!("Time breakdown: {:.2} seconds", total_seconds);
    } else if total_seconds < 3600.0 {
        let minutes = total_seconds / 60.0;
        let seconds = total_seconds % 60.0;
        println!("Time breakdown: {:.0} minutes {:.2} seconds", minutes.floor(), seconds);
    } else {
        let hours = total_seconds / 3600.0;
        let minutes = (total_seconds % 3600.0) / 60.0;
        let seconds = total_seconds % 60.0;
        println!("Time breakdown: {:.0} hours {:.0} minutes {:.2} seconds",
                 hours.floor(), minutes.floor(), seconds);
    }

    // Add hashing rate estimation if it took more than a second
    if total_seconds >= 1.0 {
        // This is a rough estimate, as we don't know exact attempts
        let estimated_attempts = rayon::current_num_threads() as f64 * total_seconds * 100000.0; // assuming ~100k attempts per thread per second
        println!("Estimated hashing rate: {:.2} hashes/second", estimated_attempts / total_seconds);
    }
}
fn find_valid_mint(
    payer_pubkey: &Pubkey,
    desired_suffix: Option<String>,
    num_gpus: u32,
    mut num_cpus: u32,
    case_insensitive: bool,
) -> Result<(Pubkey, u64), ThreadSafeError> { // Adjusted return error type
    let boop_program_id = Pubkey::from_str(BOOP_PROGRAM_ID).map_err(|e| Box::new(e) as ThreadSafeError)?;
    let wsol_mint_pubkey = Pubkey::from_str(WSOL_MINT).map_err(|e| Box::new(e) as ThreadSafeError)?;
    let wsol_mint_bytes_arr = wsol_mint_pubkey.to_bytes();
    if num_cpus == 0 {
        num_cpus = rayon::current_num_threads() as u32;
    }
    if let Some(suffix) = desired_suffix.clone() {
        println!("Mining valid mint address with suffix '{}'", suffix);

        #[cfg(feature = "gpu")]
        if num_gpus > 0 {
            println!("Attempting GPU mining with {} GPU(s)...", num_gpus);
        }
        println!("Using {} CPU(s) for mining.", num_cpus);
        let cpu_result = (0..num_cpus).into_par_iter().find_map_any(|_i| {
            // let base_sha = Sha256::new().chain_update(payer_pubkey); // Not used in current logic
            loop {
                if EXIT.load(AtomicOrdering::Acquire) {
                    return None;
                }

                let salt_cpu = rand::random::<u64>();
                let mint_seeds = &[b"mint", payer_pubkey.as_ref(), &salt_cpu.to_le_bytes()];
                let (mint_pubkey, _) = Pubkey::find_program_address(mint_seeds, &boop_program_id);
                let mint_pubkey_str = mint_pubkey.to_string();

                let suffix_matches_cpu = if case_insensitive {
                    mint_pubkey_str.to_lowercase().ends_with(&suffix.to_lowercase())
                } else {
                    mint_pubkey_str.ends_with(&suffix)
                };
                let current_mint_bytes = mint_pubkey.to_bytes();
                let numerical_matches = current_mint_bytes.cmp(&wsol_mint_bytes_arr) == Ordering::Less;

                if suffix_matches_cpu && numerical_matches {
                    EXIT.store(true, AtomicOrdering::Release);
                    return Some((mint_pubkey, salt_cpu));
                }
            }
        });

        if let Some((mint, salt)) = cpu_result {
            return Ok((mint, salt));
        } else {
            // This error also needs to be ThreadSafeError if find_valid_mint's signature is ThreadSafeError
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No valid mint found after extensive search.")) as ThreadSafeError);
        }

    } else {
        println!("Mining valid mint address");
        let mut salt: u64;
        let mut attempts = 0;
        loop {
            if EXIT.load(AtomicOrdering::Acquire) {
                // This part of the loop (no suffix) is unlikely to be reached if suffix mining is active and finds something.
                // If it is reached, and EXIT is true, we should probably error or indicate no specific mint found.
                // For now, let finding a mint be the primary exit condition.
                return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Interrupted, "Search interrupted by another thread.")) as ThreadSafeError);
            }
            salt = rand::random::<u64>();
            let mint_seeds = &[b"mint", payer_pubkey.as_ref(), &salt.to_le_bytes()];
            let (mint_pubkey, _) = Pubkey::find_program_address(mint_seeds, &boop_program_id);
            let mint_pubkey_bytes = mint_pubkey.to_bytes();

            let numerical_matches = mint_pubkey_bytes.cmp(&wsol_mint_bytes_arr) == Ordering::Less;
            if numerical_matches {
                return Ok((mint_pubkey, salt));
            }
            attempts += 1;
            if attempts % 100000 == 0 {
                println!("Tried {} salts...", attempts);
            }
        }
    }
}



fn generate_or_load_keypair(path: &str) -> Result<Keypair, ThreadSafeError> {
    if std::path::Path::new(path).exists() {
        let keypair_bytes_str = std::fs::read_to_string(path).map_err(|e| Box::new(e) as ThreadSafeError)?;
        let keypair_bytes: Vec<u8> = serde_json::from_str(&keypair_bytes_str).map_err(|e| Box::new(e) as ThreadSafeError)?;
        Ok(Keypair::from_bytes(&keypair_bytes).map_err(|e| Box::new(e) as ThreadSafeError)?)
    } else {
        let keypair = Keypair::new();
        let keypair_bytes_slice = keypair.to_bytes(); // This is [u8; 64]
        let mut file = File::create(path).map_err(|e| Box::new(e) as ThreadSafeError)?;
        // serde_json::to_string expects a slice, to_bytes() returns an array, so pass as slice.
        file.write_all(serde_json::to_string(&keypair_bytes_slice.as_slice())?.as_bytes()).map_err(|e| Box::new(e) as ThreadSafeError)?;
        println!("New keypair generated and saved to {}", path);
        Ok(keypair)
    }
}
fn create_token_instruction(
    boop_program_id: &Pubkey,
    config_pubkey: &Pubkey,
    metadata_pubkey: &Pubkey,
    mint_pubkey: &Pubkey,
    payer_pubkey: &Pubkey,
    salt: u64,
    name: &str,
    symbol: &str,
    uri: &str,
) -> Result<Instruction, ThreadSafeError> {
    let discriminator: [u8; 8] = [84, 52, 204, 228, 24, 140, 234, 75];
    let mut data = Vec::with_capacity(8 + 8 + 4 + name.len() + 4 + symbol.len() + 4 + uri.len()); // Added 4 bytes for each length
    data.extend_from_slice(&discriminator);
    data.extend_from_slice(&salt.to_le_bytes());
    data.extend_from_slice(&(name.len() as u32).to_le_bytes());
    data.extend_from_slice(name.as_bytes());
    data.extend_from_slice(&(symbol.len() as u32).to_le_bytes());
    data.extend_from_slice(symbol.as_bytes());
    data.extend_from_slice(&(uri.len() as u32).to_le_bytes());
    data.extend_from_slice(uri.as_bytes());
    let accounts = vec![
        AccountMeta::new_readonly(*config_pubkey, false),
        AccountMeta::new(*metadata_pubkey, false),
        AccountMeta::new(*mint_pubkey, false),
        AccountMeta::new(*payer_pubkey, true),
        AccountMeta::new_readonly(Pubkey::from_str(RENT_SYSVAR).map_err(|e| Box::new(e) as ThreadSafeError)?, false),
        AccountMeta::new_readonly(Pubkey::from_str(SYSTEM_PROGRAM).map_err(|e| Box::new(e) as ThreadSafeError)?, false),
        AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM).map_err(|e| Box::new(e) as ThreadSafeError)?, false),
        AccountMeta::new_readonly(Pubkey::from_str(TOKEN_METADATA_PROGRAM).map_err(|e| Box::new(e) as ThreadSafeError)?, false),
    ];
    Ok(Instruction {
        program_id: *boop_program_id,
        accounts,
        data,
    })
}
fn deploy_bonding_curve_instruction(
    boop_program_id: &Pubkey,
    mint_pubkey: &Pubkey,
    vault_authority_pubkey: &Pubkey,
    bonding_curve_pubkey: &Pubkey,
    bonding_curve_sol_vault_pubkey: &Pubkey,
    bonding_curve_vault_pubkey: &Pubkey,
    config_pubkey: &Pubkey,
    payer_pubkey: &Pubkey,
    salt: u64,
) -> Result<Instruction, ThreadSafeError> {
    let discriminator: [u8; 8] = [180, 89, 199, 76, 168, 236, 217, 138];
    let creator = *payer_pubkey;
    let mut data = Vec::with_capacity(8 + 32 + 8);
    data.extend_from_slice(&discriminator);
    data.extend_from_slice(creator.as_ref());
    data.extend_from_slice(&salt.to_le_bytes());
    let accounts = vec![
        AccountMeta::new(*mint_pubkey, false),
        AccountMeta::new_readonly(*vault_authority_pubkey, false),
        AccountMeta::new(*bonding_curve_pubkey, false),
        AccountMeta::new(*bonding_curve_sol_vault_pubkey, false),
        AccountMeta::new(*bonding_curve_vault_pubkey, false),
        AccountMeta::new_readonly(*config_pubkey, false),
        AccountMeta::new(*payer_pubkey, true),
        AccountMeta::new_readonly(Pubkey::from_str(SYSTEM_PROGRAM).map_err(|e| Box::new(e) as ThreadSafeError)?, false),
        AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM).map_err(|e| Box::new(e) as ThreadSafeError)?, false),
        AccountMeta::new_readonly(Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM).map_err(|e| Box::new(e) as ThreadSafeError)?, false),
    ];
    Ok(Instruction {
        program_id: *boop_program_id,
        accounts,
        data,
    })
}


fn create_associated_token_account(
    payer: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
) -> Result<Instruction, Box<dyn std::error::Error + Send + Sync>> {
    let associated_token_program = Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM)?;
    let token_program = Pubkey::from_str(TOKEN_PROGRAM)?;
    let system_program = Pubkey::from_str(SYSTEM_PROGRAM)?;
    let rent_sysvar = Pubkey::from_str(RENT_SYSVAR)?;

    // Derive the ATA address for the wallet and mint
    let seeds = &[
        wallet.as_ref(),
        token_program.as_ref(),
        mint.as_ref(),
    ];
    let (associated_token_address, _) =
        Pubkey::find_program_address(seeds, &associated_token_program);

    // Create instruction to create ATA
    let accounts = vec![
        AccountMeta::new(*payer, true),                       // Payer
        AccountMeta::new(associated_token_address, false),    // ATA address
        AccountMeta::new_readonly(*wallet, false),            // Wallet address
        AccountMeta::new_readonly(*mint, false),              // Mint address
        AccountMeta::new_readonly(system_program, false),     // System program
        AccountMeta::new_readonly(token_program, false),      // Token program
        AccountMeta::new_readonly(rent_sysvar, false),        // Rent sysvar
    ];

    Ok(Instruction {
        program_id: associated_token_program,
        accounts,
        data: vec![], // ATA create instruction has no data
    })
}

fn buy_token_instruction(
    mint: &Pubkey,
    buyer: &Pubkey,
    recipient_token_account: &Pubkey,
    amount_in: u64,
    amount_out_min: u64,
) -> Result<Instruction, Box<dyn std::error::Error + Send + Sync>> {
    let boop_program_id = Pubkey::from_str(BOOP_PROGRAM_ID)?;
    let (config_pubkey, _) = Pubkey::find_program_address(&[b"config"], &boop_program_id);
    let (vault_authority, _) = Pubkey::find_program_address(&[b"vault_authority"], &boop_program_id);
    let (bonding_curve, _) = Pubkey::find_program_address(&[b"bonding_curve", mint.as_ref()], &boop_program_id);
    let (trading_fees_vault, _) = Pubkey::find_program_address(&[b"trading_fees_vault", mint.as_ref()], &boop_program_id);
    let (bonding_curve_vault, _) = Pubkey::find_program_address(&[b"bonding_curve_vault", mint.as_ref()], &boop_program_id);
    let (bonding_curve_sol_vault, _) = Pubkey::find_program_address(&[b"bonding_curve_sol_vault", mint.as_ref()], &boop_program_id);

    let system_program = Pubkey::from_str(SYSTEM_PROGRAM)?;
    let token_program = Pubkey::from_str(TOKEN_PROGRAM)?;
    let associated_token_program = Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM)?;
    let wsol_mint = Pubkey::from_str(WSOL_MINT)?;

    // Buy token discriminator: [138, 127, 14, 91, 38, 87, 115, 105]
    let discriminator: [u8; 8] = [138, 127, 14, 91, 38, 87, 115, 105];
    let mut data = Vec::with_capacity(8 + 8 + 8); // Discriminator + buy_amount (u64) + amount_out_min (u64)
    data.extend_from_slice(&discriminator);
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&amount_out_min.to_le_bytes());

    let accounts = vec![
        AccountMeta::new_readonly(*mint, false),
        AccountMeta::new(bonding_curve, false),
        AccountMeta::new(trading_fees_vault, false),
        AccountMeta::new(bonding_curve_vault, false),
        AccountMeta::new(bonding_curve_sol_vault, false),
        AccountMeta::new(*recipient_token_account, false),
        AccountMeta::new(*buyer, true), // Buyer signs the transaction
        AccountMeta::new_readonly(config_pubkey, false),
        AccountMeta::new_readonly(vault_authority, false),
        AccountMeta::new_readonly(wsol_mint, false),
        AccountMeta::new_readonly(system_program, false),
        AccountMeta::new_readonly(token_program, false),
        AccountMeta::new_readonly(associated_token_program, false),
    ];

    Ok(Instruction {
        program_id: boop_program_id,
        accounts,
        data,
    })
}