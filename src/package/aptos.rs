use actix_multipart::Multipart;
use actix_web::http;
use actix_web::http::header::HeaderMap;
use actix_web::http::Uri;
use actix_web::web::Bytes;
use aptos_sdk::crypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use aptos_sdk::crypto::{Signature, ValidCryptoMaterialStringExt};
use aptos_sdk::types::transaction::TransactionArgument::Address;
use ed25519_dalek::Signature as DalekSignature;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use std::io::Cursor;
use std::str::FromStr;
use std::{env, future};
use crate::routes::aptos::SignatureInfo;
// use ipfs_api_backend_actix::{IpfsApi, IpfsClient, TryFromUri};

#[derive(Serialize, Deserialize, Debug)]
struct IPFSFile {
    ethereum_public_key: String,
    ethereum_address: String,
    aptos_public_key: String,
    aptos_address: String,
    message: String,
    ethereum_signature: String,
    aptos_signature: String,
}

pub fn verify_signature_by_public_key_ethereum(
    ethereum_signature: &str,
    ethereum_address: &str,
) -> bool {
    let converted_signature = match ethers::types::Signature::from_str(ethereum_signature) {
        Ok(signature) => signature,
        Err(e) => {
            println!("Signature Error: {:?}", e);
            return false;
        }
    };

    let ethereum_address = match ethers::types::Address::from_str(ethereum_address) {
        Ok(address) => address,
        Err(e) => {
            println!("Address Error: {:?}", e);
            return false;
        }
    };

    match converted_signature.verify("aptosgazua", ethereum_address) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn verify_signature_by_public_key_aptos(
    message: &str,
    aptos_signature: &str,
    aptos_public_key: &str,
) -> bool {
    let signature = Ed25519Signature::from_encoded_string(aptos_signature).unwrap();
    let pubkey = Ed25519PublicKey::from_encoded_string(aptos_public_key).unwrap();
    let result = signature.verify_arbitrary_msg(message.as_ref(), &pubkey);
    result.is_ok()
}

pub fn store_database(
    signature_info: &SignatureInfo,
) -> bool {
    // TODO: Store database
    true
}

pub async fn upload_ipfs(data: String) -> Result<String, String> {
    let IPFS_API_KEY = env::var("IPFS_API_KEY").expect("IPFS_API_KEY must be set");
    let IPFS_API_KEY_SECRET =
        env::var("IPFS_API_KEY_SECRET").expect("IPFS_API_KEY_SECRET must be set");

    let client = reqwest::Client::new();
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "Authorization",
        format!(
            "Basic {}",
            base64::encode(format!("{}:{}", IPFS_API_KEY, IPFS_API_KEY_SECRET))
        )
        .parse()
        .unwrap(),
    );

    let form: reqwest::multipart::Form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(data.as_bytes().to_vec()).file_name("ipfs_upload.json"),
    );

    let mut response = client
        .post("https://ipfs.infura.io:5001/api/v0/add")
        .headers(headers)
        .multipart(form)
        .send()
        .await
        .map_err(|e| {
            println!("Response Error: {:?}", e);
            e.to_string()
        })?;

    let text = response.text().await.map_err(|e| e.to_string())?;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let hash = json["Hash"].as_str().unwrap();
    println!("hash: {}", hash);
    Ok(hash.to_string())
}

#[cfg(test)]
mod tests {
    use crate::package::aptos::tests::AccountSignature::Ed25519Signature;
    use crate::package::aptos::{upload_ipfs, verify_signature_by_public_key_ethereum};
    use aptos_sdk::crypto::ed25519::Ed25519Signature as Ed25519SignatureTuple;
    use aptos_sdk::crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
    use aptos_sdk::crypto::{
        signing_message, CryptoMaterialError, PrivateKey, Signature, SigningKey, Uniform,
        ValidCryptoMaterialStringExt, VerifyingKey,
    };
    use aptos_sdk::rest_client::aptos_api_types::AccountSignature;
    use aptos_sdk::types::transaction::TransactionArgument::Address;
    use cosmos_sdk_proto::traits::MessageExt;
    use ed25519_dalek::Keypair as DalekKeyPair;
    use ed25519_dalek::{PublicKey, Signature as DalekSignature, Signer, Verifier};
    use ethers::signers::{LocalWallet, Signer as LocalSigner};
    use ethers::types::SignatureError;
    use ipfs_api_backend_actix::{IpfsApi, IpfsClient};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::env;
    use std::str::FromStr;

    #[test]
    fn sign_message_by_aptos_public_key() {
        // given : test_config.rs
        let mut rng = StdRng::from_seed([0u8; 32]);
        let message_original = "Naheeya, Denver Gazua...";
        println!("message: {:?}", message_original);

        let message = message_original.as_bytes();
        println!("message in u8 vector: {:?}", message);

        let msg_str = message
            .iter()
            .map(|i| (*i as u8) as char)
            .collect::<String>();
        assert_eq!(msg_str, message_original);

        let privkey = Ed25519PrivateKey::generate(&mut rng);
        let pubkey = privkey.public_key();

        // when
        let signature = privkey.sign_arbitrary_message(message);
        let signature_bytes = signature.to_bytes();
        println!("signature in bytes: {:?}", signature_bytes);
        println!("signature in string format: {:?}", signature.to_string());

        // then
        let result = signature.verify_arbitrary_msg(message, &pubkey);
        println!("result: {:?}", result);
        assert!(result.is_ok());

        // convert string to pubKey structure
        // let pubkey_string = "0x79bcb88da2e388fe5c73db849bad35a933b6bc9e45f62a6c23957ec5c483d0a5".to_string();
        let pubkey_string = pubkey.to_string();
        println!("pubkey: {:?}", pubkey);
        let pubkey_to_ed25519 = Ed25519PublicKey::from_encoded_string(&pubkey_string).unwrap();
        println!("pubkey_to_ed25519: {:?}", pubkey_to_ed25519);
        assert_eq!(pubkey_to_ed25519, pubkey);

        // the following aptos sdk ed25519 helper tool doesn't work in public fashion (outside of the crate)
        // let signature_to_ed25519 = ed25519_dalek::Signature::from_bytes(bytes).unwrap();
        // println!("signature to ed25519: {:?}", signature_to_ed25519.unwrap());
        // let signature_to_ed25519 = DalekSignature::try_from(bytes).unwrap();
        let signature_to_ed25519 =
            Ed25519SignatureTuple::try_from(signature_bytes.as_ref()).unwrap();
        println!("signature to ed25519: {:?}", signature_to_ed25519);
        assert_eq!(signature_to_ed25519, signature);
    }

    #[test]
    fn test_verify_signature_by_public_key_aptos() {
        let message_original = "aptosgazua";
        let message = message_original.as_bytes();

        let mut rng = rand::thread_rng();
        let privkey = aptos_sdk::crypto::ed25519::Ed25519PrivateKey::generate(&mut rng);
        let pubkey = privkey.public_key();
        println!("pubkey: {:?}", pubkey);
        let signature = privkey.sign_arbitrary_message(message);
        println!("signature: {:?}", signature);

        let signature_str = signature.to_string();
        let pubkey_str = pubkey.to_string();

        // Given
        let signature = signature_str.clone();
        let pubkey = pubkey_str.clone();

        // When
        let result =
            super::verify_signature_by_public_key_aptos(message_original, &signature, &pubkey);

        // Then
        assert!(result, "Expected the signature to be valid");
    }

    // reference: https://docs.rs/ethers-signers/0.5.4/ethers_signers/index.html
    #[actix_web::test]
    async fn test_verify_signature_by_public_key_ethereum() {
        // given
        // get private key from environment variable
        let private_key_env =
            env::var("PRIVATE_KEY_ETHEREUM").expect("PRIVATE_KEY_ETHEREUM must be set");
        let wallet = private_key_env.parse::<LocalWallet>().unwrap();
        let signature = wallet.sign_message("aptosgazua").await.unwrap();

        // when
        let signature_str = signature.to_string();
        println!("signature: {:?}", signature_str);
        println!("wallet address: {:?}", wallet.address());
        let converted_signature = ethers::types::Signature::from_str(&signature_str).unwrap();

        // then
        assert!(converted_signature
            .verify("aptosgazua", wallet.address())
            .is_ok());
        assert!(verify_signature_by_public_key_ethereum(
            &signature_str,
            "0x01725BE700413D34bCC5e961de1d0C777d3A52F4"
        ));
    }

    #[actix_web::test]
    async fn test_upload_ipfs() {
        let data = r#"{
        "ethereum_public_key": "none",
        "ethereum_address": "0x01725BE700413D34bCC5e961de1d0C777d3A52F4",
        "aptos_public_key": "0x917e745db1b1edc9ce62a8ed62b1cfcf261b4a5a21d58b167874e6cf6fa68aa3",
        "aptos_address": "0x470196fa19f82ece3bfe1f4658c12098f752c5ae01a43a4f57cb46fbf05c1011",
        "message": "aptosgazua",
        "ethereum_signature": "71bcbc3edb59e4182c7d8dddf38df23d5220194fbe0e6f4577d4137c91c678a00825785fee253b93944c05202e339109e295cc523818995e5307813a8282e3cc1b",
        "aptos_signature": "35b6acdafabae15db4083b60bd801bd7e532c5fd038844d592b0b677f67b6dfb12ed2a810ea107c23c27e6ecce300cf9233c3efe5c8fb59248ee2aafc9be7a00"
    }"#.to_string();

        let hash = upload_ipfs(data.clone()).await;
        assert!(hash.is_ok());
        assert!(!hash.unwrap().as_str().is_empty());

        // let downloaded_data = download_ipfs(hash.unwrap().as_str()).await;
        // assert!(downloaded_data.is_ok());
    }
}
