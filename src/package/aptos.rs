pub fn verify_signature_by_public_key_ethereum(ethereum_signature: &str, ethereum_address: &str) -> bool {
    panic!("Not implemented yet")
}

pub fn verify_signature_by_public_key_aptos(aptos_signature: &str, aptos_address: &str) -> bool {
    panic!("Not implemented yet")
}

#[cfg(test)]
mod tests {
    use crate::package::aptos::tests::AccountSignature::Ed25519Signature;
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
    use rand::rngs::StdRng;
    use rand::SeedableRng;

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
}
