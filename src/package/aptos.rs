#[cfg(test)]
mod tests {
    use aptos_sdk::crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
    use aptos_sdk::crypto::{
        signing_message, PrivateKey, Signature, SigningKey, Uniform, ValidCryptoMaterialStringExt,
        VerifyingKey,
    };
    use aptos_sdk::types::transaction::TransactionArgument::Address;
    use rand::prelude::StdRng;
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
        println!("signature: {:?}", signature);

        // then
        let result = signature.verify_arbitrary_msg(message, &pubkey);
        println!("result: {:?}", result);
        assert!(result.is_ok());

        // convert string to pubKey structure
        let pubkey_string = pubkey.to_string();
        println!("pubkey: {:?}", pubkey);
        let pubkey_to_ed25519 = Ed25519PublicKey::from_encoded_string(&pubkey_string).unwrap();
        println!("pubkey_to_ed25519: {:?}", pubkey_to_ed25519);
        assert_eq!(pubkey_to_ed25519, pubkey);enc
    }
}
