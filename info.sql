CREATE TABLE IF NOT EXISTS NAMELINK_INFO (
                                             id TEXT PRIMARY KEY,
                                             ethereum_public_key TEXT,
                                             ethereum_address TEXT,
                                             aptos_public_key TEXT,
                                             aptos_address TEXT,
                                             message TEXT,
                                             ethereum_signature TEXT,
                                             aptos_signature TEXT
);
