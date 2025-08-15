use anyhow::Result;
use crypto::{
    ibe::{generate_key_pair, extract},
    seal_encrypt, seal_decrypt, 
    EncryptionInput, IBEPublicKeys, IBEUserSecretKeys, ObjectID
};
use fastcrypto::groups::bls12381::{G2Element, Scalar};
use rand::thread_rng;
use std::collections::HashMap;

pub struct BasicDemo {
    pub package_id: ObjectID,
    pub identity: Vec<u8>,
    pub threshold: u8,
    pub key_servers: Vec<ObjectID>,
    pub master_keys: Vec<Scalar>,
    pub public_keys: Vec<G2Element>,
}

impl BasicDemo {
    pub fn new() -> Result<Self> {
        println!("🔧 Setting up basic Seal encryption demo...");
        
        // Generate package ID (simulated)
        let package_id = ObjectID::random();
        
        // Create identity for encryption
        let identity = b"user@example.com".to_vec();
        
        // Set threshold (2 out of 3 key servers)
        let threshold = 2;
        
        // Generate 3 key servers
        let mut key_servers = Vec::new();
        let mut master_keys = Vec::new();
        let mut public_keys = Vec::new();
        
        for i in 0..3 {
            let (master_key, public_key) = generate_key_pair(&mut thread_rng());
            let server_id = ObjectID::random();
            
            key_servers.push(server_id);
            master_keys.push(master_key);
            public_keys.push(public_key);
            
            println!("   📡 Created key server {}: {}", i + 1, server_id);
        }
        
        Ok(BasicDemo {
            package_id,
            identity,
            threshold,
            key_servers,
            master_keys,
            public_keys,
        })
    }
    
    pub fn encrypt_with_aes(&self, message: &[u8]) -> Result<(crypto::EncryptedObject, [u8; 32])> {
        println!("🔒 Encrypting message with AES-256-GCM...");
        println!("   📝 Message: \"{}\"", String::from_utf8_lossy(message));
        println!("   🆔 Identity: \"{}\"", String::from_utf8_lossy(&self.identity));
        println!("   📦 Package ID: {}", self.package_id);
        println!("   🔢 Threshold: {}/{}", self.threshold, self.key_servers.len());
        
        let result = seal_encrypt(
            self.package_id,
            self.identity.clone(),
            self.key_servers.clone(),
            &IBEPublicKeys::BonehFranklinBLS12381(self.public_keys.clone()),
            self.threshold,
            EncryptionInput::Aes256Gcm {
                data: message.to_vec(),
                aad: None,
            },
        )?;
        
        println!("   ✅ Encryption successful!");
        Ok(result)
    }
    
    pub fn encrypt_with_hmac(&self, message: &[u8]) -> Result<(crypto::EncryptedObject, [u8; 32])> {
        println!("🔒 Encrypting message with HMAC-256-CTR...");
        println!("   📝 Message: \"{}\"", String::from_utf8_lossy(message));
        
        let result = seal_encrypt(
            self.package_id,
            self.identity.clone(),
            self.key_servers.clone(),
            &IBEPublicKeys::BonehFranklinBLS12381(self.public_keys.clone()),
            self.threshold,
            EncryptionInput::Hmac256Ctr {
                data: message.to_vec(),
                aad: None,
            },
        )?;
        
        println!("   ✅ Encryption successful!");
        Ok(result)
    }
    
    pub fn encrypt_plain(&self) -> Result<(crypto::EncryptedObject, [u8; 32])> {
        println!("🔒 Generating encryption key (Plain mode)...");
        println!("   🆔 Identity: \"{}\"", String::from_utf8_lossy(&self.identity));
        
        let result = seal_encrypt(
            self.package_id,
            self.identity.clone(),
            self.key_servers.clone(),
            &IBEPublicKeys::BonehFranklinBLS12381(self.public_keys.clone()),
            self.threshold,
            crypto::EncryptionInput::Plain,
        )?;
        
        println!("   ✅ Key generation successful!");
        Ok(result)
    }
    
    pub fn decrypt(&self, encrypted_object: &crypto::EncryptedObject) -> Result<Vec<u8>> {
        println!("🔓 Decrypting message...");
        
        // Create full identity (package_id + identity_data)
        let full_id = crypto::create_full_id(&self.package_id, &self.identity);
        
        // Extract user secret keys from first `threshold` key servers
        let mut user_secret_keys = HashMap::new();
        for i in 0..(self.threshold as usize) {
            let secret_key = extract(&self.master_keys[i], &full_id);
            user_secret_keys.insert(self.key_servers[i], secret_key);
            println!("   🔑 Extracted secret key from server {}", i + 1);
        }
        
        let result = seal_decrypt(
            encrypted_object,
            &IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
            Some(&IBEPublicKeys::BonehFranklinBLS12381(self.public_keys.clone())),
        )?;
        
        println!("   ✅ Decryption successful!");
        Ok(result)
    }
    
    pub fn run_aes_demo(&self) -> Result<()> {
        println!("\n🚀 === AES-256-GCM Demo ===");
        
        let message = b"Hello, Seal! This is encrypted with AES-256-GCM.";
        
        let (encrypted_object, _symmetric_key) = self.encrypt_with_aes(message)?;
        let decrypted_message = self.decrypt(&encrypted_object)?;
        
        println!("🎯 Decrypted message: \"{}\"", String::from_utf8_lossy(&decrypted_message));
        
        // Verify the message matches
        if decrypted_message == message {
            println!("✅ AES demo successful - message matches!");
        } else {
            anyhow::bail!("❌ AES demo failed - message mismatch!");
        }
        
        Ok(())
    }
    
    pub fn run_hmac_demo(&self) -> Result<()> {
        println!("\n🚀 === HMAC-256-CTR Demo ===");
        
        let message = b"Hello, Seal! This is encrypted with HMAC-256-CTR.";
        
        let (encrypted_object, _symmetric_key) = self.encrypt_with_hmac(message)?;
        let decrypted_message = self.decrypt(&encrypted_object)?;
        
        println!("🎯 Decrypted message: \"{}\"", String::from_utf8_lossy(&decrypted_message));
        
        // Verify the message matches
        if decrypted_message == message {
            println!("✅ HMAC demo successful - message matches!");
        } else {
            anyhow::bail!("❌ HMAC demo failed - message mismatch!");
        }
        
        Ok(())
    }
    
    pub fn run_plain_demo(&self) -> Result<()> {
        println!("\n🚀 === Plain Key Derivation Demo ===");
        
        let (encrypted_object, original_key) = self.encrypt_plain()?;
        let derived_key = self.decrypt(&encrypted_object)?;
        
        println!("🎯 Original key: {}", hex::encode(&original_key));
        println!("🎯 Derived key:  {}", hex::encode(&derived_key));
        
        // Verify the keys match
        if derived_key == original_key {
            println!("✅ Plain demo successful - keys match!");
        } else {
            anyhow::bail!("❌ Plain demo failed - key mismatch!");
        }
        
        Ok(())
    }
    
    pub fn run_all_demos(&self) -> Result<()> {
        self.run_aes_demo()?;
        self.run_hmac_demo()?;
        self.run_plain_demo()?;
        println!("\n🎉 All basic demos completed successfully!");
        Ok(())
    }
}

impl Default for BasicDemo {
    fn default() -> Self {
        Self::new().expect("Failed to create BasicDemo")
    }
}