use anyhow::Result;
use crypto::{
    ibe::{generate_key_pair, extract},
    seal_encrypt, seal_decrypt,
    create_full_id, EncryptionInput, IBEPublicKeys, IBEUserSecretKeys, ObjectID
};
use fastcrypto::groups::bls12381::{G2Element, Scalar};
use rand::thread_rng;
use std::collections::HashMap;

pub struct ThresholdDemo {
    pub package_id: ObjectID,
    pub identity: Vec<u8>,
    pub key_servers: Vec<KeyServer>,
}

#[derive(Clone)]
pub struct KeyServer {
    pub object_id: ObjectID,
    pub master_key: Scalar,
    pub public_key: G2Element,
    pub name: String,
}

impl KeyServer {
    fn new(name: String) -> Self {
        let (master_key, public_key) = generate_key_pair(&mut thread_rng());
        KeyServer {
            object_id: ObjectID::random(),
            master_key,
            public_key,
            name,
        }
    }
}

impl ThresholdDemo {
    pub fn new(num_servers: usize) -> Self {
        println!("🏗️  Setting up threshold encryption with {} key servers...", num_servers);
        
        let mut key_servers = Vec::new();
        
        for i in 0..num_servers {
            let server = KeyServer::new(format!("KeyServer-{}", i + 1));
            println!("   📡 Created {}: {}", server.name, server.object_id);
            key_servers.push(server);
        }
        
        ThresholdDemo {
            package_id: ObjectID::random(),
            identity: b"sensitive-document@company.com".to_vec(),
            key_servers,
        }
    }
    
    pub fn demo_threshold_encryption(&self, threshold: u8) -> Result<()> {
        println!("\n🚀 === Threshold Encryption Demo ({}/{}) ===", threshold, self.key_servers.len());
        
        let message = format!("Secret message requiring {}-out-of-{} key servers for decryption.", threshold, self.key_servers.len());
        
        // Extract key server info
        let object_ids: Vec<ObjectID> = self.key_servers.iter().map(|s| s.object_id).collect();
        let public_keys: Vec<G2Element> = self.key_servers.iter().map(|s| s.public_key).collect();
        
        println!("🔒 Encrypting with threshold {}/{}...", threshold, self.key_servers.len());
        println!("   📝 Message: \"{}\"", message);
        println!("   🆔 Identity: \"{}\"", String::from_utf8_lossy(&self.identity));
        println!("   📡 Available servers: {}", self.key_servers.len());
        
        // Encrypt the message
        let (encrypted_object, _) = seal_encrypt(
            self.package_id,
            self.identity.clone(),
            object_ids,
            &IBEPublicKeys::BonehFranklinBLS12381(public_keys.clone()),
            threshold,
            EncryptionInput::Aes256Gcm {
                data: message.as_bytes().to_vec(),
                aad: None,
            },
        )?;
        
        println!("   ✅ Encryption successful!");
        
        // Test decryption with exactly threshold number of servers
        println!("\n🔓 Testing decryption with minimum servers ({}):", threshold);
        self.test_decryption_with_servers(&encrypted_object, &public_keys, threshold as usize, true)?;
        
        // Test decryption with more than threshold servers (if possible)
        if self.key_servers.len() > threshold as usize {
            let extra_servers = std::cmp::min(self.key_servers.len(), threshold as usize + 1);
            println!("\n🔓 Testing decryption with extra servers ({}):", extra_servers);
            self.test_decryption_with_servers(&encrypted_object, &public_keys, extra_servers, true)?;
        }
        
        // Test failure with insufficient servers
        if threshold > 1 {
            println!("\n❌ Testing decryption failure with insufficient servers ({}):", threshold - 1);
            self.test_decryption_with_servers(&encrypted_object, &public_keys, (threshold - 1) as usize, false)?;
        }
        
        println!("   ✅ Threshold encryption demo completed!");
        Ok(())
    }
    
    fn test_decryption_with_servers(
        &self,
        encrypted_object: &crypto::EncryptedObject,
        public_keys: &[G2Element],
        num_servers: usize,
        should_succeed: bool,
    ) -> Result<()> {
        let full_id = create_full_id(&self.package_id, &self.identity);
        
        // Use the first `num_servers` key servers
        let mut user_secret_keys = HashMap::new();
        let selected_servers = &self.key_servers[..num_servers];
        
        for server in selected_servers {
            let secret_key = extract(&server.master_key, &full_id);
            user_secret_keys.insert(server.object_id, secret_key);
            println!("   🔑 Using secret key from {}", server.name);
        }
        
        let decrypt_result = seal_decrypt(
            encrypted_object,
            &IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
            Some(&IBEPublicKeys::BonehFranklinBLS12381(public_keys.to_vec())),
        );
        
        match (decrypt_result, should_succeed) {
            (Ok(decrypted), true) => {
                let decrypted_message = String::from_utf8_lossy(&decrypted);
                println!("   ✅ Decryption successful: \"{}\"", decrypted_message);
            }
            (Err(e), false) => {
                println!("   ✅ Decryption correctly failed: {}", e);
            }
            (Ok(_), false) => {
                anyhow::bail!("❌ Decryption unexpectedly succeeded when it should have failed");
            }
            (Err(e), true) => {
                anyhow::bail!("❌ Decryption unexpectedly failed: {}", e);
            }
        }
        
        Ok(())
    }
    
    pub fn demo_server_rotation(&self) -> Result<()> {
        println!("\n🚀 === Key Server Rotation Demo ===");
        
        if self.key_servers.len() < 3 {
            println!("   ⚠️  Need at least 3 servers for rotation demo");
            return Ok(());
        }
        
        let threshold = 2u8;
        let message = b"Document that survives server rotation";
        
        // Encrypt with all servers
        let object_ids: Vec<ObjectID> = self.key_servers.iter().map(|s| s.object_id).collect();
        let public_keys: Vec<G2Element> = self.key_servers.iter().map(|s| s.public_key).collect();
        
        println!("🔒 Encrypting document with all servers...");
        let (encrypted_object, _) = seal_encrypt(
            self.package_id,
            self.identity.clone(),
            object_ids,
            &IBEPublicKeys::BonehFranklinBLS12381(public_keys.clone()),
            threshold,
            EncryptionInput::Aes256Gcm {
                data: message.to_vec(),
                aad: None,
            },
        )?;
        
        // Test different combinations of servers
        let server_combinations = vec![
            vec![0, 1],  // First two servers
            vec![0, 2],  // First and third
            vec![1, 2],  // Second and third
        ];
        
        println!("\n🔄 Testing different server combinations:");
        
        for (i, combination) in server_combinations.iter().enumerate() {
            let server_names: Vec<String> = combination.iter()
                .map(|&idx| self.key_servers[idx].name.clone())
                .collect();
            
            println!("\n   Combination {}: {} + {}", i + 1, server_names[0], server_names[1]);
            
            let full_id = create_full_id(&self.package_id, &self.identity);
            let mut user_secret_keys = HashMap::new();
            
            for &server_idx in combination {
                let server = &self.key_servers[server_idx];
                let secret_key = extract(&server.master_key, &full_id);
                user_secret_keys.insert(server.object_id, secret_key);
            }
            
            let decrypt_result = seal_decrypt(
                &encrypted_object,
                &IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
                Some(&IBEPublicKeys::BonehFranklinBLS12381(public_keys.clone())),
            );
            
            match decrypt_result {
                Ok(decrypted) => {
                    if decrypted == message {
                        println!("     ✅ Decryption successful with this combination");
                    } else {
                        println!("     ❌ Decryption produced wrong result");
                    }
                }
                Err(e) => {
                    println!("     ❌ Decryption failed: {}", e);
                }
            }
        }
        
        println!("\n💡 This demonstrates how threshold encryption provides resilience:");
        println!("   - Any {} servers out of {} can decrypt the document", threshold, self.key_servers.len());
        println!("   - System continues working even if some servers are offline");
        println!("   - No single server can decrypt alone (requires cooperation)");
        
        Ok(())
    }
    
    pub fn demo_access_patterns(&self) -> Result<()> {
        println!("\n🚀 === Access Pattern Demo ===");
        
        let threshold = 2u8;
        
        // Create different documents with different access requirements
        let documents = vec![
            ("public-announcement.txt", b"Public company announcement"),
            ("hr-policy.pdf", b"Internal HR policy document"),
            ("financial-report.xlsx", b"Confidential quarterly data"),
        ];
        
        let object_ids: Vec<ObjectID> = self.key_servers.iter().map(|s| s.object_id).collect();
        let public_keys: Vec<G2Element> = self.key_servers.iter().map(|s| s.public_key).collect();
        
        println!("🗂️  Encrypting different document types:");
        
        for (filename, content) in &documents {
            let document_identity = format!("document:{}", filename).into_bytes();
            
            println!("\n   📄 Document: {}", filename);
            println!("      Identity: \"{}\"", String::from_utf8_lossy(&document_identity));
            
            let (encrypted_object, _) = seal_encrypt(
                self.package_id,
                document_identity.clone(),
                object_ids.clone(),
                &IBEPublicKeys::BonehFranklinBLS12381(public_keys.clone()),
                threshold,
                EncryptionInput::Aes256Gcm {
                    data: content.to_vec(),
                    aad: None,
                },
            )?;
            
            // Simulate access attempt
            println!("      🔓 Simulating authorized access...");
            
            let full_id = create_full_id(&self.package_id, &document_identity);
            let mut user_secret_keys = HashMap::new();
            
            // Use first `threshold` servers
            for i in 0..(threshold as usize) {
                let server = &self.key_servers[i];
                let secret_key = extract(&server.master_key, &full_id);
                user_secret_keys.insert(server.object_id, secret_key);
            }
            
            let decrypted = seal_decrypt(
                &encrypted_object,
                &IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
                Some(&IBEPublicKeys::BonehFranklinBLS12381(public_keys.clone())),
            )?;
            
            if decrypted == *content {
                println!("      ✅ Access granted - content verified");
            } else {
                println!("      ❌ Access failed - content mismatch");
            }
        }
        
        println!("\n💡 Each document has a unique identity, creating separate access controls");
        println!("   - Same key servers, same threshold, but different encryption keys");
        println!("   - Fine-grained access control per document/resource");
        
        Ok(())
    }
    
    pub fn run_all_demos(&self) -> Result<()> {
        // Test different threshold values
        for threshold in 2..=std::cmp::min(3, self.key_servers.len() as u8) {
            self.demo_threshold_encryption(threshold)?;
        }
        
        self.demo_server_rotation()?;
        self.demo_access_patterns()?;
        
        println!("\n🎉 All threshold encryption demos completed successfully!");
        Ok(())
    }
}

impl Default for ThresholdDemo {
    fn default() -> Self {
        Self::new(3) // Default to 3 key servers
    }
}