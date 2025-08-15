use anyhow::Result;
use crypto::{
    ibe::{generate_key_pair, extract, verify_user_secret_key, generate_seed, derive_master_key, into_key_pair},
    create_full_id, ObjectID
};
use fastcrypto::serde_helpers::ToFromByteArray;
use rand::thread_rng;

pub struct KeyManagementDemo {
    pub package_id: ObjectID,
    pub identities: Vec<Vec<u8>>,
}

impl KeyManagementDemo {
    pub fn new() -> Self {
        KeyManagementDemo {
            package_id: ObjectID::random(),
            identities: vec![
                b"alice@example.com".to_vec(),
                b"bob@example.com".to_vec(),
                b"charlie@example.com".to_vec(),
            ],
        }
    }
    
    pub fn demo_key_generation(&self) -> Result<()> {
        println!("\n🚀 === Key Generation Demo ===");
        
        println!("🔑 Generating IBE master key pair...");
        let (master_key, public_key) = generate_key_pair(&mut thread_rng());
        
        println!("   Master Key: {}", hex::encode(master_key.to_byte_array()));
        println!("   Public Key: {}", hex::encode(bcs::to_bytes(&public_key)?));
        
        // Demonstrate key extraction for different identities
        println!("\n👥 Extracting user secret keys for different identities:");
        
        for (i, identity) in self.identities.iter().enumerate() {
            let full_id = create_full_id(&self.package_id, identity);
            let user_secret_key = extract(&master_key, &full_id);
            
            println!("   User {}: {}", i + 1, String::from_utf8_lossy(identity));
            println!("   Full ID: {}", hex::encode(&full_id));
            println!("   Secret Key: {}", hex::encode(bcs::to_bytes(&user_secret_key)?));
            
            // Verify the user secret key
            match verify_user_secret_key(&user_secret_key, &full_id, &public_key) {
                Ok(_) => println!("   ✅ Secret key verification successful"),
                Err(e) => println!("   ❌ Secret key verification failed: {}", e),
            }
            println!();
        }
        
        Ok(())
    }
    
    pub fn demo_seed_based_keys(&self) -> Result<()> {
        println!("\n🚀 === Seed-Based Key Derivation Demo ===");
        
        println!("🌱 Generating seed for deterministic key derivation...");
        let seed = generate_seed(&mut thread_rng());
        println!("   Seed: {}", hex::encode(seed));
        
        println!("\n🔄 Deriving multiple key pairs from the same seed:");
        
        for index in 0..3 {
            let derived_master_key = derive_master_key(&seed, index);
            let (master_key, public_key) = into_key_pair(derived_master_key);
            
            println!("   Index {}: ", index);
            println!("     Master Key: {}", hex::encode(master_key.to_byte_array()));
            println!("     Public Key: {}", hex::encode(bcs::to_bytes(&public_key)?));
            
            // Extract a user secret key for the first identity
            let full_id = create_full_id(&self.package_id, &self.identities[0]);
            let user_secret_key = extract(&master_key, &full_id);
            
            // Verify it works
            match verify_user_secret_key(&user_secret_key, &full_id, &public_key) {
                Ok(_) => println!("     ✅ Derived key verification successful"),
                Err(e) => println!("     ❌ Derived key verification failed: {}", e),
            }
        }
        
        println!("\n💡 Note: Same seed + same index = same key pair (deterministic)");
        
        Ok(())
    }
    
    pub fn demo_identity_namespacing(&self) -> Result<()> {
        println!("\n🚀 === Identity Namespacing Demo ===");
        
        let (master_key, _public_key) = generate_key_pair(&mut thread_rng());
        
        println!("🏷️  Package ID: {}", self.package_id);
        println!("🆔 Demonstrating how identities are namespaced by package ID:");
        
        let identity = b"user@example.com";
        
        // Show how different package IDs create different full identities
        let package_ids = vec![
            ObjectID::random(),
            ObjectID::random(), 
            self.package_id,
        ];
        
        for (i, pkg_id) in package_ids.iter().enumerate() {
            let full_id = create_full_id(pkg_id, identity);
            let user_secret_key = extract(&master_key, &full_id);
            
            println!("\n   Context {}: Package ID = {}", i + 1, pkg_id);
            println!("   Identity: \"{}\"", String::from_utf8_lossy(identity));
            println!("   Full ID: {}", hex::encode(&full_id));
            println!("   Secret Key: {}", hex::encode(bcs::to_bytes(&user_secret_key)?));
            
            if pkg_id == &self.package_id {
                println!("   👆 This is our main package context");
            }
        }
        
        println!("\n💡 Note: Same identity + different package = different secret keys");
        
        Ok(())
    }
    
    pub fn demo_key_verification(&self) -> Result<()> {
        println!("\n🚀 === Key Verification Demo ===");
        
        let (master_key, public_key) = generate_key_pair(&mut thread_rng());
        let identity = &self.identities[0];
        let full_id = create_full_id(&self.package_id, identity);
        
        println!("🔍 Generating and verifying user secret keys...");
        
        // Generate correct secret key
        let correct_secret_key = extract(&master_key, &full_id);
        
        println!("   Identity: \"{}\"", String::from_utf8_lossy(identity));
        println!("   Correct Secret Key: {}", hex::encode(bcs::to_bytes(&correct_secret_key)?));
        
        // Test correct verification
        match verify_user_secret_key(&correct_secret_key, &full_id, &public_key) {
            Ok(_) => println!("   ✅ Correct key verification: PASSED"),
            Err(e) => println!("   ❌ Correct key verification: FAILED ({})", e),
        }
        
        // Test with wrong secret key (different identity)
        let wrong_full_id = create_full_id(&self.package_id, &self.identities[1]);
        let wrong_secret_key = extract(&master_key, &wrong_full_id);
        
        match verify_user_secret_key(&wrong_secret_key, &full_id, &public_key) {
            Ok(_) => println!("   ❌ Wrong key verification: UNEXPECTEDLY PASSED"),
            Err(_) => println!("   ✅ Wrong key verification: CORRECTLY FAILED"),
        }
        
        // Test with wrong public key
        let (_, wrong_public_key) = generate_key_pair(&mut thread_rng());
        
        match verify_user_secret_key(&correct_secret_key, &full_id, &wrong_public_key) {
            Ok(_) => println!("   ❌ Wrong public key verification: UNEXPECTEDLY PASSED"),
            Err(_) => println!("   ✅ Wrong public key verification: CORRECTLY FAILED"),
        }
        
        Ok(())
    }
    
    pub fn run_all_demos(&self) -> Result<()> {
        self.demo_key_generation()?;
        self.demo_seed_based_keys()?;
        self.demo_identity_namespacing()?;
        self.demo_key_verification()?;
        println!("\n🎉 All key management demos completed successfully!");
        Ok(())
    }
}

impl Default for KeyManagementDemo {
    fn default() -> Self {
        Self::new()
    }
}