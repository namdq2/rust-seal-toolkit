use anyhow::Result;
use crypto::{
    ibe::{generate_key_pair, extract},
    seal_encrypt, seal_decrypt,
    create_full_id, EncryptionInput, IBEPublicKeys, IBEUserSecretKeys, ObjectID
};
use fastcrypto::groups::bls12381::{G2Element, Scalar};
use rand::thread_rng;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub struct FileDemo {
    pub package_id: ObjectID,
    pub master_keys: Vec<Scalar>,
    pub public_keys: Vec<G2Element>,
    pub key_servers: Vec<ObjectID>,
    pub threshold: u8,
    pub temp_dir: PathBuf,
}

impl FileDemo {
    pub fn new() -> Result<Self> {
        println!("📁 Setting up file encryption demo...");
        
        // Create temporary directory for demo files
        let temp_dir = std::env::temp_dir().join("seal-demo");
        fs::create_dir_all(&temp_dir)?;
        println!("   📂 Created temp directory: {}", temp_dir.display());
        
        // Set up 3 key servers with threshold 2
        let mut master_keys = Vec::new();
        let mut public_keys = Vec::new();
        let mut key_servers = Vec::new();
        
        for i in 0..3 {
            let (master_key, public_key) = generate_key_pair(&mut thread_rng());
            let server_id = ObjectID::random();
            
            master_keys.push(master_key);
            public_keys.push(public_key);
            key_servers.push(server_id);
            
            println!("   🔑 Created key server {}: {}", i + 1, server_id);
        }
        
        Ok(FileDemo {
            package_id: ObjectID::random(),
            master_keys,
            public_keys,
            key_servers,
            threshold: 2,
            temp_dir,
        })
    }
    
    fn create_sample_files(&self) -> Result<Vec<(PathBuf, String)>> {
        let large_file_content = "Large file content\n".repeat(1000);
        let files = vec![
            ("document.txt", "This is a sample text document with sensitive information."),
            ("config.json", r#"{"database": {"host": "localhost", "password": "secret123"}}"#),
            ("image.txt", "Binary data representation: [Image content would be here]"),
            ("large_file.txt", &large_file_content),
        ];
        
        let mut created_files = Vec::new();
        
        for (filename, content) in files {
            let file_path = self.temp_dir.join(filename);
            fs::write(&file_path, content)?;
            created_files.push((file_path, filename.to_string()));
            println!("   📄 Created: {} ({} bytes)", filename, content.len());
        }
        
        Ok(created_files)
    }
    
    pub fn encrypt_file(&self, file_path: &Path, output_path: &Path) -> Result<()> {
        println!("🔒 Encrypting file: {}", file_path.display());
        
        // Read file content
        let file_content = fs::read(file_path)?;
        println!("   📊 File size: {} bytes", file_content.len());
        
        // Use filename as identity
        let filename = file_path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let identity = format!("file:{}", filename).into_bytes();
        
        println!("   🆔 Identity: \"{}\"", String::from_utf8_lossy(&identity));
        
        // Encrypt the file
        let (encrypted_object, symmetric_key) = seal_encrypt(
            self.package_id,
            identity,
            self.key_servers.clone(),
            &IBEPublicKeys::BonehFranklinBLS12381(self.public_keys.clone()),
            self.threshold,
            EncryptionInput::Aes256Gcm {
                data: file_content,
                aad: None,
            },
        )?;
        
        // Save encrypted object and key
        let encrypted_data = bcs::to_bytes(&encrypted_object)?;
        fs::write(output_path, &encrypted_data)?;
        
        // Also save symmetric key for reference
        let key_path = output_path.with_extension("key");
        fs::write(&key_path, hex::encode(symmetric_key))?;
        
        println!("   ✅ Encrypted to: {}", output_path.display());
        println!("   🔑 Symmetric key saved to: {}", key_path.display());
        println!("   📏 Encrypted size: {} bytes", encrypted_data.len());
        
        Ok(())
    }
    
    pub fn decrypt_file(&self, encrypted_path: &Path, output_path: &Path) -> Result<()> {
        println!("🔓 Decrypting file: {}", encrypted_path.display());
        
        // Read encrypted object
        let encrypted_data = fs::read(encrypted_path)?;
        let encrypted_object: crypto::EncryptedObject = bcs::from_bytes(&encrypted_data)?;
        
        println!("   📊 Encrypted size: {} bytes", encrypted_data.len());
        println!("   🔢 Threshold: {}", encrypted_object.threshold);
        
        // Extract the filename from the identity
        let identity_str = String::from_utf8_lossy(&encrypted_object.id);
        println!("   🆔 Identity: \"{}\"", identity_str);
        
        // Create full identity
        let full_id = create_full_id(&encrypted_object.package_id, &encrypted_object.id);
        
        // Get user secret keys from first `threshold` servers
        let mut user_secret_keys = HashMap::new();
        for i in 0..(self.threshold as usize) {
            let secret_key = extract(&self.master_keys[i], &full_id);
            user_secret_keys.insert(self.key_servers[i], secret_key);
            println!("   🔑 Using key from server {}", i + 1);
        }
        
        // Decrypt
        let decrypted_data = seal_decrypt(
            &encrypted_object,
            &IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
            Some(&IBEPublicKeys::BonehFranklinBLS12381(self.public_keys.clone())),
        )?;
        
        // Write decrypted file
        fs::write(output_path, &decrypted_data)?;
        
        println!("   ✅ Decrypted to: {}", output_path.display());
        println!("   📏 Original size: {} bytes", decrypted_data.len());
        
        Ok(())
    }
    
    pub fn demo_file_encryption(&self) -> Result<()> {
        println!("\n🚀 === File Encryption Demo ===");
        
        // Create sample files
        let sample_files = self.create_sample_files()?;
        
        for (file_path, filename) in &sample_files {
            println!("\n📄 Processing file: {}", filename);
            
            // Define paths
            let encrypted_path = self.temp_dir.join(format!("{}.encrypted", filename));
            let decrypted_path = self.temp_dir.join(format!("{}.decrypted", filename));
            
            // Encrypt file
            self.encrypt_file(file_path, &encrypted_path)?;
            
            // Decrypt file  
            self.decrypt_file(&encrypted_path, &decrypted_path)?;
            
            // Verify integrity
            let original_content = fs::read(file_path)?;
            let decrypted_content = fs::read(&decrypted_path)?;
            
            if original_content == decrypted_content {
                println!("   ✅ File integrity verified - contents match!");
            } else {
                anyhow::bail!("❌ File integrity check failed for {}", filename);
            }
        }
        
        Ok(())
    }
    
    pub fn demo_batch_encryption(&self) -> Result<()> {
        println!("\n🚀 === Batch File Encryption Demo ===");
        
        // Create a directory structure
        let batch_dir = self.temp_dir.join("batch_demo");
        fs::create_dir_all(&batch_dir)?;
        
        let files_to_encrypt = vec![
            ("invoice_001.txt", "Invoice #001: $1,250.00"),
            ("invoice_002.txt", "Invoice #002: $2,375.00"),
            ("customer_data.json", r#"{"customers": [{"name": "Alice", "id": 1001}]}"#),
            ("report.md", "# Monthly Report\n\nSales increased by 15%"),
        ];
        
        println!("📦 Creating batch of files to encrypt...");
        
        for (filename, content) in &files_to_encrypt {
            let file_path = batch_dir.join(filename);
            fs::write(&file_path, content)?;
            println!("   📄 Created: {}", filename);
        }
        
        // Encrypt all files
        let encrypted_dir = self.temp_dir.join("encrypted_batch");
        fs::create_dir_all(&encrypted_dir)?;
        
        println!("\n🔒 Encrypting all files...");
        
        for (filename, _) in &files_to_encrypt {
            let source_path = batch_dir.join(filename);
            let encrypted_path = encrypted_dir.join(format!("{}.seal", filename));
            
            self.encrypt_file(&source_path, &encrypted_path)?;
        }
        
        // Decrypt all files  
        let decrypted_dir = self.temp_dir.join("decrypted_batch");
        fs::create_dir_all(&decrypted_dir)?;
        
        println!("\n🔓 Decrypting all files...");
        
        for (filename, _) in &files_to_encrypt {
            let encrypted_path = encrypted_dir.join(format!("{}.seal", filename));
            let decrypted_path = decrypted_dir.join(filename);
            
            self.decrypt_file(&encrypted_path, &decrypted_path)?;
        }
        
        // Verify all files
        println!("\n🔍 Verifying batch integrity...");
        let mut all_verified = true;
        
        for (filename, original_content) in &files_to_encrypt {
            let decrypted_path = decrypted_dir.join(filename);
            let decrypted_content = fs::read_to_string(&decrypted_path)?;
            
            if decrypted_content == *original_content {
                println!("   ✅ {}: verified", filename);
            } else {
                println!("   ❌ {}: integrity check failed", filename);
                all_verified = false;
            }
        }
        
        if all_verified {
            println!("🎉 Batch encryption/decryption successful!");
        } else {
            anyhow::bail!("❌ Some files failed integrity checks");
        }
        
        Ok(())
    }
    
    pub fn demo_file_metadata(&self) -> Result<()> {
        println!("\n🚀 === File Metadata Demo ===");
        
        let test_file = self.temp_dir.join("metadata_test.txt");
        let content = "File with metadata demonstration";
        fs::write(&test_file, content)?;
        
        // Create identity with metadata
        let metadata = serde_json::json!({
            "filename": "metadata_test.txt",
            "owner": "alice@company.com", 
            "department": "engineering",
            "classification": "confidential",
            "created": "2024-01-15T10:30:00Z"
        });
        
        let identity_with_metadata = format!("file:{}:metadata:{}", 
            test_file.file_name().unwrap().to_string_lossy(),
            metadata.to_string()
        ).into_bytes();
        
        println!("🏷️  Enhanced identity with metadata:");
        println!("   {}", String::from_utf8_lossy(&identity_with_metadata));
        
        // Encrypt with metadata-enhanced identity
        let (encrypted_object, _) = seal_encrypt(
            self.package_id,
            identity_with_metadata.clone(),
            self.key_servers.clone(),
            &IBEPublicKeys::BonehFranklinBLS12381(self.public_keys.clone()),
            self.threshold,
            EncryptionInput::Aes256Gcm {
                data: content.as_bytes().to_vec(),
                aad: Some(metadata.to_string().into_bytes()),  // Use metadata as AAD
            },
        )?;
        
        println!("🔒 Encrypted with metadata as Additional Authenticated Data (AAD)");
        
        // Decrypt
        let full_id = create_full_id(&self.package_id, &identity_with_metadata);
        let mut user_secret_keys = HashMap::new();
        
        for i in 0..(self.threshold as usize) {
            let secret_key = extract(&self.master_keys[i], &full_id);
            user_secret_keys.insert(self.key_servers[i], secret_key);
        }
        
        let decrypted = seal_decrypt(
            &encrypted_object,
            &IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
            Some(&IBEPublicKeys::BonehFranklinBLS12381(self.public_keys.clone())),
        )?;
        
        if decrypted == content.as_bytes() {
            println!("✅ Metadata-enhanced encryption successful!");
        } else {
            anyhow::bail!("❌ Metadata-enhanced encryption failed");
        }
        
        println!("\n💡 This demonstrates how to include file metadata in the encryption:");
        println!("   - Metadata becomes part of the identity (access control)");
        println!("   - AAD ensures metadata integrity without encryption");
        println!("   - Fine-grained access control based on file attributes");
        
        Ok(())
    }
    
    pub fn run_all_demos(&self) -> Result<()> {
        self.demo_file_encryption()?;
        self.demo_batch_encryption()?;
        self.demo_file_metadata()?;
        
        println!("\n🎉 All file encryption demos completed successfully!");
        
        // Clean up
        println!("\n🧹 Cleaning up temporary files...");
        fs::remove_dir_all(&self.temp_dir)?;
        println!("   ✅ Cleanup complete");
        
        Ok(())
    }
}

impl Drop for FileDemo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

impl Default for FileDemo {
    fn default() -> Self {
        Self::new().expect("Failed to create FileDemo")
    }
}