# Seal Rust Integration Demo

This demo project shows how to integrate **Seal** (Decentralized Secrets Management) into your Rust applications. Seal uses Identity-Based Encryption (IBE) and threshold cryptography to provide secure, decentralized encryption services.

## 🎯 What You'll Learn

- How to use Seal's native Rust API for encryption/decryption
- Key management with IBE (Identity-Based Encryption)
- Threshold encryption with multiple key servers
- File encryption and batch processing
- Best practices for integrating Seal into production applications

## 🏗️ Project Structure

```
src/
├── main.rs              # CLI interface and demo orchestration
├── basic_demo.rs        # Basic encryption/decryption examples
├── key_management.rs    # Key generation and management
├── threshold_demo.rs    # Multi-server threshold encryption
└── file_demo.rs         # File encryption operations
```

## 🚀 Quick Start

### Prerequisites

- Rust 1.87+ (as specified in rust-toolchain.toml)
- Git (to clone the Seal repository)

### Build and Run

1. **Navigate to the demo directory:**
   ```bash
   cd examples/rust-demo
   ```

2. **Build the project:**
   ```bash
   cargo build
   ```

3. **Run the interactive demo:**
   ```bash
   cargo run interactive
   ```

4. **Or run specific demos:**
   ```bash
   # Basic encryption examples
   cargo run basic
   
   # Key management demonstrations  
   cargo run keys
   
   # Threshold encryption (3 servers by default)
   cargo run threshold --servers 5
   
   # File encryption operations
   cargo run files
   
   # Run everything
   cargo run all
   ```

## 📚 Demo Modules

### 1. Basic Encryption (`basic_demo.rs`)

Demonstrates fundamental Seal encryption operations:

- **AES-256-GCM**: Symmetric encryption with authentication
- **HMAC-256-CTR**: Counter mode with HMAC authentication  
- **Plain Key Derivation**: Generate encryption keys from identities

```rust
// Example: Encrypt with AES-256-GCM
let (encrypted_object, symmetric_key) = seal_encrypt(
    package_id,
    identity_data,
    key_server_object_ids,
    &IBEPublicKeys::BonehFranklinBLS12381(public_keys),
    threshold,
    EncryptionInput::Aes256Gcm {
        data: message.to_vec(),
        aad: None,
    },
)?;
```

### 2. Key Management (`key_management.rs`)

Shows how to manage IBE keys:

- **Master Key Generation**: Create IBE key pairs
- **User Secret Key Extraction**: Derive keys for specific identities
- **Seed-Based Derivation**: Deterministic key generation
- **Identity Namespacing**: Package-scoped identities
- **Key Verification**: Validate key correctness

```rust
// Example: Generate master keys and extract user keys
let (master_key, public_key) = generate_key_pair(&mut thread_rng());
let full_id = create_full_id(&package_id, &identity);
let user_secret_key = extract(&master_key, &full_id);
```

### 3. Threshold Encryption (`threshold_demo.rs`)

Demonstrates multi-server threshold schemes:

- **T-out-of-N Encryption**: Require cooperation of T servers out of N total
- **Server Rotation**: Access control survives server failures
- **Access Patterns**: Different identities for fine-grained control

```rust
// Example: 2-out-of-3 threshold encryption
let threshold = 2u8;
let (encrypted_object, _) = seal_encrypt(
    package_id,
    identity,
    key_server_object_ids,  // 3 servers
    &IBEPublicKeys::BonehFranklinBLS12381(public_keys),
    threshold,              // Only need 2 to decrypt
    encryption_input,
)?;
```

### 4. File Operations (`file_demo.rs`)

Shows practical file encryption scenarios:

- **Single File Encryption**: Encrypt/decrypt individual files
- **Batch Processing**: Handle multiple files efficiently  
- **Metadata Integration**: Include file metadata in access control

```rust
// Example: Encrypt a file with metadata
let identity_with_metadata = format!("file:{}:metadata:{}", 
    filename, metadata_json
).into_bytes();

let (encrypted_object, _) = seal_encrypt(
    package_id,
    identity_with_metadata,
    key_servers,
    public_keys,
    threshold,
    EncryptionInput::Aes256Gcm {
        data: file_content,
        aad: Some(metadata_bytes), // Authenticated metadata
    },
)?;
```

## 🔧 Integration Guide

### Adding Seal to Your Rust Project

1. **Add dependencies to `Cargo.toml`:**
   ```toml
   [dependencies]
   # Core Seal crypto library
   seal-crypto = { path = "path/to/seal/crates/crypto" }
   
   # Required dependencies
   fastcrypto = { git = "https://github.com/MystenLabs/fastcrypto", rev = "69d496c71fb37e3d22fe85e5bbfd4256d61422b9", features = ["aes"] }
   sui_types = { git = "https://github.com/mystenlabs/sui", rev = "42ba6c0", package = "sui-types"}
   bcs = "0.1.6"
   rand = "0.8.5"
   ```

2. **Import Seal components:**
   ```rust
   use crypto::{
       seal_encrypt, seal_decrypt,
       EncryptionInput, IBEPublicKeys, IBEUserSecretKeys,
       ibe::{generate_key_pair, extract},
       create_full_id, ObjectID
   };
   ```

3. **Basic usage pattern:**
   ```rust
   // 1. Set up key servers (or connect to existing ones)
   let (master_key, public_key) = generate_key_pair(&mut thread_rng());
   let key_server_id = ObjectID::random();
   
   // 2. Define identity and package context
   let package_id = ObjectID::from_str("your_package_id")?;
   let identity = b"user@example.com".to_vec();
   
   // 3. Encrypt data
   let (encrypted_object, _) = seal_encrypt(
       package_id,
       identity.clone(),
       vec![key_server_id],
       &IBEPublicKeys::BonehFranklinBLS12381(vec![public_key]),
       1, // threshold
       EncryptionInput::Aes256Gcm {
           data: your_data,
           aad: None,
       },
   )?;
   
   // 4. Decrypt data (with proper authorization)
   let full_id = create_full_id(&package_id, &identity);
   let user_secret_key = extract(&master_key, &full_id);
   
   let decrypted = seal_decrypt(
       &encrypted_object,
       &IBEUserSecretKeys::BonehFranklinBLS12381(
           HashMap::from([(key_server_id, user_secret_key)])
       ),
       Some(&IBEPublicKeys::BonehFranklinBLS12381(vec![public_key])),
   )?;
   ```

## 🏛️ Architecture Concepts

### Identity-Based Encryption (IBE)
- **Master Keys**: Generated by key servers, used to extract user keys
- **Public Keys**: Shared publicly, used for encryption  
- **User Secret Keys**: Extracted for specific identities, used for decryption
- **Identities**: Namespaced by Sui package ID: `[PackageID][IdentityData]`

### Threshold Encryption
- **Threshold (T)**: Minimum number of key servers needed for decryption
- **Total Servers (N)**: Total number of key servers in the system
- **Secret Sharing**: Data encrypted with shares distributed across servers
- **Fault Tolerance**: System works as long as T servers are available

### Access Control
- **Package-Based**: Different Sui packages = different namespaces
- **Identity-Based**: Fine-grained access per identity string
- **Server Cooperation**: No single server can decrypt alone (if T > 1)

## 🔍 Command Line Options

```bash
# Basic encryption demos
cargo run basic                    # All basic demos
cargo run basic --aes-only        # Only AES-256-GCM
cargo run basic --hmac-only       # Only HMAC-256-CTR  
cargo run basic --plain-only      # Only plain key derivation

# Key management demos  
cargo run keys                     # All key management demos
cargo run keys --generation-only  # Only key generation
cargo run keys --seed-only        # Only seed-based derivation
cargo run keys --namespace-only   # Only identity namespacing
cargo run keys --verify-only      # Only key verification

# Threshold encryption demos
cargo run threshold                # Default 3 servers
cargo run threshold --servers 5   # Custom server count
cargo run threshold --basic-only  # Only basic threshold demo
cargo run threshold --rotation-only # Only server rotation demo
cargo run threshold --access-only  # Only access patterns demo

# File operation demos
cargo run files                    # All file demos
cargo run files --basic-only      # Only basic file encryption
cargo run files --batch-only      # Only batch processing
cargo run files --metadata-only   # Only metadata integration

# Comprehensive demos
cargo run all                      # Everything with default settings
cargo run all --servers 5         # Everything with custom server count

# Interactive mode
cargo run interactive              # Choose demos interactively
```

## 🧪 Testing

Run the included tests to verify functionality:

```bash
# Run all tests
cargo test

# Run specific test modules  
cargo test basic_demo
cargo test key_management
cargo test threshold_demo
cargo test file_demo

# Run with output
cargo test -- --nocapture
```

## 🌟 Key Features Demonstrated

### Security Features
- ✅ **Identity-Based Encryption**: No need to exchange keys beforehand
- ✅ **Threshold Security**: Requires cooperation of multiple servers
- ✅ **Access Control**: Package and identity-based permissions
- ✅ **Authenticated Encryption**: Built-in data integrity verification
- ✅ **Forward Secrecy**: Each encryption uses fresh randomness

### Practical Features
- ✅ **File Encryption**: Handle arbitrary file types and sizes
- ✅ **Batch Processing**: Efficient bulk operations
- ✅ **Metadata Support**: Include file attributes in access control
- ✅ **Error Handling**: Comprehensive error reporting
- ✅ **Testing**: Unit tests for all major functionality

### Performance Features  
- ✅ **Native Rust**: No foreign function interface overhead
- ✅ **Efficient Cryptography**: BLS12-381 curve operations
- ✅ **Minimal Dependencies**: Only essential cryptographic libraries
- ✅ **Memory Safety**: Rust's memory safety guarantees

## 🔗 Next Steps

After running these demos, you can:

1. **Study the source code** to understand implementation details
2. **Modify the examples** to match your use case
3. **Integrate Seal** into your existing Rust applications
4. **Set up real key servers** using the `key-server` crate
5. **Deploy on Sui blockchain** using the Move contracts in `move/`

## 📖 Additional Resources

- **Seal Repository**: https://github.com/MystenLabs/seal
- **Sui Documentation**: https://docs.sui.io
- **IBE Cryptography**: [Boneh-Franklin IBE](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf)
- **BLS Signatures**: [BLS12-381 Curve](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04)

## 🤝 Contributing

If you find issues or have suggestions for improving these demos:

1. Check existing issues in the Seal repository
2. Create detailed bug reports or feature requests
3. Submit pull requests with improvements

## 📄 License

This demo is licensed under the Apache License 2.0, same as the Seal project.

---

**Happy encrypting with Seal! 🦭🔒**