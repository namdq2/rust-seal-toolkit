use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber;

mod basic_demo;
mod key_management;
mod threshold_demo;
mod file_demo;

use basic_demo::BasicDemo;
use key_management::KeyManagementDemo;
use threshold_demo::ThresholdDemo;
use file_demo::FileDemo;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(name = "seal-demo")]
#[command(about = "Seal Rust Integration Demo - Learn how to use Seal for encryption in Rust applications")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run basic encryption/decryption demonstrations
    Basic {
        /// Run only AES-256-GCM demo
        #[arg(long)]
        aes_only: bool,
        /// Run only HMAC-256-CTR demo  
        #[arg(long)]
        hmac_only: bool,
        /// Run only plain key derivation demo
        #[arg(long)]
        plain_only: bool,
    },
    /// Demonstrate key management operations
    Keys {
        /// Show only key generation demo
        #[arg(long)]
        generation_only: bool,
        /// Show only seed-based key derivation demo
        #[arg(long)]
        seed_only: bool,
        /// Show only identity namespacing demo
        #[arg(long)]
        namespace_only: bool,
        /// Show only key verification demo
        #[arg(long)]
        verify_only: bool,
    },
    /// Demonstrate threshold encryption with multiple key servers
    Threshold {
        /// Number of key servers to create (default: 3)
        #[arg(short, long, default_value_t = 3)]
        servers: usize,
        /// Show only basic threshold demo
        #[arg(long)]
        basic_only: bool,
        /// Show only server rotation demo
        #[arg(long)]
        rotation_only: bool,
        /// Show only access patterns demo
        #[arg(long)]
        access_only: bool,
    },
    /// Demonstrate file encryption and decryption
    Files {
        /// Show only basic file encryption demo
        #[arg(long)]
        basic_only: bool,
        /// Show only batch encryption demo
        #[arg(long)]
        batch_only: bool,
        /// Show only metadata demo
        #[arg(long)]
        metadata_only: bool,
    },
    /// Run all demonstrations (comprehensive overview)
    All {
        /// Number of key servers for threshold demo (default: 3)
        #[arg(short, long, default_value_t = 3)]
        servers: usize,
    },
    /// Interactive mode - choose demos interactively
    Interactive,
}

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();

    println!("🚀 Seal Rust Integration Demo");
    println!("===============================");
    println!("This demo shows how to integrate Seal encryption into your Rust applications.");
    println!();

    match &cli.command {
        Commands::Basic { aes_only, hmac_only, plain_only } => {
            run_basic_demo(*aes_only, *hmac_only, *plain_only)?;
        }
        Commands::Keys { generation_only, seed_only, namespace_only, verify_only } => {
            run_key_management_demo(*generation_only, *seed_only, *namespace_only, *verify_only)?;
        }
        Commands::Threshold { servers, basic_only, rotation_only, access_only } => {
            run_threshold_demo(*servers, *basic_only, *rotation_only, *access_only)?;
        }
        Commands::Files { basic_only, batch_only, metadata_only } => {
            run_file_demo(*basic_only, *batch_only, *metadata_only)?;
        }
        Commands::All { servers } => {
            run_all_demos(*servers)?;
        }
        Commands::Interactive => {
            run_interactive_mode()?;
        }
    }

    println!("\n✨ Demo completed! Check the source code to see how each feature is implemented.");
    println!("📚 For more information, visit: https://github.com/MystenLabs/seal");

    Ok(())
}

fn run_basic_demo(aes_only: bool, hmac_only: bool, plain_only: bool) -> Result<()> {
    let demo = BasicDemo::new()?;

    if aes_only {
        demo.run_aes_demo()
    } else if hmac_only {
        demo.run_hmac_demo()
    } else if plain_only {
        demo.run_plain_demo()
    } else {
        demo.run_all_demos()
    }
}

fn run_key_management_demo(generation_only: bool, seed_only: bool, namespace_only: bool, verify_only: bool) -> Result<()> {
    let demo = KeyManagementDemo::new();

    if generation_only {
        demo.demo_key_generation()
    } else if seed_only {
        demo.demo_seed_based_keys()
    } else if namespace_only {
        demo.demo_identity_namespacing()
    } else if verify_only {
        demo.demo_key_verification()
    } else {
        demo.run_all_demos()
    }
}

fn run_threshold_demo(servers: usize, basic_only: bool, rotation_only: bool, access_only: bool) -> Result<()> {
    if servers < 2 {
        anyhow::bail!("Need at least 2 key servers for threshold encryption");
    }

    let demo = ThresholdDemo::new(servers);

    if basic_only {
        demo.demo_threshold_encryption(2)
    } else if rotation_only {
        demo.demo_server_rotation()
    } else if access_only {
        demo.demo_access_patterns()
    } else {
        demo.run_all_demos()
    }
}

fn run_file_demo(basic_only: bool, batch_only: bool, metadata_only: bool) -> Result<()> {
    let demo = FileDemo::new()?;

    if basic_only {
        demo.demo_file_encryption()
    } else if batch_only {
        demo.demo_batch_encryption()
    } else if metadata_only {
        demo.demo_file_metadata()
    } else {
        demo.run_all_demos()
    }
}

fn run_all_demos(servers: usize) -> Result<()> {
    println!("🎯 Running comprehensive demo of all Seal features...\n");

    // Basic encryption/decryption
    println!("━━━ BASIC ENCRYPTION ━━━");
    let basic_demo = BasicDemo::new()?;
    basic_demo.run_all_demos()?;

    // Key management
    println!("\n━━━ KEY MANAGEMENT ━━━");
    let key_demo = KeyManagementDemo::new();
    key_demo.run_all_demos()?;

    // Threshold encryption
    println!("\n━━━ THRESHOLD ENCRYPTION ━━━");
    let threshold_demo = ThresholdDemo::new(servers);
    threshold_demo.run_all_demos()?;

    // File operations
    println!("\n━━━ FILE OPERATIONS ━━━");
    let file_demo = FileDemo::new()?;
    file_demo.run_all_demos()?;

    println!("\n🎉 🎉 🎉 ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY! 🎉 🎉 🎉");

    Ok(())
}

fn run_interactive_mode() -> Result<()> {
    use std::io::{self, Write};

    loop {
        println!("\n🎮 Interactive Demo Mode");
        println!("========================");
        println!("Choose a demo to run:");
        println!("  1. Basic Encryption (AES, HMAC, Plain key derivation)");
        println!("  2. Key Management (Generation, verification, namespacing)");
        println!("  3. Threshold Encryption (Multi-server, fault tolerance)");
        println!("  4. File Operations (File encryption, batch processing)");
        println!("  5. Run All Demos");
        println!("  6. Exit");
        println!();

        print!("Enter your choice (1-6): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim() {
            "1" => {
                run_basic_demo(false, false, false)?;
            }
            "2" => {
                run_key_management_demo(false, false, false, false)?;
            }
            "3" => {
                println!("How many key servers? (default: 3): ");
                let mut servers_input = String::new();
                io::stdin().read_line(&mut servers_input)?;
                let servers = servers_input.trim().parse().unwrap_or(3);
                
                if servers < 2 {
                    println!("❌ Need at least 2 servers. Using 3.");
                    run_threshold_demo(3, false, false, false)?;
                } else {
                    run_threshold_demo(servers, false, false, false)?;
                }
            }
            "4" => {
                run_file_demo(false, false, false)?;
            }
            "5" => {
                println!("How many key servers for threshold demo? (default: 3): ");
                let mut servers_input = String::new();
                io::stdin().read_line(&mut servers_input)?;
                let servers = servers_input.trim().parse().unwrap_or(3);
                
                run_all_demos(servers.max(2))?;
            }
            "6" => {
                println!("👋 Thanks for trying the Seal Rust demo!");
                break;
            }
            _ => {
                println!("❌ Invalid choice. Please enter 1-6.");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_demo() -> Result<()> {
        let demo = BasicDemo::new()?;
        demo.run_aes_demo()?;
        Ok(())
    }

    #[test]
    fn test_key_management_demo() -> Result<()> {
        let demo = KeyManagementDemo::new();
        demo.demo_key_generation()?;
        Ok(())
    }

    #[test]
    fn test_threshold_demo() -> Result<()> {
        let demo = ThresholdDemo::new(3);
        demo.demo_threshold_encryption(2)?;
        Ok(())
    }

    #[test]
    fn test_file_demo() -> Result<()> {
        let demo = FileDemo::new()?;
        // Just test basic functionality without cleanup for tests
        let temp_file = std::env::temp_dir().join("test.txt");
        std::fs::write(&temp_file, "test content")?;
        
        let encrypted_file = std::env::temp_dir().join("test.txt.encrypted");
        demo.encrypt_file(&temp_file, &encrypted_file)?;
        
        let decrypted_file = std::env::temp_dir().join("test.txt.decrypted");
        demo.decrypt_file(&encrypted_file, &decrypted_file)?;
        
        let original = std::fs::read(&temp_file)?;
        let decrypted = std::fs::read(&decrypted_file)?;
        assert_eq!(original, decrypted);
        
        // Cleanup
        let _ = std::fs::remove_file(&temp_file);
        let _ = std::fs::remove_file(&encrypted_file);
        let _ = std::fs::remove_file(&decrypted_file);
        
        Ok(())
    }
}