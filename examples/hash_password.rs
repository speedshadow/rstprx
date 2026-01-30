// Generate Argon2 password hash for config
use rama_elite_proxy::auth::AuthManager;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: cargo run --example hash_password <password>");
        println!("\nExample:");
        println!("  cargo run --example hash_password mySecurePassword123");
        return;
    }

    let password = &args[1];
    let hash = AuthManager::hash_password(password);
    
    println!("\n✅ Password hash generated successfully!\n");
    println!("Add this to your config.yaml:\n");
    println!("auth:");
    println!("  default_password: \"{}\"", hash);
    println!("\n⚠️  Keep this hash secret!");
}
