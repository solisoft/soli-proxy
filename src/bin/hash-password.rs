use soli_proxy::auth::generate_hash;
use std::io::{self, Write};

fn main() {
    println!("Soli Proxy - Password Hasher");
    println!("============================\n");

    let args: Vec<String> = std::env::args().collect();
    let password = parse_password(&args);

    match password {
        Some(pw) => {
            if pw.is_empty() {
                eprintln!("Error: Password cannot be empty\n");
                print_help();
                return;
            }

            let hash = generate_hash(&pw);
            println!("\nGenerated bcrypt hash:");
            println!("{}", hash);
            println!("\nUse in proxy.conf:");
            println!(
                "  example.com -> http://localhost:8080/ @auth:admin:{}",
                hash
            );
            println!("\nOr for multiple users:");
            println!(
                "  example.com -> http://localhost:8080/ @auth:user1:{} @auth:user2:{}",
                hash, hash
            );
        }
        None => {
            print_help();
        }
    }
}

fn parse_password(args: &[String]) -> Option<String> {
    if args.len() < 2 {
        // No args - prompt interactively
        print!("Enter password: ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        return Some(input.trim().to_string());
    }

    match args[1].as_str() {
        "--help" | "-h" => None,
        arg if arg.starts_with("--password=") => {
            // --password=VALUE
            Some(arg.strip_prefix("--password=")?.to_string())
        }
        "--password" => {
            // --password VALUE (requires next arg)
            if args.len() >= 3 {
                Some(args[2].clone())
            } else {
                eprintln!("Error: --password requires a value\n");
                None
            }
        }
        // Positional argument (password directly)
        p if !p.starts_with('-') => Some(p.to_string()),
        _ => {
            eprintln!("Error: Unknown argument: {}\n", args[1]);
            None
        }
    }
}

fn print_help() {
    println!("Usage:");
    println!("  soli-proxy hash-password [PASSWORD]");
    println!("  soli-proxy hash-password --password=PASSWORD");
    println!();
    println!("Options:");
    println!("  PASSWORD          Password to hash (prompts if not provided)");
    println!("  --password=VALUE  Password via flag (equals syntax)");
    println!("  --password VALUE  Password via flag (space syntax)");
    println!("  --help, -h        Show this help message");
    println!();
    println!("Examples:");
    println!("  soli-proxy hash-password");
    println!("  soli-proxy hash-password mysecret123");
    println!("  soli-proxy hash-password --password=mysecret123");
    println!("  soli-proxy hash-password --password mysecret123");
}
