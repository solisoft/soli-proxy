use soli_proxy::auth::generate_hash;

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
        // No args - prompt interactively using no-echo input
        let password = rpassword::read_password().expect("Failed to read password");
        return Some(password);
    }

    match args[1].as_str() {
        "--help" | "-h" => None,
        "--unsafe-cli-password" => {
            // Explicitly allow CLI password (warns about argv/syslog exposure)
            if args.len() >= 3 {
                eprintln!("WARNING: Passing passwords via command line exposes them in argv, shell history, and process listings.");
                eprintln!(
                    "WARNING: Use interactive mode (no arguments) for safer password entry.\n"
                );
                Some(args[2].clone())
            } else {
                eprintln!("Error: --unsafe-cli-password requires a password argument\n");
                None
            }
        }
        _ => {
            eprintln!("Error: Passing passwords via command line arguments is not supported.");
            eprintln!("Run without arguments to use secure interactive prompt, or");
            eprintln!("pass --unsafe-cli-password PASSWORD to explicitly acknowledge the risk.\n");
            None
        }
    }
}

fn print_help() {
    println!("Usage:");
    println!("  soli-proxy hash-password");
    println!();
    println!("Options:");
    println!("  (no arguments)     Secure interactive prompt (recommended)");
    println!("  --unsafe-cli-password PASSWORD  Pass password via CLI (NOT recommended)");
    println!("  --help, -h                        Show this help message");
    println!();
    println!("Examples:");
    println!("  soli-proxy hash-password");
    println!("  soli-proxy hash-password --unsafe-cli-password mysecret123");
}
