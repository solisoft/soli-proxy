use soli_proxy::auth::{generate_hash, hash_password};

fn main() {
    println!("Soli Proxy - Password Hasher");
    println!("============================\n");

    let args: Vec<String> = std::env::args().collect();
    let cost = parse_cost(&args);
    if cost == Some(0) {
        eprintln!("Error: --cost attend un entier entre 4 et 31\n");
        print_help();
        return;
    }
    let password = parse_password(&args);

    match password {
        Some(pw) => {
            if pw.is_empty() {
                eprintln!("Error: Password cannot be empty\n");
                print_help();
                return;
            }

            // ⚠️ Le coût se choisit, parce qu'il ne se choisit pas au hasard.
            //
            // bcrypt au facteur 12 met ~300 ms à vérifier, et le proxy vérifie
            // sur chaque requête : une page et ses quinze sous-ressources
            // paient quinze fois. Le cache de `auth::verify_once` règle le
            // gros du problème ; abaisser le facteur règle la première
            // requête. Pour un portail de recette — pas une base de mots de
            // passe clients — 8 est un compromis défendable.
            let hash = match cost {
                Some(cost) => hash_password(&pw, cost),
                None => generate_hash(&pw),
            };
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

/// `--cost N`, où qu'il soit sur la ligne. `Some(0)` signale une valeur
/// illisible ou hors des bornes de bcrypt, que l'appelant refuse.
fn parse_cost(args: &[String]) -> Option<u32> {
    let position = args.iter().position(|arg| arg == "--cost")?;
    match args
        .get(position + 1)
        .and_then(|raw| raw.parse::<u32>().ok())
    {
        Some(cost) if (4..=31).contains(&cost) => Some(cost),
        _ => Some(0),
    }
}

fn parse_password(args: &[String]) -> Option<String> {
    if args.len() < 2 {
        // No args - prompt interactively using no-echo input
        let password = rpassword::read_password().expect("Failed to read password");
        return Some(password);
    }

    let args: Vec<String> = args
        .iter()
        .enumerate()
        .filter(|(index, arg)| {
            let previous = index.checked_sub(1).and_then(|i| args.get(i));
            arg.as_str() != "--cost" && previous.map(|p| p != "--cost").unwrap_or(true)
        })
        .map(|(_, arg)| arg.clone())
        .collect();
    if args.len() < 2 {
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
    println!("  --cost N           Facteur bcrypt (4-31). Defaut : 12.");
    println!("  --help, -h                        Show this help message");
    println!();
    println!("Examples:");
    println!("  soli-proxy hash-password");
    println!("  soli-proxy hash-password --unsafe-cli-password mysecret123");
}
