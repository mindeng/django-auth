use std::io::{self, BufRead, Write};

use clap::{Parser, Subcommand};
use django_auth::*;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encode a password in Django-style
    Encode,

    /// Verify a Django stored hashed password
    Verify,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encode => {
            let (password, salt, iterations) = {
                (
                    get_user_input("Input password: "),
                    get_user_input("Input salt: "),
                    get_user_input_number("Input number of iterations: "),
                )
            };

            println!(
                "✅ Encoded password: {}",
                django_encode_password(&password, &salt, iterations).unwrap()
            );
        }
        Commands::Verify => {
            let (password, hashed_password) = {
                (
                    get_user_input("Input password: "),
                    get_user_input("Input Django stored password: "),
                )
            };

            let res = django_auth(&password, &hashed_password);
            match res {
                Ok(ok) => {
                    if ok {
                        println!("✅ Password verified!")
                    } else {
                        println!("❌ Password verification failed!")
                    }
                }
                Err(err) => println!("💔 Verification error: {:?}", err),
            }
        }
    }
}

fn get_user_input(prompt: &str) -> String {
    print!("{prompt}");
    io::stdout().flush().expect("failed to write to stdout");

    let stdin = io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .expect("failed to read password")
        .expect("failed to read from stdin");

    line
}

fn get_user_input_number(prompt: &str) -> u32 {
    let res = get_user_input(prompt).parse::<u32>();
    if let Ok(n) = res {
        return n;
    }

    loop {
        println!("Please input a number, try again!");
        let res = get_user_input(prompt).parse::<u32>();
        if let Ok(n) = res {
            return n;
        }
    }
}
