use std::{
    collections::HashSet,
    error::Error,
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
};

use reqwest::blocking::get;

use clap::Parser;

#[derive(Parser)]
#[command(name = "Baker", about = "Pi-Hole blocklist consolidator")]
struct Args {
    #[arg(short)]
    input: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let sources = read_sources(&args.input)?;
    let mut domains = HashSet::new();

    for url in sources {
        match fetch_url_contents(&url) {
            Ok(content) => {
                for line in content.lines() {
                    if let Some(domain) = extract_domain(line) {
                        domains.insert(domain.to_string());
                    }
                }
            }
            Err(e) => eprintln!("Error fetching {}: {}", url, e),
        }
    }

    write_blocklist("blocklist.txt", &domains)?;
    println!("Wrote {} unique domains to blocklist.txt", domains.len());

    Ok(())
}

fn read_sources(path: &str) -> std::io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let urls = reader
        .lines()
        .filter_map(Result::ok)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect();

    Ok(urls)
}

fn fetch_url_contents(url: &str) -> Result<String, Box<dyn Error>> {
    let response = get(url)?;
    if !response.status().is_success() {
        Err(format!("Failed to fetch {}: {}", url, response.status()))?
    } else {
        Ok(response.text()?)
    }
}

fn extract_domain(line: &str) -> Option<&str> {
    let line = line.trim();

    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let parts: Vec<&str> = line.split_whitespace().collect();

    match parts.len() {
        1 => Some(parts[0]),
        2 => Some(parts[1]),
        _ => None,
    }
}

fn write_blocklist(path: &str, domains: &HashSet<String>) -> std::io::Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    for domain in domains {
        writeln!(writer, "0.0.0.0 {}", domain)?;
    }

    Ok(())
}
