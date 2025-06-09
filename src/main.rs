use std::{
    collections::HashSet,
    error::Error,
    fs::File,
    io::{BufWriter, Write},
};

use reqwest::blocking::get;

use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "sources/"]
struct Sources;

enum Category {
    Ads,
    Trackers,
    Malware,
    Phishing,
    SmartTV,
    NSFW,
}

impl Category {
    fn filename(&self) -> &'static str {
        match self {
            Category::Ads => "ads.txt",
            Category::Trackers => "trackers.txt",
            Category::Malware => "malware.txt",
            Category::Phishing => "phishing.txt",
            Category::SmartTV => "smart_tv.txt",
            Category::NSFW => "nsfw.txt",
        }
    }
}

use clap::Parser;

#[derive(Parser)]
#[command(name = "Baker", about = "Pi-Hole blocklist consolidator")]
struct Args {
    #[arg(long)]
    ads: bool,
    #[arg(long)]
    trackers: bool,
    #[arg(long)]
    malware: bool,
    #[arg(long)]
    phishing: bool,
    #[arg(long)]
    smart_tv: bool,
    #[arg(long)]
    nsfw: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let categories = selected_category(&args);

    let mut sources = Vec::new();
    for cat in &categories {
        let urls = read_sources(cat);
        sources.extend(urls);
    }

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

fn read_sources(cat: &Category) -> Vec<String> {
    let filename = cat.filename();
    if let Some(content) = Sources::get(filename) {
        let text = std::str::from_utf8(content.data.as_ref()).unwrap_or("");
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_string)
            .collect()
    } else {
        eprintln!("Missing embedded source file: {}", filename);
        vec![]
    }
}

fn fetch_url_contents(url: &str) -> Result<String, Box<dyn Error>> {
    let response = get(url)?;
    if !response.status().is_success() {
        Err(format!("Failed to fetch {}: {}", url, response.status()))?
    } else {
        Ok(response.text()?)
    }
}

fn extract_domain(line: &str) -> Option<String> {
    let line = line.trim();

    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    if let Ok(parsed) = url::Url::parse(line) {
        return parsed.host_str().map(|host| host.to_string());
    }

    let cleaned = line
        .trim_start_matches("||")
        .trim_start_matches("0.0.0.0 ")
        .trim_start_matches("127.0.0.1 ")
        .trim_end_matches('^')
        .trim();

    if cleaned.contains('/') || cleaned.contains(' ') {
        return None;
    }

    if cleaned.contains('.') && !cleaned.contains(':') {
        Some(cleaned.to_string())
    } else {
        None
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

fn selected_category(args: &Args) -> Vec<Category> {
    let mut cat = Vec::new();

    if args.ads {
        cat.push(Category::Ads);
    }
    if args.trackers {
        cat.push(Category::Trackers);
    }
    if args.malware {
        cat.push(Category::Malware);
    }
    if args.phishing {
        cat.push(Category::Phishing);
    }
    if args.smart_tv {
        cat.push(Category::SmartTV);
    }
    if args.nsfw {
        cat.push(Category::NSFW);
    }

    cat
}
