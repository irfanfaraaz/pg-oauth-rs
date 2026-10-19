use std::{env, path::PathBuf, process::Command};

/// Finds the pg_config whose server headers match the server we build for:
/// `PGRX_PG_CONFIG_PATH`, then `PG_CONFIG`, then the pgrx config file, then PATH.
fn pg_config() -> String {
    if let Ok(path) = env::var("PGRX_PG_CONFIG_PATH").or_else(|_| env::var("PG_CONFIG")) {
        return path;
    }
    pgrx_config_entry().unwrap_or_else(|| "pg_config".into())
}

/// Reads `[configs] pgNN = "path"` from `$PGRX_HOME/config.toml` (default `~/.pgrx`).
fn pgrx_config_entry() -> Option<String> {
    let key = if env::var_os("CARGO_FEATURE_PG19").is_some() {
        "pg19"
    } else if env::var_os("CARGO_FEATURE_PG18").is_some() {
        "pg18"
    } else {
        return None;
    };
    let home = match env::var_os("PGRX_HOME") {
        Some(h) => PathBuf::from(h),
        None => PathBuf::from(env::var_os("HOME")?).join(".pgrx"),
    };
    let file = home.join("config.toml");
    println!("cargo:rerun-if-changed={}", file.display());
    let text = std::fs::read_to_string(file).ok()?;

    let mut in_configs = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_configs = line == "[configs]";
            continue;
        }
        if !in_configs {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

fn main() {
    println!("cargo:rerun-if-changed=src/shim.c");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PGRX_PG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PG_CONFIG");
    println!("cargo:rerun-if-env-changed=PGRX_HOME");
    println!("cargo:rerun-if-env-changed=HOME");

    let pg_config = pg_config();
    let include = match Command::new(&pg_config).arg("--includedir-server").output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => {
            eprintln!("error: `{pg_config} --includedir-server` failed; set PG_CONFIG to a pg_config with server headers");
            std::process::exit(1);
        }
    };

    cc::Build::new().file("src/shim.c").include(include).compile("pg_oauth_rs_shim");
}
