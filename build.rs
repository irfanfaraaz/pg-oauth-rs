use std::{env, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=src/shim.c");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PGRX_PG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PG_CONFIG");

    let pg_config = env::var("PGRX_PG_CONFIG_PATH")
        .or_else(|_| env::var("PG_CONFIG"))
        .unwrap_or_else(|_| "pg_config".into());
    let include = match Command::new(&pg_config).arg("--includedir-server").output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => {
            eprintln!("error: `{pg_config} --includedir-server` failed; set PG_CONFIG to a pg_config with server headers");
            std::process::exit(1);
        }
    };

    cc::Build::new().file("src/shim.c").include(include).compile("pg_oauth_rs_shim");
}
