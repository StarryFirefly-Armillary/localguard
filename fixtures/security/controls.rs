// ARTIFICIAL STATIC FIXTURE - DO NOT EXECUTE, compile, or fetch crates.
// Client builders are parsed only; no client is built or request sent.
fn vulnerable_certificates() {
    let builder = reqwest::Client::builder();
    // ruleid: localguard.security.rust-tls-no-cert-validation
    let _unused = builder.danger_accept_invalid_certs(true);
}

fn vulnerable_hostnames() {
    let builder = reqwest::Client::builder();
    // ruleid: localguard.security.rust-tls-no-cert-validation
    let _unused = builder.danger_accept_invalid_hostnames(true);
}

fn clean_certificates() {
    let builder = reqwest::Client::builder();
    // ok: localguard.security.rust-tls-no-cert-validation
    let _unused = builder.danger_accept_invalid_certs(false);
}

fn clean_hostnames() {
    let builder = reqwest::Client::builder();
    // ok: localguard.security.rust-tls-no-cert-validation
    let _unused = builder.danger_accept_invalid_hostnames(false);
}
