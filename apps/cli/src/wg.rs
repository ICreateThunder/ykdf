//! `ykdf wg`: derive `WireGuard` keys and assemble configs.
//!
//! `WireGuard` keys are Curve25519 in base64, which is exactly the `x25519`
//! profile: the private key is `base64(secret)` and
//! [`ykdf_core::public_key_string`] already emits the `WireGuard` public-key
//! encoding. So this module is a thin presentation and assembly layer over the
//! existing derivation path, pinned to x25519. The key is always re-derived from
//! the `YubiKey`; only the non-secret network fields come from flags.

use std::io::Write;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ykdf_core::{Pipeline, Profile, ProfileOutput, derive, public_key_string};
use zeroize::{Zeroize, Zeroizing};

use crate::cli::{WgCommand, WgConfigArgs, WgDerive, WgPeerArgs};
use crate::derive::{apply_passphrase, build_context, extract_ikm};
use crate::error::CliError;

/// A resolved recipe for `wg`: the derivation parameters after merging a recipe
/// (if any) with explicit flags, plus the recipe's `[wg]` extension when present.
/// The profile is always x25519, so it is not stored here.
struct WgParams {
    pipeline: Pipeline,
    purpose: String,
    index: u32,
    layered: bool,
    wg: Option<ykdf_config::WgConfig>,
}

pub fn run_wg(command: WgCommand, config: Option<&Path>) -> Result<(), CliError> {
    match command {
        WgCommand::Key(d) => run_key(&d, config),
        WgCommand::Pubkey(d) => run_pubkey(&d, config),
        WgCommand::Peer(args) => run_peer(&args, config),
        WgCommand::Config(args) => run_config(&args, config),
    }
}

/// Merge an optional recipe with explicit flags, using the same precedence as
/// `derive` (flag > recipe field > `[defaults]` > profile default). The recipe's
/// profile must be x25519; anything else is a mistake for a `WireGuard` key.
fn resolve_wg_params(d: &WgDerive, config: Option<&Path>) -> Result<WgParams, CliError> {
    let recipe = match d.recipe.as_deref() {
        Some(name) => Some(ykdf_config::Catalogue::load(config)?.resolve(name)?),
        None => None,
    };

    if let Some(r) = &recipe {
        if r.profile != Profile::X25519 {
            return Err(CliError::WgProfileMismatch {
                profile: r.profile.as_str(),
            });
        }
    }

    let purpose = match &d.purpose {
        Some(p) => p.clone(),
        None => recipe
            .as_ref()
            .map(|r| r.purpose.clone())
            .ok_or(CliError::MissingPurpose)?,
    };
    let pipeline = d
        .pipeline
        .clone()
        .map(Into::into)
        .or_else(|| recipe.as_ref().and_then(|r| r.pipeline))
        .unwrap_or_else(|| Profile::X25519.default_pipeline());
    let index = d
        .index
        .or_else(|| recipe.as_ref().map(|r| r.index))
        .unwrap_or(0);
    let layered = d.layered || recipe.as_ref().is_some_and(|r| r.layered);
    let wg = recipe.and_then(|r| r.wg);

    Ok(WgParams {
        pipeline,
        purpose,
        index,
        layered,
        wg,
    })
}

/// Derive the x25519 keypair from the resolved parameters.
fn derive_keypair(d: &WgDerive, params: &WgParams) -> Result<ProfileOutput, CliError> {
    let context = build_context(
        Profile::X25519,
        params.pipeline,
        &params.purpose,
        params.index,
    )?;
    let mut master_key = extract_ikm(
        d.ikm_file.as_ref(),
        params.layered,
        d.transport.to_override(),
        params.pipeline,
    )?;
    if d.passphrase {
        master_key = apply_passphrase(&master_key, params.pipeline)?;
    }
    derive(&master_key, &context).map_err(CliError::Core)
}

/// The base64 private key. `wg` pins the profile to x25519, which always derives
/// a `SecretKey`, so the other variants cannot occur.
fn private_key(output: &ProfileOutput) -> Zeroizing<String> {
    match output {
        ProfileOutput::SecretKey(k) => Zeroizing::new(BASE64.encode(k.0)),
        _ => unreachable!("wg pins the profile to x25519, which always derives a SecretKey"),
    }
}

/// The base64 public key (the `WireGuard` public-key encoding).
fn public_key(output: &ProfileOutput) -> Result<String, CliError> {
    public_key_string(output, Profile::X25519).ok_or(CliError::NoPubkey { profile: "x25519" })
}

/// A flag list wins wholesale; otherwise fall back to the recipe's list.
fn merge_list(flag: &[String], recipe: Option<&[String]>) -> Vec<String> {
    if flag.is_empty() {
        recipe.map(<[String]>::to_vec).unwrap_or_default()
    } else {
        flag.to_vec()
    }
}

fn run_key(d: &WgDerive, config: Option<&Path>) -> Result<(), CliError> {
    let params = resolve_wg_params(d, config)?;
    let output = derive_keypair(d, &params)?;
    let key = private_key(&output);
    // Zeroizing wipes the buffer on drop.
    let line = Zeroizing::new(format!("{}\n", key.as_str()));
    std::io::stdout()
        .write_all(line.as_bytes())
        .map_err(CliError::OutputWrite)
}

fn run_pubkey(d: &WgDerive, config: Option<&Path>) -> Result<(), CliError> {
    let params = resolve_wg_params(d, config)?;
    let output = derive_keypair(d, &params)?;
    let public = public_key(&output)?;
    println!("{public}");
    Ok(())
}

fn run_peer(args: &WgPeerArgs, config: Option<&Path>) -> Result<(), CliError> {
    let params = resolve_wg_params(&args.derive, config)?;
    let output = derive_keypair(&args.derive, &params)?;
    let public = public_key(&output)?;

    // AllowedIPs defaults to the recipe's interface address (the IPs this
    // device owns), which is what the other end routes back to it.
    let allowed_ips = merge_list(
        &args.allowed_ips,
        params.wg.as_ref().map(|w| w.address.as_slice()),
    );
    if allowed_ips.is_empty() {
        return Err(CliError::WgMissingAllowedIps);
    }

    let block = self_peer_block(&public, &allowed_ips, args.endpoint.as_deref());
    println!("{block}");
    Ok(())
}

fn run_config(args: &WgConfigArgs, config: Option<&Path>) -> Result<(), CliError> {
    let params = resolve_wg_params(&args.derive, config)?;
    let output = derive_keypair(&args.derive, &params)?;
    let private = private_key(&output);
    let wg = params.wg.as_ref();

    // Flags override the recipe's [wg] fields.
    let address = merge_list(&args.address, wg.map(|w| w.address.as_slice()));
    if address.is_empty() {
        return Err(CliError::WgMissingAddress);
    }
    let listen_port = args.listen_port.or_else(|| wg.and_then(|w| w.listen_port));
    let dns = merge_list(&args.dns, wg.map(|w| w.dns.as_slice()));
    let mtu = args.mtu.or_else(|| wg.and_then(|w| w.mtu));

    let mut text = Zeroizing::new(interface_block(
        private.as_str(),
        &address,
        listen_port,
        &dns,
        mtu,
    ));

    // A CLI --peer-pubkey replaces the recipe's peers wholesale; otherwise emit
    // one [Peer] block per recipe peer.
    if let Some(pubkey) = &args.peer_pubkey {
        text.push_str("\n\n");
        text.push_str(&config_peer_block(
            pubkey,
            args.endpoint.as_deref(),
            &args.allowed_ips,
            args.keepalive,
        ));
    } else if let Some(wg) = wg {
        for peer in &wg.peers {
            text.push_str("\n\n");
            text.push_str(&config_peer_block(
                &peer.public_key,
                peer.endpoint.as_deref(),
                &peer.allowed_ips,
                peer.keepalive,
            ));
        }
    }
    text.push('\n');

    write_config(args.output.as_deref(), &text)
}

/// Build the `[Interface]` block. Optional fields are omitted when unset.
///
/// One of the intermediate lines holds the base64 private key, so the line
/// buffers are zeroized after the block is assembled. The joined result carries
/// the key too and is wrapped in `Zeroizing` by the caller.
fn interface_block(
    private_b64: &str,
    address: &[String],
    listen_port: Option<u16>,
    dns: &[String],
    mtu: Option<u32>,
) -> String {
    let mut lines = vec![
        String::from("[Interface]"),
        format!("PrivateKey = {private_b64}"),
        format!("Address = {}", address.join(", ")),
    ];
    if let Some(port) = listen_port {
        lines.push(format!("ListenPort = {port}"));
    }
    if !dns.is_empty() {
        lines.push(format!("DNS = {}", dns.join(", ")));
    }
    if let Some(mtu) = mtu {
        lines.push(format!("MTU = {mtu}"));
    }
    let joined = lines.join("\n");
    for line in &mut lines {
        line.zeroize();
    }
    joined
}

/// Build a `[Peer]` block for a remote peer (used by `wg config`).
fn config_peer_block(
    pubkey: &str,
    endpoint: Option<&str>,
    allowed_ips: &[String],
    keepalive: Option<u16>,
) -> String {
    let mut lines = vec![String::from("[Peer]"), format!("PublicKey = {pubkey}")];
    if let Some(endpoint) = endpoint {
        lines.push(format!("Endpoint = {endpoint}"));
    }
    if !allowed_ips.is_empty() {
        lines.push(format!("AllowedIPs = {}", allowed_ips.join(", ")));
    }
    if let Some(secs) = keepalive {
        lines.push(format!("PersistentKeepalive = {secs}"));
    }
    lines.join("\n")
}

/// Build a `[Peer]` block describing this device (used by `wg peer`), for the
/// other end to paste into its config.
fn self_peer_block(pubkey: &str, allowed_ips: &[String], endpoint: Option<&str>) -> String {
    let mut lines = vec![
        String::from("[Peer]"),
        format!("PublicKey = {pubkey}"),
        format!("AllowedIPs = {}", allowed_ips.join(", ")),
    ];
    if let Some(endpoint) = endpoint {
        lines.push(format!("Endpoint = {endpoint}"));
    }
    lines.join("\n")
}

/// Write the config to stdout, or to a file created with mode 0600 (the config
/// carries a private key).
fn write_config(path: Option<&Path>, content: &str) -> Result<(), CliError> {
    match path {
        None => std::io::stdout()
            .write_all(content.as_bytes())
            .map_err(CliError::OutputWrite),
        Some(path) => {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .map_err(|source| CliError::OutputFile {
                    path: path.to_path_buf(),
                    source,
                })?;
            file.write_all(content.as_bytes())
                .map_err(|source| CliError::OutputFile {
                    path: path.to_path_buf(),
                    source,
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        config_peer_block, interface_block, merge_list, private_key, public_key, self_peer_block,
    };
    use ykdf_core::{Context, Ikm, Profile, derive, extract};

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn merge_list_prefers_flags_then_recipe_then_empty() {
        let flag = strings(&["10.0.0.9/24"]);
        let recipe = strings(&["10.0.0.2/24"]);
        // Flag wins wholesale.
        assert_eq!(merge_list(&flag, Some(&recipe)), flag);
        // No flag falls back to the recipe.
        assert_eq!(merge_list(&[], Some(&recipe)), recipe);
        // Neither is empty.
        assert!(merge_list(&[], None).is_empty());
    }

    #[test]
    fn interface_minimal_omits_optional_lines() {
        let block = interface_block("KEY", &strings(&["10.0.0.2/24"]), None, &[], None);
        assert_eq!(
            block,
            "[Interface]\nPrivateKey = KEY\nAddress = 10.0.0.2/24"
        );
    }

    #[test]
    fn interface_full_joins_repeatable_fields() {
        let block = interface_block(
            "KEY",
            &strings(&["10.0.0.2/24", "fd00::2/64"]),
            Some(51820),
            &strings(&["1.1.1.1", "1.0.0.1"]),
            Some(1420),
        );
        assert_eq!(
            block,
            "[Interface]\n\
             PrivateKey = KEY\n\
             Address = 10.0.0.2/24, fd00::2/64\n\
             ListenPort = 51820\n\
             DNS = 1.1.1.1, 1.0.0.1\n\
             MTU = 1420"
        );
    }

    #[test]
    fn config_peer_minimal_is_pubkey_only() {
        let block = config_peer_block("PUB", None, &[], None);
        assert_eq!(block, "[Peer]\nPublicKey = PUB");
    }

    #[test]
    fn config_peer_full_orders_fields() {
        let block = config_peer_block(
            "PUB",
            Some("vpn.example.com:51820"),
            &strings(&["0.0.0.0/0", "::/0"]),
            Some(25),
        );
        assert_eq!(
            block,
            "[Peer]\n\
             PublicKey = PUB\n\
             Endpoint = vpn.example.com:51820\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n\
             PersistentKeepalive = 25"
        );
    }

    #[test]
    fn self_peer_block_advertises_this_device() {
        let block = self_peer_block("PUB", &strings(&["10.0.0.2/32"]), Some("host:51820"));
        assert_eq!(
            block,
            "[Peer]\n\
             PublicKey = PUB\n\
             AllowedIPs = 10.0.0.2/32\n\
             Endpoint = host:51820"
        );
    }

    /// Derive the x25519 keypair from the golden IKM (0x00..0x1f), the same way
    /// the `format` feature's own tests do.
    fn keypair() -> ykdf_core::ProfileOutput {
        let ctx = Context::new(Profile::X25519, "wg-test", 0).unwrap();
        let ikm = Ikm::new((0u8..32).collect()).unwrap();
        let mk = extract(&ikm, ctx.pipeline()).unwrap();
        derive(&mk, &ctx).unwrap()
    }

    #[test]
    fn private_key_is_44_char_base64() {
        let out = keypair();
        let key = private_key(&out);
        assert_eq!(key.len(), 44);
        assert!(key.ends_with('='));
    }

    #[test]
    fn public_key_matches_shared_encoding() {
        let out = keypair();
        // wg pubkey must be byte-identical to `pubkey --profile x25519`, which
        // is exactly what public_key_string produces.
        let expected = ykdf_core::public_key_string(&out, Profile::X25519).unwrap();
        assert_eq!(public_key(&out).unwrap(), expected);
        assert_eq!(expected.len(), 44);
    }
}
