use crate::logging::LOG_TARGET;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AppConfig {
    pub user: Option<String>,
    #[serde(rename = "pass")]
    pub password: Option<String>,
    pub wifi_ssid: Option<String>,
    pub iface: Option<String>,
    /// Clave WPA para `nmcli` (red no abierta). Opcional.
    pub wifi_password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EffectiveNetwork {
    pub iface: String,
    pub wifi_ssid: String,
    pub wifi_password: Option<String>,
}

pub fn merged_network(cli_iface: &Option<String>, cli_ssid: &Option<String>, cfg: Option<&AppConfig>) -> EffectiveNetwork {
    let c = cfg;
    EffectiveNetwork {
        iface: cli_iface
            .clone()
            .or_else(|| c.and_then(|x| x.iface.clone()))
            .unwrap_or_else(|| "wlan0".into()),
        wifi_ssid: cli_ssid
            .clone()
            .or_else(|| c.and_then(|x| x.wifi_ssid.clone()))
            .unwrap_or_else(|| "UABC-2.4G".into()),
        wifi_password: c.and_then(|x| x.wifi_password.clone()).filter(|s| !s.is_empty()),
    }
}

pub fn load_config(cli_config: &Option<PathBuf>) -> Result<Option<AppConfig>, String> {
    let path: Option<PathBuf> = match cli_config {
        Some(p) => {
            if !p.is_file() {
                return Err(format!("No existe el archivo --config: {}", p.display()));
            }
            Some(p.clone())
        }
        None => {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.json");
            if manifest.is_file() {
                Some(manifest)
            } else {
                std::env::current_dir()
                    .ok()
                    .map(|d| d.join("config.json"))
                    .filter(|p| p.is_file())
            }
        }
    };

    let Some(path) = path else {
        return Ok(None);
    };

    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("No se pudo leer {}: {e}", path.display()))?;
    let c: AppConfig =
        serde_json::from_str(&text).map_err(|e| format!("JSON inválido en {}: {e}", path.display()))?;
    tracing::info!(
        target: LOG_TARGET,
        "[Config] Archivo cargado: {}",
        path.display()
    );
    Ok(Some(c))
}

pub fn resolve_auth_user(cli_auth: &Option<String>, cfg: Option<&AppConfig>) -> Option<String> {
    cli_auth
        .clone()
        .or_else(|| cfg.and_then(|c| c.user.clone()))
        .filter(|s| !s.is_empty())
}

pub fn resolve_auth_password(cfg: Option<&AppConfig>) -> Option<String> {
    cfg.and_then(|c| c.password.clone()).filter(|s| !s.is_empty())
}

pub fn auto_login_credentials(
    cli_auth: &Option<String>,
    cfg: Option<&AppConfig>,
) -> Result<(String, String), String> {
    if cfg.is_none() {
        return Err(
            "--auto-login necesita config.json con user y pass (usa --config o deja config.json en el proyecto/cwd)"
                .into(),
        );
    }
    let user = resolve_auth_user(cli_auth, cfg).ok_or_else(|| {
        "En config.json define «user» (portal UABC) o pasa --auth usuario".to_string()
    })?;
    let pass = resolve_auth_password(cfg).ok_or_else(|| {
        "«pass» en config.json es obligatorio para --auto-login (no hay prompt en segundo plano)".to_string()
    })?;
    Ok((user, pass))
}
