use reqwest;
use std::collections::HashMap;
use std::time::Duration;

use std::process::Command;

pub fn login(username: &str, password: &str) -> Result<bool, Box<dyn std::error::Error>> {
    check_uabc_connection()?;

    let local_id = get_local_id()?;

    let login_success = send_login(username, password, &local_id)?;

    if login_success {
        return Ok(true);
    }

    Ok(false)
}

fn get_local_id() -> Result<String, Box<dyn std::error::Error>> {
    let client = build_client(true);

    let response = client.get("https://pcw.uabc.mx/").send()?;

    if response.status().is_redirection() {
        if let Some(location) = response.headers().get("Location") {
            let url = location.to_str().unwrap_or_default();
            if let Some(pos) = url.find("url=") {
                let local_id = &url[(pos + 4)..];
                return Ok(local_id.to_string());
            }
        }
    }

    Err("Portal cautivo no disponible".into())
}

fn send_login(
    email: &str,
    password: &str,
    local_id: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let client = build_client(false);

    let mut form = HashMap::new();
    form.insert("url", local_id);
    form.insert("username", email);
    form.insert("password", password);

    let response = client.post("https://pcw.uabc.mx/").form(&form).send()?;

    if response.status().is_success() {
        let body = response.text()?;
        return Ok(body.contains("<title>Login Successful</title>"));
    }

    Ok(false)
}

fn check_uabc_connection() -> Result<bool, Box<dyn std::error::Error>> {
    match get_current_ssid() {
        Ok(name) => {
            if name.contains("UABC") {
                Ok(true)
            } else {
                Err("No estás conectado a la red UABC".into())
            }
        }
        Err(_) => Err("No te encuentras en una red Wifi".into()),
    }
}

fn build_client(no_redirect: bool) -> reqwest::blocking::Client {
    let mut builder = reqwest::blocking::Client::builder().timeout(Duration::from_secs(5));

    if no_redirect {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    builder.build().expect("Failed to build HTTP client")
}

fn get_current_ssid() -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("iwgetid").arg("-r").output()?;

    if !output.status.success() {
        return Err("El comando falló".into());
    }

    let wifi_name = String::from_utf8(output.stdout)?.trim().to_string();

    Ok(wifi_name)
}
