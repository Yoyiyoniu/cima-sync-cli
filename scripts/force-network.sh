#!/usr/bin/env bash
# Fuerza conexión WiFi a un SSID concreto (por defecto UABC-2.4G) en Raspberry Pi OS.
# Uso: force-network.sh [interfaz] [ssid]
# Red abierta: solo iface + ssid. WPA: export CIMA_SYNC_WIFI_PASSWORD='...'
# Requiere root para nmcli / wpa_cli en la mayoría de sistemas.

set -u

IFACE="${1:-wlan0}"
SSID="${2:-UABC-2.4G}"

log() {
  printf '%s\n' "[force-network] $*" >&2
}

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  log "Sin privilegios root; reintentando con sudo..."
  exec sudo -E env PATH="$PATH" bash "$0" "$IFACE" "$SSID"
fi

if ! ip link show "$IFACE" &>/dev/null; then
  log "Interfaz '$IFACE' no existe. Interfaces:"
  ip -brief link show >&2 || true
  exit 1
fi

ip link set "$IFACE" up 2>/dev/null || true

# nmcli "SSID not found" = escaneo; lentitud = demasiados rescans.
# Cambio de red: bajar el *perfil* activo en la interfaz, no solo disconnect.

# Modo lento (más reintentos + networking off/on): export CIMA_SYNC_WIFI_PATIENT=1

wifi_scan_seen_by_nmcli() {
  local line
  while IFS= read -r line; do
    line="${line//$'\r'/}"
    [[ "$line" == "$SSID" ]] && return 0
  done < <(nmcli -t -f SSID dev wifi list ifname "$IFACE" 2>/dev/null)
  return 1
}

wifi_scan_seen_by_iw_simple() {
  command -v iw &>/dev/null || return 1
  iw dev "$IFACE" scan 2>/dev/null | grep -F "SSID: $SSID" >/dev/null
}

nmcli_wifi_rescan() {
  if nmcli device wifi rescan ifname "$IFACE" 2>/dev/null; then
    return 0
  fi
  nmcli device wifi rescan 2>/dev/null || true
}

# Baja la conexión activa en esta interfaz (suelo necesario para *cambiar* de SSID).
nmcli_down_wifi_on_iface() {
  local c
  c=$(nmcli -g GENERAL.CONNECTION device show "$IFACE" 2>/dev/null | head -1)
  c="${c//$'\r'/}"
  if [[ -n "$c" && "$c" != "--" ]]; then
    log "Bajando perfil activo «$c» en $IFACE"
    nmcli connection down "$c" 2>/dev/null || true
  fi
  nmcli device disconnect "$IFACE" 2>/dev/null || true
}

nmcli_try_connect() {
  local wait="${CIMA_SYNC_NMCLI_WAIT:-35}"
  if [[ -n "${CIMA_SYNC_WIFI_PASSWORD:-}" ]]; then
    nmcli -w "$wait" device wifi connect "$SSID" password "$CIMA_SYNC_WIFI_PASSWORD" ifname "$IFACE"
  else
    # Sin «--» delante del SSID: varias versiones de nmcli dan «invalid extra argument».
    nmcli -w "$wait" device wifi connect "$SSID" ifname "$IFACE"
  fi
}

if command -v nmcli &>/dev/null; then
  log "NetworkManager: cambiar a «$SSID» en $IFACE (rápido; CIMA_SYNC_WIFI_PATIENT=1 si falla)"
  command -v rfkill &>/dev/null && rfkill unblock wifi 2>/dev/null || true
  nmcli general networking on 2>/dev/null || true
  nmcli radio wifi on 2>/dev/null || true
  nmcli device set "$IFACE" managed yes 2>/dev/null || true

  nmcli_down_wifi_on_iface
  sleep 1

  ok=0
  for i in 1 2 3; do
    nmcli_wifi_rescan
    sleep 2
    if nmcli_try_connect; then
      ok=1
      break
    fi
    log "Intento rápido $i/3"
  done

  if [[ "$ok" != "1" ]]; then
    log "Reinicio breve del enlace $IFACE y un intento más"
    ip link set "$IFACE" down 2>/dev/null || true
    sleep 1
    ip link set "$IFACE" up 2>/dev/null || true
    sleep 1
    nmcli_down_wifi_on_iface
    sleep 1
    nmcli_wifi_rescan
    sleep 2
    if nmcli_try_connect; then
      ok=1
    fi
  fi

  if [[ "$ok" != "1" && "${CIMA_SYNC_WIFI_PATIENT:-}" == "1" ]]; then
    log "Modo paciente: más rescans y ciclo networking…"
    for round in 1 2 3 4; do
      nmcli_wifi_rescan
      sleep 3
      wifi_scan_seen_by_nmcli && log "SSID en lista nmcli (ronda $round)"
    done
    for try in 1 2; do
      if nmcli_try_connect; then
        ok=1
        break
      fi
      nmcli_wifi_rescan
      sleep 4
    done
    if [[ "$ok" != "1" ]]; then
      nmcli networking off 2>/dev/null || true
      sleep 2
      nmcli networking on 2>/dev/null || true
      sleep 4
      nmcli radio wifi on 2>/dev/null || true
      nmcli device set "$IFACE" managed yes 2>/dev/null || true
      nmcli_wifi_rescan
      sleep 3
      nmcli_try_connect && ok=1
    fi
  fi

  if [[ "$ok" != "1" ]]; then
    log "No se pudo conectar a «$SSID». SSID visibles (nmcli):"
    nmcli -f SSID,SIGNAL,SECURITY dev wifi list ifname "$IFACE" 2>/dev/null | head -20 >&2 || true
    if wifi_scan_seen_by_iw_simple; then
      log "«iw scan» ve el AP; prueba CIMA_SYNC_WIFI_PATIENT=1 o revisa el nombre exacto del SSID."
    else
      log "No aparece «$SSID» en escaneo (alcance o nombre distinto)."
    fi
    exit 1
  fi

  log "Estado nmcli:"
  nmcli -t -f DEVICE,TYPE,STATE dev status 2>/dev/null | grep -E "^${IFACE}:" || nmcli dev status 2>/dev/null | head -15 || true
  nmcli -t -f ACTIVE,SSID dev wifi 2>/dev/null | grep -E '^yes:' || true
  exit 0
fi

if command -v wpa_cli &>/dev/null && wpa_cli -i "$IFACE" ping 2>/dev/null | grep -q PONG; then
  log "wpa_supplicant: red abierta «$SSID» en $IFACE (sin nmcli)"
  nid="$(wpa_cli -i "$IFACE" add_network 2>/dev/null | grep -E '^[0-9]+$' | head -1)"
  if [[ ! "$nid" =~ ^[0-9]+$ ]]; then
    log "No se pudo add_network en wpa_cli."
    exit 1
  fi
  wpa_cli -i "$IFACE" set_network "$nid" ssid "\"$SSID\"" >/dev/null
  wpa_cli -i "$IFACE" set_network "$nid" key_mgmt NONE >/dev/null
  wpa_cli -i "$IFACE" set_network "$nid" scan_ssid 1 >/dev/null
  wpa_cli -i "$IFACE" enable_network "$nid" >/dev/null
  wpa_cli -i "$IFACE" select_network "$nid" >/dev/null
  sleep 3
  wpa_cli -i "$IFACE" status 2>/dev/null || true
  exit 0
fi

if systemctl is-active --quiet dhcpcd 2>/dev/null; then
  log "Solo dhcpcd activo; no se puede elegir SSID desde aquí. Reiniciando dhcpcd…"
  log "Instala NetworkManager o configura wpa_supplicant para $SSID."
  systemctl restart dhcpcd
  exit 0
fi

if systemctl is-active --quiet NetworkManager 2>/dev/null; then
  log "NetworkManager activo pero sin nmcli en PATH; reiniciando servicio…"
  systemctl restart NetworkManager
  exit 0
fi

if systemctl is-active --quiet systemd-networkd 2>/dev/null; then
  log "Reiniciando systemd-networkd (SSID no aplicado automáticamente)."
  systemctl restart systemd-networkd
  exit 0
fi

log "No se encontró nmcli ni wpa_cli usable; no se pudo forzar $SSID."
log "La interfaz $IFACE quedó en up."
exit 1
