#!/usr/bin/env bash
# Interactive SSH management menu for DoH Health Monitor.
set -Eeuo pipefail

readonly PLUGIN_ID="doh-health-monitor"
readonly PLUGIN_BIN_NAME="doh-health-monitor"
readonly PANEL_SERVICE_NAME="lucx-plugin-doh-health-monitor"
readonly DHM_SYMLINK_PATH="/usr/local/bin/dhm"

MANAGEMENT_SCRIPT_PATH=""
MANAGEMENT_SCRIPT_DIR=""
if [[ -f "${BASH_SOURCE[0]:-}" ]]; then
  MANAGEMENT_SCRIPT_PATH="$(readlink -f -- "${BASH_SOURCE[0]}" 2>/dev/null || true)"
  if [[ -n "$MANAGEMENT_SCRIPT_PATH" && -f "$MANAGEMENT_SCRIPT_PATH" ]]; then
    MANAGEMENT_SCRIPT_DIR="$(cd -- "$(dirname -- "$MANAGEMENT_SCRIPT_PATH")" && pwd -P)"
  fi
fi

WEB_CHILD_PID=""
WEB_READ_FD=""
WEB_WRITE_FD=""

fail() {
  printf '[FAIL] %s\n' "$*" >&2
  return 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Запустите меню от root: sudo -i, затем повторите запуск."
    exit 1
  fi
}

detect_panel_cwd() {
  local proc exe cwd process_uid selected="" preferred=""
  for proc in /proc/[0-9]*; do
    [[ -r "$proc/exe" && -r "$proc/cwd" && -r "$proc/status" ]] || continue

    # The menu runs as root. Never infer the panel data directory from an
    # x-ui process owned by another UID.
    process_uid="$(awk '$1 == "Uid:" { print $2; exit }' "$proc/status" 2>/dev/null || true)"
    [[ "$process_uid" == "$EUID" ]] || continue

    exe="$(readlink "$proc/exe" 2>/dev/null || true)"
    exe="${exe% (deleted)}"
    [[ "${exe##*/}" == "x-ui" ]] || continue
    cwd="$(readlink "$proc/cwd" 2>/dev/null || true)"
    [[ -n "$cwd" ]] || continue
    if [[ "$exe" == "/usr/local/x-ui/x-ui" ]]; then
      if [[ -z "$preferred" ]]; then
        preferred="$cwd"
      elif [[ "$preferred" != "$cwd" ]]; then
        fail "Обнаружено несколько основных процессов LucX-UI с разными рабочими каталогами; задайте LUCX_PLUGIN_DATA явно."
        return 1
      fi
    elif [[ -z "$selected" ]]; then
      selected="$cwd"
    elif [[ "$selected" != "$cwd" ]]; then
      selected="__ambiguous__"
    fi
  done

  if [[ -n "$preferred" ]]; then
    printf '%s\n' "$preferred"
  elif [[ "$selected" == "__ambiguous__" ]]; then
    fail "Обнаружено несколько процессов LucX-UI с разными рабочими каталогами; задайте LUCX_PLUGIN_DATA явно."
    return 1
  elif [[ -n "$selected" ]]; then
    printf '%s\n' "$selected"
  else
    # Same fallback used by the Go integration package when x-ui is not found.
    printf '%s\n' "/usr/local/x-ui"
  fi
}

resolve_plugin_paths() {
  local panel_cwd data_dir
  if [[ -n "${LUCX_PLUGIN_DATA:-}" ]]; then
    data_dir="$LUCX_PLUGIN_DATA"
    [[ "$data_dir" == /* ]] || data_dir="$PWD/$data_dir"
  else
    panel_cwd="$(detect_panel_cwd)" || return 1
    data_dir="${panel_cwd}/bin/plugins/${PLUGIN_ID}/data"
  fi

  PLUGIN_DATA_DIR="$data_dir"
  PLUGIN_BIN="$(dirname "$data_dir")/bin/$PLUGIN_BIN_NAME"
  PLUGIN_ROOT_DIR="$(cd -- "$(dirname -- "$PLUGIN_BIN")/.." && pwd -P)"
  PLUGIN_VERSION="$(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$PLUGIN_ROOT_DIR/manifest.json" 2>/dev/null | head -n 1)"

  if [[ ! -x "$PLUGIN_BIN" || ! -f "$PLUGIN_BIN" ]]; then
    fail "Не найден исполняемый файл плагина: $PLUGIN_BIN"
    printf 'Проверьте установку плагина или задайте LUCX_PLUGIN_DATA.\n' >&2
    return 1
  fi
}


ensure_dhm_symlink() {
  local plugin_scripts_dir current_target

  # A process-substitution launch (bash <(curl ...)) has no persistent script
  # path. Keep that GitHub bootstrap mode working without creating a dangling
  # link; only the installed copy inside the plugin package creates /usr/local/bin/dhm.
  [[ -n "$MANAGEMENT_SCRIPT_PATH" && -n "$MANAGEMENT_SCRIPT_DIR" ]] || return 0
  plugin_scripts_dir="$(cd -- "$(dirname -- "$PLUGIN_BIN")/../scripts" 2>/dev/null && pwd -P)" || return 0
  [[ "$MANAGEMENT_SCRIPT_DIR" == "$plugin_scripts_dir" ]] || return 0
  [[ "$MANAGEMENT_SCRIPT_PATH" == "$plugin_scripts_dir/plugin-management.sh" ]] || return 0

  if ! mkdir -p "$(dirname -- "$DHM_SYMLINK_PATH")"; then
    printf '[WARN] Не удалось создать каталог для команды dhm: %s\n' "$(dirname -- "$DHM_SYMLINK_PATH")" >&2
    return 0
  fi

  if ! chmod 0755 "$MANAGEMENT_SCRIPT_PATH"; then
    printf '[WARN] Не удалось сделать локальный скрипт исполняемым: %s\n' "$MANAGEMENT_SCRIPT_PATH" >&2
    return 0
  fi

  if [[ -L "$DHM_SYMLINK_PATH" ]]; then
    current_target="$(readlink -f -- "$DHM_SYMLINK_PATH" 2>/dev/null || true)"
    if [[ "$current_target" == "$MANAGEMENT_SCRIPT_PATH" ]]; then
      return 0
    fi
    printf '[WARN] %s уже указывает на другой файл; ссылка не изменена.\n' "$DHM_SYMLINK_PATH" >&2
    return 0
  fi
  if [[ -e "$DHM_SYMLINK_PATH" ]]; then
    printf '[WARN] %s уже существует и не является симлинком; файл не изменён.\n' "$DHM_SYMLINK_PATH" >&2
    return 0
  fi

  if ln -s -- "$MANAGEMENT_SCRIPT_PATH" "$DHM_SYMLINK_PATH"; then
    printf '[OK] Создана команда dhm -> %s\n' "$MANAGEMENT_SCRIPT_PATH"
  elif [[ -L "$DHM_SYMLINK_PATH" ]] && [[ "$(readlink -f -- "$DHM_SYMLINK_PATH" 2>/dev/null || true)" == "$MANAGEMENT_SCRIPT_PATH" ]]; then
    :
  else
    printf '[WARN] Не удалось создать симлинк %s.\n' "$DHM_SYMLINK_PATH" >&2
  fi
}


resolve_ssh_tunnel_user() {
  local user="${SSH_TUNNEL_USER:-${SUDO_USER:-${USER:-root}}}"
  if [[ ! "$user" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\$?$ ]]; then
    fail "Имя пользователя SSH-туннеля содержит недопустимые символы."
    return 1
  fi
  printf '%s\n' "$user"
}

parse_web_ui_ready_port() {
  local ready="${1:-}" port
  if [[ ! "$ready" =~ ^WEB_UI_READY\ port=([0-9]{1,5})\ token=[A-Za-z0-9_-]{43}$ ]]; then
    return 1
  fi
  port="${BASH_REMATCH[1]}"
  if (( port < 1 || port > 65535 )); then return 1; fi
  printf '%s\n' "$port"
}

parse_web_ui_ready_token() {
  local ready="${1:-}" token
  if [[ ! "$ready" =~ ^WEB_UI_READY\ port=[0-9]{1,5}\ token=([A-Za-z0-9_-]{43})$ ]]; then
    return 1
  fi
  token="${BASH_REMATCH[1]}"
  printf '%s\n' "$token"
}

build_ssh_tunnel_command() {
  local local_port="$1" remote_port="$2" user="$3" address="$4"
  [[ "$local_port" =~ ^[0-9]{1,5}$ && "$remote_port" =~ ^[0-9]{1,5}$ ]] || return 1
  (( local_port >= 1 && local_port <= 65535 && remote_port >= 1 && remote_port <= 65535 )) || return 1
  [[ "$user" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\$?$ ]] || return 1
  [[ "$address" =~ ^[A-Za-z0-9][A-Za-z0-9._:%-]*$ ]] || return 1
  printf 'ssh -o ExitOnForwardFailure=yes -L %s:127.0.0.1:%s %s@%s\n' "$local_port" "$remote_port" "$user" "$address"
}

resolve_server_address() {
  local address="" client_addr="" client_port="" server_port="" extra=""

  # An explicit override is useful when SSH terminates behind NAT or a proxy.
  address="${SERVER_ADDRESS:-}"
  if [[ -z "$address" && -n "${SSH_CONNECTION:-}" ]]; then
    read -r client_addr client_port address server_port extra <<< "$SSH_CONNECTION"
    if [[ -n "$extra" || -z "$client_addr" || -z "$client_port" || -z "$server_port" ]]; then
      address=""
    fi
  fi

  if [[ -z "$address" ]]; then
    printf 'Не удалось определить адрес SSH-сервера автоматически. Введите IP или hostname для подключения с Windows: ' >&2
    if ! IFS= read -r address </dev/tty; then
      return 1
    fi
  fi

  if [[ ! "$address" =~ ^[A-Za-z0-9][A-Za-z0-9._:%-]*$ ]]; then
    fail "Адрес сервера содержит недопустимые символы."
    return 1
  fi
  printf '%s\n' "$address"
}

detect_plugin_service() {
  local panel_load="" standalone_load="" panel_active=0 standalone_active=0

  if ! command -v systemctl >/dev/null 2>&1; then
    # Let the Go checker report the missing preflight tool with its usual message.
    printf '%s\n' "$PANEL_SERVICE_NAME"
    return 0
  fi

  panel_load="$(systemctl show --property=LoadState --value "$PANEL_SERVICE_NAME" 2>/dev/null || true)"
  standalone_load="$(systemctl show --property=LoadState --value "$SYSTEMD_SERVICE_NAME" 2>/dev/null || true)"

  if systemctl is-active --quiet "$PANEL_SERVICE_NAME"; then
    panel_active=1
  fi
  if systemctl is-active --quiet "$SYSTEMD_SERVICE_NAME"; then
    standalone_active=1
  fi

  if (( panel_active == 1 && standalone_active == 1 )); then
    fail "Одновременно активны panel и standalone службы DoH Health Monitor. Оставьте только одного владельца процесса и повторите проверку."
    return 1
  fi
  if (( standalone_active == 1 )); then
    printf '%s\n' "$SYSTEMD_SERVICE_NAME"
    return 0
  fi
  if (( panel_active == 1 )); then
    printf '%s\n' "$PANEL_SERVICE_NAME"
    return 0
  fi

  # If neither unit is running, use the only installed unit so the Go checker
  # can report that it is inactive. Do not guess when both managers are installed.
  if [[ "$standalone_load" == "loaded" && "$panel_load" == "loaded" ]]; then
    fail "Обе службы DoH Health Monitor установлены, но ни одна не активна. Запустите выбранный менеджер процесса или удалите неиспользуемый unit."
    return 1
  elif [[ "$standalone_load" == "loaded" ]]; then
    printf '%s\n' "$SYSTEMD_SERVICE_NAME"
  else
    # Preserve the panel-mode diagnostic when its service is the only loaded
    # one or neither unit has been installed.
    printf '%s\n' "$PANEL_SERVICE_NAME"
  fi
}

run_check() {
  local checker_file="" package_scripts_dir="" rc plugin_service
  printf 'Проверка состояния плагина через Go read-only command...\n'
  if ! plugin_service="$(detect_plugin_service)"; then
    return 1
  fi
  printf '[INFO] Используется служба плагина: %s\n' "$plugin_service"
  if ! "$PLUGIN_BIN" check --plugin-service "$plugin_service"; then
    fail "Go-проверка плагина завершилась с ошибкой."
    return 1
  fi

  # Run only the checker shipped in the installed plugin package. Do not
  # download a mutable shell script and execute it as root.
  package_scripts_dir="$(cd -- "$(dirname -- "$PLUGIN_BIN")/../scripts" 2>/dev/null && pwd -P || true)"
  if [[ -n "$package_scripts_dir" && -r "$package_scripts_dir/check-dns-integration.sh" ]]; then
    checker_file="$package_scripts_dir/check-dns-integration.sh"
  elif [[ -n "$MANAGEMENT_SCRIPT_DIR" && -r "$MANAGEMENT_SCRIPT_DIR/check-dns-integration.sh" ]]; then
    checker_file="$MANAGEMENT_SCRIPT_DIR/check-dns-integration.sh"
  else
    fail "В установленном ZIP отсутствует scripts/check-dns-integration.sh. Переустановите архив плагина 2.3.5."
    return 1
  fi

  printf 'Проверка Xray DNS path выполняется в режиме read-only; конфигурация не изменяется.\n'
  printf '[INFO] Проверяется наличие DNS direct rule с domain; все найденные domain будут выведены. Geosite asset и клиентский end-to-end путь требуют отдельной проверки.\n'
  if LUCX_PLUGIN_DATA="$PLUGIN_DATA_DIR" DOH_SKIP_PLUGIN_HEALTH_CHECK=1 bash "$checker_file"; then
    rc=0
  else
    rc=$?
  fi
  return "$rc"
}


readonly SYSTEMD_SERVICE_NAME="doh-health-monitor.service"
readonly SYSTEMD_TIMER_NAME="doh-health-monitor-healthcheck.timer"
readonly SYSTEMD_HEALTHCHECK_SERVICE="doh-health-monitor-healthcheck.service"
readonly SYSTEMD_HEALTHCHECK_PATH="/usr/local/libexec/doh-health-monitor-healthcheck"
readonly PANEL_AUTOSTART_SERVICE_NAME="doh-health-monitor-panel-autostart.service"
readonly SYSTEMD_UNIT_DIR="/etc/systemd/system"
readonly PANEL_API_TOKEN_NAME="doh-health-monitor-plugin-management"
readonly PANEL_API_LOCK_PATH="/run/lock/doh-health-monitor-panel-api.lock"

PANEL_CLI=""
PANEL_API_BASE_URL=""
PANEL_API_CURL_CONFIG=""
PANEL_API_LOCK_FD=""
PANEL_API_TOKEN_ACTIVE=0
PANEL_API_CLEANUP_TRAP_INSTALLED=0
PANEL_API_INSECURE=0
PANEL_API_RESPONSE=""

systemd_quote() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//%/%%}"
  printf '"%s"' "$value"
}

render_panel_api_autostart() {
  local script_path="$1" data_dir="$2" panel_service="${3:-x-ui.service}"
  cat <<EOF
[Unit]
Description=Start DoH Health Monitor through the LucX-UI plugin API
Wants=network-online.target $panel_service
After=network-online.target $panel_service
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=oneshot
Environment=$(systemd_quote "LUCX_PLUGIN_DATA=$data_dir")
ExecStart=/bin/bash $(systemd_quote "$script_path") --panel-api-start-on-boot
TimeoutStartSec=180
Restart=on-failure
RestartSec=20s
UMask=0077
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
}

systemd_require_available() {
  command -v systemctl >/dev/null 2>&1 || {
    fail "systemctl не найден; автозапуск доступен только на systemd-хосте."
    return 1
  }
  [[ -d /run/systemd/system ]] || {
    fail "systemd не запущен как системный init; unit нельзя безопасно активировать."
    return 1
  }
}

pid_file_running_for_plugin() {
  local pid_file="$PLUGIN_DATA_DIR/doh-health-monitor.pid" pid actual expected
  [[ -s "$pid_file" ]] || return 1
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  actual="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
  expected="$(readlink -f "$PLUGIN_BIN" 2>/dev/null || true)"
  [[ -n "$expected" && "$actual" == "$expected" ]]
}

extract_panel_setting() {
  local key="$1" output="$2"
  sed -n "s/^${key}:[[:space:]]*//p" <<<"$output" | tail -n 1 | tr -d '\r'
}

panel_api_discover() {
  local panel_cwd settings listen_output port base_path listen_ip host scheme
  panel_cwd="$(detect_panel_cwd)" || return 1
  PANEL_CLI="$panel_cwd/x-ui"
  [[ -x "$PANEL_CLI" && -f "$PANEL_CLI" ]] || {
    fail "Не найден CLI панели: $PANEL_CLI"
    return 1
  }
  settings="$("$PANEL_CLI" setting -show=true 2>/dev/null)" || {
    fail "Не удалось прочитать настройки LucX-UI через локальный CLI."
    return 1
  }
  listen_output="$("$PANEL_CLI" setting -getListen=true 2>/dev/null)" || {
    fail "Не удалось прочитать адрес прослушивания LucX-UI."
    return 1
  }

  port="$(extract_panel_setting port "$settings")"
  base_path="$(extract_panel_setting webBasePath "$settings")"
  listen_ip="$(extract_panel_setting listenIP "$listen_output")"
  [[ "$port" =~ ^[0-9]{1,5}$ ]] && (( port >= 1 && port <= 65535 )) || {
    fail "CLI панели вернул некорректный порт; API URL не сформирован."
    return 1
  }

  case "$base_path" in
    ""|"/") base_path="" ;;
    *)
      [[ "$base_path" == /* ]] || base_path="/$base_path"
      base_path="${base_path%/}"
      [[ "$base_path" =~ ^/[A-Za-z0-9._~/-]+$ && ! "$base_path" =~ (^|/)\.\.?(/|$) ]] || {
        fail "webBasePath содержит неподдерживаемые символы; API URL не сформирован."
        return 1
      }
      ;;
  esac

  case "$listen_ip" in
    ""|"0.0.0.0") host="127.0.0.1" ;;
    "::"|"::0") host="::1" ;;
    *) host="$listen_ip" ;;
  esac
  if ! python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$host" >/dev/null 2>&1; then
    fail "LucX-UI listenIP не является IP-адресом; API-клиент отказывается отправлять admin-токен."
    return 1
  fi
  if [[ "$host" == *:* ]]; then host="[$host]"; fi

  if grep -Fq "Panel is secure with SSL" <<<"$settings"; then
    scheme="https"
    PANEL_API_INSECURE=1
  else
    scheme="http"
    PANEL_API_INSECURE=0
  fi
  PANEL_API_BASE_URL="$scheme://$host:$port${base_path}/panel/api"
}

panel_api_token_from_output() {
  sed -n 's/^[[:space:]]*apiToken:[[:space:]]*//p' <<<"$1" | tail -n 1 | tr -d '\r'
}

panel_api_json_success() {
  python3 -c 'import json,sys
try:
    value=json.load(sys.stdin)
except Exception:
    sys.exit(2)
sys.exit(0 if value.get("success") is True else 1)' <<<"$1"
}

panel_api_json_running() {
  python3 -c 'import json,sys
try:
    value=json.load(sys.stdin)
    obj=value.get("obj")
    running=obj.get("running") if isinstance(obj,dict) else None
except Exception:
    sys.exit(2)
if value.get("success") is not True or not isinstance(running,bool):
    sys.exit(2)
print("running" if running else "stopped")' <<<"$1"
}

panel_api_token_id_from_response() {
  python3 -c 'import json,sys
try:
    value=json.load(sys.stdin)
    rows=value.get("obj")
    if value.get("success") is not True or not isinstance(rows,list):
        sys.exit(2)
    matches=[row.get("id") for row in rows if isinstance(row,dict) and row.get("name")==sys.argv[1] and row.get("scope")=="admin"]
    if len(matches)!=1 or not isinstance(matches[0],int) or matches[0]<=0:
        sys.exit(2)
    print(matches[0])
except Exception:
    sys.exit(2)' "$PANEL_API_TOKEN_NAME" <<<"$1"
}

panel_api_begin() {
  local token_output token
  if (( PANEL_API_CLEANUP_TRAP_INSTALLED == 0 )); then
    trap 'panel_api_finish' EXIT
    PANEL_API_CLEANUP_TRAP_INSTALLED=1
  fi
  command -v curl >/dev/null 2>&1 || { fail "curl не найден."; return 1; }
  command -v python3 >/dev/null 2>&1 || { fail "python3 не найден; нужен стандартный JSON/IP parser."; return 1; }
  command -v flock >/dev/null 2>&1 || { fail "flock не найден."; return 1; }
  install -d -m 0755 /run/lock || return 1
  exec {PANEL_API_LOCK_FD}>"$PANEL_API_LOCK_PATH" || return 1
  chmod 0600 "$PANEL_API_LOCK_PATH" || return 1
  flock -x "$PANEL_API_LOCK_FD" || return 1

  if ! panel_api_discover; then
    panel_api_finish
    return 1
  fi

  # The panel CLI rotates only this reserved token name. Plaintext is held in
  # memory and a short-lived root-only curl config; it is never written to disk.
  token_output="$("$PANEL_CLI" setting -getApiToken=true \
    -tokenName="$PANEL_API_TOKEN_NAME" -tokenScope=admin 2>&1)" || {
    fail "Не удалось выпустить временный admin API token через CLI панели."
    panel_api_finish
    return 1
  }
  # Mark the reserved slot active before parsing stdout. If CLI output changes,
  # cleanup still rotates the slot and invalidates any newly issued token.
  PANEL_API_TOKEN_ACTIVE=1
  token="$(panel_api_token_from_output "$token_output")"
  unset token_output
  [[ "$token" =~ ^[A-Za-z0-9_-]{32,128}$ ]] || {
    unset token
    fail "CLI панели не вернул ожидаемый API token; API-запрос не выполнялся."
    panel_api_finish
    return 1
  }
  PANEL_API_CURL_CONFIG="$(mktemp /run/doh-health-monitor-api.XXXXXX)" || {
    unset token
    fail "Не удалось создать временный curl config в /run."
    panel_api_finish
    return 1
  }
  chmod 0600 "$PANEL_API_CURL_CONFIG"
  printf 'header = "Authorization: Bearer %s"\n' "$token" >"$PANEL_API_CURL_CONFIG"
  unset token
}

panel_api_request() {
  local method="$1" route="$2" body="${3:-}"
  local -a args
  args=(--silent --show-error --fail --noproxy '*' --connect-timeout 3 --max-time 10
        --config "$PANEL_API_CURL_CONFIG" --request "$method"
        --url "$PANEL_API_BASE_URL$route" --header "Accept: application/json")
  if (( PANEL_API_INSECURE == 1 )); then args+=(--insecure); fi
  if [[ -n "$body" ]]; then
    args+=(--header "Content-Type: application/json" --data-binary "$body")
  fi
  PANEL_API_RESPONSE="$(curl -q "${args[@]}")"
}

panel_api_finish() {
  local token_id
  if (( PANEL_API_TOKEN_ACTIVE == 1 )); then
    if [[ -n "$PANEL_API_CURL_CONFIG" ]] &&
       panel_api_request GET "/setting/apiTokens" &&
       token_id="$(panel_api_token_id_from_response "$PANEL_API_RESPONSE" 2>/dev/null)"; then
      if panel_api_request POST "/setting/apiTokens/delete/$token_id" '{"expectedScope":"admin"}' &&
         panel_api_json_success "$PANEL_API_RESPONSE"; then
        PANEL_API_TOKEN_ACTIVE=0
      fi
    fi
    # If the API could not revoke the one-shot token, rotate the reserved slot
    # locally. This invalidates the token held by the temporary curl config.
    if (( PANEL_API_TOKEN_ACTIVE == 1 )) && [[ -n "$PANEL_CLI" && -x "$PANEL_CLI" ]]; then
      "$PANEL_CLI" setting -getApiToken=true \
        -tokenName="$PANEL_API_TOKEN_NAME" -tokenScope=admin >/dev/null 2>&1 || true
    fi
  fi
  [[ -z "$PANEL_API_CURL_CONFIG" ]] || rm -f -- "$PANEL_API_CURL_CONFIG"
  PANEL_API_CURL_CONFIG=""
  PANEL_API_TOKEN_ACTIVE=0
  if [[ -n "$PANEL_API_LOCK_FD" ]]; then
    flock -u "$PANEL_API_LOCK_FD" >/dev/null 2>&1 || true
    eval "exec ${PANEL_API_LOCK_FD}>&-" || true
    PANEL_API_LOCK_FD=""
  fi
}

panel_api_read_plugin_state() {
  panel_api_request GET "/plugins/$PLUGIN_ID/status" || return 1
  panel_api_json_running "$PANEL_API_RESPONSE"
}

panel_api_wait_plugin_state() {
  local expected="$1" attempts="${2:-20}" state i
  for ((i=0; i<attempts; i++)); do
    if state="$(panel_api_read_plugin_state 2>/dev/null)" && [[ "$state" == "$expected" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

panel_api_action() {
  local action="$1" expected
  case "$action" in
    start|restart) expected="running" ;;
    stop) expected="stopped" ;;
    *) fail "Недопустимое действие API."; return 1 ;;
  esac
  panel_api_begin || return 1
  if ! panel_api_request POST "/plugins/$PLUGIN_ID/$action" '{}'; then
    fail "LucX-UI API не принял команду $action для $PLUGIN_ID."
    panel_api_finish
    return 1
  fi
  if ! panel_api_json_success "$PANEL_API_RESPONSE"; then
    fail "LucX-UI API вернул success=false для команды $action."
    panel_api_finish
    return 1
  fi
  if ! panel_api_wait_plugin_state "$expected" 20; then
    fail "LucX-UI API принял $action, но ожидаемое состояние $expected не появилось."
    panel_api_finish
    return 1
  fi
  panel_api_finish
  printf '[OK] LucX-UI: %s; plugin %s.\n' "$action" "$expected"
}

panel_api_show_status() {
  local state enabled
  panel_api_begin || return 1
  if ! state="$(panel_api_read_plugin_state)"; then
    fail "Не удалось получить статус плагина через LucX-UI API."
    panel_api_finish
    return 1
  fi
  enabled="$(systemctl is-enabled "$PANEL_AUTOSTART_SERVICE_NAME" 2>/dev/null || true)"
  printf '[INFO] Состояние плагина в LucX-UI: %s\n' "$state"
  printf '[INFO] Автозапуск через API при загрузке: %s\n' "${enabled:-disabled}"
  panel_api_finish
}

remove_legacy_standalone_autostart() {
  systemctl disable --now "$SYSTEMD_TIMER_NAME" >/dev/null 2>&1 || true
  systemctl disable --now "$SYSTEMD_SERVICE_NAME" >/dev/null 2>&1 || true
  if systemctl is-active --quiet "$SYSTEMD_TIMER_NAME" ||
     systemctl is-active --quiet "$SYSTEMD_SERVICE_NAME"; then
    fail "Не удалось остановить старый standalone systemd manager; API-автозапуск не включён."
    return 1
  fi
  rm -f -- "$SYSTEMD_UNIT_DIR/$SYSTEMD_SERVICE_NAME" \
    "$SYSTEMD_UNIT_DIR/$SYSTEMD_HEALTHCHECK_SERVICE" \
    "$SYSTEMD_UNIT_DIR/$SYSTEMD_TIMER_NAME" \
    "$SYSTEMD_HEALTHCHECK_PATH"
  systemctl daemon-reload
}

install_panel_api_autostart() {
  local state unit_tmp panel_load script_path
  systemd_require_available || return 1
  [[ -x "$PLUGIN_BIN" && -f "$PLUGIN_BIN" ]] || {
    fail "Не найден исполняемый файл плагина: $PLUGIN_BIN"
    return 1
  }
  panel_load="$(systemctl show --property=LoadState --value x-ui.service 2>/dev/null || true)"
  [[ "$panel_load" == "loaded" ]] || {
    fail "Не найдена служба x-ui.service. Не удалось задать правильный порядок запуска API-autostart."
    return 1
  }

  panel_api_begin || return 1
  if ! state="$(panel_api_read_plugin_state)"; then
    fail "LucX-UI API недоступен или плагин не установлен в менеджере панели."
    panel_api_finish
    return 1
  fi
  if ! remove_legacy_standalone_autostart; then
    panel_api_finish
    return 1
  fi
  if [[ "$state" == "stopped" ]] && pid_file_running_for_plugin; then
    fail "Обнаружен работающий экземпляр вне менеджера LucX-UI. Остановите его вручную и повторите включение."
    panel_api_finish
    return 1
  fi

  if [[ "$state" != "running" ]]; then
    if ! panel_api_request POST "/plugins/$PLUGIN_ID/start" '{}' ||
       ! panel_api_json_success "$PANEL_API_RESPONSE" ||
       ! panel_api_wait_plugin_state running 20; then
      fail "Не удалось передать запуск плагина менеджеру LucX-UI."
      panel_api_finish
      return 1
    fi
  fi

  script_path="$MANAGEMENT_SCRIPT_PATH"
  [[ -n "$script_path" && -f "$script_path" ]] || script_path="$PLUGIN_ROOT_DIR/scripts/plugin-management.sh"
  install -d -m 0755 "$SYSTEMD_UNIT_DIR"
  unit_tmp="$(mktemp)" || { panel_api_finish; return 1; }
  render_panel_api_autostart "$script_path" "$PLUGIN_DATA_DIR" x-ui.service >"$unit_tmp"
  if ! install -m 0644 "$unit_tmp" "$SYSTEMD_UNIT_DIR/$PANEL_AUTOSTART_SERVICE_NAME"; then
    rm -f "$unit_tmp"
    fail "Не удалось установить API-autostart systemd unit."
    panel_api_finish
    return 1
  fi
  rm -f "$unit_tmp"
  systemctl daemon-reload
  if ! systemctl enable "$PANEL_AUTOSTART_SERVICE_NAME"; then
    fail "Не удалось включить API-autostart unit."
    panel_api_finish
    return 1
  fi
  panel_api_finish
  printf '[OK] Автозапуск включён: при загрузке VPS скрипт вызовет LucX-UI API после x-ui.service.\n'
  printf '[INFO] Сам DNS-процесс остаётся под управлением Plugin Manager; кнопки Start/Stop в панели управляют им напрямую.\n'
}

disable_panel_api_autostart() {
  systemd_require_available || return 1
  systemctl disable --now "$PANEL_AUTOSTART_SERVICE_NAME" >/dev/null 2>&1 || true
  rm -f -- "$SYSTEMD_UNIT_DIR/$PANEL_AUTOSTART_SERVICE_NAME"
  systemctl daemon-reload
  systemctl reset-failed "$PANEL_AUTOSTART_SERVICE_NAME" >/dev/null 2>&1 || true
  printf '[OK] API-автозапуск отключён. Текущий процесс не останавливался; при необходимости нажмите Stop в панели.\n'
}

manage_panel_api_autostart() {
  local choice
  while true; do
    printf '\nLucX-UI API — управление DoH Health Monitor\n'
    printf '%s\n' '  1) Запустить через LucX-UI API'
    printf '%s\n' '  2) Остановить через LucX-UI API'
    printf '%s\n' '  3) Перезапустить через LucX-UI API'
    printf '%s\n' '  4) Включить автозапуск при загрузке VPS'
    printf '%s\n' '  5) Отключить автозапуск'
    printf '%s\n' '  6) Статус плагина и автозапуска'
    printf '%s\n' '  0) Назад'
    printf 'Выберите действие: '
    if ! IFS= read -r choice </dev/tty; then
      printf '\nУправляющий терминал закрыт.\n'
      return 1
    fi
    case "$choice" in
      1) panel_api_action start || printf '[WARN] Не удалось запустить плагин через API.\n' >&2 ;;
      2) panel_api_action stop || printf '[WARN] Не удалось остановить плагин через API.\n' >&2 ;;
      3) panel_api_action restart || printf '[WARN] Не удалось перезапустить плагин через API.\n' >&2 ;;
      4) install_panel_api_autostart || printf '[WARN] Не удалось включить API-автозапуск.\n' >&2 ;;
      5) disable_panel_api_autostart || printf '[WARN] Не удалось отключить API-автозапуск.\n' >&2 ;;
      6) panel_api_show_status || printf '[WARN] Не удалось получить состояние через API.\n' >&2 ;;
      0) return 0 ;;
      *) printf 'Неизвестный пункт меню.\n' ;;
    esac
  done
}

panel_api_start_on_boot() {
  local state i
  panel_api_begin || return 1
  state=""
  # x-ui.service is ordered before this oneshot; tolerate a delayed listener
  # or DB/API initialization after the unit reaches active.
  for ((i=0; i<60; i++)); do
    if state="$(panel_api_read_plugin_state 2>/dev/null)"; then
      break
    fi
    sleep 2
  done
  if [[ -z "$state" ]]; then
    fail "LucX-UI API не стал доступен в течение 120 секунд; plugin не запускался."
    panel_api_finish
    return 1
  fi
  if [[ "$state" == "stopped" ]]; then
    if ! panel_api_request POST "/plugins/$PLUGIN_ID/start" '{}' ||
       ! panel_api_json_success "$PANEL_API_RESPONSE" ||
       ! panel_api_wait_plugin_state running 20; then
      fail "LucX-UI API не смог запустить $PLUGIN_ID после загрузки VPS."
      panel_api_finish
      return 1
    fi
  fi
  panel_api_finish
  printf '[OK] DoH Health Monitor запущен через LucX-UI Plugin Manager API.\n'
}

close_pipe_fd() {
  local fd="$1"
  if [[ "$fd" =~ ^[0-9]+$ ]]; then
    eval "exec ${fd}>&-" || true
  fi
}

stop_web_ui() {
  if [[ -n "$WEB_WRITE_FD" ]]; then
    close_pipe_fd "$WEB_WRITE_FD"
    WEB_WRITE_FD=""
  fi
  if [[ -n "$WEB_CHILD_PID" ]]; then
    local rc=0
    if wait "$WEB_CHILD_PID"; then
      rc=0
    else
      rc=$?
    fi
    if (( rc != 0 )); then
      printf '[WARN] Процесс Web UI завершился с кодом %d.\n' "$rc" >&2
    fi
    WEB_CHILD_PID=""
  fi
  if [[ -n "$WEB_READ_FD" ]]; then
    close_pipe_fd "$WEB_READ_FD"
    WEB_READ_FD=""
  fi
}

run_dns_config() {
  printf '\nНастройка DNS mode плагина...\n'
  printf 'Будет изменён только config.json; Xray routing, firewall и TProxy не затрагиваются.\n'
  LUCX_PLUGIN_DATA="$PLUGIN_DATA_DIR" "$PLUGIN_BIN" config
}

run_web_ui() {
  local ready remote_port bootstrap_token server_address tunnel_user tunnel_command read_status extra
  printf 'Запуск отдельного процесса Web UI...\n'
  coproc WEB_UI { LUCX_PLUGIN_DATA="$PLUGIN_DATA_DIR" "$PLUGIN_BIN" web; }
  WEB_CHILD_PID="$WEB_UI_PID"
  WEB_READ_FD="${WEB_UI[0]}"
  WEB_WRITE_FD="${WEB_UI[1]}"

  if ! IFS= read -r -t 10 ready <&"$WEB_READ_FD"; then
    fail "Web UI не сообщил о готовности за 10 секунд или завершился при запуске."
    stop_web_ui
    return 1
  fi
  if ! remote_port="$(parse_web_ui_ready_port "$ready")" || ! bootstrap_token="$(parse_web_ui_ready_token "$ready")"; then
    fail "Web UI вернул некорректный readiness-ответ: $ready"
    stop_web_ui
    return 1
  fi
  if ! server_address="$(resolve_server_address)"; then
    stop_web_ui
    fail "Не удалось получить адрес SSH-сервера для команды туннеля."
    return 1
  fi
  if ! tunnel_user="$(resolve_ssh_tunnel_user)"; then
    stop_web_ui
    return 1
  fi
  if ! tunnel_command="$(build_ssh_tunnel_command 19876 "$remote_port" "$tunnel_user" "$server_address")"; then
    stop_web_ui
    fail "Не удалось сформировать безопасную SSH-команду туннеля."
    return 1
  fi

  printf '\n[OK] Web UI слушает только 127.0.0.1:%s.\n' "$remote_port"
  printf '\nНа Windows откройте отдельный PowerShell и выполните:\n'
  printf '%s\n' "$tunnel_command"
  printf 'Затем откройте в браузере: http://127.0.0.1:19876/?token=%s\n' "$bootstrap_token"
  printf 'Если локальный порт 19876 занят, замените его в SSH-команде и URL браузера на один и тот же свободный порт. Удалённый порт %s не меняйте.\n' "$remote_port"
  printf 'Оставьте открытыми эту SSH-сессию и отдельную SSH-сессию туннеля.\n'
  printf 'Нажмите Enter здесь, чтобы остановить Web UI и вернуться в меню.\n'

  while true; do
    if IFS= read -r -t 1 extra <&"$WEB_READ_FD"; then
      printf '[WARN] Неожиданный дополнительный вывод Web UI; останавливаю процесс.\n' >&2
      break
    else
      read_status=$?
      if (( read_status != 142 )); then
        printf '[WARN] Процесс Web UI завершился до команды остановки.\n' >&2
        break
      fi
    fi
    if IFS= read -r -t 0.1 _ </dev/tty; then
      break
    else
      read_status=$?
      if (( read_status != 142 )); then
        printf '\nУправляющий терминал закрыт; останавливаю Web UI.\n'
        break
      fi
    fi
  done
  stop_web_ui
  printf 'Web UI остановлен.\n'
}

show_menu() {
  printf '\nDoH Health Monitor 2.3.5 — управление\n'
  printf '%s\n' '  1) Проверить plugin и утверждённый Xray Geosite DNS path (read-only)'
  printf '%s\n' '  2) Запустить Web UI через SSH-туннель'
  printf '%s\n' '  3) Переключить DNS mode / настроить resolver upstreams'
  printf '%s\n' '  4) Управление через LucX-UI API и автозапуск'
  printf '%s\n' '  0) Выход'
  printf '%s\n' '  Примечание: Xray DNS policy задаётся вручную по doc/GEOSITE-DNS-ROUTING-DESIGN.md.'
  printf 'Выберите действие: '
}

main() {
  require_root
  resolve_plugin_paths || exit 1
  if [[ "${1:-}" == "--panel-api-start-on-boot" ]]; then
    panel_api_start_on_boot || exit 1
    exit 0
  fi
  ensure_dhm_symlink
  trap 'stop_web_ui; exit 130' INT
  trap 'stop_web_ui; exit 129' HUP
  trap 'stop_web_ui; exit 143' TERM

  while true; do
    local choice
    show_menu
    if ! IFS= read -r choice </dev/tty; then
      printf '\nЗавершение: управляющий терминал закрыт.\n'
      break
    fi

    case "$choice" in
      1) run_check || printf '[WARN] Диагностика завершилась с ошибками.\n' >&2 ;;
      2) run_web_ui || printf '[WARN] Не удалось запустить Web UI.\n' >&2 ;;
      3) run_dns_config || printf '[WARN] DNS-конфигурация не изменена.\n' >&2 ;;
      4) manage_panel_api_autostart || printf '[WARN] Управление LucX-UI API завершилось с ошибкой.\n' >&2 ;;
      0) printf 'Выход.\n'; break ;;
      *) printf 'Неизвестный пункт меню.\n' ;;
    esac
  done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
