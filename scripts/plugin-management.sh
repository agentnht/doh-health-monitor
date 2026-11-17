#!/usr/bin/env bash
# Interactive SSH management menu for DoH Health Monitor.
set -Eeuo pipefail

readonly PLUGIN_ID="doh-health-monitor"
readonly PLUGIN_BIN_NAME="doh-health-monitor"
readonly RAW_BASE_URL="https://raw.githubusercontent.com/agentnht/doh-health-monitor/main"
readonly CHECK_SCRIPT_URL="${RAW_BASE_URL}/scripts/check-dns-integration.sh"
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
  local proc exe cwd proc_uid selected="" preferred=""
  for proc in /proc/[0-9]*; do
    [[ -r "$proc/exe" && -r "$proc/cwd" ]] || continue
    proc_uid="$(awk '/^Uid:/ { print $2; exit }' "$proc/status" 2>/dev/null || true)"
    [[ "$proc_uid" == "$EUID" ]] || continue
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


confirm_action() {
  local prompt="$1" answer
  printf '%s [y/N]: ' "$prompt"
  if ! IFS= read -r answer </dev/tty; then
    printf '\n'
    return 1
  fi
  [[ "$answer" == "y" || "$answer" == "Y" ]]
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

run_plugin_action() {
  local action="$1"
  if ! confirm_action "Подтвердите операцию '$action'"; then
    printf 'Операция отменена.\n'
    return 0
  fi

  printf 'Выполняется %s...\n' "$action"
  if LUCX_PLUGIN_DATA="$PLUGIN_DATA_DIR" "$PLUGIN_BIN" "$action"; then
    printf '[OK] Операция %s завершена.\n' "$action"
  else
    local rc=$?
    printf '[FAIL] Операция %s завершилась с кодом %d.\n' "$action" "$rc" >&2
  fi
}

run_check() {
  local checker_file="" rc
  printf 'Проверка состояния плагина через Go read-only command...\n'
  if ! "$PLUGIN_BIN" check; then
    fail "Go-проверка плагина завершилась с ошибкой."
    return 1
  fi

  # Execute only the checker packaged with this plugin release. Never
  # download mutable branch content and execute it as root.
  if [[ -z "$MANAGEMENT_SCRIPT_DIR" || ! -f "$MANAGEMENT_SCRIPT_DIR/check-dns-integration.sh" ]]; then
    fail "В ZIP плагина отсутствует check-dns-integration.sh; удалённое выполнение отключено."
    return 1
  fi
  checker_file="$MANAGEMENT_SCRIPT_DIR/check-dns-integration.sh"

  printf 'Проверка выполняется в режиме read-only; конфигурация Xray не изменяется.\n'
  if DOH_SKIP_PLUGIN_HEALTH_CHECK=1 bash "$checker_file"; then
    rc=0
  else
    rc=$?
  fi
  return "$rc"
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

run_web_ui() {
  local ready remote_port launch_token server_address read_status extra
  printf 'Запуск отдельного процесса Web UI...\n'

  # The shell owns the coprocess stdin writer. Go sees EOF when this session
  # exits or this descriptor is closed, including an abrupt SSH disconnect.
  coproc WEB_UI { LUCX_PLUGIN_DATA="$PLUGIN_DATA_DIR" "$PLUGIN_BIN" web; }
  WEB_CHILD_PID="$WEB_UI_PID"
  WEB_READ_FD="${WEB_UI[0]}"
  WEB_WRITE_FD="${WEB_UI[1]}"

  if ! IFS= read -r -t 10 ready <&"$WEB_READ_FD"; then
    fail "Web UI не сообщил о готовности за 10 секунд или завершился при запуске."
    stop_web_ui
    return 1
  fi
  if [[ ! "$ready" =~ ^WEB_UI_READY[[:space:]]port=([0-9]{1,5})[[:space:]]token=([A-Za-z0-9_-]{40,})$ ]]; then
    fail "Web UI вернул некорректный readiness-ответ."
    stop_web_ui
    return 1
  fi
  remote_port="${BASH_REMATCH[1]}"
  launch_token="${BASH_REMATCH[2]}"
  if (( remote_port < 1 || remote_port > 65535 )); then
    fail "Web UI сообщил недопустимый TCP-порт."
    stop_web_ui
    return 1
  fi

  if ! server_address="$(resolve_server_address)"; then
    stop_web_ui
    fail "Не удалось получить адрес SSH-сервера для команды туннеля."
    return 1
  fi
  printf '\n[OK] Web UI слушает только 127.0.0.1:%s.\n' "$remote_port"
  printf '\nНа Windows откройте отдельный PowerShell и выполните:\n'
  printf 'ssh -o ExitOnForwardFailure=yes -L 19876:127.0.0.1:%s root@%s\n' "$remote_port" "$server_address"
  printf 'Затем откройте в браузере: http://127.0.0.1:19876/?access_token=%s\n' "$launch_token"
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
  printf '\nDoH Health Monitor — управление\n'
  printf '%s\n' '  1) Интегрировать DNS в LucX-UI / Xray'
  printf '%s\n' '  2) Удалить DNS-интеграцию'
  printf '%s\n' '  3) Проверить состояние (только чтение)'
  printf '%s\n' '  4) Запустить Web UI через SSH-туннель'
  printf '%s\n' '  0) Выход'
  printf 'Выберите действие: '
}

main() {
  require_root
  resolve_plugin_paths || exit 1
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
      1) run_plugin_action integrate ;;
      2) run_plugin_action remove ;;
      3) run_check || printf '[WARN] Диагностика завершилась с ошибками.\n' >&2 ;;
      4) run_web_ui || printf '[WARN] Не удалось запустить Web UI.\n' >&2 ;;
      0) printf 'Выход.\n'; break ;;
      *) printf 'Неизвестный пункт меню.\n' ;;
    esac
  done
}

main "$@"
