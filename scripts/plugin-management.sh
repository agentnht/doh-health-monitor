#!/usr/bin/env bash
# Interactive SSH management menu for DoH Health Monitor.
set -Eeuo pipefail

readonly PLUGIN_ID="doh-health-monitor"
readonly PLUGIN_BIN_NAME="doh-health-monitor"
readonly RAW_BASE_URL="https://raw.githubusercontent.com/agentnht/doh-health-monitor/feature/plugin-management-ui"
readonly CHECK_SCRIPT_URL="${RAW_BASE_URL}/scripts/check-dns-integration.sh"

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
  local proc exe cwd selected="" preferred=""
  for proc in /proc/[0-9]*; do
    [[ -r "$proc/exe" && -r "$proc/cwd" ]] || continue
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

confirm_action() {
  local prompt="$1" answer
  printf '%s [y/N]: ' "$prompt"
  if ! IFS= read -r answer </dev/tty; then
    printf '\n'
    return 1
  fi
  [[ "$answer" == "y" || "$answer" == "Y" ]]
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
  local tmp rc
  if command -v curl >/dev/null 2>&1; then
    tmp="$(mktemp)"
    if ! curl --fail --silent --show-error --location "$CHECK_SCRIPT_URL" --output "$tmp"; then
      rm -f "$tmp"
      fail "Не удалось загрузить read-only скрипт диагностики."
      return 1
    fi
  elif command -v wget >/dev/null 2>&1; then
    tmp="$(mktemp)"
    if ! wget -q "$CHECK_SCRIPT_URL" -O "$tmp"; then
      rm -f "$tmp"
      fail "Не удалось загрузить read-only скрипт диагностики."
      return 1
    fi
  else
    fail "Для загрузки скрипта диагностики нужен curl или wget."
    return 1
  fi

  printf 'Проверка выполняется в режиме read-only; конфигурация Xray не изменяется.\n'
  if bash "$tmp"; then
    rc=0
  else
    rc=$?
  fi
  rm -f "$tmp"
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
  local ready remote_port server_address read_status extra
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
  if [[ ! "$ready" =~ ^WEB_UI_READY\ port=([0-9]{1,5})$ ]]; then
    fail "Web UI вернул некорректный readiness-ответ: $ready"
    stop_web_ui
    return 1
  fi
  remote_port="${BASH_REMATCH[1]}"
  if (( remote_port < 1 || remote_port > 65535 )); then
    fail "Web UI сообщил недопустимый TCP-порт."
    stop_web_ui
    return 1
  fi

  server_address="${SERVER_ADDRESS:-SERVER_ADDRESS}"
  printf '\n[OK] Web UI слушает только 127.0.0.1:%s.\n' "$remote_port"
  printf '\nНа Windows откройте отдельный PowerShell и выполните:\n'
  printf 'ssh -o ExitOnForwardFailure=yes -L 19876:127.0.0.1:%s root@%s\n' "$remote_port" "$server_address"
  printf 'Затем откройте в браузере: http://127.0.0.1:19876/\n'
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
