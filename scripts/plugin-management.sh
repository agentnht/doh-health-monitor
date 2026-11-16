#!/usr/bin/env bash
# Interactive SSH management menu for DoH Health Monitor.
set -Eeuo pipefail

readonly PLUGIN_ID="doh-health-monitor"
readonly PLUGIN_BIN_NAME="doh-health-monitor"
readonly RAW_BASE_URL="https://raw.githubusercontent.com/agentnht/doh-health-monitor/feature/plugin-management-ui"
readonly CHECK_SCRIPT_URL="${RAW_BASE_URL}/scripts/check-dns-integration.sh"

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
  local proc exe cwd selected=""
  for proc in /proc/[0-9]*; do
    [[ -r "$proc/exe" && -r "$proc/cwd" ]] || continue
    exe="$(readlink "$proc/exe" 2>/dev/null || true)"
    exe="${exe% (deleted)}"
    [[ "${exe##*/}" == "x-ui" ]] || continue
    cwd="$(readlink "$proc/cwd" 2>/dev/null || true)"
    [[ -n "$cwd" ]] || continue
    if [[ -z "$selected" ]]; then
      selected="$cwd"
    elif [[ "$selected" != "$cwd" ]]; then
      fail "Обнаружено несколько процессов LucX-UI с разными рабочими каталогами; задайте LUCX_PLUGIN_DATA явно."
      return 1
    fi
  done
  if [[ -n "$selected" ]]; then
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

show_menu() {
  printf '\nDoH Health Monitor — управление\n'
  printf '%s\n' '  1) Интегрировать DNS в LucX-UI / Xray'
  printf '%s\n' '  2) Удалить DNS-интеграцию'
  printf '%s\n' '  3) Проверить состояние (только чтение)'
  printf '%s\n' '  4) Web UI (будет доступен на следующем этапе)'
  printf '%s\n' '  0) Выход'
  printf 'Выберите действие: '
}

main() {
  require_root
  resolve_plugin_paths || exit 1

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
      4) printf 'Web UI пока не реализован. Он будет добавлен отдельным этапом без запуска DNS-демона.\n' ;;
      0) printf 'Выход.\n'; break ;;
      *) printf 'Неизвестный пункт меню.\n' ;;
    esac
  done
}

main "$@"
