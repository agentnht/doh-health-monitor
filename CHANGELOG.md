# Changelog

## [Unreleased]

## [1.6.0] - 2026-11-10

## Что нового в 1.6.0

### Локальные DNS-переопределения local_hosts
- Добавлена необязательная настройка `local_hosts` для задания локальных DNS-ответов по точным именам хостов.
- По умолчанию `local_hosts` пустой: если ничего не настроено, DNS-запросы продолжают обрабатываться обычным DoH-механизмом без изменений.
- Для A возвращаются только заданные IPv4-адреса, для AAAA — только заданные IPv6-адреса.
- Если для запрошенного семейства адресов список пуст, возвращается NOERROR/NODATA, а не NXDOMAIN.
- Для HTTPS (тип 65) и SVCB (тип 64) у настроенных имён возвращается пустой ответ. Это убирает DNS-подсказки с IP-адресами и ECH-конфигурацию, но не отключает HTTPS или TLS.
- Запросы других типов и запросы к именам, отсутствующим в `local_hosts`, по-прежнему идут через DoH.
- Локальные DNS-ответы используют TTL 60 секунд; флаг AD сбрасывается.
- Поддерживается только точное совпадение имени: без wildcard. Регистр не учитывается, завершающая точка нормализуется.

### Конфигурация и документация
- Добавлена проверка имён хостов и IP-адресов при загрузке конфигурации; IPv4 и IPv6 проверяются отдельно.
- Изменения `local_hosts` применяются через hot reload без перезапуска плагина. При ошибке новая конфигурация отклоняется, а последняя корректная продолжает работать.
- README дополнен подробной русскоязычной инструкцией: примеры JSON, выбор IP-адресов, поведение A/AAAA/HTTPS/SVCB, hot reload и проверка через `dig`.

### Важные замечания
- `local_hosts` влияет только на DNS-ответы и сам по себе не настраивает маршрутизацию трафика через прокси.
- Приложения, использующие собственный DoH-резолвер, могут обходить локальный DNS-плагин.
- Клиентская DNSSEC-валидация может отклонять локальные неподписанные ответы; сброс AD не отключает такую проверку.

### Проверки
- `go vet ./...` — passed.
- `go test ./...` — passed.
- GitHub Actions CI — passed.

## [1.5.0]

### Reliability
- Resolve DoH endpoint A/AAAA records automatically through independent bootstrap DNS resolvers.
- Benchmark all resolved DoH IPs concurrently using a real DoH query and pin traffic to the fastest responsive address.
- Refresh bootstrap addresses every six hours and after connection failures, retaining the last working IP list during temporary DNS failures.
- Keep TLS hostname verification and SNI while dialing resolved IP addresses.
- Preserve legacy bootstrap_ips as optional fallback addresses.

### Packaging
- Exclude README.md and examples/ from release ZIPs; keep them in the source repository.

## [1.4.0]

### Security
- Strengthened OIDC issuer and discovery URL validation.
- Hardened Gemini API key file handling.
- Improved Unix event socket cleanup to prevent removal of replaced sockets.

### Reliability
- Detect HTTP and Gemini response read failures and oversized response bodies.
- Clear stale active upstream state when no usable upstream remains.
- Added regression tests for security and health-state handling.

### Documentation
- Updated installation and version information.
- Clarified LucX-UI event handling.
- Removed legacy resolver references.
- Clarified rollback and data-directory removal behavior.

## [1.3.0]

- Initial tracked release: UDP/TCP DNS proxy with DoH upstreams, health monitoring, `/healthz` and `/status`, optional Gemini API mode.
