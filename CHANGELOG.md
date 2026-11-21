## [2.3.2] - 2026-11-21

### Security hardening
- Web UI больше не выдаёт сессионную cookie любому loopback-клиенту: доступ начинается с одноразового bootstrap-токена, который SSH-меню выводит в URL. Токен сравнивается constant-time, потребляется один раз, затем выполняется redirect без секрета в адресной строке.
- DNS/HTTP listener validation принимает только loopback IP literal и порты 1–65535; внешний bind и некорректные порты отклоняются до сохранения конфигурации.
- Gemini API key нельзя сохранить поверх `config.json`, файлов источников, логов, backup или временных файлов.
- Ошибки DoH транспортов больше не раскрывают URL path/query и endpoint credentials; URL выбранного endpoint-а в `/status` ограничен origin.
- Исправлена маска секретов в Web UI logs; префикс `Authorization: Bearer` сохраняется, значение заменяется на `[REDACTED]`.
- Чтение `config.json`, DoH/health/local-hosts sources и файлов перед backup выполняется через bounded `O_NOFOLLOW` reader; сам открытый descriptor проверяется как regular file, устраняя гонку `Lstat` → `ReadFile`.
- Подробный loopback `/status` требует случайный bearer-токен из `$LUCX_PLUGIN_DATA/status-api.token` (0600); неаутентифицированный `/healthz` возвращает только `ok`. Web UI backend аутентифицируется к `/status` локальным токеном, не раскрывая его браузеру.
- Bootstrap IP DoH endpoint-ов фильтруются по глобальной публичной адресации; частные, loopback, link-local, multicast и зарезервированные IP не пробуются.
- Удалён неиспользуемый Go panel-integration subsystem: выдача admin-токенов, panel API mutation, Xray planner и диагностический Tunnel lifecycle больше не входят в исходники sidecar. Оставлен только read-only preflight службы/listener/status.
- Полностью удалена Go-зависимость SQLite (`modernc.org/sqlite`) и её транзитивные зависимости; в sidecar больше нет SQLite driver, `database/sql` panel adapter или build-tagged legacy пути.

### DNS reliability and wire correctness
- При отказе всех upstream-ов режима `resolver` возвращается DNS `SERVFAIL`, а не синтетический `NOERROR/NODATA`; искусственный ответ не попадает в кэш.
- Resolver upstream failures используют cooldown, чтобы запросы не ожидали последовательные timeout каждого заранее известного упавшего upstream-а.
- ActiveDoHSelector переключается на здоровую альтернативу в первом probe cycle при score=0, обходя `MinimumHold` и `SwitchCooldown`; если здоровой альтернативы нет, выбор немедленно отзывается.
- UDP DNS payload ограничивается размером, объявленным клиентом в EDNS OPT, либо классическим лимитом 512 байт без EDNS. При усечении ответ сохраняет целые DNS questions/resource records, получает флаг `TC` и согласованные section counts.
- Error DNS packets теперь содержат корректный заголовок и только валидную question section; malformed короткий запрос получает полноценный 12-byte `FORMERR`.
- Исправлена индексация результатов Web UI dig test при более чем 50 запросах.
- OIDC discovery URL с trailing slash/query/fragment отклоняется при разборе, а не проходит валидацию и падает на проверке issuer.

### Reload, management and build
- `reload_interval_seconds` используется как фактический интервал hot reload; после изменения конфигурации таймер перенастраивается.
- Изменение listener addresses или `dns_max_concurrent` сохраняется в конфигурации, но runtime использует прежние bound values до перезапуска. Остальные изменения config/source продолжают применяться без блокировки всего reload цикла.
- Web UI HTTP listener test требует реального ответа `/healthz`; свободный порт больше не считается признаком работающего listener-а.
- Новые listener addresses проверяются попыткой bind до записи конфигурации; занятый порт отклоняется заранее.
- CI проверяет `gofmt`, `staticcheck`, `govulncheck`, race detector и coverage; GitHub Actions закреплены по commit SHA. Release assets публикуются без перезаписи существующих файлов.
- Go CI выполняет `go test -race ./...`; legacy panel/SQLite integration suite удалён вместе с неиспользуемым кодом и зависимостями.

### Version
- Go binary, User-Agent strings, management menu и `manifest.json` синхронизированы на `2.3.2`.
- README дополнен новыми границами безопасности, DNS failover/truncation и правилами hot reload.

# Changelog

## [2.3.1] - 2026-11-21

### Defaults: DoH providers and health checks
- Добавлен DoH endpoint Pereval: `pereval;https://free.pereval.top/dns-query`. Он включён во встроенный `defaults/doh-servers.txt` и пример конфигурации.
- Добавлена обязательная проверка `notebook.google.com`: DNS A/AAAA и HTTPS GET `https://notebook.google.com/` с ожидаемым HTTP 200; `verify_oidc=0`.
- Обновлены embedded defaults и примеры; регрессионный тест проверяет семь DoH provider rows (включая `system-dns`) и десять health-check записей, а также точные параметры Pereval и Notebook.
- Изменения defaults применяются автоматически при первой установке/первом создании файлов. Уже существующие пользовательские `doh-servers.txt` и `tst-domen.txt` при обновлении намеренно сохраняются без автоматической перезаписи.

### Version
- Версия Go-бинарника и `manifest.json` обновлена до `2.3.1`.

## [2.3.0] - 2026-11-21

### Local hosts editor
- Добавлен управляемый `local-hosts.txt` и редактор Local hosts в Web UI; редактируются только точные DNS-имена, системный `/etc/hosts` не затрагивается.
- При первом старте существующие `local_hosts` из `config.json` однократно мигрируют в новый файл; уже существующий `local-hosts.txt` не перезаписывается.
- Добавлены проверки hostname, отдельных IPv4/IPv6 списков, дубликатов и лимитов; комментарии и отключённые строки сохраняются.
- Изменение файла выполняется через `local-hosts.txt.bak` с правами `0600`, атомарную замену и общий межпроцессный config lock; daemon применяет валидный новый snapshot через hot reload до 30 секунд.
- Добавлены регрессионные тесты миграции, source checksum/runtime config generation, API/UI сохранения, backup и отклонения некорректных записей.

### Geosite DNS routing
- Добавлены два взаимоисключающих режима DNS listener-а: `endpoint_ip` (default) и `resolver`.
- Geosite matching вынесен на сторону Xray: DNS port 53 направляется в DNS outbound, его `settings.rules` отправляют Geosite HIT через `direct` на plugin listener, а остальные запросы — через `hijack` во встроенный DNS Xray.
- Добавлен read-only checker структуры DNS path: он находит direct rule с непустым `domain` и выводит найденные значения; конкретная Geosite-категория, число/порядок DNS rules и catch-all action не зашиты в проверку. Команды CLI `integrate/remove` и Web UI mutation endpoint отключены, так как унаследованный planner не совместим с этой DNS-моделью.
- Плагин не включает собственный Geosite matcher и не ведёт динамическую базу пользовательских QNAME.

### ActiveDoHSelector и endpoint_ip
- Выделен самостоятельный `internal/activedoh.Selector` с восемью контрольными доменами, A/AAAA DoH probes и HTTPS/TLS probes с проверкой SNI/Host/certificate.
- Режим `endpoint_ip` возвращает bootstrap IP выбранного DoH endpoint-а, а не IP запрошенного сайта.
- Добавлены freshness, deterministic scoring, anti-flap, failure grace cycles, minimum hold, switch cooldown и config generation fencing.
- TTL ответов ограничен 60 секундами и остатком freshness endpoint-а; synthetic NODATA не кэшируется.

### Resolver mode и DNS cache
- Добавлены упорядоченные upstream-ы `system`, UDP, TCP и DoH с последовательным fallback по транспортным ошибкам, timeout, SERVFAIL, REFUSED и unusable truncated responses.
- System resolver по умолчанию использует `/etc/resolv.conf`; `resolver_upstreams: []` остаётся явно пустым списком и не восстанавливается в default автоматически.
- Для UDP DNS добавлен retry по TCP при TC; system resolver отказывается от прямого совпадения nameserver с локальным plugin listener на порту 53.
- Разделены cache namespace/generation режимов 1 и 2. Positive cache TTL режима 2 ограничен 300 секундами; первый ответ клиенту сохраняет upstream TTL.
- Negative caching NXDOMAIN/NODATA использует `min(SOA RR TTL, SOA.MINIMUM)` с cap 300 секунд. Исправлена классификация CNAME→NODATA; ответы без SOA и synthetic NODATA не кэшируются.

### Контрольные домены
- Встроенный `tst-domen.txt` сокращён до девяти проверок: восемь доменов ActiveDoHSelector и отдельная OIDC-проверка `accounts.google.com`.
- Уже существующий пользовательский `tst-domen.txt` при обновлении сохраняется; для применения нового набора к старой установке требуется резервная копия и ручная замена файла.

### DNS wire policy и документация
- Plugin DNS listener обслуживает A/AAAA; остальные QTYPE получают `NOERROR`/NODATA без SOA и без кэширования.
- Добавлены примеры `resolver_upstreams`, README с двумя режимами и ручной схемой Xray Geosite DNS outbound.
- Синхронизирован `manifest.json` и version string бинарника на `2.3.0`.

### Проверки
- GitHub Actions: `go vet ./...`, `go test ./...`, module tidy, shell/JavaScript syntax и Linux amd64 build.
- Отдельный DoH integration workflow: Go integration/unit tests, Python compile/unit tests, synthetic SQLite lifecycle и shell syntax.
- CI #1046: module tidy, shell/JavaScript syntax, management/checker regression tests, `go vet ./...`, `go test ./...` и Linux amd64 package build — PASS; DoH integration #891 — PASS.
- VPS smoke tests пройдены: read-only Xray preflight, клиентский DNS path для `habr.com`/ `example.com`, ActiveDoH failover, resolver A/AAAA, CLI/Web UI DNS mode save, backup permissions и hot reload. Внутренний Xray matcher trace не заявляется.
- Runtime-проверки Local hosts UI и SSH tunnel под non-root не проводились и не входят в release acceptance scope.

## [2.2.1] - 2026-11-17

### Интерактивный Web UI
- Web UI расширен от read-only dashboard до полноценного интерфейса управления, запускаемого по запросу из SSH-меню и доступного через SSH-туннель.
- Добавлена навигация по разделам: обзор, конфигурация, DoH-сервера, домены и проверки, логи.
- Добавлено редактирование поддерживаемых разделов `config.json`: DNS listeners, таймауты, health, cache, bootstrap resolvers и Gemini API; доступны сброс поддерживаемых параметров к значениям по умолчанию и индикация необходимости перезапуска для изменений listener-ов.
- Добавлены редакторы `doh-servers.txt` и `tst-domen.txt`: сохранение порядка, управление активностью строк через комментарии и проверка данных до записи.
- Добавлена загрузка Gemini API key в настроенный приватный файл с правами `0600`; значение ключа не возвращается через API.
- Добавлен ограниченный просмотр журнала плагина и отдельный сохраняемый журнал операций интеграции/деинтеграции.

### Диагностика и интеграция
- Добавлены операционные проверки конфигурации, исходных файлов, DNS listener-портов и реальные DNS A/AAAA-запросы к настроенному UDP listener. Результаты показывают домен, тип запроса, ответ и длительность.
- Добавлены подтверждаемые действия Integrate / DeIntegrate в Web UI; они используют существующий Go workflow, а не отдельную реализацию интеграции.
- Диагностическая проверка Xray сохраняется read-only; обычный запуск Web UI не останавливает и не перезапускает DNS daemon.

### Безопасность
- Все management API-маршруты защищены сессионной HttpOnly cookie и проверками loopback Host/Origin.
- Для файлов управления используется allowlist; конфигурация и текстовые источники валидируются до атомарной записи.
- Входные JSON-данные ограничены по размеру и структуре; команды диагностики используют фиксированные аргументы без shell-интерполяции браузерного ввода.
- Операции Integrate / DeIntegrate требуют явного подтверждения; секрет Gemini не раскрывается браузеру и сохраняется с правами `0600`.

### Проверки
- CI: `go vet ./...`, `go test ./...`, проверка синтаксиса shell и JavaScript, сборка тестового пакета Linux amd64.
- Отдельный DoH integration test workflow.
- Runtime-проверки на пользовательском VPS не считаются выполненными GitHub Actions и в этот список не включены.

## [2.2.0] - 2026-11-17

### SSH-меню и Web UI мониторинга
- Добавлен интерактивный Bash-скрипт управления плагином `scripts/plugin-management.sh`. Он запускается из SSH-сессии от root и предоставляет пункты Integrate, Remove, read-only Check и запуск Web UI.
- Установочный ZIP теперь включает `scripts/plugin-management.sh` и используемый им `scripts/check-dns-integration.sh`; локально установленное меню выполняет read-only checker без дополнительной загрузки из сети.
- При первом запуске меню из каталога установленного плагина создаёт симлинк `/usr/local/bin/dhm`. Короткая команда `dhm` запускает то же меню; существующий файл или чужая ссылка не перезаписываются.
- Сохранён альтернативный запуск непосредственно из GitHub через `bash <(curl -fsSL https://raw.githubusercontent.com/agentnht/doh-health-monitor/main/scripts/plugin-management.sh)`. Поскольку скрипт в этом режиме передаётся через process substitution, он не создаёт постоянный симлинк.
- Команды Integrate и Remove вызываются из существующего Go CLI после явного подтверждения; диагностика Check не изменяет настройки Xray. Дополнительная проверка конфигурации Xray выполняется отдельным read-only скриптом.
- В Go-бинарник добавлены отдельные режимы `check` и `web`; обычный запуск без аргументов по-прежнему запускает DNS daemon.
- Добавлен встроенный Web UI, запускаемый только по запросу из SSH-меню. Он работает отдельным процессом и не останавливает, не перезапускает и не перенастраивает DNS daemon.
- Web UI слушает только `127.0.0.1` на динамически назначенном ОС порту. Скрипт получает фактический порт через readiness-сообщение, формирует команду SSH local port forwarding и адрес для браузера. Открывать порт в firewall или менять UFW не требуется.
- Жизненный цикл Web UI привязан к управляющей SSH-сессии: при штатном выходе, сигналах завершения или потере управляющего соединения процесс корректно завершает HTTP-сервер. Закрытие только отдельного SSH-туннеля не останавливает Web UI, пока управляющая сессия остаётся активной.
- Добавлен защищённый read-only API `GET /api/v1/status` с cookie сессии `HttpOnly`/ `SameSite=Strict`, проверками Host/Origin, запретом кеширования и ограниченным набором возвращаемых полей. Секреты, конфигурация целиком и сырые ошибки не выдаются; изменяющих API-маршрутов нет.
- Dashboard показывает доступность daemon, версию, DNS listeners, счётчики запросов и ошибок, состояние cache и Gemini API, upstream-группы и состояния серверов. Для каждого upstream доступны время последней проверки, streak-счётчики и результаты отдельных DNS/HTTP-проверок.
- Компактная панель использует две верхнеуровневые области и три колонки данных; состояния UP/DOWN визуально различаются. Раскрытые подробности upstream сохраняются при периодическом и ручном обновлении. Check duration обозначает длительность полного цикла проверок, а не RTT одного DNS-запроса.

### Надёжность DNS и восстановление upstream
- Добавлена общая строгая валидация DNS-ответов от DoH и системных DNS-resolver-ов: сверяются transaction ID, QR, OPCODE, QNAME, QTYPE и QCLASS исходного запроса. Несовпадающий или некорректный ответ отклоняется.
- Добавлен 30-секундный cooldown для upstream после неудачного пользовательского запроса. Пока он действует, доступные серверы пробуются раньше проблемного; успешный запрос снимает cooldown досрочно, а по истечении срока upstream снова участвует в обычном порядке.
- Если все upstream находятся в cooldown, для следующей попытки выбирается сервер с ближайшим временем окончания cooldown, чтобы не отправлять каждый запрос одновременно на все известные проблемные endpoint.
- При сетевой/транспортной ошибке соединения с выбранным DoH IP выполняется повторная попытка с другим адресом из уже разрешённых или настроенных резервных IP. Альтернативные адреса предварительно проверяются DoH-пробой; при неудаче выполняется обычный failover на следующий upstream.
- Добавлены регрессионные тесты на несовпадения QNAME/QTYPE/QCLASS и другие поля DNS-ответа, порядок и восстановление после cooldown, а также выбор альтернативного IP.

### Устойчивость Integrate и диагностического self-test
- Учтено отложенное применение изменений Xray со стороны LucX-UI: проверка временного диагностического Tunnel ожидает появления TCP/UDP loopback listeners до 75 секунд с учётом фонового цикла применения панели.
- Неуспешный DNS self-test больше не отменяет уже применённую и подтверждённую постоянную DNS-интеграцию. Временные диагностические ресурсы очищаются отдельно; ошибки теста и очистки сообщаются независимо.

### Управление DoH upstream и health-check через текстовые источники
- `doh-servers.txt` стал единственным источником истины для DoH providers: формат `stable_id;https_url`, порядок строк задаёт приоритет, hostname endpoint можно менять без переименования ID.
- Добавлен `tst-domen.txt` с шестью полями: domain, qtypes, required, http_url, expected_status и verify_oidc. HTTP выполняется только при заданном URL; required влияет только на итоговый health state.
- Встроенные `doh-servers.txt` и `tst-domen.txt` создаются при первом запуске только при отсутствии пользовательских файлов. Старый URL-only DoH список автоматически мигрирует к стабильным ID.
- `config.json` генерируется из двух файлов-источников с сохранением остальных настроек. SHA-256 двух файлов хранится в памяти процесса; файлы проверяются каждые 30 секунд.
- Валидные изменения применяются атомарно через новый runtime snapshot без перезапуска DNS-процесса. Некорректные изменения целиком отклоняются; ранее применённая конфигурация продолжает работать.
- После успешной перезагрузки источников конфигурации health-check цикл запускается немедленно, а не ожидает окончания стандартного интервала мониторинга.
- Удалены необязательные HTTP-пробы корневых URL `ssl.gstatic.com` и `www.googleapis.com`; DNS-проверки оставлены.
- Показатель `latency_ms` переименован в `check_duration_ms` / Check duration: это длительность полного health-check цикла upstream.

### Миграция
- Старые hostname-based upstream IDs сопоставляются со стабильными IDs (включая `doh.dagami.ru` → `dagami`); прочие настройки `config.json`, в том числе кэш, local_hosts, Gemini API, Bootstrap DNS и integration flag, сохраняются.
- Старые пользовательские текстовые файлы сохраняются; существующий `tst-domen.txt` не перезаписывается. Проверка формата не исправляет и не удаляет ошибочный пользовательский файл.

### Проверки
- Добавлены тесты создания встроенных файлов, сохранения существующих файлов, миграции старого формата, разбора полного набора полей, стабильных provider IDs, генерации config.json, сохранения несвязанных настроек и контрольных сумм.
- Добавлен сценарий отклонения некорректного источника с сохранением последнего рабочего runtime.

## [2.1.0] - 2026-11-16

### Go 2.1.0 live staging validation
- 2026-11-16: установленный основной Go-бинарник версии 2.1.0 успешно проверен на тестовом VPS командами `integrate` и `remove`; отдельный тестовый executable не использовался.
- Preflight подтвердил активный сервис `lucx-plugin-doh-health-monitor`, слушатели `127.0.0.1:5355` по UDP/TCP и JSON status API; endpoint LucX-UI был автоматически обнаружен, installer-provided credential успешно загружен.
- `integrate` добавил DNS outbound `dns-out`, DNS server `127.0.0.1:5355` и глобальное TCP/UDP правило для порта 53. Запись панели прошла API read-back verification; правило `xui-dns-allow` осталось под управлением LucX-UI.
- Диагностический Tunnel (inbound ID 1, loopback port 15353) успешно вернул положительные DNS A-ответы по UDP и TCP: `104.20.23.154` и `172.66.147.243`. Временная allow-запись `finalRule` и диагностический inbound были удалены; очистка подтверждена read-back и анализом внешних ссылок.
- `remove` успешно удалил выбранные постоянные ресурсы без внешних ссылок (port-53 route, `dns-out`, DNS server `127.0.0.1:5355`); API read-back подтвердил удаление, итоговый флаг `integration=false`.
- Финальное состояние тестового VPS после проверки: постоянная DNS-интеграция удалена намеренно, поскольку за успешным `integrate` последовал успешный `remove`.

### Go daemon startup and upstream probe results
- Полный `plugin.log` подтверждает штатный старт sidecar 2.1.0: создан первичный `data/config.json`, загружены 6 upstreams и 1 group, подняты DNS UDP/TCP на `127.0.0.1:5355`, HTTP status listener на `127.0.0.1:18765` и Unix event socket; процесс перешёл в `READY`.
- Startup DoH IP discovery выбрал рабочий адрес для каждого проверенного hostname. Отдельные кандидаты дали ошибки: IPv6 `network is unreachable`, а также timeout и `connection refused` для отдельных IPv4 адресов. Для каждого hostname при этом был выбран успешный IP; предупреждения не помешали запуску.
- После успешного `integrate` и после `remove` daemon зарегистрировал `CONFIG reloaded` без ошибок. Это согласуется с успешным обновлением флага `integration` и hot reload конфигурации работающим процессом.

### Runtime DNS smoke tests
- `curl http://127.0.0.1:18765/healthz` вернул `ok`; `/status` вернул корректный JSON с версией `2.1.0`, loopback listeners и `active_upstream: system-dns`.
- В status snapshot выбранный `system-dns` имел состояние `up`; также `up` были `dns.bezmezhau.com`, `dns.comss.one` и `doh.dagami.ru`. Два из шести кандидатов — `dns.zapret.moe` и `eu.geohide.ru` — имели состояние `down` из-за обязательной Gemini HTTP-проверки (EOF и redirect на Google Sorry соответственно). Поэтому health-check всех upstream не был полностью зелёным, но выбранный `system-dns` работал штатно.
- В status snapshot: `queries=2`, `failures=0`, `udp_dropped=0`, `tcp_rejected=0`, очереди и активные соединения пустые.
- `dig @127.0.0.1 -p 5355 example.com A` по UDP и тот же запрос с `+tcp` по TCP оба вернули `NOERROR` и два A-ответа (`104.20.23.154`, `172.66.147.243`); измеренное время — 15 ms по UDP и 1 ms по TCP.

### Перенос интеграции в Go
- В основной бинарник добавлены явные команды `integrate` и `remove`; обычный запуск DNS daemon не обращается к API панели и не получает admin credential.
- Получение/переиспользование локального admin API credential выполняется только внутри `integrate` или `remove`; секрет не выводится в журнал и хранится вне каталога плагина с правами 0600.
- Успешный `integrate` записывает `integration: true` в `$LUCX_PLUGIN_DATA/config.json`; успешный `remove` сбрасывает флаг. При ошибке операции состояние не меняется.
- Версия пакета и манифеста повышена до 2.1.0. Автоматический запуск интеграции и автоматический remove при удалении плагина в этот релиз не входят.

### Безопасность сборки
- Предпочтительный Go toolchain и CI закреплены на Go 1.27.4 для включения исправления GO-2026-6859 в net/http; директива go 1.23 сохранена как минимальная версия языка/модуля.

### Интеграция с LucX-UI
- Исправлена передача SSL-контекста в пользовательский HTTPS-обработчик: режим IP SAN теперь использует SNI `localhost`, сохраняет проверку цепочки сертификата и отдельно проверяет точный IP SAN; версия адаптера 1.5.1.
- TLS-автоопределение разделяет HTTP без сертификата, HTTPS с IP SAN и HTTPS с DNS SAN. Для IP-сертификата SNI отделён от проверяемого IP SAN, при этом проверка цепочки доверия остаётся обязательной; для явного HTTPS URL добавлены `--tls-mode` и `--tls-name`.
- Версия Xray переведена из блокирующего allowlist-гейта в диагностическую информацию: неизвестная или не определившаяся версия не требует ручного RISK; совместимость проверяется по фактическому API, структуре конфигурации и read-back.
- Bearer credential больше не запрашивается у оператора: адаптер читает `XUI_API_TOKEN` из root-only install result, переиспользует собственный защищённый credential или создаёт отдельный именованный API-токен через локальную CLI LucX-UI; добавлены проверки безопасного хранения и тесты.
- Исправлено использование автоматически обнаруженного URL: API-клиент получает разрешённый endpoint, а не необязательный аргумент `--base-url`.
- Исправлено интерактивное чтение подтверждений из /dev/tty: устройство открывается отдельными потоками чтения и записи, поскольку TTY не поддерживает seek и режим Python r+ завершается ошибкой.
- API-адаптер автоматически определяет локальный URL панели из read-only настроек SQLite, включая порт, web base path, TLS и webDomain; учитывает runtime XUI_PORT и не печатает скрытый web base path.

### Поведение Integrate / Remove
- Integrate применяет единый desired-state план, затем проверяет DNS через диагностический Tunnel по UDP и TCP. После попытки теста выполняется очистка: каждый inbound и `finalRule` удаляется только при отсутствии внешнего использования вне диагностического плана. Ранее существовавший/переиспользованный объект не сохраняется только из-за своего происхождения. Очистка выполняется и при ошибке теста; ошибка очистки выводится отдельно.
- Remove использует тот же план интеграции, удаляет только выбранные им ресурсы без внешних ссылок и отправляет все безопасные удаления одним API update. Точное loopback allow-исключение `127.0.0.1:5355` в `direct.settings.finalRules` удаляется при отсутствии внешних DNS-потребителей; сам outbound `direct`, `geoip:private` block и остальные правила сохраняются.
- Удалён пользовательский CLI-флаг `--plan-only`; возможный перезапуск Xray сообщается NOTICE без интерактивного подтверждения.

### Семантическое DNS-планирование и Integrate / Remove
- Добавлен общий read-only анализатор Xray-конфига: повторно использует совместимый DNS-outbound независимо от тега, DNS-сервер и подходящие routing/balancer-цепочки; добавляет только недостающие объекты.
- Новые outbound tags и routing ruleTags выбираются с проверкой всех используемых тегов, включая inbound/outbound/balancer/API/DNS server/DNS application, и префиксов balancer/observatory selectors, а также незакрытых ссылок из routing rules и fallbackTag; ссылки в новых правилах используют фактически выбранные имена. Дубли определённых Xray-тегов блокируют план.
- Добавлен анализ порядка и пересечений правил порта 53: частные правила сохраняются, а широкие конфликтующие правила, которые перехватили бы DNS до fallback, блокируют план вместо создания недостижимого правила. DNS-outbound с ограниченными qType/domain или DNS server с ограничениями queryStrategy/IP не ошибочно считаются полностью совместимыми.
- API apply и offline dry-run используют общий планировщик; runtime checker также определяет outbound по активному правилу порта 53, а не по фиксированному имени.
- API-адаптер переведён на две директивы `integrate` и `remove`; обе строят новый план по текущему состоянию панели, без backup, snapshot, ownership journal и rollback.
- Integrate переиспользует совместимые DNS-объекты, добавляет недостающие и запускает Tunnel self-test. Маркеры Tunnel используются только для идентификации диагностического ресурса; решение об удалении inbound и `finalRule` принимается по внешним ссылкам в live-конфигурации, а не по `added/reused`.
- Remove находит DNS outbound/server/port-53 route по семантическим признакам, проверяет ссылки (routing, balancer, observatory, proxy chain, DNS policy) и удаляет только неподелённые объекты; после каждого API update выполняется read-back и новый план. Версия API-адаптера: 1.7.0.

### Безопасность интеграции
- API-адаптер не сохраняет и не восстанавливает прежнюю конфигурацию Xray. При следующем вызове выбирается только Integrate или Remove, и решение строится по текущему live state.

## [2.0.1] - 2026-11-11

### Интеграция с LucX-UI
- README дополнен пошаговой инструкцией ручного подключения DNS-шлюза через редактор Xray в LucX-UI без запуска интеграционного скрипта.
- Добавлены английская и русская версии документации по API-интеграции, безопасной проверке конфигурации, резервному копированию и откату.
- API-адаптер проверяет версию Xray на целевом VPS: непроверенная версия сопровождается предупреждением и требует явного подтверждения; версия LucX-UI показывается только как справочная и не блокирует работу.

## [2.0.0] - 2026-11-11

### Системный DNS как полноценный upstream
- Добавлен `system-dns` — первый кандидат в Google-профиле, использующий nameserver-ы VPS из `/etc/resolv.conf`.
- Системный DNS проходит тот же набор DNS, Gemini HTTPS и Google Accounts OIDC проверок, что и DoH-кандидаты; он участвует в выборе активного шлюза и автоматическом failover на DoH при отказе.
- DNS-пакеты передаются системным nameserver-ам напрямую по UDP; при усечённом ответе выполняется повтор по TCP. Серверы из `resolv.conf` перебираются в указанном порядке с ограниченным таймаутом.
- Старые `config.json` автоматически нормализуются: `system-dns` добавляется первым в памяти, сохраняя относительный приоритет существующих DoH. Редактировать `doh-servers.txt` для системного DNS не требуется.
- В `/status` показываются текущие системные nameserver-ы и ошибка чтения resolver-конфигурации, если она возникла.
- `bootstrap_resolvers` остаются отдельным механизмом и используются только для разрешения hostname DoH endpoint.

### Ресурсная устойчивость и health-check
- Интервал полного цикла health-проверок по умолчанию составляет 25 минут; одна успешная проверка возвращает upstream в `up`, одна неудачная переводит его в `down` (`success_threshold=1`, `failure_threshold=1`).
- HTTP-клиенты одноразовых pinned health/Gemini-проверок закрывают idle connections; для transport заданы ограниченные idle-пулы и таймаут.
- UDP обрабатывается фиксированным пулом рабочих потоков и ограниченной очередью; TCP ограничен 128 одновременными соединениями, с idle/read и write timeout.
- DNS-кэш ограничен одновременно числом записей и байтами (8 MiB по умолчанию), использует FIFO eviction и хэшированные ключи; включённый кэш с `max_entries=0` запрещён.
- Убрана запись журнала на каждый успешный DNS-запрос; удалённые upstream/group health-записи и Gemini timestamps очищаются при hot reload.
- В `/status` добавлены счётчики UDP/TCP нагрузки и отказов, размер кэша, число goroutines, показатели heap и накопленное user/system CPU-время процесса.
- Добавлены регрессионные тесты ресурсных ограничений и benchmark cache hit.

### Проверки на VPS
- При временной недоступности системных nameserver-ов активный upstream автоматически переключился с `system-dns` на `doh.dagami.ru`.
- После восстановления системного DNS следующий health-check вернул активный upstream на `system-dns`.

## [1.7.1] - 2026-11-10

### Архитектура DNS-шлюза
- Оставлен единственный профиль пригодности DoH-серверов — `google`; проверка пригодности для обычного использования удалена.
- Удалён выбор профиля по QNAME: контрольные домены больше не участвуют в маршрутизации пользовательских DNS-запросов.
- Любой DNS-запрос, поступивший на локальный listener, передаётся через активный DoH-upstream профиля `google`, независимо от запрашиваемого домена.
- Старые конфигурации с несколькими группами автоматически нормализуются до единственной группы `google`; legacy-поля `domains` и `fake_dns` принимаются, но не используются.
- Список Google health-checks приведён к 25 уникальным контрольным доменам; Gemini и Google Accounts остаются обязательными проверками.
- Обновлены пример конфигурации, README и тесты произвольных QNAME через Google DoH gateway.

## [1.7.0] - 2026-11-10

## Что нового в 1.7.0

### Диагностика DoH bootstrap и выбора IP
- В `/status` добавлен объект `doh_bootstrap` с разрешёнными A/AAAA IP для каждого upstream, bootstrap resolver, временем разрешения и текущим выбранным IP.
- Для последнего цикла выбора сохраняются все проверенные кандидаты, источник адресов, результат DoH/TLS-проверки и задержка каждого IP.
- В журнал добавлены отдельные строки `DoH IP probe` по каждому IP-кандидату: успешные проверки записываются как INFO, ошибки — как WARN.
- Итоговая строка `DoH IP selected` дополнена временем окончания pin-периода.
- Проверки IP по-прежнему выполняются параллельно; TLS SNI и проверка сертификата используют hostname DoH endpoint.
- Сохранены шестичасовой pin выбранного IP, принудительное обновление после ошибки подключения и резервный механизм `bootstrap_ips`.

### DoH proxy providers по умолчанию
- Стандартный список upstream заменён на GeoHide EU (`eu.geohide.ru`), Dagami (`doh.dagami.ru`), Comss.one (`dns.comss.one`), Bezmezhau (`dns.bezmezhau.com`) и Zapret (`dns.zapret.moe`).
- Все пять провайдеров добавлены в стандартный приоритет всех доменных групп и в автоматически создаваемый `doh-servers.txt`.
- Shecan исключён до обновления TLS-сертификата. Google Public DNS, Cloudflare и Quad9 исключены из списка DoH upstream и не являются резервными proxy-серверами.
- Независимые bootstrap DNS IP (`1.1.1.1`, `8.8.8.8`) сохранены только для разрешения адресов самих DoH hostname; они не используются как upstream для пользовательских запросов.
- Health-check Google, OpenAI и YouTube переведены на лёгкие контрольные URL, проверенные с VPS.

### Проверки
- Добавлены тесты на сбор подробных результатов параллельной проверки IP и безопасный снимок bootstrap-статуса.

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
