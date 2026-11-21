# DoH DNS Proxy & Health Monitor для LucX-UI

**Версия:** 2.3.2  
**Платформа:** Linux x86-64 (`amd64`), статический Go-бинарник  
**Тип:** LucX-UI sidecar, `apiVersion: 1`  
**Режим Gemini API:** необязательный, управляется параметром `gemini_api.enabled`

## 1. Назначение

DoH Health Monitor — локальный DNS sidecar для LucX-UI/Xray. В линейке 2.3.x обработка Geosite DNS-потока разделена между Xray и плагином: Xray сопоставляет QNAME с Geosite и выбирает DNS-ветку, а плагин обслуживает только те запросы, которые Xray направляет в его DNS listener. В самом плагине нет собственного Geosite matcher и динамической базы пользовательских QNAME.

Плагин поддерживает два взаимоисключающих режима обработки A/AAAA запросов:

- **`endpoint_ip` (режим по умолчанию):** ActiveDoHSelector выбирает один доступный DoH endpoint по восьми контрольным доменам. Для DNS-запроса плагин возвращает bootstrap IP выбранного DoH endpoint-а, а не IP запрошенного сайта. Это режим для схемы, где дальнейшее назначение трафика определяет Xray.
- **`resolver`:** плагин разрешает исходное имя запроса через независимый упорядоченный список `resolver_upstreams`. По умолчанию используется системный resolver ОС сервера; можно настроить UDP, TCP и DoH upstream-ы.

Обычная DNS-ветка listener-а принимает A и AAAA. Для точно совпавшего имени из управляемого `local-hosts.txt` плагин возвращает настроенные локальные A/AAAA; HTTPS/SVCB и остальные неподдерживаемые QTYPE получают `NOERROR`/NODATA без SOA и без кэширования. CNAME RR в составе ответа upstream на A/AAAA сохраняются.

`bootstrap_resolvers` и `resolver_upstreams` — разные настройки: первые разрешают hostname DoH endpoint-ов для исходящих соединений самого плагина, вторые выполняют обычный DNS resolve пользовательского QNAME только в режиме `resolver`.

### Что умеет

- UDP и TCP DNS listener по умолчанию на `127.0.0.1:5355`; конфигурация принимает только loopback IP literals и валидные порты 1–65535.
- DNS UDP payload учитывает EDNS buffer size клиента (или 512 байт без EDNS); при нехватке места ответ обрезается по границе RR и получает флаг TC.
- ActiveDoHSelector: восемь контрольных доменов, A/AAAA DNS probes через кандидатов DoH, затем HTTPS/TLS probes по IP с исходными hostname, SNI, HTTP Host и проверкой сертификата.
- Отдельный режим `endpoint_ip` с TTL до 60 секунд, ограниченным временем актуальности выбранного endpoint-а.
- Режим `resolver` с последовательным fallback через system, UDP, TCP и DoH upstream-ы; упавшие upstream-ы получают cooldown, а отказ всех upstream-ов возвращает DNS SERVFAIL вместо ложного NODATA.
- Раздельные cache namespace/generation для двух режимов; режим 2 использует positive cache TTL не более 300 секунд и SOA-based negative caching по RFC 2308.
- Сохранение исходного TTL upstream в первом ответе; ограничения TTL применяются к отдельной копии, помещаемой в кэш.
- Независимые bootstrap DNS для разрешения hostname DoH endpoint-ов.
- Существующий health monitor upstream-ов, DNS/HTTP проверки и необязательная Gemini API проверка.
- `/healthz` и `/status` на localhost.
- Приём и журналирование событий LucX-UI через Unix socket.
- Интерактивный Web UI для поддерживаемых настроек и диагностики; доступ через SSH-туннель.

### Где настраивается Geosite

Geosite matching находится в правилах внутри Xray DNS outbound (`dns-out.settings.rules`), а не в обычных routing rules и не в плагине. Запросы, совпавшие с Geosite, направляются действием `direct` на `127.0.0.1:5355`; остальные передаются действием `hijack` встроенному DNS Xray. Для этого нужен routing rule, отправляющий DNS-трафик TCP/UDP порта 53 в `dns-out`.

### Чего плагин не делает

- Не загружает и не разбирает Geosite assets, не поддерживает собственный matcher и не ведёт динамическую QNAME database.
- Не определяет по одному DNS-пакету, какое правило Xray совпало; разделение потоков должно произойти до передачи пакета listener-у.
- Не обслуживает отдельные QTYPE HTTPS/SVCB, MX, TXT и другие типы; для них listener возвращает NODATA.
- Не выполняет полноценную DNSSEC validation и не устанавливает AD в синтетических ответах.
- Не меняет Xray DNS policy при обычном запуске daemon. Geosite rules настраиваются вручную; автоматические CLI/Web UI операции изменения Xray отключены в линейке 2.3.x, поскольку прежний planner не соответствует этой схеме.
- Не отключает проверку TLS-сертификатов и hostname.

## 2. Схема работы

```text
WireGuard / TProxy client
          |
          v
     Xray inbound
          |
          v
 routing: TCP/UDP port 53 -> dns-out
          |
          v
   dns-out.settings.rules
       /           \
  Geosite HIT    catch-all
   direct         hijack
      |              |
      v              v
127.0.0.1:5355   Xray built-in DNS
 plugin listener   (e.g. Quad9)
      |
      v
 endpoint_ip OR resolver
```

В `endpoint_ip` плагин возвращает IP выбранного DoH сервера для A/AAAA запроса. В `resolver` он возвращает результат разрешения исходного QNAME через `resolver_upstreams`. Это независимые режимы: при ошибке одного режима нельзя переключаться в другой.

`rewriteNetwork: udp` в DNS outbound определяет транспорт локального участка Xray → plugin listener. Для текущей схемы используется UDP; это не описание внешнего транспорта WireGuard.

Системный resolver ОС в режиме `resolver` не означает встроенный DNS Xray. Необходимо проверить `/etc/resolv.conf` и сетевые перенаправления, чтобы исключить DNS-петлю через локальный stub, TProxy или NAT.

## 3. Состав пакета и расположение файлов

Установочный ZIP содержит необходимые для установки файлы и скрипты управления:

```text
manifest.json
bin/doh-health-monitor
scripts/
├── plugin-management.sh
└── check-dns-integration.sh
```

`plugin-management.sh` запускает SSH-меню, а `check-dns-integration.sh` используется его read-only диагностикой. `README.md` и каталог `examples/` остаются в GitHub-репозитории, но в установочный ZIP не включаются. Автоматического обновления плагина нет: новую версию устанавливают повторно через менеджер плагинов.

После первого запуска в приватной папке `$LUCX_PLUGIN_DATA` автоматически создаются:

```text
$LUCX_PLUGIN_DATA/
├── config.json       # генерируемая рабочая конфигурация + прочие настройки
├── doh-servers.txt   # ID провайдера и URL DoH, одна запись на строку
├── tst-domen.txt     # DNS/HTTP health-check настройки, одна проверка на строку
└── local-hosts.txt   # точные DNS-переопределения, одна запись на hostname
```
Если `gemini_api.enabled` включён, дополнительно создайте:

```text
$LUCX_PLUGIN_DATA/gemini_api_key
```

Вся изменяемая информация хранится только в `LUCX_PLUGIN_DATA`. Плагин не должен писать в каталог бинарника, `/etc`, `/tmp` или другие места.

## 4. Установка в LucX-UI

1. Для опубликованного релиза скачайте ZIP с соответствующим номером версии. Для релиза `v2.3.2` используйте пакет `doh-health-monitor-v2.3.2.zip` со страницы GitHub Releases.
2. В LucX-UI откройте менеджер плагинов и установите ZIP.
3. Запустите плагин из панели.
4. При первом запуске плагин создаст `config.json`, `doh-servers.txt`, `tst-domen.txt` и `local-hosts.txt`. Уже существующие текстовые файлы не перезаписываются (старый URL-only список DoH автоматически мигрирует в новый формат). Если `local-hosts.txt` отсутствует, старые записи `local_hosts` из `config.json` однократно переносятся в новый файл.
5. Посмотрите журнал плагина. Нормальный старт содержит строки примерно такого вида:

```text
level=INFO START id=doh-health-monitor version=2.3.2 arch=amd64 data=...
level=INFO CONFIG loaded ... gemini_api=false
level=INFO EVENT_SOCKET listening ...
level=INFO READY DNS=127.0.0.1:5355/127.0.0.1:5355 HTTP=127.0.0.1:18765
```

6. Запустите Web UI через SSH-меню и откройте его по адресу локального SSH-туннеля. В интерфейсе доступны редакторы поддерживаемых параметров `config.json`, `doh-servers.txt`, `tst-domen.txt` и `local-hosts.txt`.

### SSH-меню и Web UI

После установки плагина доступны два способа запуска меню.

**Способ 1 — локальный скрипт из установленного ZIP (рекомендуется).**

При стандартном расположении LucX-UI подключитесь к VPS по SSH и выполните от root:

```bash
bash /usr/local/x-ui/bin/plugins/doh-health-monitor/scripts/plugin-management.sh
```

Если LucX-UI установлен в другом каталоге, замените путь на фактический каталог установленного плагина. При первом запуске локальной копии скрипт создаст симлинк `/usr/local/bin/dhm`. После этого меню можно запускать короткой командой:

```bash
dhm
```

Существующий файл или ссылка `/usr/local/bin/dhm`, если они указывают на другой объект, не перезаписываются. После удаления самого плагина удалите оставшуюся ссылку командой `rm -f /usr/local/bin/dhm`.

**Способ 2 — запуск непосредственно из GitHub (сохраняется как альтернативный вариант).**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/agentnht/doh-health-monitor/v2.3.2/scripts/plugin-management.sh)
```

Этот способ запускает только меню из process substitution; локальный packaged checker рядом с установленным плагином при этом всё равно должен присутствовать. Скрипт не скачивает и не исполняет изменяемый checker от root. Для полноценной проверки используйте установленную копию меню из ZIP.

Если вы подключились не под root, сначала выполните `sudo -i`, затем запустите выбранный вариант.

Меню предоставляет следующие действия:

1. **Проверить состояние** — read-only проверка плагина и структуры утверждённого Xray Geosite DNS path.
2. **Запустить Web UI** — интерфейс управления плагином и read-only диагностики, доступный через SSH-туннель.
3. **Переключить DNS mode / настроить resolver upstreams** — интерактивное изменение режима и списка resolver upstreams с подтверждением.
0. **Выход**.

Web UI содержит:
- **Конфигурация** — редактор поддерживаемых параметров listeners, таймаутов, health, cache, bootstrap resolvers и Gemini API; для изменения listener-портов интерфейс сообщает о необходимости перезапуска.
- **DoH-сервера** и **Домены** — редакторы `doh-servers.txt` и `tst-domen.txt`, сохраняющие порядок строк и состояние включения/отключения.
- **Local hosts** — редактор `local-hosts.txt`: точный hostname и списки IPv4/IPv6, комментарии и отключённые строки сохраняются. Запись изменяется только в DNS-плагине; системный `/etc/hosts` не затрагивается. Перед записью создаётся `local-hosts.txt.bak` (0600), а файл атомарно заменяется. Проверенные изменения автоматически применяются демоном после hot reload; интервал задаётся `reload_interval_seconds` (1–300 секунд, встроенное значение по умолчанию — 5 секунд). Изменение адресов listener-ов и `dns_max_concurrent` сохраняется, но применяется после перезапуска плагина; остальные настройки и source-файлы продолжают hot reload.
- **Проверка состояния** — проверки конфигурации, файлов, портов и реальные DNS-запросы к настроенному UDP listener с отображением домена, типа записи, ответа и времени.
- **Логи** — ограниченный просмотр журнала плагина.

Web UI не содержит кнопок изменения Xray-конфигурации. Настройка Geosite DNS выполняется вручную через штатный редактор панели по нормативному design doc.

Доступ к Web UI начинается с одноразового bootstrap-токена, который SSH-меню выводит вместе с локальным URL. Первый запрос атомарно обменивает билет на HttpOnly/SameSite cookie и очищает токен из адресной строки; повторное использование билета отклоняется. Каждый Web UI API-запрос требует сессионную cookie; дополнительно проверяются Host/Origin. Интерфейс слушает только loopback и предназначен для доступа через SSH local port forwarding. Не пересылайте bootstrap URL и не публикуйте вывод SSH-меню. Ключ Gemini сохраняется в отдельный файл с правами `0600`, его содержимое не возвращается браузеру.

При запуске Web UI меню напечатает готовую SSH-команду для Windows PowerShell и локальный URL с одноразовым bootstrap-токеном. Оставьте открытыми управляющую SSH-сессию и отдельную сессию туннеля. Нажмите Enter в управляющей сессии, чтобы остановить Web UI и вернуться в меню; при закрытии SSH-сессии Web UI также завершается.

Скрипт рассчитан на уже установленный плагин. Он не устанавливает и не обновляет сам плагин, не открывает порты в firewall и не изменяет UFW.

### Требования по архитектуре и сети

- Этот ZIP содержит бинарник только `linux/amd64`.
- `permissions.network` пустой массив: плагину разрешена сеть для DoH и HTTPS health-check. Не устанавливайте `network: ["none"]`.
- `panelApi` grant не запрашивается и admin credential панели не используется. Плагин не изменяет Xray-конфигурацию; Geosite DNS policy настраивается оператором вручную.
- Listener-ы по умолчанию привязаны только к `127.0.0.1`; другие значения допускаются только как IP loopback literal (`127.0.0.1`, `::1` и т.п.), не `0.0.0.0` и не hostname.
- Bootstrap IP DoH endpoint-ов фильтруются: частные, loopback, link-local, multicast, documentation и прочие non-global адреса не используются.
- `/status` не раскрывает filesystem path каталога конфигурации, системный список DNS и ошибки чтения resolv.conf; URL выбранного DoH endpoint-а публикуется только как origin без path/query.

## 5. Конфигурация плагина

### 5.1 `config.json`

Это генерируемый рабочий файл. Плагин обновляет из текстовых источников `upstreams`, `groups[].upstreams`, `groups[].checks` и `local_hosts` (из `local-hosts.txt`); остальные настройки — DNS listeners, Bootstrap DNS, резервные IP, тайминги, пороги, кэш и Gemini API — сохраняются. Поле `integration` из прежней модели больше не управляет Xray и игнорируется для Geosite DNS policy.

Образец `examples/config.example.json` доступен в GitHub-репозитории, но не входит в ZIP. При первом старте плагин создаёт реальный `config.json` из встроенного шаблона. Обычно достаточно редактировать созданный файл.

### 5.1.1 Режимы Geosite DNS в линейке 2.3.x

> DNS architecture и management smoke tests введены в `v2.3.0`; defaults обновлены в `v2.3.1`; исправления надёжности DNS, Web UI и локальной security boundary включены в `v2.3.2` и перечислены в `CHANGELOG.md`.

В новой модели `dns_mode` выбирает ровно один способ обработки запросов, пришедших на DNS listener плагина:

| Значение | Поведение |
|---|---|
| `endpoint_ip` (default) | ActiveDoHSelector выбирает один DoH endpoint по восьми контрольным доменам. На A/AAAA запрос плагин отвечает IP самого выбранного DoH endpoint-а, а не IP запрошенного сайта. |
| `resolver` | Плагин разрешает исходное QNAME через список `resolver_upstreams` в заданном порядке. Это обычный DNS resolve запрошенного имени. |

Пример настройки режима 2:

```json
{
  "dns_mode": "resolver",
  "resolver_upstreams": [
    { "id": "system", "name": "System resolver (OS)", "type": "system" },
    { "id": "quad9-udp", "name": "Quad9 UDP", "type": "udp", "address": "9.9.9.9" },
    { "id": "cloudflare-tcp", "name": "Cloudflare TCP", "type": "tcp", "address": "1.1.1.1:53" },
    {
      "id": "quad9-doh",
      "name": "Quad9 DoH",
      "type": "doh",
      "url": "https://dns.quad9.net/dns-query",
      "bootstrap_ips": ["9.9.9.9"]
    }
  ]
}
```

Типы upstream-а:

- `system` — системный resolver ОС сервера; nameserver-ы читаются из `/etc/resolv.conf`.
- `udp` / `tcp` — обычный DNS upstream. `address` должен быть IP literal; порт необязателен и по умолчанию равен 53. Hostname здесь не принимается.
- `doh` — HTTPS DoH endpoint. Задаётся через `url`; `bootstrap_ips` необязателен и содержит IP literal для подключения без предварительного разрешения hostname.

Порядок объектов в `resolver_upstreams` задаёт fallback-порядок. Следующий upstream пробуется при транспортной ошибке/таймауте, SERVFAIL, REFUSED или непригодном усечённом ответе. Валидный NXDOMAIN или NOERROR/NODATA считается окончательным DNS-ответом и не маскируется следующим upstream-ом. Если все upstream-ы исчерпаны, плагин возвращает синтетический NOERROR/NODATA без SOA и не кэширует его.

Если `resolver_upstreams` отсутствует или имеет значение `null`, применяется default — один system resolver. Явный пустой массив `[]` означает, что upstream-ов нет; в режиме `resolver` запросы завершатся синтетическим NOERROR/NODATA. Чтобы отключить system resolver, укажите непустой список других upstream-ов или явно задайте нужный порядок.

`bootstrap_resolvers` — отдельная настройка для bootstrap hostname-ов DoH endpoint-ов. Она не является списком пользовательских DNS upstream-ов режима 2 и не подменяет `resolver_upstreams`.

**QTYPE и TTL:** listener плагина обслуживает A и AAAA. Другие типы DNS-запросов получают NOERROR/NODATA без SOA и без кэширования. CNAME RR, пришедшие в составе ответа на A/AAAA от upstream-а, сохраняются. В режиме `endpoint_ip` TTL ответа не превышает 60 секунд и дополнительно ограничивается остатком freshness выбранного endpoint-а. В режиме `resolver` положительный cache TTL ограничен 300 секундами; NXDOMAIN/NODATA кэшируется только при наличии SOA и с TTL по RFC 2308, ограниченным сверху 300 секундами. Первый ответ клиенту сохраняет upstream TTL, а cap применяется к отдельной копии для кэша.

#### Listener-ы и общие параметры

```json
{
  "dns_listen_udp": "127.0.0.1:5355",
  "dns_listen_tcp": "127.0.0.1:5355",
  "http_listen": "127.0.0.1:18765",
  "reload_interval_seconds": 5,
  "dns_query_timeout_seconds": 15,
  "doh_timeout_seconds": 10,
  "dns_max_concurrent": 256
}
```

| Параметр | Назначение | Ограничения/значение по умолчанию |
|---|---|---|
| `dns_listen_udp` | UDP DNS listener | `127.0.0.1:5355` |
| `dns_listen_tcp` | TCP DNS listener | `127.0.0.1:5355` |
| `http_listen` | HTTP status listener | `127.0.0.1:18765` |
| `reload_interval_seconds` | Устаревший параметр старого hot reload; сохранён для совместимости | Новые текстовые источники проверяются каждые 30 секунд |
| `dns_query_timeout_seconds` | Общий таймаут DNS-запроса | 15 секунд, диапазон 1–120 |
| `doh_timeout_seconds` | Таймаут одного DoH запроса | 10 секунд, диапазон 1–60 |
| `dns_max_concurrent` | Лимит одновременных DNS запросов | 256, диапазон 1–4096 |

**Перезапуск самого плагина требуется**, если меняются `dns_listen_udp`, `dns_listen_tcp`, `http_listen` или `dns_max_concurrent`. Остальные параметры `config.json` и оба текстовых источника применяются автоматической перезагрузкой; `doh-servers.txt` и `tst-domen.txt` проверяются каждые 30 секунд. При изменении `http_listen` также измените `health.target` в manifest и переустановите плагин, иначе probe панели продолжит обращаться к прежнему адресу.

### 5.1.2 Локальные DNS-переопределения `local-hosts.txt`

Файл управляет только локальными DNS-ответами плагина. Он не является системным hosts-файлом и не меняет `/etc/hosts`, маршрутизацию Xray, firewall или TProxy.

Формат: `hostname;IPv4[,IPv4...];IPv6[,IPv6...]`, одна запись на hostname. Пустое поле IPv4 или IPv6 допустимо; суммарно требуется хотя бы один адрес. Пример:

```text
# hostname;ipv4[,ipv4...];ipv6[,ipv6...]
nas.home.arpa;192.0.2.10;fd00::10
printer.home.arpa;192.0.2.20,192.0.2.21;
```

Поддерживаются точные DNS-имена; wildcard и произвольные пути не принимаются. Hostname нормализуется к нижнему регистру без завершающей точки. Допускается до 1000 записей и до 16 IPv4 и 16 IPv6 адресов на hostname. Проверяются корректность hostname, семейство IP и дубли. Пустые строки и строки комментариев `#` сохраняются; отключить запись можно флажком в Web UI — строка станет комментарием, не удаляясь.

При первом запуске, если `local-hosts.txt` ещё нет, существующий `local_hosts` из старого `config.json` переносится в новый файл. Если файл уже существует, он является единственным источником истины; содержимое `config.json` будет синхронизировано при загрузке/перезагрузке конфигурации.

Web UI создаёт `local-hosts.txt.bak` с правами `0600` перед атомарной заменой. Демон проверяет хэш файла вместе с остальными источниками каждые 30 секунд. Некорректное содержимое отвергается целиком: последний рабочий runtime snapshot остаётся активным, а причина отображается в status/log.

### 5.2 Health-check и ActiveDoHSelector

Обычный health monitor продолжает собирать DNS/HTTP/OIDC результаты по группам `config.json`. Он показывает состояние upstream-ов и не является тем же механизмом, что ActiveDoHSelector.

ActiveDoHSelector режима `endpoint_ip` независимо оценивает настроенные DoH endpoint-ы по восьми контрольным доменам: `chatgpt.com`, `claude.ai`, `gemini.google.com`, `elevenlabs.io`, `grok.com`, `www.perplexity.ai`, `notebooklm.google.com` и `aistudio.google.com`. Для каждого кандидата выполняются A/AAAA запросы через проверяемый DoH, затем HTTPS/TLS probes напрямую к IP сайта с исходным hostname/SNI/Host и проверкой сертификата.

Selector использует freshness, score, failure grace cycles, minimum hold и switch cooldown для снижения flapping. Системный resolver не является кандидатом ActiveDoHSelector: он может использоваться отдельно в `resolver_upstreams` режима 2.

Настройки `health.interval_seconds`, `failure_threshold` и `success_threshold` относятся к существующему health monitor и не заменяют политику ActiveDoHSelector. Новый DNS-запрос в режиме `resolver` выполняет собственный последовательный fallback по списку `resolver_upstreams`.

### 5.3 DNS cache

```json
"cache": {
  "enabled": true,
  "min_ttl_seconds": 0,
  "max_ttl_seconds": 300,
  "negative_ttl_seconds": 15,
  "max_entries": 8192,
  "max_bytes": 8388608
}
```

- `enabled`, `max_entries` и `max_bytes` управляют общим RAM-кэшем.
- В режиме `endpoint_ip` синтетические A/AAAA ответы имеют TTL не более 60 секунд и дополнительно ограничиваются остатком freshness выбранного DoH endpoint-а. Synthetic NODATA не кэшируется.
- В режиме `resolver` положительный cache TTL ограничен сверху 300 секундами; исходный TTL первого ответа upstream не изменяется.
- Для NXDOMAIN и NODATA с SOA negative TTL равен `min(SOA RR TTL, SOA.MINIMUM)`, с верхней границей 300 секунд. Это включает NODATA после CNAME chain: CNAME RR сохраняются, но срок negative-кэша конечного QNAME определяется SOA.
- Отрицательные ответы без пригодной SOA, TTL=0, SERVFAIL/REFUSED и синтетический NODATA при исчерпании upstream-ов не кэшируются. `negative_ttl_seconds` не используется как fallback TTL в режиме `resolver`.
- При чтении TTL уменьшается на прошедшее время. Пространства кэша режимов 1 и 2 независимы; generation защищают от повторного наполнения кэша старыми запросами после переключения конфигурации.

Кэш находится в RAM и очищается при перезапуске плагина. Смена выбранного DoH endpoint-а влияет на cache режима `endpoint_ip`, но сама по себе не сбрасывает cache режима `resolver`.

### 5.4 DoH endpoints и bootstrap

`doh-servers.txt` содержит настроенные upstream-ы и DoH URL в формате `стабильный_ID;HTTPS_URL`. Эти DoH URL используются существующей health-monitor моделью и как кандидаты ActiveDoHSelector режима `endpoint_ip`; системный DNS не рассматривается selector-ом как DoH endpoint.

Для каждой DoH hostname плагин получает bootstrap A/AAAA через независимые `bootstrap_resolvers` (по умолчанию `1.1.1.1` и `8.8.8.8`). Bootstrap IP нужны для соединения с DoH endpoint-ом; они не разрешают пользовательские QNAME.
`resolver_upstreams` режима `resolver` — отдельный список. Он не читается из `doh-servers.txt` и задаёт собственный упорядоченный набор `system`, `udp`, `tcp` и `doh` upstream-ов. Если поле отсутствует или равно `null`, используется один system resolver. Явный пустой массив `[]` означает, что upstream-ов нет.

Пример строк `doh-servers.txt`:

```text
# id;url
system-dns;
geohide-eu;https://eu.geohide.ru/dns-query
dagami;https://dns.dagami.ru/dns-query
comss-one;https://dns.comss.one/dns-query
bezmezhau;https://dns.bezmezhau.com/dns-query
zapret;https://dns.zapret.moe/dns-query
pereval;https://free.pereval.top/dns-query
```

Новая установка по умолчанию включает `pereval` с URL `https://free.pereval.top/dns-query`. Порядок строк по-прежнему влияет на существующие upstream groups. ActiveDoHSelector выбирает DoH endpoint по результатам контрольных DNS/HTTPS/TLS probes и своей anti-flap политике; не следует трактовать `system-dns` как fallback-кандидата selector-а.

Старый URL-only `doh-servers.txt` и hostname-based IDs поддерживают предусмотренную в проекте миграцию. Изменения конфигурации проходят валидацию и применяются через runtime snapshot.

### 5.5 Полный список health-check в `tst-domen.txt`

Файл управляет всеми параметрами проверок. Каждая строка содержит шесть полей:

`domain;qtypes;required;http_url;expected_status;verify_oidc`

Пример:

```text
# domain;qtypes;required;http_url;expected_status;verify_oidc
play.google.com;A,AAAA;0;;;0
gemini.google.com;A,AAAA;1;https://gemini.google.com/;200;0
accounts.google.com;A,AAAA;1;https://accounts.google.com/.well-known/openid-configuration;200;1
```

| Поле | Назначение |
|---|---|
| `domain` | Контрольное доменное имя |
| `qtypes` | DNS-типы через запятую: `A`, `AAAA`, `TXT`, `HTTPS`, `65` и т. д. Проверяются по порядку до первого успешного ответа |
| `required` | `1` — обязательная проверка, `0` — диагностическая |
| `http_url` | Необязательный HTTPS URL. Пустое поле означает только DNS |
| `expected_status` | Допустимые HTTP-коды через запятую, например `200,301,302`. Пустое поле означает стандартный диапазон 2xx/3xx |
| `verify_oidc` | `1` — проверить OIDC issuer в JSON discovery response, `0` — не проверять |

Пустые строки и комментарии, начинающиеся с `#`, игнорируются. Домены должны быть уникальными. HTTP URL должен использовать HTTPS и тот же hostname, что и поле `domain`. Для `verify_oidc=1` URL должен оканчиваться на `/.well-known/openid-configuration`.

**HTTP выполняется только при непустом `http_url`.** Флаг `required` не включает и не выключает саму пробу: он определяет только влияние результата на общий статус upstream. Ошибка необязательной DNS/HTTP-проверки видна в диагностике, но не переводит upstream в `down`.

Встроенный шаблон содержит десять проверок: восемь фиксированных доменов ActiveDoHSelector (`chatgpt.com`, `claude.ai`, `gemini.google.com`, `elevenlabs.io`, `grok.com`, `www.perplexity.ai`, `notebooklm.google.com`, `aistudio.google.com`), отдельный `accounts.google.com` для OIDC и дополнительный обязательный `notebook.google.com`. Для `notebook.google.com` выполняются A/AAAA и HTTPS-проверка `https://notebook.google.com/` с ожидаемым HTTP 200. Обязательны HTTP-проверки Gemini, Notebook и OIDC Google Accounts; остальные семь строк служат DNS-диагностикой. Сам ActiveDoHSelector использует свои восемь доменов непосредственно из кода и не читает `tst-domen.txt`.

### 5.6 Автоматическое создание, контроль изменений и config.json

Встроенные шаблоны `defaults/doh-servers.txt` и `defaults/tst-domen.txt` упакованы в бинарник. При первой установке они создают в `$LUCX_PLUGIN_DATA` списки с upstream `pereval;https://free.pereval.top/dns-query` и обязательной A/AAAA + HTTPS-проверкой `notebook.google.com` (HTTP 200). Если файл уже существует, его пользовательское содержимое сохраняется и используется: обновление плагина не добавляет новые строки автоматически и не перезаписывает операторский список. Повреждённый существующий файл также не заменяется шаблоном автоматически. Чтобы получить новые defaults на уже установленной системе, добавьте строки вручную через Web UI или в соответствующие файлы.

При запуске и затем каждые 30 секунд плагин рассчитывает SHA-256 обоих файлов. Хэши хранятся только в оперативной памяти процесса — отдельного checksum-файла нет. При изменении содержимого плагин проверяет оба файла, формирует новые `upstreams`, `groups[].upstreams` и `groups[].checks`, атомарно записывает сгенерированный `config.json` и применяет новый runtime-снимок без остановки DNS-процесса.

Если любой файл имеет неверный формат или новая конфигурация не проходит проверку, она целиком отклоняется. Пользовательские файлы не перезаписываются, а DNS продолжает работать на последнем успешно применённом снимке. Одинаковая ошибка журнала не повторяется каждые 30 секунд; новая попытка выполняется после следующего изменения файлов или исправления конфигурации.

Остальные настройки `config.json` не генерируются из текстовых файлов и сохраняются при каждом обновлении. Ручное редактирование управляемых полей `upstreams`, `groups[].upstreams` и `groups[].checks` не рекомендуется: при следующей генерации их содержимое будет заменено источниками `doh-servers.txt` и `tst-domen.txt`.

### 5.7 Необязательная проверка Gemini API

Встроенная проверка генерации полностью выключена по умолчанию:

```json
"gemini_api": {
  "enabled": false,
  "required_for_group": false,
  "group_id": "google",
  "model": "gemini-3.8-flash",
  "interval_seconds": 1800,
  "key_file": "gemini_api_key",
  "prompt": "Reply with exactly OK.",
  "max_output_tokens": 8
}
```

Чтобы включить:

1. Создайте Gemini API key в Google AI Studio: <https://aistudio.google.com/api-keys>.
2. Убедитесь, что ключу разрешено вызывать Gemini API; не вставляйте его в JSON.
3. Создайте файл `$LUCX_PLUGIN_DATA/gemini_api_key`, содержащий только ключ, без кавычек и перевода строки. Права файла — `600`, владелец должен совпадать с пользователем процесса плагина.
4. В `config.json` установите `"enabled": true`.
5. Проверьте `group_id`, `model`, `interval_seconds`; перезапустите плагин, если одновременно меняли listener или хотите немедленно применить ключ. Обычный `config.json` перечитывается автоматически.

Параметры:

- `enabled` — главный флаг. При `false` ключ не читается и запросы Gemini API не выполняются.
- `required_for_group` — если `true`, сетевые/серверные ошибки Gemini API учитываются в health state Google-группы. Ошибки ключа/прав (`401/403`) и квоты (`429`) не объявляются отказом DNS upstream.
- `group_id` — группа, к которой привязать проверку.
- `model` — имя модели Gemini API.
- `interval_seconds` — минимальный интервал проверки для каждого DoH upstream, не менее 60 секунд.
- `key_file` — относительный путь внутри `LUCX_PLUGIN_DATA`; абсолютные пути и выход за каталог запрещены.
- `prompt` — короткий тестовый prompt.
- `max_output_tokens` — лимит ответа.

Тестовая генерация расходует квоту/токены API. Уменьшайте частоту проверок с учётом количества upstream. Если `required_for_group=false`, результат API виден в `/status` и логах, но сам по себе не переключает DNS.

**Без API:** оставьте `enabled:false`; удалять другие поля не нужно. Ключ создавать не требуется.

## 6. Подключение к панели / Xray

**Нормативная схема и полный пример JSON приведены в [doc/GEOSITE-DNS-ROUTING-DESIGN.md, §4.4](doc/GEOSITE-DNS-ROUTING-DESIGN.md).**

Для утверждённой схемы DNS path такой:

1. Клиентский WireGuard/TProxy inbound передаёт DNS-трафик в Xray. В примере конфигурации из §4.4 пользовательский inbound не показан; inbound `api` на `127.0.0.1:62789` относится к Xray API панели и не заменяет клиентский inbound. Клиентский path-level smoke test через sing-box → AWG → VPS TProxy уже выполнен для `habr.com` и `example.com`; наблюдения и ограничения доказанного приведены в design doc §8.
2. Routing rule `network: tcp,udp`, `port: 53` направляет DNS-пакеты в outbound `dns-out`. Это правило стоит до общего `geoip:private` block.
3. В `dns-out.settings.rules` правило с `action: direct` и непустым `domain` направляет совпавшие QNAME на rewrite target `127.0.0.1:5355`. Значения `domain` определяются политикой оператора; `geosite:habr` в design doc — пример, а не жёстко зашитое требование checker-а.
4. `rewriteNetwork: udp` задаёт UDP на локальном участке Xray DNS outbound → plugin listener. Это отдельный участок, не внешний транспорт WireGuard/TProxy.
5. Catch-all `action: hijack` передаёт все остальные QNAME встроенному DNS Xray, upstream которого задан в `dns.servers` (в утверждённом JSON — Quad9 DoH `https://9.9.9.9/dns-query`).

**Не добавляйте** `127.0.0.1:5355` в `dns.servers`, `xui-dns-allow` в `routing.rules`, отдельный маршрут для порта 5355 или исключение в `direct.settings.finalRules`. Действие `direct` внутри DNS outbound пересылает пакет на rewrite target; это не `freedom` outbound и не проходит через `freedom.finalRules`.

### Проверка утверждённой схемы

Пункт 1 SSH-меню запускает read-only checker. Он проверяет:
- ровно одно глобальное TCP/UDP port-53 routing rule, направленное в DNS outbound;
- DNS outbound с UDP rewrite на plugin listener;
- наличие хотя бы одного DNS rule с `action: "direct"` и непустым массивом `domain`; все найденные значения `domain` выводятся в отчёт. Конкретная категория, число и порядок DNS rules, а также catch-all action checker-ом не фиксируются;
- порядок port-53 rule перед `geoip:private` block, если такой block присутствует;
- хотя бы одного upstream в `dns.servers` для встроенного DNS Xray;
- отсутствие plugin listener в `dns.servers`;
- текущий DNS mode из Status API и, для `endpoint_ip`, ID/hostname/IP/score активного DoH endpoint-а. URL endpoint-а не выводится.

Checker не изменяет конфигурацию. Он остаётся структурной проверкой и сам по себе не доказывает наличие категории в реально загруженном Geosite asset или точное внутреннее решение Xray matcher-а. Клиентские path-level smoke tests через sing-box → AWG → VPS TProxy уже выполнены для `habr.com` и `example.com`; результаты и границы доказанного приведены в [design doc §8](doc/GEOSITE-DNS-ROUTING-DESIGN.md).

### Отключённые операции изменения Xray

Команды CLI `integrate` и `remove`, panel API adapter, admin-token minting, Xray planner и диагностический Tunnel lifecycle удалены из исходников плагина. Прямой вызов устаревших CLI-директив отклоняется; Web UI mutation endpoint отвечает HTTP 410 Gone. Xray Geosite DNS rules настраиваются вручную по утверждённой схеме; бинарник плагина выполняет только read-only preflight и не изменяет панель/Xray.

Изменения Xray выполняются только вручную по §4.4. Автоматизация будет отдельной задачей после end-to-end проверки и отдельного проектирования безопасного planner-а.

Для режима `endpoint_ip` плагин возвращает bootstrap IP выбранного DoH endpoint-а. Для режима `resolver` плагин разрешает исходный QNAME через отдельный `resolver_upstreams`. В обоих случаях эта логика применяется только к запросам, которые Xray направил через Geosite `direct` на локальный listener плагина.

Подробные ограничения QTYPE, cache/TTL, DNS loop checks и результаты приёмочных проверок описаны в design doc §4.4 и §9.

## 7. Проверка работы

### 7.1 Health endpoint

```bash
curl -i http://127.0.0.1:18765/healthz
```

Ожидается `HTTP 200` и текст `ok`.

### 7.2 Подробный статус

```bash
curl -s http://127.0.0.1:18765/status | jq .
```

Смотрите:

- `groups` — состояние существующего health monitor и выбранный `active_upstream` группы; это не ActiveDoHSelector;
- health state `up`, `down`, `unknown`;
- `failure_streak` / `success_streak`;
- `checks` — DNS/HTTP результаты отдельных контрольных точек;
- `last_error`, `check_duration_ms` — длительность всего цикла проверок данного upstream, а не время одного DNS-запроса;
- `active_doh` — выбранный endpoint режима `endpoint_ip`, его IP, freshness, score и generation; `queries`, `cache_hits`, `failures` — счётчики DNS работы;
- `active_udp`, `udp_queue_depth`, `udp_dropped`, `active_tcp`, `tcp_rejected` — текущая нагрузка и отказы при переполнении ограниченных очередей/соединений;
- `goroutines`, `heap_alloc_bytes`, `heap_inuse_bytes`, `heap_sys_bytes` — показатели runtime Go;
- `cpu_user_ns`, `cpu_system_ns` — накопленное CPU-время процесса в user/system mode; разница между двумя замерами за интервал позволяет оценить использование CPU;
- `cache.bytes` и `cache.max_bytes` — фактический размер и предел DNS-кэша.
- `gemini_api` — состояние необязательной Gemini API проверки.

### 7.3 Проверка локального DNS по UDP

Установите `dnsutils` (Debian):

```bash
sudo apt-get update
sudo apt-get install -y dnsutils
```

Затем:

```bash
dig @127.0.0.1 -p 5355 example.com A +time=5 +tries=1
dig @127.0.0.1 -p 5355 example.com AAAA +time=5 +tries=1
dig @127.0.0.1 -p 5355 google.com HTTPS +time=5 +tries=1
```

В режиме `endpoint_ip` ответ содержит IP выбранного DoH endpoint-а. В режиме `resolver` возвращается адрес исходного QNAME через выбранный `resolver_upstreams`. Запросы HTTPS/SVCB и другие QTYPE вне A/AAAA возвращают `NOERROR`/NODATA.

### 7.4 Проверка TCP DNS

```bash
dig +tcp @127.0.0.1 -p 5355 example.com A +time=5 +tries=1
```

### 7.5 Проверка реального DNS пути через Xray

Проверьте на клиенте, что его DNS направлен в Xray inbound, затем посмотрите результат разрешения и логи Xray. Убедитесь, что выбранные в панели DNS-запросы действительно доходят до локального listener `127.0.0.1:5355`.

### 7.6 Проверка failover

Не проверяйте failover блокировкой публичного DoH на рабочем сервере без резервного доступа. Для безопасного теста используйте тестовую копию конфигурации или временный отдельный upstream с неверным/нерабочим URL и его bootstrap. Убедитесь, что:

1. `/status` показывает проблему конкретного upstream;
2. после `failure_threshold` неудачных циклов он помечается `down`;
3. новый DNS запрос пробует следующий upstream из списка `google.upstreams`;
4. после `success_threshold` успешных циклов сервер снова появляется как `up`.
### 7.7 Проверка изменения настроек

- Измените URL в строке `doh-servers.txt`, не меняя стабильный ID; добавление и удаление провайдеров также выполняются только через этот файл.
- Измените строку или параметр в `tst-domen.txt`; в течение 30 секунд после проверки источников в журнале должна появиться `CONFIG reloaded`.
- Если один из текстовых файлов ошибочный, плагин отклонит всю новую конфигурацию, сохранит предыдущий runtime и запишет ошибку один раз для данного содержимого.

## 8. Журналы и диагностика

Плагин пишет только в stdout/stderr; LucX-UI собирает это в `plugin.log`. Смотрите лог карточки плагина или файл журнала, путь к которому показывает ваша версия панели.

Частые случаи:

| Сообщение/симптом | Причина / действие |
|---|---|
| `address already in use` | Порт UDP/TCP 5355 или HTTP 18765 занят; выберите свободные loopback порты в config и обновите outbound/manifest health target соответственно |
| Ошибка разбора `doh-servers.txt` | Проверьте формат `ID;https://host/dns-query`, уникальность ID и HTTPS URL |
| Ошибка разбора `tst-domen.txt` | Проверьте шесть полей в строке, qtypes, флаги 0/1 и HTTP URL |
| `all upstreams failed` | Проверьте nameserver-ы из `/etc/resolv.conf` по UDP/TCP 53, `bootstrap_resolvers`, HTTPS egress VPS, резервные `bootstrap_ips` (если заданы), URL/путь DoH, TLS и доступность провайдера |
| HTTP `401/403` на контрольном URL | Может быть блокировка/авторизация; задайте правильный `expected_status` или `required:false`, если это не индикатор полного отказа |
| `/healthz` OK, но DNS не отвечает | Смотрите `/status`, `plugin.log`, занят ли порт, совпадает ли `rewritePort` Xray с `dns_listen_udp/tcp` |
| DNS через Xray возвращает пустой ответ для TXT/MX/HTTPS | Для QTYPE вне A/AAAA `NOERROR`/NODATA ожидаем. Проверьте catch-all `hijack` и совместимость конкретной встроенной версии Xray; если проблема с A/AAAA, проверьте Geosite rule и rewrite target `127.0.0.1:5355`. |

## 9. Безопасность

- DNS и HTTP listeners по умолчанию слушают только `127.0.0.1`.
- Не публикуйте `5355`/`18765` на внешнем интерфейсе.
- Не устанавливайте `permissions.network: ["none"]`: это изолирует сетевой namespace и лишит DoH возможности работать.
- Не добавляйте `panelApi`: доступ к служебным Xray API не нужен и контрактом не разрешён.
- `gemini_api_key` не логируется и должен иметь права `600`.
- Не кладите секреты в JSON, manifest, командную строку или тикеты.
- Не отключайте TLS-сертификат verification. Плагин подключается к bootstrap IP, но проверяет сертификат на hostname DoH endpoint.
- Sidecar ограничен собственным `$LUCX_PLUGIN_DATA`; при правильном runner каталоги системы остаются read-only.

## 10. Остановка, откат и удаление

### Откат DNS до старой конфигурации

1. Верните Xray `dns-out` rewrite target/port на адрес и порт ранее использовавшегося DNS-сервиса, если он доступен.
2. Верните прежние правила `dns-out`/routing, если они были заменены.
3. Проверьте итоговый Xray конфиг и примените его через LucX-UI.
4. Только после проверки остановите/удалите sidecar.

### Удаление и повторная установка

1. Сначала восстановите или подтвердите рабочую DNS конфигурацию Xray без sidecar.
2. Остановите плагин в LucX-UI.
3. Удалите плагин через менеджер плагинов.

При удалении плагина LucX-UI удаляет и его каталог данных `LUCX_PLUGIN_DATA`, включая `config.json`, `doh-servers.txt`, `tst-domen.txt` и `gemini_api_key`. Это означает, что повторная установка начинается с чистого состояния: при первом запуске создаются новый `config.json` со встроенными настройками (автоматический bootstrap включён по умолчанию) новые `doh-servers.txt` и `tst-domen.txt`. Пользовательские настройки и ключ Gemini не сохраняются автоматически.

Перед удалением сохраните копии файлов, которые понадобятся после переустановки. Восстанавливая старый `config.json`, помните, что его `bootstrap_ips` останутся совместимыми и будут использоваться как резервные адреса, а автоматическое разрешение через `bootstrap_resolvers` продолжит работать.

## 11. Сборка из исходников

Исходный архив распространяется отдельно от установочного ZIP. Для сборки `linux/amd64` с Go:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" \
  -o bin/doh-health-monitor .
```

Тесты и статический анализ:

```bash
go test -race ./...
go vet ./...
```

**Автоматические проверки release candidate 2.3.2:**
- GitHub Actions CI: module tidy, shell/JavaScript syntax, management helper tests, DNS checker tests, `go vet ./...`, `go test ./...`, `go test -race ./...` и Linux amd64 package build.
- Устаревшие panel mutation helpers, planner/diagnostics, admin-token minting и SQLite dependency удалены; sidecar содержит только read-only plugin preflight, не меняющий LucX-UI/Xray.
- Регрессионные тесты охватывают анонимный доступ к Web UI, одноразовый bootstrap token, listener validation, Gemini key path, DoH URL redaction, resolver SERVFAIL/cooldown, ActiveDoH hard-failure failover, EDNS-aware UDP truncation, DNS error packet shape, OIDC URL validation, reload interval, pending restart semantics, status redaction, bootstrap public-IP filtering и symlinked configuration sources.
- Эти проверки выполнены в GitHub Actions. Новый VPS release smoke test для `v2.3.2` оставлен перед публикацией; тесты на установленном релизном ZIP будут выполнены отдельно.

## 12. Ограничения текущей реализации

- В ZIP собран только `amd64`. Для ARM64 нужен отдельный бинарник и `architectures: ["arm64"]` в manifest.
- DNS cache находится в RAM.
- HTTP health-check закрепляет запрос на один A IP, полученный через проверяемый DoH. Это диагностическая проба, а не полное эмулирование браузера.
- Плагин не гарантирует доступность всех URL/функций Google по проверке нескольких контрольных точек.
- Поля `domains` и `fake_dns` старых конфигураций больше не участвуют в выборе upstream; FakeDNS настраивается отдельно в Xray.
- Переключение ActiveDoH endpoint-а в режиме `endpoint_ip` не требует перезапуска Xray; уже выданные DNS-ответы нельзя отозвать, поэтому их TTL ограничен 60 секундами.
- В режиме `resolver` системный resolver читает `/etc/resolv.conf`; защита от прямого совпадения с plugin listener не покрывает произвольные stub/TProxy/NAT цепочки.
- Перед внедрением Geosite DNS rules проверьте их на конкретной версии embedded Xray и в namespace панели.
- Перед применением объединённых Xray JSON fragments всегда проверьте их на конкретной версии Xray-core и сохраните предыдущий конфиг.

## 13. Ссылки на документацию

- [Xray DNS outbound](https://xtls.github.io/en/config/outbounds/dns.html)
- [Xray built-in DNS](https://xtls.github.io/en/config/dns)
- [Xray FakeDNS](https://xtls.github.io/en/config/fakedns.html)
- [LucX-UI sidecar plugin contract](https://raw.githubusercontent.com/AlexeyLCP/lucx-ui/refs/heads/main/docs/plugin-sidecars.md)
- [LucX-UI plugin manager](https://raw.githubusercontent.com/AlexeyLCP/lucx-ui/refs/heads/main/docs/plugin-manager.md)
- [Google AI Studio API keys](https://aistudio.google.com/api-keys)


## 14. Локальные DNS-переопределения: `local-hosts.txt`

`local-hosts.txt` — отдельный управляемый источник точных локальных DNS-переопределений плагина. Это **не** системный файл `/etc/hosts`: плагин не читает и не изменяет `/etc/hosts`, не редактирует Xray routing, firewall или TProxy.

### Формат файла

Файл находится в `$LUCX_PLUGIN_DATA/local-hosts.txt`. Одна строка соответствует одному hostname:

```text
# hostname;ipv4[,ipv4...];ipv6[,ipv6...]
panel.example.com;203.0.113.10;2001:db8::10
api.example.com;203.0.113.11;
blocked.example.com;;
```

- Первое поле — полное DNS-имя. Wildcard (`*.example.com`) не поддерживаются.
- Второе поле — один или несколько IPv4 через запятую.
- Третье поле — один или несколько IPv6 через запятую.
- Одно из полей адресов или оба могут быть пустыми. Пустая пара адресов позволяет явно возвращать NODATA для A/AAAA этого точного имени.
- Имена приводятся к нижнему регистру; завершающая точка игнорируется. Повторяющиеся имена после нормализации запрещены.
- IPv4 и IPv6 проверяются независимо. Максимум — 1000 hostname-записей, до 16 адресов каждого семейства на запись.
- Пустые строки и строки, начинающиеся с `#`, считаются комментариями. Флажок в Web UI отключает строку, сохраняя её как комментарий.

### Миграция старых настроек

Если `local-hosts.txt` ещё отсутствует, при первом старте плагин один раз переносит существующий объект `local_hosts` из `config.json` в новый файл. Если `local-hosts.txt` уже есть, он является источником истины и при старте/перезагрузке его содержимое отражается в генерируемом поле `local_hosts` файла `config.json`. Ручное редактирование `config.json` для локальных DNS-записей больше не требуется.

### Редактирование и применение

1. Откройте Web UI через SSH-меню и перейдите на вкладку **Local hosts**.
2. Добавьте hostname, IPv4/IPv6 либо отключите или удалите строку.
3. Нажмите **Сохранить hosts**. Backend проверит каждую запись и весь файл до записи.
4. Перед атомарной заменой создаётся `local-hosts.txt.bak` с правами `0600`. Lock `config.json.lock` сериализует сохранение с daemon reload и другими config writes.
5. Валидные изменения применяются автоматически в течение 30 секунд. При ошибке новый runtime snapshot отклоняется, предыдущая рабочая конфигурация продолжает обслуживать DNS.

### DNS-поведение

Для точного hostname из файла:

| Запрос | Поведение |
|---|---|
| `A` | Возвращаются только IPv4 из строки |
| `AAAA` | Возвращаются только IPv6 из строки |
| `A` при пустом IPv4 | `NOERROR`/NODATA |
| `AAAA` при пустом IPv6 | `NOERROR`/NODATA |
| `HTTPS` / `SVCB` | Локальный handler перехватывает запрос и отвечает NODATA; address hints и ECH не создаются |

Локальные ответы не устанавливают DNS AD. Клиенты с обязательной собственной DNSSEC-валидацией могут отклонять неподписанные локальные данные. Для имён, отсутствующих в файле, работает обычный выбранный `dns_mode` (`endpoint_ip` или `resolver`). Локальная DNS-запись не определяет маршрут последующего IP-трафика: необходимое поведение Xray/прокси настраивается отдельно.

### Проверка через dig

После добавления примера выше выполните на VPS:

```bash
dig @127.0.0.1 -p 5355 panel.example.com A
dig @127.0.0.1 -p 5355 panel.example.com AAAA
dig @127.0.0.1 -p 5355 panel.example.com HTTPS
dig @127.0.0.1 -p 5355 panel.example.com SVCB
```

Для A/AAAA должны вернуться только заданные адреса соответствующего семейства. HTTPS/SVCB для перечисленного hostname должны вернуть NODATA. Проверку можно повторить по TCP, добавив `+tcp`.

Диапазоны `203.0.113.0/24`, `198.51.100.0/24` и `2001:db8::/32` зарезервированы для документации и не предназначены для реального подключения.
