# DoH DNS Proxy & Health Monitor для LucX-UI

**Версия:** 2.3.0 (release candidate в `feature/geosite-dns-routing`; релиз ещё не опубликован)  
**Платформа:** Linux x86-64 (`amd64`), статический Go-бинарник  
**Тип:** LucX-UI sidecar, `apiVersion: 1`  
**Режим Gemini API:** необязательный, управляется параметром `gemini_api.enabled`

# DoH DNS Proxy & Health Monitor для LucX-UI

**Версия:** 2.3.0 (release candidate в `feature/geosite-dns-routing`; релиз ещё не опубликован)  
**Платформа:** Linux x86-64 (`amd64`), статический Go-бинарник  
**Тип:** LucX-UI sidecar, `apiVersion: 1`  
**Режим Gemini API:** необязательный, управляется параметром `gemini_api.enabled`

## 1. Назначение

DoH Health Monitor — локальный DNS sidecar для LucX-UI/Xray. В версии 2.3.0 обработка Geosite DNS-потока разделена между Xray и плагином: Xray сопоставляет QNAME с Geosite и выбирает DNS-ветку, а плагин обслуживает только те запросы, которые Xray направляет в его DNS listener. В самом плагине нет собственного Geosite matcher и динамического Auto Hosts списка.

Плагин поддерживает два взаимоисключающих режима обработки A/AAAA запросов:

- **`endpoint_ip` (режим по умолчанию):** ActiveDoHSelector выбирает один доступный DoH endpoint по восьми контрольным доменам. Для DNS-запроса плагин возвращает bootstrap IP выбранного DoH endpoint-а, а не IP запрошенного сайта. Это режим для схемы, где дальнейшее назначение трафика определяет Xray.
- **`resolver`:** плагин разрешает исходное имя запроса через независимый упорядоченный список `resolver_upstreams`. По умолчанию используется системный resolver ОС сервера; можно настроить UDP, TCP и DoH upstream-ы.

Пользовательский DNS listener принимает запросы типов A и AAAA. Другие QTYPE (включая HTTPS/SVCB, MX и TXT) возвращают `NOERROR`/NODATA без SOA и без кэширования. CNAME RR в составе ответа upstream на A/AAAA сохраняются.

`bootstrap_resolvers` и `resolver_upstreams` — разные настройки: первые разрешают hostname DoH endpoint-ов для исходящих соединений самого плагина, вторые выполняют обычный DNS resolve пользовательского QNAME только в режиме `resolver`.

### Что умеет

- UDP и TCP DNS listener по умолчанию на `127.0.0.1:5355`.
- ActiveDoHSelector: восемь контрольных доменов, A/AAAA DNS probes через кандидатов DoH, затем HTTPS/TLS probes по IP с исходными hostname, SNI, HTTP Host и проверкой сертификата.
- Отдельный режим `endpoint_ip` с TTL до 60 секунд, ограниченным временем актуальности выбранного endpoint-а.
- Режим `resolver` с последовательным fallback через system, UDP, TCP и DoH upstream-ы.
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

- Не загружает и не разбирает Geosite assets, не поддерживает собственный matcher и не ведёт Auto Hosts/QNAME database.
- Не определяет по одному DNS-пакету, какое правило Xray совпало; разделение потоков должно произойти до передачи пакета listener-у.
- Не обслуживает отдельные QTYPE HTTPS/SVCB, MX, TXT и другие типы; для них listener возвращает NODATA.
- Не выполняет полноценную DNSSEC validation и не устанавливает AD в синтетических ответах.
- Не меняет Xray DNS policy при обычном запуске daemon. Geosite rules в целевой конфигурации Xray настраиваются вручную; автоматизация панели для этой схемы отложена до интеграционной проверки.
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
└── tst-domen.txt     # DNS/HTTP health-check настройки, одна проверка на строку
```

Если `gemini_api.enabled` включён, дополнительно создайте:

```text
$LUCX_PLUGIN_DATA/gemini_api_key
```

Вся изменяемая информация хранится только в `LUCX_PLUGIN_DATA`. Плагин не должен писать в каталог бинарника, `/etc`, `/tmp` или другие места.

## 4. Установка в LucX-UI

1. Для опубликованного релиза скачайте ZIP с соответствующим номером версии. Для подготовленной в этой ветке версии имя пакета — `doh-health-monitor-v2.3.0.zip`; скачать его со страницы Releases можно будет только после слияния PR и публикации тега `v2.3.0`.
2. В LucX-UI откройте менеджер плагинов и установите ZIP.
3. Запустите плагин из панели.
4. При первом запуске плагин создаст `config.json`, `doh-servers.txt` и `tst-domen.txt` из встроенных шаблонов. Уже существующие текстовые файлы не перезаписываются (старый URL-only список DoH автоматически мигрирует в новый формат).
5. Посмотрите журнал плагина. Нормальный старт содержит строки примерно такого вида:

```text
level=INFO START id=doh-health-monitor version=2.3.0 arch=amd64 data=...
level=INFO CONFIG loaded ... gemini_api=false
level=INFO EVENT_SOCKET listening ...
level=INFO READY DNS=127.0.0.1:5355/127.0.0.1:5355 HTTP=127.0.0.1:18765
```

6. Запустите Web UI через SSH-меню и откройте его по адресу локального SSH-туннеля. В интерфейсе доступны редакторы поддерживаемых параметров `config.json`, `doh-servers.txt` и `tst-domen.txt`. Записи `local_hosts` пока не имеют отдельного редактора и настраиваются непосредственно в `config.json`.

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
bash <(curl -fsSL https://raw.githubusercontent.com/agentnht/doh-health-monitor/main/scripts/plugin-management.sh)
```

Этот способ по-прежнему работает, но скрипт поступает через process substitution и не имеет постоянного файлового пути, поэтому симлинк `dhm` при таком запуске не создаётся. Для этого варианта требуется `curl`; read-only checker при необходимости загружается из GitHub. Для локального пакетного варианта checker уже включён в ZIP и используется без дополнительной загрузки.

Если вы подключились не под root, сначала выполните `sudo -i`, затем запустите выбранный вариант.

Меню предоставляет следующие действия:

1. **Интегрировать DNS в LucX-UI / Xray** — явный запуск операции `integrate` с подтверждением.
2. **Удалить DNS-интеграцию** — явный запуск `remove` с подтверждением.
3. **Проверить состояние** — read-only диагностика плагина и DNS-интеграции.
4. **Запустить Web UI** — интерактивный интерфейс управления и диагностики, доступный через SSH-туннель.
0. **Выход**.

Web UI содержит:
- **Конфигурация** — редактор поддерживаемых параметров listeners, таймаутов, health, cache, bootstrap resolvers и Gemini API; для изменения listener-портов интерфейс сообщает о необходимости перезапуска.
- **DoH-сервера** и **Домены** — редакторы `doh-servers.txt` и `tst-domen.txt`, сохраняющие порядок строк и состояние включения/отключения. Изменения проходят валидацию и автоматически применяются демоном после обнаружения файловых изменений.
- **Проверка состояния** — проверки конфигурации, файлов, портов и реальные DNS-запросы к настроенному UDP listener с отображением домена, типа записи, ответа и времени.
- **Логи** — ограниченный просмотр журнала плагина и отдельный журнал операций Integrate/Remove.
- **Integrate / DeIntegrate** — запуск существующих операций Go после явного подтверждения.

Каждый Web UI API-запрос требует сессионную cookie; дополнительно проверяются Host/Origin. Интерфейс слушает только loopback и предназначен для доступа через SSH local port forwarding. Ключ Gemini сохраняется в отдельный файл с правами `0600`, его содержимое не возвращается браузеру.

При запуске Web UI меню напечатает готовую SSH-команду для Windows PowerShell и локальный URL для браузера. Оставьте открытыми управляющую SSH-сессию и отдельную сессию туннеля. Нажмите Enter в управляющей сессии, чтобы остановить Web UI и вернуться в меню; при закрытии SSH-сессии Web UI также завершается.

Скрипт рассчитан на уже установленный плагин. Он не устанавливает и не обновляет сам плагин, не открывает порты в firewall и не изменяет UFW.

### Требования по архитектуре и сети

- Этот ZIP содержит бинарник только `linux/amd64`.
- `permissions.network` пустой массив: плагину разрешена сеть для DoH и HTTPS health-check. Не устанавливайте `network: ["none"]`.
- `panelApi` grant не запрашивается: scoped-токен плагина не имеет доступа к `/xray/`; только явные `integrate`/`remove` используют локальный admin credential, получаемый в момент выполнения команды.
- Listener-ы по умолчанию привязаны только к `127.0.0.1`.

## 5. Конфигурация плагина

### 5.1 `config.json`

Это генерируемый рабочий файл. Плагин обновляет из текстовых источников только `upstreams`, `groups[].upstreams` и `groups[].checks`; остальные настройки — DNS listeners, Bootstrap DNS, резервные IP, тайминги, пороги, кэш, `local_hosts`, Gemini API и флаг интеграции — сохраняются. Поле `integration` управляется командами Go CLI.

Образец `examples/config.example.json` доступен в GitHub-репозитории, но не входит в ZIP. При первом старте плагин создаёт реальный `config.json` из встроенного шаблона. Обычно достаточно редактировать созданный файл.

### 5.1.1 Режимы Geosite DNS в версии 2.3.0

> **Статус версии:** схема и код версии 2.3.0 находятся в ветке `feature/geosite-dns-routing` и Draft [PR #11](https://github.com/agentnht/doh-health-monitor/pull/11). Ветка содержит `manifest.json` и бинарный version string `2.3.0`, но официальный GitHub Release/tag `v2.3.0` ещё не опубликован. Не устанавливайте эту ветку в production до прохождения интеграционных проверок и публикации релиза.

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
```

Порядок строк по-прежнему влияет на существующие upstream groups. ActiveDoHSelector выбирает DoH endpoint по результатам контрольных DNS/HTTPS/TLS probes и своей anti-flap политике; не следует трактовать `system-dns` как fallback-кандидата selector-а.

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

Первоначальный встроенный файл содержит 25 контрольных доменов. Обязательны Gemini и Google Accounts (включая OIDC issuer); остальные проверки диагностические. Две прежние необязательные HTTP-пробы корневых URL `ssl.gstatic.com` и `www.googleapis.com` удалены: для них оставлена DNS-проверка, без ожидаемого 404.

### 5.6 Автоматическое создание, контроль изменений и config.json

Встроенные шаблоны `defaults/doh-servers.txt` и `defaults/tst-domen.txt` упакованы в бинарник. Если соответствующего файла нет, он создаётся в `$LUCX_PLUGIN_DATA` из встроенного шаблона. Если файл уже существует, его пользовательское содержимое сохраняется и используется. Повреждённый существующий файл не заменяется шаблоном автоматически.

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

DNS-шлюз плагина доступен по адресу:

- UDP: `127.0.0.1:5355`
- TCP: `127.0.0.1:5355`

В панели/Xray укажите этот адрес как DNS upstream для тех запросов, которые должны проходить через выбранный Google DoH. Панель самостоятельно определяет, какие домены, назначения или правила используют этот upstream.

Плагин не требует передачи ему routing rules, не знает о них и не использует QNAME для маршрутизации. Не нужно добавлять контрольные домены в FakeDNS whitelist или синхронизировать их с `groups[].domains`: такого механизма в шлюзе больше нет.

Если в вашей конфигурации Xray используется FakeDNS, настройка FakeDNS остаётся независимой задачей Xray. Плагин не создаёт fake IP и не меняет FakeDNS pool. Убедитесь, что запросы, которые должны пройти через DoH, действительно направляются на `127.0.0.1:5355`, а не перехватываются FakeDNS или другим DNS upstream.

При переключении активного DoH-сервера перезапуск Xray не требуется: адрес локального шлюза не меняется.

### Проверка и директивы API-адаптера

Пользовательский CLI предоставляет только постоянные директивы `integrate` и `remove`; диагностический Tunnel создаётся, проверяется и очищается автоматически внутри `integrate`. Флаг `--plan-only` в пользовательском CLI отсутствует.

Фактический `integrate` сначала проверяет DoH Health Monitor (systemd-службу, TCP/UDP listener на `127.0.0.1:5355` и локальный `/status`), затем одним чтением получает конфигурацию панели, строит план и применяет только недостающие постоянные DNS-объекты. После этого он создаёт диагностический loopback-only Tunnel, если его ещё нет, и выполняет положительные DNS A-запросы по UDP и TCP. После попытки self-test `integrate` выполняет очистку диагностических ресурсов и при успехе, и при ошибке теста. Для каждого inbound и `finalRule` проверяется внешнее использование в live-конфигурации: неиспользуемый вне диагностического плана объект удаляется, используемый или неоднозначный сохраняется. Маркеры `added/reused` и факт прежнего существования не определяют владение. Если Tunnel уже существует, команда проверяет его, не создавая второй.

`remove` не требует работающего плагина и работает только с постоянным DNS-планом: выбирает соответствующие маршрут, outbound и DNS server, проверяет внешние ссылки и удаляет только безопасные ресурсы одной записью через API панели. Он не анализирует и не изменяет inbound или `direct.settings.finalRules`: это диагностические ресурсы, которые обязан очищать `integrate` после self-test. Если они остались, это ошибка диагностической очистки, а не задача `remove`. Возможный автоматический перезапуск Xray панелью выводится как NOTICE; отдельного подтверждения нет. При нестандартной установке можно передать `--plugin-service`, `--plugin-status-url` и `--plugin-port`.

Если `--base-url` не передан, адаптер автоматически определяет локальный адрес панели по настройкам `webPort`, `webBasePath`, TLS-сертификату и `webDomain`. Для этого он читает только необходимые строки SQLite в режиме `mode=ro`; база не изменяется. Runtime-переопределение `XUI_PORT` учитывается. Само значение web base path не печатается. При PostgreSQL или нестандартном размещении можно явно передать `--base-url` (для другого SQLite-файла — `--panel-db`).

Совместимость определяется по фактическому ответу API и структуре конфигурации, а не по номерам версий LucX-UI или Xray: адаптер проверяет доступность endpoint настроек Xray, структуру `xraySetting`, метаданные `outboundTestUrl` и поддерживаемую структуру конфигурации. Неизвестный формат — причина остановки. Изменения применяются только после построения плана без блокирующих конфликтов; результат каждой записи проверяется повторным чтением через API панели.

### Семантическое планирование и директивы Integrate / Remove

API-адаптер, offline dry-run и runtime checker используют общий анализатор `scripts/xray_dns_planner.py`. Он проверяет совместимость существующих DNS outbound/server, связи routing rules и balancers, порядок и пересечения правил порта 53. Совпадение только по имени тега не считается достаточным: проверяется реальное назначение объекта и параметры, которые могут изменить обработку DNS.

Подходящие существующие объекты переиспользуются даже при нестандартных тегах. Если нужного объекта нет, добавляется только недостающая часть. Новые outbound tags и routing `ruleTag` выбираются свободными с учётом всех существующих тегов inbound/outbound/balancer/API/DNS/rules и префиксов balancer selectors; новые правила сразу используют выбранные имена. Эквивалентные дубликаты сохраняются без добавления ещё одной копии. Несовместимые или неоднозначные пересечения приводят к остановке плана, а пользовательские объекты автоматически не переписываются и не удаляются.

Постоянные директивы Integrate и Remove используют один desired-state план только для DNS-объектов. Integrate добавляет только недостающие постоянные DNS-объекты, затем выполняет UDP/TCP self-test через отдельный диагностический план и после теста очищает диагностические inbound и `finalRule` по live-проверке использования за пределами этого плана. Это правило одинаково для ранее существовавших и добавленных объектов, независимо от маркеров `added/reused`. Очистка выполняется и после неуспешного теста; ошибка очистки сообщается отдельно. Remove удаляет только постоянные DNS-объекты и не знает о диагностических inbound или `finalRule`. Полные снимки Xray, журналы владения и snapshot-based rollback не используются.

### Автоматизированная интеграция (Go CLI)

В бинарник плагина встроены две явные команды. Их запуск не зависит от старта или перезапуска DNS daemon:

```bash
sudo /usr/local/x-ui/bin/plugins/doh-health-monitor/bin/doh-health-monitor integrate
sudo /usr/local/x-ui/bin/plugins/doh-health-monitor/bin/doh-health-monitor remove
```

`integrate` проверяет сервис и оба loopback DNS listener-а, читает актуальную конфигурацию панели, добавляет только недостающие постоянные DNS-объекты, затем проверяет UDP/TCP DNS через временный Tunnel и очищает диагностические объекты по live-анализу внешних ссылок. `remove` удаляет только неиспользуемые постоянные DNS-объекты; диагностические Tunnel и `direct.settings.finalRules` он не изменяет.

Admin API credential запрашивается или переиспользуется только во время явного выполнения одной из этих команд. Токен не получается при старте, остановке или работе DNS daemon. Секрет хранится отдельно от каталога плагина в root-only файле. После успешного `integrate` в $LUCX_PLUGIN_DATA/config.json устанавливается `"integration": true`; после успешного `remove` значение становится `false`. При ошибке операции флаг не обновляется. Изменения API могут привести к автоматическому перезапуску Xray со стороны LucX-UI.
### Ручная настройка Geosite DNS routing через LucX-UI

Для схемы версии 2.3.0 Geosite matching задаётся **внутри DNS outbound**, а не отдельными доменными `routing.rules`. Сначала обычное routing-правило направляет DNS пакеты на порт 53 в `dns-out`; затем Xray DNS outbound разбирает QNAME и сопоставляет его с Geosite.

**Перед началом:** установите сборку 2.3.0 после её публикации, убедитесь, что UDP listener доступен на `127.0.0.1:5355`, сохраните резервную копию Xray-конфигурации. Настройку выполняйте в редакторе LucX-UI, а не напрямую в SQLite/runtime-файле. Схема требует проверки на фактической встроенной версии Xray и в network namespace процесса Xray.

#### 1. Настройте DNS outbound

В `outbounds` добавьте или аккуратно дополните один outbound `dns-out`:

```json
{
  "tag": "dns-out",
  "protocol": "dns",
  "settings": {
    "rewriteNetwork": "udp",
    "rewriteAddress": "127.0.0.1",
    "rewritePort": 5355,
    "rules": [
      {
        "action": "direct",
        "domain": ["geosite:category-name"]
      },
      {
        "action": "hijack"
      }
    ]
  }
}
```

Замените `geosite:category-name` на реально установленную Geosite category. Правило `direct` должно стоять перед catch-all `hijack`. В этом контексте `direct` — действие DNS outbound, которое отправляет исходный DNS-пакет на rewrite target `127.0.0.1:5355`; это не обычный `freedom` outbound tag.

`rewriteNetwork: udp` задаёт транспорт только на локальном участке Xray DNS outbound → plugin listener. Внешний клиентский путь WireGuard/TProxy может быть UDP; это отдельный участок.

#### 2. Направьте DNS port 53 в DNS outbound

В `routing.rules` добавьте правило TCP/UDP порта 53:

```json
{
  "type": "field",
  "network": "tcp,udp",
  "port": "53",
  "outboundTag": "dns-out"
}
```

Разместите его до пользовательских правил, которые могут перехватить DNS port 53. Не добавляйте второе правило port 53 → `freedom` после него: при first-match routing оно будет недостижимо. Если подходящее правило уже есть, не дублируйте его.

#### 3. Настройте встроенный DNS Xray для catch-all hijack

В `dns.servers` задайте обычный upstream для запросов, которые не совпали с Geosite. Например, для Quad9 DoH можно использовать URL с IP literal, чтобы не требовался bootstrap hostname:

```json
"dns": {
  "servers": ["https://9.9.9.9/dns-query"],
  "disableFallback": false
}
```

Этот upstream относится к встроенному DNS Xray и обслуживает catch-all `hijack`. Он не является `resolver_upstreams` плагина и не управляет режимом `resolver`.

#### 4. Сохраните конфигурацию и проверьте путь

Проверьте JSON и сохраните его штатным способом через LucX-UI. Учтите, что панель может перезапустить Xray. На VPS сначала проверьте listener плагина напрямую:

```bash
curl -fsS http://127.0.0.1:18765/healthz
curl -fsS http://127.0.0.1:18765/status | jq .
dig @127.0.0.1 -p 5355 example.com A +time=5 +tries=1
dig +tcp @127.0.0.1 -p 5355 example.com A +time=5 +tries=1
```

Затем проверьте клиентский запрос через WireGuard/TProxy и Xray. Убедитесь, что Geosite QNAME попадает в правило `direct`, listener доступен из network namespace Xray и ответ возвращается клиенту; non-Geosite запрос должен идти по `hijack` к встроенному DNS Xray.

**Ограничения и предостережения:**

- Plugin DNS listener отвечает только на A/AAAA. Запросы других QTYPE, направленные в плагин, получают `NOERROR`/NODATA.
- В проверенном upstream Xray catch-all `hijack` не является универсальной пересылкой всех QTYPE: не-A/AAAA запросы могут получить `NOERROR`/пустой ответ. Поведение встроенной версии панели нужно проверить отдельно.
- Наличие Geosite category зависит от фактически загруженного asset. Нельзя считать category доступной только потому, что она существует в другом geosite-репозитории.
- Системный resolver режима `resolver` может образовать косвенную петлю через локальный stub/TProxy/NAT. Проверьте `/etc/resolv.conf` и сетевой путь.
- Эта инструкция описывает ручную настройку. `integrate`/`remove` пока не генерируют и не валидируют Geosite DNS policy автоматически.

Подробная архитектура и ссылки на исходные материалы находятся в [GEOSITE-DNS-ROUTING-DESIGN.md](doc/GEOSITE-DNS-ROUTING-DESIGN.md).

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
| DNS через Xray возвращает пустой ответ для TXT/MX/HTTPS | Проверьте наличие последнего `{ "action": "direct" }` в `dns-out.settings.rules` |

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


## 14. Локальные DNS-переопределения: `local_hosts`

`local_hosts` — необязательный локальный аналог файла `hosts`. Он позволяет задать собственные IP-адреса для отдельных доменных имён. Такие записи обрабатываются самим плагином и **не отправляются на DoH upstream**.

Функция отключена по умолчанию: в новом `config.json` уже есть пустой объект:

```json
"local_hosts": {}
```

Если оставить его пустым, обычная работа DNS через DoH не меняется. Заполнять `local_hosts` нужно только тогда, когда действительно требуется вручную закрепить адрес конкретного домена.

### Формат записи

Добавьте объект домена внутрь `local_hosts`. Для каждого домена можно указать один или несколько IPv4 и IPv6 адресов:

```json
"local_hosts": {
  "panel.example.com": {
    "ipv4": ["203.0.113.10"],
    "ipv6": ["2001:db8::10"]
  },
  "api.example.com": {
    "ipv4": ["203.0.113.10"],
    "ipv6": []
  }
}
```

Это фрагмент, а не весь файл: вставьте поле на верхнем уровне существующего `config.json`, рядом с `bootstrap_resolvers`, `groups` и другими основными параметрами. Если поле уже есть, отредактируйте его, не создавая второй ключ `local_hosts`.

- Ключ объекта — полное доменное имя, например `panel.example.com`.
- `ipv4` — массив IPv4 адресов. Здесь допустимы только IPv4.
- `ipv6` — массив IPv6 адресов. Здесь допустимы только IPv6.
- Несколько адресов одного семейства допустимы.
- Пустой массив означает, что адресов этого семейства нет.
- Имена сравниваются без учёта регистра; завершающая точка DNS-имени игнорируется.
- Подстановки и wildcard, например `*.example.com`, не поддерживаются. Если нужно переопределить `www.example.com` и `api.example.com`, добавьте оба имени отдельно.

### Как выбрать IP-адрес

В `local_hosts` указывайте адрес сервера, на который клиент должен фактически подключаться при обращении к этому имени.

1. Если домен обслуживается вашим VPS, посмотрите публичный IP в панели VPS или в настройках сервера.
2. Если домен должен вести на другой сервер, возьмите IP именно того сервера.
3. Если перед сайтом стоит reverse proxy, CDN или балансировщик, указывайте адрес нужного входного узла, а не случайный IP одного из backend-серверов.
4. Не копируйте автоматически адреса популярных CDN и крупных сайтов: такие адреса могут меняться, распределяться по регионам и зависеть от географии клиента. Для них обычно лучше оставить обычный DoH.

На Linux посмотреть адреса сетевых интерфейсов можно командами:

```bash
ip -4 addr
ip -6 addr
```

Эти команды показывают адреса, назначенные интерфейсам VPS; не каждый из них обязательно является публичным или подходящим для клиентского подключения. Если вы хотите узнать текущий DNS-ответ домена, используйте:

```bash
dig +short panel.example.com A
dig +short panel.example.com AAAA
```

Ответ `dig` показывает текущие DNS-адреса, но не подтверждает, что именно этот адрес нужно закрепить. Выбор адреса зависит от того, куда должен вести трафик.

### Как плагин отвечает на DNS-запросы

Для домена, который присутствует в `local_hosts`, правила такие:

| Запрос | Ответ плагина |
|---|---|
| `A` (IPv4) | Только адреса из `ipv4` |
| `AAAA` (IPv6) | Только адреса из `ipv6` |
| `AAAA`, если `ipv6: []` | `NOERROR`, пустой Answer (NODATA) |
| `A`, если `ipv4: []` | `NOERROR`, пустой Answer (NODATA) |
| `HTTPS`, `SVCB`, TXT, MX и другие QTYPE вне A/AAAA | `NOERROR`, пустой Answer (NODATA) |

Локальные записи `local_hosts` действуют для A/AAAA и используют собственную TTL-политику; флаг DNS AD в локально сформированных ответах не устанавливается. Все QTYPE вне A/AAAA получают NODATA согласно общему контракту listener-а. HTTPS/SVCB address hints и ECH-конфигурация не выдаются; это **не отключает HTTPS или TLS** на самом сайте.

Переопределение применяется только к точному имени из `local_hosts`. Для остальных доменов применяется активный режим `dns_mode`: `endpoint_ip` или `resolver`.

### Как добавить или изменить запись

1. Откройте `config.json` в каталоге данных плагина `$LUCX_PLUGIN_DATA`.
2. Найдите `local_hosts` в корне JSON.
3. Добавьте домен и нужные IP либо отредактируйте существующие массивы.
4. Сохраните файл, не удаляя запятые и остальные параметры JSON.
5. Подождите до 30 секунд (интервал проверки файлов-источников).
6. Убедитесь в журнале, что конфигурация перечитана: появится сообщение `CONFIG reloaded`. Если запись некорректна, появится `CONFIG reload rejected`; плагин продолжит использовать последнюю рабочую конфигурацию.

Перезапуск плагина для обычного изменения `local_hosts` не требуется. Изменения применяются существующим механизмом hot reload. Перед редактированием полезно сохранить копию `config.json`.

### Проверка через dig

После добавления примера выше выполните на VPS:

```bash
dig @127.0.0.1 -p 5355 panel.example.com A
dig @127.0.0.1 -p 5355 panel.example.com AAAA
dig @127.0.0.1 -p 5355 panel.example.com HTTPS
dig @127.0.0.1 -p 5355 panel.example.com SVCB
```

В ответе A должен присутствовать заданный IPv4, в AAAA — заданный IPv6. Для `api.example.com AAAA`, поскольку массив `ipv6` пустой, ожидается `status: NOERROR` и отсутствие Answer-записей. HTTPS и SVCB для перечисленных имён также должны возвращать пустой Answer. Проверку можно повторить по TCP, добавив к команде `dig` параметр `+tcp`.

Замените демонстрационные имена и адреса на свои реальные значения. Диапазоны `203.0.113.0/24`, `198.51.100.0/24` и `2001:db8::/32` зарезервированы для документации и не предназначены для реального подключения.

### Важные ограничения

- Если клиент использует собственный DNS-over-HTTPS или другой DNS-сервер напрямую, запрос может вообще не попасть в этот плагин. Для применения переопределения клиентский DNS должен проходить через него.
- Клиент, который самостоятельно проверяет DNSSEC, может отклонить локальную неподписанную запись. AD=0 не отключает DNSSEC-проверку на стороне клиента.
- Переопределение DNS само по себе не настраивает маршрутизацию Xray, firewall или прокси. Оно только меняет DNS-ответ.
- Старые ответы, уже находящиеся в кэше приложения или ОС, могут использоваться до истечения их собственного TTL.
- Неверный IP может сделать сервис недоступным; при проблеме удалите или исправьте соответствующую запись.
