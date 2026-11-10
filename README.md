# DoH DNS Proxy & Health Monitor для LucX-UI

**Версия:** 1.5.0  
**Платформа:** Linux x86-64 (`amd64`), статический Go-бинарник  
**Тип:** LucX-UI sidecar, `apiVersion: 1`  
**Режим Gemini API:** необязательный, управляется параметром `gemini_api.enabled`

## 1. Назначение

Плагин объединяет локальный DNS-прокси и мониторинг DoH upstream. Xray один раз настраивается на передачу обычных DNS-запросов локальному прокси `127.0.0.1:5355`. После этого Go-приложение самостоятельно выбирает DoH для каждого домена по группе и переключается на резервный upstream при отказе. При смене активного DoH перезапуск Xray не требуется.

Плагин может обслуживать DNS-запросы UDP и TCP, принимает DoH по HTTPS (RFC 8484), проверяет DNS/TLS/HTTP доступность и публикует состояние через локальный HTTP endpoint.

### Что умеет

- UDP DNS и TCP DNS на `127.0.0.1:5355`.
- Автоматическое разрешение A/AAAA адресов DoH upstream через независимые bootstrap DNS-серверы по IP — без зависимости от системного DNS и DNS-петли.
- Несколько независимых доменных групп: `google`, `netflix`, `openai`, `youtube`, `default` и пользовательские группы.
- Отдельный список upstream и порядок fallback для каждой группы.
- Проверка DNS-записей A/AAAA и по желанию HTTPS endpoint для каждого upstream и группы.
- Проверка HTTP статуса, TLS и (опционально) поля `issuer` в OIDC discovery document.
- Последовательный fallback при ошибке текущего DNS запроса.
- Автоматический выбор первого здорового DoH согласно приоритету группы.
- Защита от ложных переключений: 3 неудачных цикла для статуса `down`, 5 успешных для восстановления (значения меняются в конфиге).
- DNS cache с TTL и ограничением числа записей.
- Автоперечитывание `config.json` и `doh-servers.txt`.
- `/healthz` и `/status` на localhost.
- Опциональная настоящая генерация через Gemini API. По умолчанию выключена, API-ключ не нужен.
- Приём и журналирование событий LucX-UI через Unix socket (события не меняют health state или DNS failover).
- Корректное завершение по SIGINT/SIGTERM.

### Чего плагин не делает

- Не редактирует Xray config и не вызывает закрытые API панели.
- Не перезапускает Xray.
- Не подменяет FakeDNS Xray. FakeDNS остаётся функцией Xray; для отдельных доменных групп можно направлять A/AAAA в FakeDNS, а реальные запросы остальных групп — в этот локальный DoH-прокси.
- Проверки Gemini Web не имитируют авторизованную отправку сообщения в браузере. Без Gemini API проверяются DNS/TLS/HTTP зависимости. Если включить `gemini_api.enabled`, отдельно проверяется генерация ответа через Gemini API.

## 2. Схема работы

```text
Клиентские DNS-запросы
          |
          v
Xray routing: port 53 / tcp,udp
          |
          v
outbound protocol=dns (dns-out)
          |
          +-- A/AAAA домена из FakeDNS whitelist --> Xray built-in FakeDNS
          |
          +-- все остальные DNS типы/домены ------> 127.0.0.1:5355
                                                        |
                                                        v
                                               Go DNS Proxy
                                                        |
                               +------------------------+-------------------+
                               |                        |                   |
                               v                        v                   v
                           Google DoH              Cloudflare DoH        Quad9 DoH
                               ^                        ^                   ^
                               +---------- Health Monitor -----------------+
```

Прокси слушает только loopback. Он не является публичным DNS-сервером и не должен открываться в firewall на внешний интерфейс.

**Важно про FakeDNS:** когда доменная группа помечена `fake_dns: true` и её домены внесены в FakeDNS rules Xray, запросы A/AAAA этой группы обрабатываются FakeDNS, а не DoH-прокси. Монитор при этом может проверять реальные DNS/HTTPS ответы upstream для оценки доступности. Если для группы нужны реальные A/AAAA ответы через выбранный DoH, установите `fake_dns: false` и удалите домены группы из FakeDNS whitelist и правила `hijack` Xray.

## 3. Состав пакета и расположение файлов

Установочный ZIP содержит только необходимые для установки файлы:

```text
manifest.json
bin/doh-health-monitor
```

`README.md` и каталог `examples/` остаются в GitHub-репозитории, но в установочный ZIP не включаются. Автоматического обновления плагина нет: новую версию устанавливают повторно через менеджер плагинов.

После первого запуска в приватной папке `$LUCX_PLUGIN_DATA` автоматически создаются:

```text
$LUCX_PLUGIN_DATA/
├── config.json       # все параметры работы, создаётся из встроенного шаблона
└── doh-servers.txt   # один HTTPS DoH URL на строку
```

Если `gemini_api.enabled` включён, дополнительно создайте:

```text
$LUCX_PLUGIN_DATA/gemini_api_key
```

Вся изменяемая информация хранится только в `LUCX_PLUGIN_DATA`. Плагин не должен писать в каталог бинарника, `/etc`, `/tmp` или другие места.

## 4. Установка в LucX-UI

1. Скачайте `doh-health-monitor-v1.5.0.zip`.
2. В LucX-UI откройте менеджер плагинов и установите ZIP.
3. Запустите плагин из панели.
4. После первого запуска панель создаст приватную папку данных; плагин создаст в ней `config.json` и `doh-servers.txt`.
5. Посмотрите журнал плагина. Нормальный старт содержит строки примерно такого вида:

```text
level=INFO START id=doh-health-monitor version=1.5.0 arch=amd64 data=...
level=INFO CONFIG loaded ... gemini_api=false
level=INFO EVENT_SOCKET listening ...
level=INFO READY DNS=127.0.0.1:5355/127.0.0.1:5355 HTTP=127.0.0.1:18765
```

6. Откройте файлы в `$LUCX_PLUGIN_DATA` и настройте их перед подключением клиентов к новому DNS-пути.

### Требования по архитектуре и сети

- Этот ZIP содержит бинарник только `linux/amd64`.
- `permissions.network` пустой массив: плагину разрешена сеть для DoH и HTTPS health-check. Не устанавливайте `network: ["none"]`.
- `panelApi` не запрашивается: плагин не изменяет Xray через API.
- Listener-ы по умолчанию привязаны только к `127.0.0.1`.

## 5. Конфигурация плагина

### 5.1 `config.json`

Это основной файл настроек. Все группы доменов, upstream IDs, bootstrap DNS resolvers, резервные IP, тайминги, пороги, кэш, listener-ы и флаг Gemini API находятся здесь.

Образец `examples/config.example.json` доступен в GitHub-репозитории, но не входит в ZIP. При первом старте плагин создаёт реальный `config.json` из встроенного шаблона. Обычно достаточно редактировать созданный файл.

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
| `reload_interval_seconds` | Частота перечитывания конфигов | 5 секунд, диапазон 1–300 |
| `dns_query_timeout_seconds` | Общий таймаут DNS-запроса | 15 секунд, диапазон 1–120 |
| `doh_timeout_seconds` | Таймаут одного DoH запроса | 10 секунд, диапазон 1–60 |
| `dns_max_concurrent` | Лимит одновременных DNS запросов | 256, диапазон 1–4096 |

**Перезапуск самого плагина требуется**, если меняются `dns_listen_udp`, `dns_listen_tcp`, `http_listen` или `dns_max_concurrent`. Остальные параметры конфигурации перечитываются автоматически. При изменении `http_listen` также измените `health.target` в manifest и переустановите плагин, иначе probe панели продолжит обращаться к прежнему адресу.

### 5.2 Health-check и пороги failover

```json
"health": {
  "interval_seconds": 45,
  "timeout_seconds": 5,
  "failure_threshold": 3,
  "success_threshold": 5
}
```

- `interval_seconds` — как часто выполняется полный цикл проверок для каждой группы/upstream (5–3600 секунд).
- `timeout_seconds` — таймаут одной DNS/HTTP проверки (1–60 секунд).
- `failure_threshold` — сколько неудачных циклов подряд нужно для статуса `down` (1–20).
- `success_threshold` — сколько успешных циклов подряд нужно для статуса `up` (1–50).

В примере 3 последовательных неудачи исключают upstream из списка здоровых, а 5 последовательных успехов возвращают его. Если DNS-запрос в реальном времени не проходит, прокси не ждёт health threshold: он сразу пробует следующий upstream этой группы. Порог нужен для устойчивого выбора активного upstream, а не для блокировки аварийного fallback.

### 5.3 DNS cache

```json
"cache": {
  "enabled": true,
  "min_ttl_seconds": 5,
  "max_ttl_seconds": 300,
  "negative_ttl_seconds": 15,
  "max_entries": 8192
}
```

- `enabled` включает/выключает кэш.
- `min_ttl_seconds`: ответы с TTL меньше указанного не кэшируются; `0` отключает нижнее ограничение.
- `max_ttl_seconds`: максимальный TTL в кэше.
- `negative_ttl_seconds`: TTL для NXDOMAIN.
- `max_entries`: максимальное число записей; `0` снимает лимит (не рекомендуется).

При смене конфигурации кэш очищается. Кэш хранится в памяти и не сохраняется после перезапуска плагина.

### 5.4 DoH upstream и автоматический bootstrap

Для каждого DoH hostname плагин автоматически получает A и AAAA через независимые DNS-resolvers, указанные IP-адресами. По умолчанию используются:

```json
"bootstrap_resolvers": ["1.1.1.1", "8.8.8.8"],
"upstreams": [
  { "id": "dns.google", "name": "Google Public DNS" },
  { "id": "cloudflare-dns.com", "name": "Cloudflare" },
  { "id": "dns.quad9.net", "name": "Quad9" }
]
```

- `bootstrap_resolvers` — IP-адреса независимых DNS-resolvers. Они используются напрямую по UDP/TCP port 53, поэтому системный DNS и сам DoH-прокси не участвуют в разрешении DoH hostname.
- `upstreams[].id` — hostname DoH endpoint; должен совпадать с hostname URL в `doh-servers.txt`.
- `upstreams[].name` — человекочитаемое имя.
- `upstreams[].bootstrap_ips` — необязательный резервный список IP. Он используется только если автоматическое разрешение не удалось и ещё нет сохранённого рабочего списка.

Плагин параллельно измеряет время полного DoH-запроса к каждому найденному IP (включая TLS handshake и проверку сертификата) и выбирает один самый быстрый адрес. Выбранный IP кэшируется на 6 часов. При проблеме с подключением выполняется принудительное DNS-разрешение и повторный замер; если независимый DNS временно недоступен, используется последний сохранённый список IP и выбирается лучший из доступных. В журнале появляется `DoH IP selected` с выбранным адресом и временем ответа. TLS SNI и проверка сертификата всегда выполняются по hostname DoH endpoint.

Старый формат конфигурации с обязательными `bootstrap_ips` продолжает поддерживаться: эти адреса становятся резервом, а не отключают автоматическое обновление. Для нового upstream достаточно добавить объект с `id` и `name`, URL в `doh-servers.txt` и приоритет в `groups[].upstreams`.

### 5.5 `doh-servers.txt`

Один HTTPS DoH URL на строку. Пустые строки и строки, начинающиеся с `#`, игнорируются.

```text
# Один HTTPS DoH URL на строку
https://dns.google/dns-query
https://cloudflare-dns.com/dns-query
https://dns.quad9.net/dns-query
```

Путь URL может быть другим, если провайдер его требует, но схема должна быть `https://`. Для каждого hostname должен быть соответствующий объект в `upstreams`.

**Приоритет попыток задаётся в `groups[].upstreams`**, а не порядком строк файла. `doh-servers.txt` лишь задаёт URL для upstream ID. Изменение файла применяется автоматически за `reload_interval_seconds`.

Чтобы добавить провайдера:

1. Добавьте его HTTPS URL отдельной строкой в `doh-servers.txt`.
2. Добавьте в `config.json` объект `upstreams` с `id` и `name` (резервные `bootstrap_ips` необязательны).
3. В `groups[].upstreams` добавьте этот ID в нужное место приоритетного списка.
4. Дождитесь `CONFIG reloaded` в журнале и проверьте `/status`.

Чтобы временно исключить провайдера, удалите URL из файла и его ID из списков групп. Если ID остаётся в группе без URL, новая конфигурация будет отвергнута, а последняя рабочая останется активной.

### 5.6 Доменные группы

Пример:

```json
{
  "id": "google",
  "fake_dns": true,
  "domains": [
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "gemini.google.com"
  ],
  "upstreams": [
    "dns.google",
    "cloudflare-dns.com",
    "dns.quad9.net"
  ],
  "checks": [
    {
      "domain": "gemini.google.com",
      "http_url": "https://gemini.google.com/",
      "required": true,
      "expected_status": [200, 301, 302, 403]
    }
  ]
}
```

Поля группы:

- `id` — уникальное имя группы; обязательна группа `default`.
- `fake_dns` — декларативный флаг для согласования с FakeDNS whitelist Xray. Сам по себе sidecar не редактирует Xray; значение используется как документация/состояние выбранной группы.
- `domains` — suffix match. Например, `google.com` совпадает с `google.com`, `accounts.google.com`, `gemini.google.com` и т.п. Сам домен можно указать без префикса `domain:`.
- `upstreams` — упорядоченный список ID DoH. Это приоритет и порядок fallback для DNS запросов этой группы.
- `checks` — контрольные домены и HTTP URL, используемые для проверки каждого upstream.

Домен выбирает группу по самому длинному совпадающему суффиксу. Все неизвестные домены идут в `default`. Поэтому для вложенного исключения (например, отдельного API под широким `googleapis.com`) добавьте более длинное доменное правило в нужную группу. Избегайте неоднозначных пересекающихся правил, если хотите разные FakeDNS-политики для вложенных доменов.

### 5.7 Контрольные проверки `checks`

Поддерживаемые поля:

| Поле | Назначение |
|---|---|
| `domain` | Домен для DNS запроса через конкретный DoH upstream |
| `qtypes` | Необязательные DNS qtype числа, например `[1, 28]`; если пусто — проверяются A и AAAA, достаточно одного успешного ответа |
| `http_url` | Необязательный HTTPS URL; hostname разрешается через проверяемый upstream, соединение закрепляется за полученным IP, TLS сертификат проверяется штатно |
| `required` | Если `true`, неудача влияет на состояние upstream для группы; `false` — только диагностический результат |
| `expected_status` | Принимаемые HTTP статусы; если отсутствует — допустимы 200–399 |
| `verify_oidc` | Если `true`, тело ответа должно быть JSON с полем `issuer` (подходит для OIDC discovery) |

Например, для авторизации Google:

```json
{
  "domain": "accounts.google.com",
  "http_url": "https://accounts.google.com/.well-known/openid-configuration",
  "required": true,
  "expected_status": [200],
  "verify_oidc": true
}
```

Для Gemini Web можно использовать `https://gemini.google.com/`; ожидаемые коды зависят от региона/редиректов. Статус `403` иногда говорит о сетевой достижимости при блокировке конкретного автоматического клиента, поэтому принимайте его только если это соответствует вашей цели. Набор доменов Google/Gemini меняется; редактируйте контрольный список под фактически используемый клиент.

### 5.8 Необязательная проверка Gemini API

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

## 6. Подключение к Xray в LucX-UI

Далее приведены **фрагменты**, которые нужно объединить с существующим JSON. Не заменяйте целиком действующие `inbounds`, `outbounds`, `routing` и `dns`: в них есть ваши теги и настройки панели. Сначала сделайте резервную копию. Перед применением проверьте итоговый конфиг штатной командой `xray run -test -c <путь-к-конфигу>` (если панель хранит конфигурацию в другом месте — используйте её штатную проверку).

### 6.1 FakeDNS pool на корневом уровне

Добавьте в корень JSON, если хотите FakeDNS для выбранных групп:

```json
"fakedns": [
  {"ipPool": "198.18.0.0/15", "poolSize": 32768},
  {"ipPool": "2001:2::/48", "poolSize": 32768}
]
```

### 6.2 Встроенный DNS Xray

Пример `dns` для FakeDNS whitelist и локального DoH fallback самого Xray (для внутренних разрешений имён Xray):

```json
"dns": {
  "tag": "dns_inbound",
  "hosts": {
    "dns.google": ["8.8.8.8", "8.8.4.4"]
  },
  "servers": [
    {
      "address": "fakedns",
      "domains": [
        "domain:netflix.com",
        "domain:nflxvideo.net",
        "domain:nflximg.net",
        "domain:nflxso.net",
        "domain:nflxext.com",
        "domain:netflix.net",
        "domain:openai.com",
        "domain:chatgpt.com",
        "domain:oaistatic.com",
        "domain:oaiusercontent.com",
        "domain:youtube.com",
        "domain:youtubei.googleapis.com",
        "domain:googlevideo.com",
        "domain:ytimg.com",
        "domain:youtu.be",
        "domain:youtube-nocookie.com",
        "domain:google.com",
        "domain:googleapis.com",
        "domain:gstatic.com",
        "domain:googleusercontent.com",
        "domain:google.org",
        "domain:googleadservices.com",
        "domain:gemini.google.com",
        "domain:generativelanguage.googleapis.com",
        "domain:clients6.google.com",
        "domain:jnn-pa.googleapis.com",
        "domain:waa-pa.clients6.google.com"
      ],
      "skipFallback": true
    },
    "https+local://dns.google/dns-query"
  ],
  "queryStrategy": "UseIP",
  "disableCache": false,
  "disableFallback": false,
  "disableFallbackIfMatch": true,
  "enableParallelQuery": false,
  "useSystemHosts": false
}
```

Список доменов в `fakedns` должен отражать только те группы, у которых `fake_dns:true`. Если меняете `fake_dns` или `domains` в `config.json`, синхронно обновите этот список и `dns-out.settings.rules` в Xray, затем один раз перезапустите Xray. Это изменение политики FakeDNS, не обычное переключение DoH.

Fallback `https+local://dns.google/dns-query` — встроенный DNS upstream Xray для его собственных разрешений; он не выбирается монитором. `hosts` для `dns.google` задан, чтобы bootstrap hostname Xray DoH не зависел от того же DNS-запроса.

### 6.3 DNS outbound Xray

Добавьте или измените `dns-out` так, чтобы обычные DNS запросы уходили в sidecar:

```json
{
  "tag": "dns-out",
  "protocol": "dns",
  "settings": {
    "rewriteAddress": "127.0.0.1",
    "rewritePort": 5355,
    "rules": [
      {
        "action": "hijack",
        "qType": "1,28",
        "domain": [
          "domain:netflix.com",
          "domain:nflxvideo.net",
          "domain:nflximg.net",
          "domain:nflxso.net",
          "domain:nflxext.com",
          "domain:netflix.net",
          "domain:openai.com",
          "domain:chatgpt.com",
          "domain:oaistatic.com",
          "domain:oaiusercontent.com",
          "domain:youtube.com",
          "domain:youtubei.googleapis.com",
          "domain:googlevideo.com",
          "domain:ytimg.com",
          "domain:youtu.be",
          "domain:youtube-nocookie.com",
          "domain:google.com",
          "domain:googleapis.com",
          "domain:gstatic.com",
          "domain:googleusercontent.com",
          "domain:google.org",
          "domain:googleadservices.com",
          "domain:gemini.google.com",
          "domain:generativelanguage.googleapis.com",
          "domain:clients6.google.com",
          "domain:jnn-pa.googleapis.com",
          "domain:waa-pa.clients6.google.com"
        ]
      },
      {"action": "direct"}
    ]
  }
}
```

Правила обрабатываются сверху вниз:

- A/AAAA для FakeDNS whitelist идут в DNS-модуль Xray.
- Все остальные DNS запросы (`A`, `AAAA`, `TXT`, `MX`, `SRV`, `HTTPS/SVCB` и т.д.) идут на `127.0.0.1:5355`.

`rewriteNetwork` намеренно не задан: Xray сохраняет исходный UDP/TCP transport. Не ограничивайте outbound только UDP — иначе клиентские DNS-over-TCP запросы не попадут в sidecar.

Если хотите получать **реальные IP** через DoH для Google/Netflix/OpenAI/YouTube, удалите соответствующие домены из первого `hijack`-правила и из FakeDNS сервера. Тогда запросы этих доменов будут обработаны вторым `direct`-правилом и локальным DoH proxy.

### 6.4 Routing rule для клиентского DNS

В `routing.rules` добавьте правило **выше общих/перехватывающих правил**, чтобы DNS на порту 53 попадал в `dns-out`:

```json
{
  "type": "field",
  "port": "53",
  "network": "tcp,udp",
  "outboundTag": "dns-out"
}
```

Без `inboundTag` правило применяется к DNS трафику от всех Xray inbounds. Если хотите ограничить только конкретные inbounds, добавьте их реальные `tag` в `inboundTag`.

### 6.5 Sniffing на клиентских inbounds для FakeDNS

На каждом inbound, который обслуживает клиентский проксируемый трафик, проверьте наличие sniffing:

```json
"sniffing": {
  "enabled": true,
  "destOverride": ["http", "tls", "quic", "fakedns"],
  "metadataOnly": false
}
```

Не стирайте существующие `destOverride` или другие параметры sniffing; добавьте `fakedns` в уже имеющийся список. FakeDNS адрес должен быть восстановлен в исходное доменное имя до маршрутизации, иначе соединение по fake IP не заработает.

### 6.6 Что изменить в вашей старой конфигурации

В ранее показанном вами `dns-out` был настроен на `127.0.0.1:5354`, а `rewriteNetwork` был задан как `udp`. Для этой версии:

- замените `rewritePort: 5354` на `rewritePort: 5355`;
- уберите `rewriteNetwork: "udp"`, чтобы сохранялся TCP/UDP исходного запроса;
- добавьте правила `hijack` + `direct`, показанные выше;
- routing DNS port 53 оставьте с outboundTag `dns-out`;
- Убедитесь, что прежний локальный DNS listener больше не конфликтует с портом `5355` и что правила Xray направляют запросы в новый sidecar.

После первичной интеграции проверьте Xray config и один раз перезапустите Xray через LucX-UI. **Последующие переключения DoH в sidecar не требуют перезапуска Xray.** Переключайте клиентский DNS путь только после проверки ответов нового proxy.

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

- `groups` — группы и выбранный `active_upstream`;
- health state `up`, `down`, `unknown`;
- `failure_streak` / `success_streak`;
- `checks` — DNS/HTTP результаты отдельных контрольных точек;
- `last_error`, `latency_ms`;
- `queries`, `cache_hits`, `failures`;
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
dig @127.0.0.1 -p 5355 google.com TXT +time=5 +tries=1
```

`example.com` попадёт в `default` group. Для `google.com` запрос TXT проходит через локальный sidecar даже если A/AAAA для этой группы направлены в FakeDNS Xray (если он опрашивается именно через Xray DNS outbound). Прямой `dig` к `127.0.0.1:5355` всегда проверяет локальный proxy, без Xray FakeDNS.

### 7.4 Проверка TCP DNS

```bash
dig +tcp @127.0.0.1 -p 5355 example.com A +time=5 +tries=1
```

### 7.5 Проверка реального DNS пути через Xray

Проверьте на клиенте, что его DNS направлен в Xray inbound, затем посмотрите результат разрешения и логи Xray. Для группы с `fake_dns:true` A/AAAA должны возвращать IP из FakeDNS pool. Для группы с `fake_dns:false` должны приходить реальные адреса через DoH proxy.

### 7.6 Проверка failover

Не проверяйте failover блокировкой публичного DoH на рабочем сервере без резервного доступа. Для безопасного теста используйте тестовую копию конфигурации или временный отдельный upstream с неверным/нерабочим URL и его bootstrap. Убедитесь, что:

1. `/status` показывает проблему конкретного upstream;
2. после `failure_threshold` неудачных циклов он помечается `down`;
3. новый DNS запрос пробует следующий upstream из группы;
4. после `success_threshold` успешных циклов сервер снова появляется как `up`.

### 7.7 Проверка изменения настроек

- Измените комментарий или URL в `doh-servers.txt`, сохранив корректный hostname/ID; в журнале должна появиться `DOH list`/`CONFIG reloaded`.
- Измените `groups[].upstreams` или контрольный домен в `config.json`; ждите `reload_interval_seconds`.
- Если новый конфиг ошибочный (например, неизвестный upstream ID), плагин отклонит его и продолжит использовать последнюю корректную конфигурацию.

## 8. Журналы и диагностика

Плагин пишет только в stdout/stderr; LucX-UI собирает это в `plugin.log`. Смотрите лог карточки плагина или файл журнала, путь к которому показывает ваша версия панели.

Частые случаи:

| Сообщение/симптом | Причина / действие |
|---|---|
| `address already in use` | Порт UDP/TCP 5355 или HTTP 18765 занят; выберите свободные loopback порты в config и обновите outbound/manifest health target соответственно |
| `DoH server ... has no upstream/bootstrap entry` | Для нового hostname добавьте объект `upstreams` с `id` и `name` |
| `group ... references DoH server ... missing from doh-servers.txt` | Убедитесь, что URL с таким hostname есть в `doh-servers.txt` |
| `all upstreams failed` | Проверьте доступность `bootstrap_resolvers` по UDP/TCP 53, HTTPS egress VPS, резервные `bootstrap_ips` (если заданы), URL/путь DoH, TLS и доступность провайдера |
| HTTP `401/403` на контрольном URL | Может быть блокировка/авторизация; задайте правильный `expected_status` или `required:false`, если это не индикатор полного отказа |
| `/healthz` OK, но DNS не отвечает | Смотрите `/status`, `plugin.log`, занят ли порт, совпадает ли `rewritePort` Xray с `dns_listen_udp/tcp` |
| DNS через Xray возвращает пустой ответ для TXT/MX/HTTPS | Проверьте наличие последнего `{ "action": "direct" }` в `dns-out.settings.rules` |
| FakeDNS возвращает реальные IP | Проверьте `hijack` правило, FakeDNS whitelist `domains`, `qType` 1/28 и маршрутизацию port 53 в `dns-out` |
| Fake IP не преобразуется обратно в domain | Добавьте `fakedns` в `destOverride` на inbound, который принял клиентское соединение |

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

При удалении плагина LucX-UI удаляет и его каталог данных `LUCX_PLUGIN_DATA`, включая `config.json`, `doh-servers.txt` и `gemini_api_key`. Это означает, что повторная установка начинается с чистого состояния: при первом запуске создаются новый `config.json` со встроенными настройками (автоматический bootstrap включён по умолчанию) и новый `doh-servers.txt`. Пользовательские настройки и ключ Gemini не сохраняются автоматически.

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
- Плагин не гарантирует доступность всех URL/функций Google, Netflix, OpenAI или YouTube по проверке нескольких контрольных точек.
- `fake_dns` в `config.json` — источник настройки/документации. Сам Xray FakeDNS whitelist и `dns-out` rules надо синхронизировать вручную.
- Обычный DoH failover не вызывает перезапуск Xray. Для изменения Xray FakeDNS whitelist/routing потребуется однократное изменение его конфигурации и перезапуск.
- Перед применением объединённых Xray JSON fragments всегда проверьте их на конкретной версии Xray-core и сохраните предыдущий конфиг.

## 13. Ссылки на документацию

- [Xray DNS outbound](https://xtls.github.io/en/config/outbounds/dns.html)
- [Xray built-in DNS](https://xtls.github.io/en/config/dns)
- [Xray FakeDNS](https://xtls.github.io/en/config/fakedns.html)
- [LucX-UI sidecar plugin contract](https://raw.githubusercontent.com/AlexeyLCP/lucx-ui/refs/heads/main/docs/plugin-sidecars.md)
- [LucX-UI plugin manager](https://raw.githubusercontent.com/AlexeyLCP/lucx-ui/refs/heads/main/docs/plugin-manager.md)
- [Google AI Studio API keys](https://aistudio.google.com/api-keys)
