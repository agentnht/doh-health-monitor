# Утверждённый проект: Geosite DNS routing и режимы DoH

**Дата последнего обновления:** 2026-11-21  
**Статус:** Draft PR #11. Этот документ — единственный нормативный источник требований для реализации и проверки PR. Конфигурация Xray в §4.4 утверждена как целевая ручная схема. Базовая реализация двух DNS-режимов, ActiveDoHSelector, cache generation и resolver pipeline уже находится в `feature/geosite-dns-routing`. На VPS 2026-11-20 подтверждены локальные проверки listener и Xray config; полный клиентский путь через пользовательский inbound пока не проверен, поскольку такого inbound ещё нет в тестовой конфигурации.  
**База ветки:** `main`, commit `b32d4263dbb43c5162860c0def0e990aac6e6541`.

## 1. Цель и принятое решение

Утверждённое решение разделяет DNS-обработку между Xray и плагином: Xray сопоставляет QNAME с Geosite внутри DNS outbound, а плагин обслуживает только DNS-пакеты, которые Xray направляет на его локальный listener.

Утверждённое разделение ответственности:

- **LucX-UI/Xray** определяет по своим правилам, к какой DNS-ветке направить запрос.
- **Плагин** проверяет доступность настроенных DoH-серверов, выбирает активный DoH и обслуживает направленный к нему DNS-поток согласно выбранному режиму.
- **Quad9 или другой настроенный fallback** используется для обычного разрешения имён в тех случаях, которые определит выбранный режим и его конфигурация.

Плагин не содержит Geosite matcher и не выбирает DNS-ветку по QNAME. Единственная точка сопоставления Geosite — правила `dns-out.settings.rules` на стороне Xray.

## 2. Утверждённое разделение ответственности

Решение состоит из двух независимых этапов:

1. Xray получает DNS-пакет от клиентского inbound и routing-правилом по TCP/UDP destination port 53 направляет его в DNS outbound.
2. DNS outbound сопоставляет QNAME с Geosite. Совпавшие запросы пересылаются на локальный DNS listener плагина действием `direct` и rewrite target; все остальные запросы обрабатываются встроенным DNS Xray действием `hijack`.

Плагин не получает метку сработавшего Geosite-правила и не должен пытаться восстановить её по DNS-пакету. Он обслуживает свой локальный listener одинаково для любого пришедшего QNAME, применяя только настроенный `dns_mode`.

Это не схема «добавить локальный DNS сервер плагина в `dns.servers`». Geosite-запросы направляются в listener через `dns-out.settings.rewriteAddress/rewritePort`; встроенный DNS Xray используется для non-Geosite catch-all и имеет собственный upstream, например Quad9.

## 3. Два взаимоисключающих режима плагина

Плагин работает строго в одном из двух режимов. Режим задаётся конфигурацией; одновременно применять оба способа формирования DNS-ответа нельзя. **Режим 1 является значением по умолчанию.**

### Режим 1. Возврат IP активного DoH endpoint

Xray определяет домены, которые должны направляться в DNS listener плагина, используя Geosite. Для запросов, попавших в этот поток:

1. Плагин использует отдельный список DoH endpoint-ов, предназначенный только для этого режима.
2. Плагин проверяет доступность endpoint-ов и выбирает один активный по алгоритму проверок, описанному в разделе 5.
3. Для DoH URL вида `https://dns.server.com/dns-query` плагин через bootstrap разрешает hostname `dns.server.com` и получает IP-адреса endpoint-а. Например, если bootstrap-разрешение вернуло `12.12.12.12`, именно этот IP endpoint-а возвращается клиенту в DNS-ответе.
4. Если hostname endpoint-а разрешается в несколько IP-адресов, необходимо сохранить и использовать существующую поддержку нескольких адресов в коде. Для A/AAAA применяются адреса соответствующего семейства согласно логике DNS-ответа.
5. Плагин возвращает клиенту IP выбранного активного DoH endpoint-а. Он **не выполняет обычное разрешение имени запрошенного сайта**.

Важно различать три вида адресов: IP DoH endpoint-а, полученный bootstrap-разрешением его hostname; IP bootstrap DNS resolver-а; IP запрошенного клиентом сайта. В ответе режима 1 используется первый. IP bootstrap resolver-а и IP сайта не подменяют IP endpoint-а.

### Режим 2. Разрешение реального имени сайта

Xray также определяет по Geosite, какие домены направлять в плагин. Для полученного запроса плагин выполняет обычное разрешение запрошенного доменного имени и возвращает реальный IP этого домена.

DNS-выход режима 2 настраивается отдельно:

- По умолчанию используется системный resolver операционной системы сервера, на котором работает плагин.
- В качестве альтернативы пользователь может выбрать DNS-сервер из отдельного редактируемого списка. Список должен поддерживать обычные DNS-серверы и DoH-серверы.
- Этот список DNS-выходов режима 2 независим от списка DoH endpoint-ов режима 1. Изменение одного списка не должно менять или переопределять другой.

Системный resolver означает resolver ОС самого сервера/окружения плагина, а не автоматически DNS-подсистему Xray. При реализации необходимо исключить DNS-петлю, например если системная конфигурация указывает обратно на listener плагина.

### Взаимоисключение и общие правила

- В конфигурации активен только один режим; режим 1 — значение по умолчанию.
- Xray/панель отвечает за Geosite-сопоставление и направление DNS-запроса в нужный поток. Плагин не определяет Geosite-категорию запроса.
- Списки endpoint-ов режима 1 и DNS-выходов режима 2 раздельные.
- Режим 1 возвращает адрес DoH endpoint-а, полученный bootstrap-разрешением hostname этого endpoint-а; режим 2 возвращает адрес запрошенного домена.
- Переключение режима должно менять именно способ формирования DNS-ответа, не смешивая синтетический endpoint IP с обычным разрешением имени.

**Конфигурационная модель плагина утверждена.** Она сохраняет взаимоисключающий выбор одного режима (режим 1 по умолчанию), отдельный список DoH endpoint-ов режима 1, отдельный список resolver upstream-ов режима 2 и независимые bootstrap-настройки. Смысловые значения режима:

- `dns_mode: endpoint_ip` — режим 1.
- `dns_mode: resolver` — режим 2.

Списки режимов 1 и 2 не объединяются и не подменяют друг друга. Изменение сериализации/имён отдельных полей при реализации не должно менять это утверждённое разделение ответственности.

## 4. Fallback, TTL и DNS-ответы

Fallback в двух режимах имеет разную семантику. Режим 1 возвращает адрес выбранного DoH endpoint-а и не должен незаметно превращаться в обычное разрешение домена. Режим 2 разрешает исходное имя и может последовательно обращаться к собственному списку DNS upstream-ов.

### 4.1. Матрица fallback

#### Режим 1 — `endpoint_ip`

| Ситуация | Поведение |
|---|---|
| Активный DoH не выбран | Ответ `NOERROR` с пустым Answer (NODATA); не переходить к обычному resolver и не возвращать IP запрошенного сайта |
| Bootstrap не смог разрешить hostname DoH endpoint-а | `NOERROR`/NODATA |
| Сетевая ошибка при проверке/подключении к endpoint-у | Endpoint не считается пригодным; если другой активный endpoint не выбран — `NOERROR`/NODATA |
| DNS-ошибка при bootstrap-разрешении или проверке endpoint-а | Endpoint не считается пригодным; если другой активный endpoint не выбран — `NOERROR`/NODATA |
| Есть IPv4, но нет IPv6, или наоборот | Для A вернуть имеющиеся IPv4, для AAAA — имеющиеся IPv6. Если запрошенного семейства нет, вернуть `NOERROR`/NODATA; не подменять его адресом другого семейства и не считать отсутствие семейства причиной fallback |
| Нет ни IPv4, ни IPv6 | `NOERROR`/NODATA |
| Активный endpoint сменился | Новые запросы используют новый endpoint; кэш режима 1 инвалидируется |

Режим 1 не выполняет DNS-запрос имени сайта через выбранный DoH. Поэтому DNS-ошибки, относящиеся к разрешению запрошенного сайта, в этом режиме не возникают: upstream DNS используется для bootstrap hostname самого DoH endpoint-а и для его health probes. Ошибка этих операций не должна приводить к переходу в режим 2.

В этой спецификации термин `blackhole` означает отсутствие fallback-разрешения и отсутствие подмены ответа адресом другого DNS-механизма. Утверждённое wire-level поведение — DNS-ответ с RCODE `NOERROR` и пустой секцией Answer (NODATA), а не молчаливый UDP DROP и не SERVFAIL. Для синтетического NODATA не добавлять выдуманную SOA в Authority; такие ответы не кэшировать в плагине. По RFC 2308 отрицательные ответы без SOA не должны кэшироваться, поскольку у них нет корректно передаваемого negative TTL.

#### Режим 2 — `resolver`
В режиме 2 используется независимый упорядоченный список upstream-ов:

1. По умолчанию первым является системный resolver ОС сервера, на котором работает плагин.
2. Далее идут дополнительные DNS/DoH upstream-ы в явно заданном пользователем порядке.
3. Пользовательская конфигурация может задавать порядок и отключать системный resolver. Если список пуст или все upstream-ы исчерпаны, результат — `NOERROR` с пустым Answer (NODATA), а не переход в режим 1.

Правила перехода к следующему upstream:

- Сетевая/транспортная ошибка, timeout или ошибка протокола/DoH transport: попробовать следующий upstream.
- DNS SERVFAIL или REFUSED: попробовать следующий upstream.
- Усечённый ответ (TC), который нельзя корректно завершить на текущем transport: попробовать следующий upstream.
- Валидный NXDOMAIN или NOERROR/NODATA: вернуть этот ответ, не маскировать его ответом другого resolver-а.
- Когда upstream-ы исчерпаны без пригодного ответа: `NOERROR` с пустым Answer (NODATA); не кэшировать этот синтетический ответ.

Это разделяет недоступность upstream и содержательный DNS-ответ. Следующий upstream не должен вызываться только потому, что домен не существует или у него нет записи требуемого типа. Для ситуации, когда все resolver-ы вернули только DNS SERVFAIL/REFUSED/TC, сохранять последний DNS-ответ нельзя; итоговое поведение — согласованный `NOERROR`/NODATA без кэширования.

Список upstream-ов режима 2 независим от списка DoH endpoint-ов режима 1 и от bootstrap resolver-ов. Bootstrap нужен только для получения IP hostname самого DoH endpoint-а; он не является fallback-списком для разрешения произвольного имени сайта в режиме 2.

#### Граница ответственности Xray и плагина

- Плагин выполняет fallback только внутри активного режима и только по его отдельным правилам.
- Направление DNS-запросов, не попавших под Geosite-правило, и поведение при недоступности самого listener-а остаются ответственностью Xray/панели и требуют интеграционной проверки.
- Нельзя считать, что Xray автоматически выполнит fallback, если listener плагина не отвечает: это должно быть явно настроено и протестировано.

### 4.2. TTL и кэширование

#### Режим 1

- Рекомендуемый TTL для синтетического положительного A/AAAA-ответа — **60 секунд максимум**. Это короткое значение ограничивает срок, в течение которого клиент может продолжать использовать старый DoH endpoint после переключения, и ограничивает время использования клиентом устаревшего endpoint после переключения.
- Фактический TTL ответа и внутреннего cache entry равен меньшему из `60 секунд` и оставшегося freshness выбранного endpoint IP. TTL никогда не продлевает freshness.
- Если до истечения freshness осталось меньше секунды, прежний IP не выдаётся: вернуть согласованный `NOERROR`/NODATA.
- При смене активного DoH или его выбранного IP-набора увеличивать generation и немедленно инвалидировать кэш режима 1. Уже выданные клиентам DNS-ответы нельзя отозвать, поэтому TTL 60 секунд ограничивает внешнее окно устаревшего endpoint-а.
- Если активный endpoint имеет несколько адресов одного семейства, все возвращаемые адреса используют одинаковый TTL, рассчитанный по общему freshness.
- Синтетические NODATA-ответы (нет активного endpoint-а, нет адреса нужного семейства или истёк freshness) не кэшировать.

#### Режим 2

- Для положительных ответов не увеличивать TTL, полученный от upstream. Срок хранения ответа в кэше определяется минимальным TTL среди записей ответа и ограничивается сверху **300 секундами (5 минут)**. Значение 300 секунд выбрано как умеренный верхний предел для снижения повторных запросов без длительного удержания изменившихся DNS-данных; такой же MaxTTL используется в кэше v3.
- Для NXDOMAIN и валидного NODATA использовать отрицательный TTL по RFC 2308: минимум между TTL SOA RR и полем SOA.MINIMUM, ограниченный сверху 300 секундами. Это также относится к NODATA после CNAME chain: CNAME RR остаются в Answer, но если запрошенной A/AAAA записи нет, срок кэширования negative результата определяется SOA; без SOA такой ответ не кэшируется.
- Отрицательные ответы без пригодной SOA не кэшировать. Хотя v3 имеет резервный `negative_ttl_seconds = 15`, для новой схемы этот fallback не переносить: RFC 2308 рекомендует не кэшировать negative responses без SOA.
- Ответы с TTL=0, а также SERVFAIL/REFUSED и синтетические NODATA после исчерпания upstream-ов не кэшировать.
- При выдаче из кэша TTL RR уменьшается на прошедшее время; MaxTTL не меняет TTL в первом ответе upstream, а ограничивает только срок хранения.
- Кэш режима 2 инвалидируется при изменении его списка/order upstream-ов или настроек resolver-а. Смена активного DoH режима 1 сама по себе не должна очищать кэш режима 2.

#### Разделение кэшей и защита от гонок

Кэш должен иметь отдельные пространства ключей для режимов 1 и 2. Помимо QNAME/QTYPE и остальных значимых полей DNS-запроса:

- для режима 1 ключ/запись должны учитывать generation активного endpoint-а;
- для режима 2 ключ/запись должны учитывать поколение конфигурации resolver-ов;
- смена активного DoH увеличивает generation режима 1 и инвалидирует только его записи;
- изменение resolver-конфигурации режима 2 инвалидирует только его записи;
- запрос, начатый на старом snapshot/generation, не должен повторно наполнить уже инвалидированный кэш после переключения.

В PR #11 эти требования реализованы в новом cache pipeline: namespace режимов разделены, записи привязаны к generation соответствующей конфигурации, а запрос со старого snapshot не должен повторно заполнить уже инвалидированный кэш после переключения или reload.

### 4.3. CNAME, HTTPS/SVCB, DNSSEC и EDNS

Для режима 2 (как и для режима 1 на входе плагина) пользовательский DNS listener обслуживает только запросы типов A и AAAA. Для этих запросов режим 2 прозрачно передаёт DNS-пакет upstream-у и возвращает его ответ без самостоятельного синтеза или перестройки RR:

- **CNAME:** сохранять полученную upstream-ом цепочку CNAME и связанные записи. Плагин не должен заменять alias на самостоятельно найденный конечный IP.
- **HTTPS/SVCB:** отдельные QTYPE HTTPS (65) и SVCB (64) listener плагина не обслуживает: они получают `NOERROR`/NODATA без SOA и без кэширования. Проверка HTTPS/TLS в selector-е — это сетевой probe по IP после A/AAAA bootstrap, а не DNS QTYPE HTTPS.
- **DNSSEC:** передавать DO bit и DNSSEC RR без изменения. Не выставлять AD в синтетических/локально сформированных ответах, если плагин сам не выполняет DNSSEC validation. Самостоятельный DNSSEC-валидатор в текущий объём не входит.
- **EDNS:** сохранять значимые параметры запроса при upstream forwarding. В самостоятельно сформированном локальном ответе не отражать клиентские EDNS options вроде COOKIE/ECS; если нужен OPT, использовать минимальный ответный OPT с согласованными UDP payload size, extended RCODE/version и DO bit.

Для QTYPE вне A/AAAA плагин возвращает согласованный `NOERROR`/NODATA (пустой Answer, без синтетической SOA) и не кэширует ответ. Это осознанное ограничение функциональности: плагин нужен здесь для возврата IP адресов или разрешения IP, поэтому отдельные запросы HTTPS/SVCB, MX, TXT и прочих типов не обслуживаются. CNAME при этом не является самостоятельной целевой записью: CNAME RR, встретившиеся в цепочке ответа на A/AAAA, сохраняются и передаются клиенту вместе с ответом upstream.

Для выбора и проверки DoH endpoint-а дополнительные DNS QTYPE не нужны: selector разрешает контрольные домены через A/AAAA, затем проверяет HTTPS непосредственно по полученному IP с исходными hostname, TLS SNI, HTTP Host и проверкой сертификата. HTTP/TLS probe — отдельная проверка доступности сервера, а не DNS QTYPE HTTPS.

Требования к wire-ответам, CNAME, EDNS и negative cache относятся к реализации плагина и должны проверяться собственными регрессионными тестами. Это не полноценная DNSSEC validation и не обещание прозрачной поддержки всех QTYPE.

### 4.4. Утверждённая конфигурация Xray и точная DNS-схема

Ниже зафиксирована **утверждённая целевая конфигурация**, предоставленная оператором 2026-11-21. Она является нормативным примером для PR #11. Не заменять её старой моделью с локальным DNS server в `dns.servers`, дополнительным `xui-dns-allow` или отдельным routing-правилом `direct` для порта 5355.

#### Эталонный JSON

```json
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 62789,
      "protocol": "tunnel",
      "settings": {
        "rewriteAddress": "127.0.0.1"
      },
      "tag": "api"
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "finalRules": [
          {
            "action": "block",
            "ip": [
              "geoip:private"
            ]
          },
          {
            "action": "allow"
          }
        ]
      }
    },
    {
      "tag": "blocked",
      "protocol": "blackhole",
      "settings": {}
    },
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
            "domain": [
              "geosite:habr"
            ]
          },
          {
            "action": "hijack"
          }
        ]
      }
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api"
      },
      {
        "type": "field",
        "enabled": true,
        "port": "53",
        "network": "tcp,udp",
        "outboundTag": "dns-out",
        "ruleTag": "doh-health-monitor-dns-port53"
      },
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "blocked"
      }
    ],
    "domainStrategy": "AsIs"
  },
  "dns": {
    "servers": [
      {
        "address": "https://9.9.9.9/dns-query",
        "domains": [],
        "expectedIPs": [],
        "unexpectedIPs": [],
        "skipFallback": false,
        "finalQuery": true,
        "tag": "quad",
        "queryStrategy": "UseIP",
        "disableCache": false,
        "timeoutMs": 4000,
        "serveStale": false,
        "serveExpiredTTL": 0
      }
    ],
    "queryStrategy": "UseIP",
    "disableCache": false,
    "disableFallback": false,
    "disableFallbackIfMatch": false,
    "enableParallelQuery": false,
    "useSystemHosts": false,
    "serveStale": false,
    "serveExpiredTTL": 0
  },
  "log": {
    "access": "none",
    "dnsLog": false,
    "error": "",
    "loglevel": "warning",
    "maskAddress": ""
  },
  "policy": {
    "system": {
      "statsInboundDownlink": true,
      "statsInboundUplink": true,
      "statsOutboundDownlink": false,
      "statsOutboundUplink": false
    },
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    }
  },
  "api": {
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService",
      "RoutingService"
    ],
    "tag": "api"
  },
  "geodata": {
    "assets": [
      {
        "file": "geoip.dat",
        "url": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
      },
      {
        "file": "geosite.dat",
        "url": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
      },
      {
        "file": "geoip_IR.dat",
        "url": "https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat"
      },
      {
        "file": "geosite_IR.dat",
        "url": "https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat"
      },
      {
        "file": "geoip_RU.dat",
        "url": "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat"
      },
      {
        "file": "geosite_RU.dat",
        "url": "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat"
      },
      {
        "file": "geoip_ROSCOM.dat",
        "url": "https://github.com/hydraponique/roscomvpn-geoip/releases/latest/download/geoip.dat"
      },
      {
        "file": "geosite_ROSCOM.dat",
        "url": "https://github.com/hydraponique/roscomvpn-geosite/releases/latest/download/geosite.dat"
      },
      {
        "file": "geoip_GA.dat",
        "url": "https://raw.githubusercontent.com/Ground-Zerro/Geo-Aggregator/main/geodat/geoip_GA.dat"
      },
      {
        "file": "geosite_GA.dat",
        "url": "https://raw.githubusercontent.com/Ground-Zerro/Geo-Aggregator/main/geodat/geosite_GA.dat"
      }
    ],
    "cron": "0 4 * * *"
  },
  "metrics": {
    "listen": "127.0.0.1:11111",
    "tag": "metrics_out"
  },
  "stats": {}
}
```

#### Разбор конфигурации по блокам

**1. Inbound и API.** Показанный inbound `api` на `127.0.0.1:62789` — существующий loopback Tunnel для Xray API, а не пользовательский WireGuard/TProxy ingress. Клиентский inbound, через который пользовательский DNS-трафик попадает в Xray, в этом снимке ещё отсутствует; целевая схема предполагает, что такой inbound будет добавлен/существует в рабочем окружении. Его отсутствие в текущем JSON не меняет утверждённые DNS outbound и routing rules. Первое routing-правило `api → api` сохраняет доступ панели к Xray API.

**2. Outbound `direct` и private-IP policy.** `direct` — обычный `freedom` outbound с `finalRules`: сначала блокируются `geoip:private`, затем разрешается остальное. Это отдельная политика обычного freedom-трафика. Она не является частью доставки DNS-пакета из DNS outbound в plugin listener.

**3. Outbound `blocked`.** `blackhole` сохраняет блокировку трафика, совпавшего с отдельным routing-правилом `geoip:private`. Он не участвует в выборе Geosite DNS-ветки.

**4. DNS outbound `dns-out`.** Это центральная часть схемы:
- `rewriteAddress: 127.0.0.1` и `rewritePort: 5355` задают локальную цель для DNS-пакетов, которые DNS outbound отправляет действием `direct`.
- `rewriteNetwork: udp` принудительно задаёт UDP для локального участка Xray DNS outbound → plugin listener. Это не настройка внешнего транспорта WireGuard/TProxy. Входящий от клиента DNS over TCP всё равно будет направлен routing-правилом в `dns-out`, но участок до плагина в этой конфигурации использует UDP.
- Первое правило `action: direct, domain: [geosite:habr]` сопоставляет QNAME с Geosite. Совпавший запрос направляется на rewrite target `127.0.0.1:5355/UDP`.
- Второе правило `action: hijack` — catch-all для всех остальных QNAME. Оно передаёт запрос встроенному DNS Xray.
- Порядок значим: Geosite `direct` должен стоять раньше catch-all `hijack`. Не переставлять их местами.

Внутри DNS outbound `action: direct` — действие самого DNS-протокола Xray, а не ссылка на outbound с тегом `direct` и не запуск `freedom.settings.finalRules`. DNS outbound использует rewrite target и свой механизм отправки DNS-пакета. Поэтому для этого пути **не требуется**:
- добавлять `xui-dns-allow` в `routing.rules`;
- добавлять allow-правило в `direct.settings.finalRules` для `127.0.0.1:5355`;
- добавлять отдельный routing rule `port 5355 → direct`;
- разрешать plugin listener через `freedom` outbound.

**5. Routing rules.** Порядок целевой конфигурации:
1. `inboundTag: ["api"] → outboundTag: "api"` — сохранить панельный API.
2. `network: "tcp,udp", port: "53" → outboundTag: "dns-out"` — направить DNS-трафик обоих транспортов в DNS outbound. Это правило должно находиться до общего private-IP block и до любых других правил, которые могут перехватить DNS destination port 53.
3. `ip: ["geoip:private"] → blocked` — обычная блокировка частных адресов.

Именно второе правило приводит пакет в DNS outbound. Geosite сопоставляется уже после этого, внутри `dns-out.settings.rules`; доменное Geosite-правило в обычном `routing.rules` для данной схемы не требуется.

**6. Встроенный DNS Xray и upstream Quad9.** В `dns.servers` настроен только upstream `https://9.9.9.9/dns-query` с tag `quad`. Он обслуживает catch-all ветку `hijack`. Он не является plugin listener и не является `resolver_upstreams` режима `resolver` самого плагина. Loopback DNS server `127.0.0.1:5355` в `dns.servers` для утверждённой схемы не нужен: Geosite DNS-запросы поступают в плагин через DNS outbound rewrite target.

**7. DNS cache и QTYPE.** Путь Geosite `direct` передаёт пакет listener-у плагина, поэтому для него применяется кэш самого плагина. Параметры `dns.disableCache` и кэш встроенного DNS относятся к ветке `hijack`. Плагин обслуживает A/AAAA; другие QTYPE, попавшие в Geosite direct, получают от плагина `NOERROR`/NODATA без SOA. Встроенный Xray DNS hijack также не является универсальным relay для всех типов: проверенная документация Xray указывает поддержку A/AAAA, а прочие QTYPE могут завершаться пустым ответом с RCODE 0. Поведение фактически встроенной сборки следует подтвердить тестом.

**8. Geodata и assets.** Секция `geodata.assets` задаёт источники geoip/geosite наборов и ежедневное обновление по cron `0 4 * * *`. Для утверждённого правила требуется, чтобы категория `habr` реально присутствовала в загруженном Geosite asset, который использует работающий Xray. Наличие строки/категории в другом репозитории или в другом asset не доказывает, что активная сборка загрузила нужный набор.

**9. Прочие секции.** `log`, `policy`, `api.services`, `metrics.listen` и `stats` сохраняются как настройки панели/Xray и не меняют Geosite DNS policy. Metrics listener `127.0.0.1:11111` не относится к DNS listener плагина.

#### Контракт маршрутизации и проверки

| Запрос | Xray DNS outbound | Итоговая обработка |
|---|---|---|
| QNAME попадает в `geosite:habr`, QTYPE A/AAAA | `direct` → rewrite UDP `127.0.0.1:5355` | Плагин применяет текущий `dns_mode` |
| QNAME не попадает в `geosite:habr`, QTYPE A/AAAA | `hijack` | Встроенный DNS Xray, upstream `quad` / Quad9 |
| QNAME попадает в Geosite, QTYPE не A/AAAA | `direct` → plugin listener | Плагин возвращает `NOERROR`/NODATA |
| QNAME не попадает в Geosite, QTYPE не A/AAAA | `hijack` | Не считать catch-all универсальным proxy; проверить фактическую сборку Xray |

В режиме плагина `endpoint_ip` A/AAAA-ответ для Geosite-запроса содержит bootstrap IP выбранного DoH endpoint-а, а не IP запрошенного сайта. В режиме `resolver` тот же Geosite-поток разрешает исходный QNAME через отдельный `resolver_upstreams` плагина. Non-Geosite запросы не проходят через плагин и обслуживаются встроенным DNS Xray.

**Не добавлять в эту схему** локальный Xray DNS server `127.0.0.1:5355`, `xui-dns-allow`, дополнительное правило routing для порта 5355 или исключение в `freedom.finalRules`. Эти элементы не являются частью утверждённого DNS path.

#### Границы доказанного

- Документ описывает утверждённую конфигурацию и семантику DNS outbound; он не привязывает проект к определённому номеру версии LucX-UI/Xray.
- Статическая проверка JSON подтверждает структуру правил, но не доказывает, что Geosite category загружена и реально совпадает с QNAME.
- Проверка DNS listener напрямую подтверждает работу плагина, но не доказывает, что пользовательский inbound направляет пакеты в нужный routing rule.
- Полный путь WireGuard/TProxy inbound → routing port 53 → DNS outbound → plugin listener → client response проверяется только с реальным пользовательским inbound и клиентским трафиком.
- Для listener `127.0.0.1:5355` необходимо то же network namespace, что у Xray, либо отдельно подтверждённая сетевая достижимость.
- Конкретная сборка Xray должна быть проверена на `direct` rewrite, `hijack`, non-A/AAAA и порядок DNS outbound rules.

Официальные описания синтаксиса и действий DNS outbound: [Xray DNS outbound (RU)](https://xtls.github.io/ru/config/outbounds/dns.html), [Xray DNS outbound (EN)](https://xtls.github.io/en/config/outbounds/dns.html). Эти документы описывают контракт конфигурации; для конкретного форка/сборки результат подтверждается runtime-проверкой.

## 5. Выбор активного DoH endpoint по восьми контрольным доменам

Для режима `endpoint_ip` плагин самостоятельно выбирает один активный DoH endpoint из настроенного списка. Выбор основан на восьми фиксированных контрольных доменах; список не является Geosite policy и не влияет на то, какие пользовательские QNAME направляются в плагин.

Контрольные домены:
- `chatgpt.com`
- `claude.ai`
- `gemini.google.com`
- `elevenlabs.io`
- `grok.com`
- `www.perplexity.ai`
- `notebooklm.google.com`
- `aistudio.google.com`

Для каждого кандидата выполняются DNS A/AAAA probes через сам проверяемый DoH, затем HTTPS/TLS probes к полученным IP с исходными hostname, SNI, HTTP Host и проверкой сертификата. Результат выбора содержит идентификатор и hostname endpoint-а, IPv4/IPv6 адреса, freshness, generation и score.

В PR #11 самостоятельный selector реализован в `internal/activedoh/selector.go`; runtime bootstrap/probe цикл находится в `active_doh.go` и запускается примерно раз в 5 минут. Score — это фактическое число успешных probes от 0 до 8; **жёсткого порога 6/8 в алгоритме нет**. При первичном выборе подходит любой кандидат с положительным score, выбирается кандидат с наибольшим score. При равном или меньшем score сохраняется текущий endpoint. Новый более сильный кандидат должен показать преимущество два цикла подряд; переключение дополнительно ограничено minimum hold 10 минут и switch cooldown 10 минут. При нулевом score текущий endpoint получает grace на два неудачных цикла; если здорового кандидата нет, выбор затем отзывается. Максимальный возраст bootstrap endpoint — 6 часов. Наблюдавшийся на VPS `score: 6, check_count: 8` был результатом одного цикла, а не настроенным порогом.

Список health-check файла `tst-domen.txt` не является списком Geosite и не управляет маршрутом DNS-пакета. Встроенный default содержит девять проверок: восемь selector control domains и отдельную обязательную OIDC-проверку `accounts.google.com`. Результаты health monitor и ActiveDoHSelector имеют разные назначения и не должны смешиваться.

## 6. Состав реализации PR #11 и границы ответственности

PR #11 должен реализовывать только компоненты, требуемые этим документом:

1. DNS режимы `endpoint_ip` и `resolver` с независимыми наборами upstream и bootstrap-настроек.
2. ActiveDoHSelector по восьми контрольным доменам для выбора endpoint режима `endpoint_ip`.
3. DNS listener с A/AAAA wire handling, предусмотренной CNAME/EDNS обработкой и согласованной NODATA семантикой для неподдерживаемых QTYPE.
4. Раздельные cache namespace/generation и TTL/negative-cache поведение режимов.
5. Read-only проверку установленной конфигурации на соответствие ручной схеме §4.4.

Границы ответственности:
- Xray выполняет Geosite matching и разделяет DNS поток на `direct` и `hijack`.
- Плагин не загружает Geosite asset, не содержит свой matcher и не управляет Geosite category.
- Встроенный DNS Xray обслуживает catch-all `hijack`; его upstream задаётся в `dns.servers`.
- Плагин обслуживает только пакеты, поступившие на его локальный listener, и не меняет routing/Xray config при обычном старте.
- Ручное редактирование Xray config выполняется оператором через штатный редактор панели.

Не переносить в эту архитектуру механизмы, которые создают динамический QNAME list, выбирают Geosite category внутри плагина, подменяют DNS server entries или автоматически генерируют Xray policy. Такие механизмы противоречат утверждённому разделению ответственности.

## 7. Где находится Geosite и как настраивается панель

Geosite matching расположен на стороне Xray, внутри `dns-out.settings.rules`. Это зафиксированная архитектура, а не открытая альтернатива. Для утверждённого примера используется `geosite:habr` с последовательностью `direct` → catch-all `hijack`, описанной в §4.4.

На этом этапе Xray конфигурация задаётся вручную через штатный редактор панели. Плагин не применяет изменения к Xray и не меняет конфигурацию при запуске. Автоматическое создание/удаление DNS outbound и routing rules не входит в текущую задачу до завершения ручной интеграционной проверки.

Операции CLI `integrate` и `remove` и соответствующий Web UI mutation endpoint в этой ветке отключены. Прямой CLI-вызов отклоняется до обращения к API панели; старый Web UI mutation endpoint отвечает HTTP 410 Gone. Причина: унаследованный planner рассчитывает на другую модель DNS integration (локальный DNS server в `dns.servers` и panel-managed allow exception) и не распознаёт утверждённую последовательность Geosite `direct` → catch-all `hijack`. Не адаптировать этот planner в рамках PR: автоматизация Xray не входит в текущий ручной этап. Структурная проверка утверждённой схемы выполняется read-only checker-ом; сетевой end-to-end тест — отдельно на целевом inbound.

**Read-only правило PR #11:** SSH-меню содержит только проверку и запуск Web UI; Web UI не показывает panel mutation controls. `doh-health-monitor integrate` и `doh-health-monitor remove` отклоняются на уровне CLI; Web UI endpoint для старых клиентов возвращает HTTP 410. `check` выполняет только preflight плагина, а shell checker проверяет утверждённую DNS policy без записи Xray config.

## 8. Текущий статус реализации и порядок работы

### Реализовано в feature/geosite-dns-routing / PR #11

1. Конфигурационная модель двух взаимоисключающих режимов: `dns_mode: endpoint_ip | resolver`; независимые DoH upstream режима 1 и упорядоченный `resolver_upstreams` режима 2; валидация system/UDP/TCP/DoH upstream и bootstrap-настроек.
2. ActiveDoHSelector вынесен в `internal/activedoh`; восемь control domains, DNS A/AAAA probes через каждого DoH candidate и HTTPS/TLS probes по IP с исходными hostname/SNI/Host.
3. Режим `endpoint_ip` возвращает bootstrap IP выбранного DoH endpoint-а, а не IP исходного QNAME. TTL положительного ответа ограничен 60 секундами и остатком freshness.
4. Режим `resolver` выполняет последовательный fallback для system, UDP, TCP и DoH upstream-ов. Транспортные ошибки, timeout, SERVFAIL/REFUSED и неисправимый TC ведут к следующему upstream; валидные NXDOMAIN/NODATA завершают resolution.
5. Cache пространства режимов разделены. Положительный TTL режима 2 ограничен 300 секундами; negative caching требует SOA и использует `min(SOA RR TTL, SOA.MINIMUM)` с cap 300 секунд. Ответы без SOA и synthetic NODATA не кэшируются.
6. Default `tst-domen.txt` содержит девять проверок: восемь selector domains и `accounts.google.com`; пользовательские существующие файлы не перезаписываются.
7. Xray Geosite policy остаётся ручной и соответствует §4.4. Read-only checker проверяет структуру правил, но не доказывает фактическую загрузку Geosite asset или end-to-end клиентский путь.

### Проверки кода и VPS

Для code head `7fae2fdc1678f7f7cbb8ab758d60a483f151c6d1` успешно завершились оба workflow: CI run `44820128876` и DoH integration run `44820126933`. CI включает `go vet ./...`, `go test ./...`, проверку shell/JavaScript syntax, regression tests read-only Geosite DNS checker-а и Linux amd64 build. Integration workflow включает Go integration/unit tests, Python compile/unit/synthetic SQLite lifecycle tests и shell syntax. Эти результаты относятся к указанному head.

На VPS 2026-11-20 с DoH Health Monitor 2.3.0 и Xray `26.10.21` подтверждены:
- сервис плагина и HTTP status endpoint доступны;
- UDP/TCP listener плагина работает на `127.0.0.1:5355`;
- прямой A query к plugin listener по UDP и TCP возвращал bootstrap IP выбранного endpoint-а; положительный A cache hit подтверждён повторным запросом с одинаковым DNS COOKIE поведением;
- Xray config проходил `xray run -test`;
- DNS outbound с `geosite:habr` и catch-all `hijack` присутствовал в конфигурации;
- Xray и plugin service использовали один network namespace.

На момент VPS-проверки постоянного клиентского WireGuard/TProxy Tunnel inbound в конфигурации панели не было. Поэтому полный маршрут от пользовательского клиента через inbound до DNS outbound и обратно не подтверждён. Это остаётся отдельным обязательным тестом после появления inbound. Наличие текстов `habr` в файле Geosite и успешный parse config сами по себе не доказывают, что реальная QNAME lookup совпадает с нужной категорией.

## 9. Что остаётся проверить до снятия Draft

Следующие проверки не считаются завершёнными по одному только факту прохождения CI или успешного `xray run -test`:

1. Полный пользовательский путь: WireGuard/TProxy client inbound → routing TCP/UDP port 53 → `dns-out` → plugin UDP listener → ответ клиенту.
2. Реальное совпадение тестовых QNAME с `geosite:habr` в активном Geosite asset целевой сборки.
3. Порядок и фактическая семантика DNS outbound rules в используемой встроенной сборке Xray.
4. Доступность `127.0.0.1:5355/UDP` из network namespace Xray.
5. Поведение non-A/AAAA для обеих веток: Geosite `direct` в plugin listener и non-Geosite `hijack` во встроенный DNS.
6. CNAME chain, EDNS/DO, DNSSEC flags и ответы с OPT на реальных клиентских пакетах. Полноценная DNSSEC validation плагином не реализуется.
7. Сетевой egress к bootstrap DNS, выбранным DoH endpoint-ам и resolver upstream режима `resolver`.
8. Отсутствие косвенной DNS-петли через локальные stub resolver, TProxy или NAT.

Структурный checker может подтвердить, что JSON содержит ожидаемые rewrite target, Geosite direct, catch-all hijack и port-53 route. Он не должен требовать `xui-dns-allow` или считать его частью схемы; также он не может подтвердить загруженную категорию, активный runtime или фактический клиентский трафик.

## 10. Ограничения и границы изменений

- PR #11 остаётся Draft до прохождения клиентского end-to-end теста на целевом runtime и устранения найденных дефектов.
- Не добавлять внутренний Geosite matcher в плагин: Geosite matching остаётся ответственностью Xray.
- Не создавать `dns.servers` entry для `127.0.0.1:5355`; plugin listener вызывается через DNS outbound rewrite target.
- Не создавать `xui-dns-allow`, отдельное routing-исключение для порта 5355 или allow-правило в `freedom.finalRules`: они не являются частью утверждённой схемы.
- Не менять фактическую конфигурацию панели автоматически; ручная конфигурация §4.4 является целевой.
- Не считать read-only структурную проверку доказательством end-to-end работы, корректности Geosite asset или поведения конкретной встроенной сборки.
- Не привязывать архитектуру к номеру версии панели/Xray; проверять фактический формат и поведение целевого runtime.
- Версия 2.3.0 находится в feature branch как release candidate; официальный tag/release не создавать до отдельного release gate.

---

**Текущее резюме:** в PR #11 реализована базовая архитектура Geosite DNS routing: разделённые режимы `endpoint_ip` и `resolver`, ActiveDoHSelector по восьми контрольным доменам с HTTPS/TLS probes, два DNS response pipeline, независимые cache namespace/generation, fallback и TTL/negative-cache policy. `Blackhole` — `NOERROR`/NODATA без SOA и без кэширования; plugin DNS listener отвечает только на A/AAAA. Успешный CI подтверждает тесты кода на зафиксированном head, но не проверяет конкретную интеграцию LucX-UI/Xray, WireGuard/TProxy и сетевой namespace. Проверка целевого runtime и решение о дальнейшей автоматизации остаются следующими этапами.
