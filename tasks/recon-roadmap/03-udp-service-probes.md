# UDP-пробирование сервисов

Фаза: 1 — Расширение семейства сканирований
Статус: Выполнено (выпущено в 0.11.0, 2026-11-08)
Зависит от: 02-fin-null-xmas-scans (общая обработка ICMP type 3)
Роадмап: docs/recon-roadmap.md (Фаза 1)

## Цель

Достроить существующий базовый UDP-режим (`--udp` уже есть в `src/scanner/port.rs`, сообщает `open|filtered`) до полезного пробирования сервисов. Пустая UDP-датаграмма редко вызывает ответ, поэтому многие порты выглядят `open|filtered`. Прицельные payload-пробы для типовых сервисов вызывают настоящий ответ и позволяют отличить `open` от `open|filtered`, а обработка ICMP port-unreachable даёт `closed`. Это закрывает крупную разведочную поверхность (DNS, SNMP, NTP), которую TCP не видит.

## Область

- Добавить таблицу payload-проб по портам для типовых UDP-сервисов: DNS/53 (стандартный query), NTP/123, SNMP/161 (get-request с public-community), опционально NetBIOS/137, mDNS/5353.
- Классификация:
  - Пришёл UDP-ответ → `open` (факт)
  - ICMP port-unreachable (type 3, code 3) → `closed`
  - ICMP other-unreachable (админ-фильтр, code 1/2/9/10/13) → `filtered`
  - Нет ответа после ретраев → `open|filtered` (вывод, не факт)
- Переиспользовать приёмник pcap/BPF из `src/scanner/syn.rs` для чтения ICMP-ответов вместо отдельного цикла захвата; при недоступности raw — работать на UDP-сокете и различать `closed` по `ECONNREFUSED`.
- Ретраи и per-host пейсинг важнее, чем для TCP: многие хосты рейт-лимитят ICMP-ответы (RFC 1812), из-за чего `closed` теряется — документировать это.
- Пробросить в существующий `--udp` без слома текущего поведения; порт без известной пробы отправляет пустую датаграмму, как сейчас.

## Критерии приёмки

- [x] Порт с известной пробой (например, DNS/53 на резолвере) сообщает `open`, а не `open|filtered`.
- [x] ICMP port-unreachable даёт `closed`; прочие ICMP-unreachable дают `filtered`; различимы в структурированном выводе.
- [x] Молчание после ретраев остаётся `open|filtered` и явно помечено как вывод.
- [x] При недоступности raw-сокетов режим откатывается на UDP-сокет с видимым предупреждением и не заявляет ложно об `open`.
- [x] Лимиты скорости, таймауты, ретраи и конкурентность применяются к UDP-пробам.
- [x] Тесты покрывают конструирование payload-проб, классификацию по типам ICMP-ответа и различимость `open` vs `open|filtered`.

## Что сделано

- `src/scanner/port.rs`: `UdpHit` теперь несёт строку состояния (`open`/`closed`/`filtered`/`open|filtered`) вместо bool, так что каждый пробованный порт репортится со своим наблюдаемым состоянием. `classify_udp` различает ICMP port-unreachable (ConnectionRefused → closed) от прочих unreachables (HostUnreachable/NetworkUnreachable → filtered). Таблица payload-проб расширена: DNS/53 (root NS query), NTP/123 (client request), SNMP/161 (GET systemDescription с public community), NetBIOS/137 (node status query), mDNS/5353 (PTR _http._tcp.local.). Каждый payload юнит-тестится на well-formedness.
- `src/main.rs`: `scan_one` репортит каждый UDP-порт со своим статусом вместо только открытых; текстовый заголовок «Port states» для UDP-сканов, как и для ACK/stealth.
- Тесты: юнит — классификация ICMP (port-unreachable → closed, other-unreachable → filtered), well-formedness payload'ов SNMP/NetBIOS/mDNS; e2e — closed vs open различимы в структурированном выводе, silent порты репортятся с валидным состоянием, rate-limit пейсинг применяется к UDP-пробам, refusals коротко замыкают retry budget.

## Проверка вживую

`cargo test`: 136 юнит + 70 e2e + 16 интеграционных — все зелёные; clippy и fmt чистые. UDP-скан против loopback:1 (closed, ICMP refusal) и локального echo-сервера (open) даёт различимые состояния в JSONL.

## Поставка

- Ветка `feat/recon-roadmap`, четыре коммита по отдельности, каждый собирается и зелёный сам по себе:
  - `cd75802` feat(udp): classify ICMP unreachables and report all states
  - `2df199e` feat(ps): report UDP states in the scan output
  - `c38e0fa` test: cover UDP service probes and state classification
  - `6fd8574` docs(readme): document UDP service probes

## Вне области

- Полное определение версий UDP-сервисов — делегируется хендоффу в `nmap` (`-sU -sV`).
- UDP-amplification и любые нагрузочные сценарии.
