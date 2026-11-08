# TCP/ICMP traceroute

Фаза: 5 — Топология и отчётность
Статус: Выполнено (ветка feat/recon-roadmap, 2026-11-08; IPv4, нужен root/CAP_NET_RAW)
Зависит от: — (переиспользует платформу raw-пакетов из `src/scanner/syn.rs`)
Роадмап: docs/recon-roadmap.md (Фаза 5)

## Цель

Добавить traceroute (`asphyxia trace <target>`) с полатентностью по хопам и индикаторами потерь, чтобы оператор видел путь до цели и понимал, где пробирование впервые становится молчаливым.

## Область

- Строить пробы с возрастающим TTL и собирать ICMP time-exceeded (type 11) от промежуточных хопов; переиспользовать raw-socket + pcap-приёмник из `src/scanner/syn.rs`.
- Два транспорта: TCP-traceroute (SYN к заданному порту — проходит фаерволы, режущие ICMP) и ICMP-traceroute (echo). Флаг выбирает транспорт; TCP по умолчанию.
- На хоп: адрес, полатентность (несколько проб), индикатор потерь; молчащий хоп показывается как `*`, а не выпадает.
- Явно сообщать хоп, на котором пробирование впервые становится молчаливым (граница видимости).
- Уважать таймаут, ретраи (число проб на хоп) и лимиты скорости; IPv6 — либо поддержать, либо падать с ясным сообщением.

## Критерии приёмки

- [x] `asphyxia trace <target>` печатает хопы с RTT/потерями, `*` для молчащих и `first_silent_hop`.
- [x] TCP (по умолчанию) и ICMP транспорты реализованы; выбор документирован.
- [x] Отказ raw-сокета/libpcap и IPv6-цель падают с ясным сообщением, а не с ложным путём.
- [x] `-o json` — один отчёт, `-o jsonl` — `trace` + по записи на хоп + `summary`; имена полей стабильны.
- [x] Тесты покрывают TTL в IP-заголовке, разбор TCP reset, ICMP time-exceeded/unreachable с вложенным TCP/ICMP и рендер молчащего хопа.

## Вне области

- Path MTU discovery.
- Топологические графы нескольких целей (это отчётность, задача 16).


## Реализация

- `src/traceroute.rs` — `Transport` (tcp/icmp), raw IPv4 sender с `IP_HDRINCL`, один pcap-приёмник на трассу (фильтр `icmp or tcp syn/rst`), разбор ICMP time-exceeded/unreachable по вложенному пакету, TCP reset/SYN-ACK и ICMP echo reply, per-hop `loss_pct`/`silent`, `first_silent_hop`.
- `src/scanner/syn.rs` — `build_ipv4_probe_with_ttl` и общий `build_ipv4_packet`.
- `src/scanner/discovery/icmp.rs` — `build_ipv4_echo` с TTL.
- `src/cli/mod.rs` / `src/main.rs` — подкоманда `trace` с `--transport`, `--port`, `--max-hops`, `--probes`, `--timeout`, `-e`, `-o text|json|jsonl` и `--output-file`; IPv6/raw-отказы видимы.
- README/`--help` обновлены.
