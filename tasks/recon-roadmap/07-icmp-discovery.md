# ICMP echo-обнаружение

Фаза: 2 — Улучшение обнаружения хостов
Статус: Выполнено (ветка feat/recon-roadmap, 2026-11-08; IPv4; живой прогон требует root/CAP_NET_RAW)
Зависит от: —
Роадмап: docs/recon-roadmap.md (Фаза 2)

## Цель

Добавить обнаружение хостов через ICMP echo (`--discovery icmp`) для сетей, где ICMP разрешён — стандартный ping-sweep, которого сейчас нет.

## Область

- Строить raw ICMP echo-request пакеты для IPv4 (и ICMPv6 echo для IPv6, где позволяют права), следуя паттернам raw-пакетов из `src/scanner/syn.rs`.
- Сопоставлять echo-ответы с исходящими запросами (identifier + sequence).
- Аккуратно обращаться с лимитами: некоторые хосты рейт-лимитят ICMP, поэтому ретраи и per-host пейсинг важнее, чем для TCP.
- Пробросить как режим обнаружения в `Args::AddressScan`; непривилегированный дефолт остаётся connect-based пробами.
- Уважать выбор интерфейса, таймаут, ретраи, конкурентность и лимиты скорости.

## Критерии приёмки

- [x] Режим ICMP находит хосты, пропускаемые текущими TCP-пробами, там где ICMP разрешён (IPv4 raw-сокет; живой прогон требует root/CAP_NET_RAW).
- [x] ICMP destination-unreachable помечает хосты как недоступные (факт, не догадка).
- [x] Молчание после ретраев помечает хост как недоступный с записью `no-response`, отличимой в структурированном выводе от вердикта unreachable (`--show-down`, поле `reason`).
- [x] IPv6 echo-обнаружение не реализовано; IPv6-цели откатываются на TCP с ясным предупреждением (осознанное ограничение).
- [x] Тесты покрывают конструирование ICMP-пакета и checksum, разбор echo reply с IP-заголовком и без, destination-unreachable с вложенным запросом, отказы и CLI-откат.

## Вне области

- ICMP-пробы timestamp, netmask, information-request.
- OS-fingerprinting по поведению ICMP.


## Реализация

- `src/scanner/discovery/icmp.rs` — raw IPv4 ICMP-сокет, echo request с checksum, общий приёмник на поток с очередью отправки, сопоставление по sequence (id игнорируется: ядра могут его переписывать), разбор echo reply и destination-unreachable с вложенным запросом.
- `src/scanner/address.rs` / `src/main.rs` — `--discovery icmp`, параллельный обход, `--retries`, `--rate`/`--delay`, `-e`, progress bar; `--show-down` добавляет записи `status: "down"` с `reason: "unreachable" | "no-response"`.
- `src/output/mod.rs` — поля `proto`/`scan`/`discovery` со значением `icmp`, поле `reason`, колонки CSV/grep.
- `src/iface.rs` — `bind_raw` для привязки raw-сокета к `-e`.
- IPv6 и отсутствие root/CAP_NET_RAW — откат на TCP с предупреждением.
