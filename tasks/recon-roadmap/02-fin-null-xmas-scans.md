# Сканы FIN, NULL и XMAS

Фаза: 1 — Расширение семейства сканирований
Статус: Выполнено (0.11.0; ICMP `filtered` — в 0.11.1)
Зависит от: 01-ack-scan (общая обвязка флаг-профилей)
Роадмап: docs/recon-roadmap.md (Фаза 1)

## Цель

Добавить три малозаметных режима скана поверх той же платформы raw-пакетов, что и SYN: FIN (установлен `FIN`), NULL (без флагов) и XMAS (`FIN|PSH|URG`). Все три опираются на поведение по RFC 793: закрытый порт отвечает RST, открытый молча отбрасывает неожиданный пакет, поэтому молчание означает `open|filtered`.

## Область

- Обобщить конструирование TCP-пакетов в `src/scanner/syn.rs` для комбинаций FIN / NULL / XMAS (в идеале через один параметр флаг-профиля, общий с ACK-работой).
- Правила классификации по режимам:
  - Получен RST → `closed`
  - ICMP unreachable (type 3) → `filtered`
  - Нет ответа → `open|filtered`
- Новые CLI-флаги (`--scan fin|null|xmas`), проброшенные через `Args::PortScan`, с переиспользованием пути отката SYN.
- Явно помечать `open|filtered` во всех форматах вывода, чтобы выведенные состояния отличались от наблюдаемых фактов (принцип: факты важнее догадок).

## Критерии приёмки

- [x] Каждый режим сообщает `closed` (RST) и `open|filtered` (молчание); результаты никогда молча не сливаются с `open`.
- [x] ICMP unreachable классифицируется как `filtered`; pcap-фильтр теперь захватывает ICMP, а вложенный TCP-пакет даёт target/port.
- [x] IPv6 откатывается на connect-скан с предупреждением (у FIN/NULL/XMAS нет connect-эквивалента).
- [x] Применяется имеющийся откат при отказе raw-сокета/захвата.
- [x] Лимиты скорости, таймауты, ретраи и конкурентность применяются ко всем трём режимам.
- [x] Тесты покрывают конструирование флагов для каждого профиля, классификацию по режимам и различимость `open|filtered` в структурированном выводе.

## Что сделано

- `src/scanner/syn.rs`: `ProbeMode::Fin/Null/Xmas` с флаг-профилями (FIN=0x01, NULL=0x00, XMAS=FIN|PSH|URG) и метками; `classify_reply` читает RST как `closed` для всех трёх режимов по RFC 793, молчание (`Filtered`) вызывающий репортит как `open|filtered`; с Unreleased приёмник ловит ICMP unreachable, разбирает вложенный TCP и возвращает `filtered`.
- `src/cli/mod.rs`: `ScanMode::Fin/Null/Xmas` → новые `ProbeMode`, `silent_means_open_filtered()`, downgrade-сообщения называют каждый режим (FIN/NULL/XMAS).
- `src/main.rs`: `stealth_probe()` по образцу `ack_probe()` — RST финален (`closed`), молчание ретраится и репортится `open|filtered`; `status_str`/`scan_str` round-trip новых состояний и режимов; чекпоинты ключатся `tcp-fin`/`tcp-null`/`tcp-xmas` от *запрошенного* режима (совпадает с ключом даже при откате на connect); `--sV`/`--nmap` в этих режимах говорят, что делать нечего; текстовый вывод использует заголовок «Port states».
- `src/output/mod.rs`, `src/resume.rs`: документация полей `scan`/`status` расширена (`fin`/`null`/`xmas`, `closed`, `open|filtered`); тесты round-trip чекпоинтов stealth-режимов и их несовместимости друг с другом.
- Тесты: юнит — флаги каждого профиля на проводе (с контрольными суммами), матрица RST=closed / silence=open|filtered, исчерпывающий проход 0..=u8::MAX (никогда не `open`/`unfiltered`); e2e — каждый режим против loopback:1 (closed или откат), структурированный вывод несёт `"scan":"fin|null|xmas"` и только RFC-793-состояния, IPv6-откат с предупреждением, конфликт с `--udp`, пейсинг `--rate`, ключ чекпоинта `tcp-fin`.

## Проверка вживую

`cargo test`: 131 юнит + 64 e2e + 16 интеграционных — все зелёные; clippy и fmt чистые. Без привилегий проверен путь отката: печатается «FIN scan needs root/CAP_NET_RAW — falling back to connect scan», результаты помечаются `"scan":"connect"`.

## Поставка

- Ветка `feat/recon-roadmap`, пять коммитов по отдельности, каждый собирается и зелёный сам по себе:
  - `293bc8d` feat(syn): add FIN, NULL and XMAS probe profiles
  - `e6cb335` feat(cli): accept --scan fin|null|xmas
  - `2584bfc` feat(ps): report FIN/NULL/XMAS results as closed or open|filtered
  - `b2a3247` test: cover FIN/NULL/XMAS flag profiles, classification and output
  - `675c69e` docs(readme): document the FIN/NULL/XMAS scans

## Вне области

- Эвристики под Windows-цели (некоторые стеки отвечают RST на открытые порты; отмечено в README как caveat, не угадывается).
