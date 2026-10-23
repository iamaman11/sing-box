# sing-box — единственный рабочий интерфейс /host

Канон: защищённый [main](https://github.com/iamaman11/sing-box). Никаких отдельных пользовательских `/vm`, `/windows`, `/vultr`, `/credentials`, ручного SSH/docker exec.

| Команда | Текущая реальная семантика |
| --- | --- |
| `/host status [machine-id] [--deep]` | read-only: Git desired, runner, native Agent/SCM; для VM — bounded Docker-контейнеры, Compose scope, установленная конфигурация, локальная сеть, DNS и nft readback; неизвестность = UNPROVEN |
| `/host apply <machine-id>` | разовый типизированный Git ReleaseSet → native root Agent; установка пустой VM, Start/Stop, ReplaceRelease, согласованная конфигурация по immutable Git desired, журнал и receipt |
| `/host apply <machine-id> config/vultr-edge/line1-gateway` | точная ограниченная правка конфигурации Line1 с Git-authorized signed intent, без изменения других Docker ресурсов |
| `/host apply <machine-id> config/vultr-edge/line2-proxy` | точная ограниченная правка конфигурации Line2 |
| `/host recover <machine-id>` | типизированный read-only preflight; нельзя replay UNKNOWN; не универсальная переустановка |

## Единственный VM owner

До первого bootstrap: Vultr API + SSH строго для установки первого Agent/runner. Git защищает неизменяемый ReleaseSet, native receipt identity и Worker signer pin. После bootstrap GitHub-hosted SSH refresh отсутствует. Уже установленный root Agent выполняет `local host-refresh` без аргументов: берёт `releases/latest` и `heads/main`, сверяет SHA/asset/публичные ключи, атомарно обновляет trust и собственный бинарник под общим root lock. Runner имеет только разрешённую пару `host-refresh` и `host-apply`, без общего root или Docker socket. При несоответствии точной версии бинарника ReleaseSet — BLOCKED до исправления, не replay.

## Реальные границы (не выдавать за готовое)

- DNS, firewall, маршрутизация VM: read-only kernel/nft/DNS + Docker network resources; **произвольная самостоятельная нативная мутация DNS/firewall/host routes НЕ реализована** как `/host apply`. Нельзя запускать shell/SSH вместо handler.
- Windows: `sing-box-windows-lab` намеренно `STOPPED / PROXY_ONLY`. Нативный Windows SYSTEM apply, управляемый TUN, reboot/rollback приёмка — НЕ ПРИНЯТЫ. Не запускать SCM и не менять TUN/DNS/default route.
- Worker Access: тестовый JWT контракт PASS, физический `/v1/host/authorize` до исправления Access политики даёт `403`; без read-only доказательства фактической конфигурации подписанный INSTALL не считать рабочим.
- Точные положительные сетевые результаты (3/3 контейнера, 4/4 Line1, 6/6 Line2, TLS, auth, DIRECT/WARP) требуют физической проверки после нового CREATE. CI и GitHub runner не заменяют end-to-end proof.
- Никаких других агентов, служб, A/B recovery, дублирующих desired/secret registries и бесконечных retry.

## Как выполнять запрос из чата

Прочитать защищённый `main` → `/host status --deep` → объяснить один exact reason → при доказанном scope обновить Git desired/release → `/host apply` через Issue #1 и дождаться GitHub Actions + signed native receipt → независимая внешняя проверка. GitHub connector в этом чате может публиковать операторские команды в Issue #1 и читать Actions, но не имеет прямых root/SCM/Vultr полномочий. Секреты остаются в защищённом GitHub Environment/Worker, а физическое исполнение принадлежит только установленному Agent/Controller. Публикация комментария не является доказательством созданной VM или успешного native receipt. При отсутствии инструмента, штатной авторизации или receipt результат остаётся UNPROVEN.

**Транспортный контракт:** Rust формирует закрытый `HostWorkflowOperation` и записывает `operation` в существующий GitHub Actions scalar output; условия Actions читают поле `operation` через `needs.host.outputs.operation`. Текстовые строки лога не разрешают mutation. Внутренние Rust read-only/ReleaseSet build verbs — не дополнительные пользовательские `/host` команды. Удалён парсер старых прямых Vultr/VPC/application и VM credential/bootstrap mutation команд.

JSON не является форматом внутренних управляющих решений. JSON используется только там, где необходим внешнему GitHub API или matrix; `/host` operation — закрытый Rust enum → неизбежный скалярный output Actions. HostIntent/receipt/readback — Protobuf.

VM `edge-agent` does not expose the old gRPC acceptance listener or retired direct bundle/credential mutation CLI; both were removed as executable code, not merely hidden. Exact physical VM operations are strictly `host status|apply|recover`; receipt registration continuation is also decoded from bounded Rust-generated schema-1 `host_action_json`. Status is read-only; apply/recover are signed native owner transactions. Do not infer a successful install from a CI-only ReleaseSet.
