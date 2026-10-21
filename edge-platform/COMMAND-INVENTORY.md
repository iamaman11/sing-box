# Команды sing-box — один целевой интерфейс

**Единственный разрешённый публичный API нового продукта** — `/host status [machine-id] [--deep]`, `/host apply <machine-id>`, `/host recover <machine-id>`. Команда изменения всегда требует однозначный `machine_id`. Содержимое `desired` — только типизированный Git-owned ресурс, никаких сохранённых ручных профилей.

| Команда | Требуемое поведение | Что сейчас доказано |
| --- | --- | --- |
| `/host status` | Ограниченная read-only диагностика парка, независимые ответы; `UNPROVEN` не PASS | Windows + acceptance VM работают; production runner всё ещё queued |
| `/host apply <id>` | Один Rust intent → новый per-resource ReleaseSet → native install/reinstall/replace → физическое подтверждение | **UNPROVEN**: coordinator готовит PREPARED; VM runner может передать intent root Agent, но Git target/trust не принят; Windows read-only |
| `/host recover <id>` | Для *новой* типизированной операции: read-only diagnosis → ограниченная замена/переустановка только собственных ресурсов, без повтора UNKNOWN | **UNPROVEN**: VM — signed one-shot, без replay; Windows — только preflight; физическая приёмка отсутствует |

## Исторические входы (ЗАПРЕЩЕНЫ, даже если код ещё содержит их)

`/windows`, `/vm`, `/production`, `/credentials`, `/vultr`, `/vpc`, `/application`, старые workflow исторической A/B, любые прежние профили, ручные пути, миграции и резервные secret-fallback. Не запускать их ни из ChatGPT, ни локально, ни через отдельный workflow. В PR #402 публичный Issue ingress к этим backend уже удалён; reusable backend файлы пока существуют в Git как исторический код, но не вызываются оператором. Нативная fresh install/replace реализация ещё не принята; никаких обходных вызовов backend.

## VM root trust (внутренняя операция, не четвёртая публичная команда)

Root-only `edge-agent local host-enroll <machine-id> <release-set-sha256>`
проверяет опубликованный ReleaseSet, Git tree/spec и публичный ключ Worker
из **того же** защищённого Git registry. Аргумента с ключом и fallback нет.
Refresh меняет только `trust.pb`, сохраняя journal; `*.pending.pb` и
общий kernel lock блокируют небезопасное обновление.
Диагностика: `UNENROLLED` / `PROTECTED_LOCAL_ONLY` /
`UNKNOWN_NO_REPLAY` / `UNPROVEN`. Runner не получает sudo enrollment
и произвольные VM mutations. Rust `host native-result` аутентифицирует
подписанный receipt, но transport-копия без проверки — `UNAUTHENTICATED`.
Физическая приёмка ещё UNPROVEN.

## VM deep diagnostics — per-resource protobuf (source-only)

`host status <id> --deep` использует один существующий root Agent
(`local host-resources`) для bounded protobuf по каждому Git-owned Docker
ресурсу: presence, Compose owner, container ID, running, health, image,
restart count и reason. Не читает env, credentials или Docker logs.
GitHub переносит копию, Rust Orchestrator сверяет её со своим
каноническим реестром и печатает причины по контейнерам.
Runner-копия не аутентифицирует root и не даёт mutation; verb отсутствует — UNPROVEN.

## Docker resources — один Git-owned scope

`hosts.textproto` теперь задаёт для каждой VM только отсортированные
`vm_containers` (container name + Compose project/service). Это не второй
compose/config: образ, ports, secrets и настройки остаются в ReleaseSet.
Rust Agent читает scope из защищённого `trust.pb` и перед STOP/RUNNING
сверяет Docker labels + immutable ID; незаявленный/чужой контейнер не
становится своим. Без trust или без selectors состояние `UNPROVEN`,
а не доступ ко всем контейнерам. VM target по-прежнему unset/observe-only.
Это только код PR #403; физическая приёмка — UNPROVEN.

## VM first-use (только код)

Git `vm_first_use_credential` — Worker-v2 generation/digest.
Signed INSTALL: Worker proof → durable BEGIN → ACTIVE и native Docker.
Сбой — `UNKNOWN_NO_REPLAY`. Worker issuance/physical acceptance — UNPROVEN.

## Допуск новой операции

Только строго типизированные `machine_id / resource_id / desired_digest / immutable_release / operation_id / native_owner` и однозначные `READY | DEGRADED | BLOCKED | UNKNOWN_NO_REPLAY`. Нет старого `Issue #26` как mutation authority: старые comments — неизменяемый архив, не исходное желаемое состояние. Для сбоя секретов — fresh Worker-provision с **новой** resource identity, без переноса старой A/B, только после проверки границ собственности старого ресурса. Удалять старые файлы и контейнеры можно при доказанном scope и сохранённом способе доступа; не трогать Cloudflare One, Mesh других проектов и общую инфраструктуру.

До физической приёмки **система не 10/10**. VM root execution требует явный Git RUNNING/STOPPED target, защищённый trust и подпись Worker; старые mutation-команды запрещены. [Нормативная архитектура](ARCHITECTURE.md), [единственный план](FINALIZATION-PLAN.md), [живой курсор](https://github.com/iamaman11/sing-box/issues/26).


First-use: draft PR до CREATE → enrollment → protected merge/ReleaseSet → root trust refresh → signed INSTALL. UNKNOWN без replay; физически UNPROVEN.
