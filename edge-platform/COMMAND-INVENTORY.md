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

Существующий `edge-agent local host-enroll` от root проверяет опубликованный
ReleaseSet, точный Git tree/spec и pinned Worker key. Повторный вызов с тем же
`machine_id` и ключом атомарно заменяет **один** `trust.pb`,
сохраняя прежний журнал; `*.pending.pb` блокирует обновление.
Один kernel lock исключает пересечение с `local host-apply`. Диагностика
отличает `UNENROLLED`, `PROTECTED_LOCAL_ONLY`,
`UNKNOWN_NO_REPLAY` и `UNPROVEN`. Это source code PR #403, не
физическая приёмка и не разрешение runner запускать root enrollment.
Runner со старыми прямыми `sudo`-правами **не допускается** к VM
apply/recover. Внутренний Rust `host native-result` сверяет
intent/result по registry/desired/release, но его transport-копия
остаётся `UNAUTHENTICATED`, не физическим receipt.
Сквозной автоматический lifecycle для Windows и VM пока не доказан.

## VM deep diagnostics — per-resource protobuf (source-only)

`host status <id> --deep` использует один существующий root Agent
(`local host-resources`) для bounded protobuf по каждому Git-owned Docker
ресурсу: presence, Compose owner, container ID, running, health, image,
restart count и reason. Не читает env, credentials или Docker logs.
GitHub переносит копию, Rust Orchestrator сверяет её со своим
каноническим реестром и печатает причины по контейнерам.
Runner-копия не аутентифицирует root и не разрешает mutation;
отсутствие установленного verb — UNPROVEN, не PASS.

## Docker resources — один Git-owned scope

`hosts.textproto` теперь задаёт для каждой VM только отсортированные
`vm_containers` (container name + Compose project/service). Это не второй
compose/config: образ, ports, secrets и настройки остаются в ReleaseSet.
Rust Agent читает scope из защищённого `trust.pb` и перед STOP/RUNNING
сверяет Docker labels + immutable ID; незаявленный/чужой контейнер не
становится своим. Без trust или без selectors состояние `UNPROVEN`,
а не доступ ко всем контейнерам. VM target по-прежнему unset/observe-only.
Это код PR #403, не физическая установка или проверка публичного интернета.

## Допуск новой операции

Только строго типизированные `machine_id / resource_id / desired_digest / immutable_release / operation_id / native_owner` и однозначные `READY | DEGRADED | BLOCKED | UNKNOWN_NO_REPLAY`. Нет старого `Issue #26` как mutation authority: старые comments — неизменяемый архив, не исходное желаемое состояние. Для сбоя секретов — fresh Worker-provision с **новой** resource identity, без переноса старой A/B, только после проверки границ собственности старого ресурса. Удалять старые файлы и контейнеры можно при доказанном scope и сохранённом способе доступа; не трогать Cloudflare One, Mesh других проектов и общую инфраструктуру.

До физической приёмки **система не 10/10**. VM root execution требует явный Git RUNNING/STOPPED target, защищённый trust и подпись Worker; старые mutation-команды запрещены. [Нормативная архитектура](ARCHITECTURE.md), [единственный план](FINALIZATION-PLAN.md), [живой курсор](https://github.com/iamaman11/sing-box/issues/26).
