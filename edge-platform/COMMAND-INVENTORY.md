# Команды sing-box — один целевой интерфейс

**Единственный разрешённый публичный API нового продукта** — `/host status [machine-id] [--deep]`, `/host apply <machine-id>`, `/host recover <machine-id>`. Команда изменения всегда требует однозначный `machine_id`. Содержимое `desired` — только типизированный Git-owned ресурс, никаких сохранённых ручных профилей.

| Команда | Требуемое поведение | Что сейчас доказано |
| --- | --- | --- |
| `/host status` | Ограниченная read-only диагностика парка, независимые ответы; `UNPROVEN` не PASS | Windows + acceptance VM работают; production runner всё ещё queued |
| `/host apply <id>` | Один Rust intent → новый per-resource ReleaseSet → native install/reinstall/replace → физическое подтверждение | **НЕ ПРИНЯТО**: текущий Host выдаёт только `APPLY_PREFLIGHT` и `host_native_install_authority=NOT_YET_ACCEPTED`, мутаций нет |
| `/host recover <id>` | Для *новой* типизированной операции: read-only diagnosis → ограниченная замена/переустановка только собственных ресурсов, без повтора UNKNOWN | **НЕ ПРИНЯТО**: только `RECOVER_PREFLIGHT`; старый A/B journal больше не участвует в Host-допуске |

## Исторические входы (ЗАПРЕЩЕНЫ, даже если код ещё содержит их)

`/windows`, `/vm`, `/production`, `/credentials`, `/vultr`, `/vpc`, `/application`, старые workflow исторической A/B, любые прежние профили, ручные пути, миграции и резервные secret-fallback. Не запускать их ни из ChatGPT, ни локально, ни через отдельный workflow. В PR #402 публичный Issue ingress к этим backend уже удалён; reusable backend файлы пока существуют в Git как исторический код, но не вызываются оператором. Нативная fresh install/replace реализация ещё не принята; никаких обходных вызовов backend.

## Допуск новой операции

Только строго типизированные `machine_id / resource_id / desired_digest / immutable_release / operation_id / native_owner` и однозначные `READY | DEGRADED | BLOCKED | UNKNOWN_NO_REPLAY`. Нет старого `Issue #26` как mutation authority: старые comments — неизменяемый архив, не исходное желаемое состояние. Для сбоя секретов — fresh Worker-provision с **новой** resource identity, без переноса старой A/B, только после проверки границ собственности старого ресурса. Удалять старые файлы и контейнеры можно при доказанном scope и сохранённом способе доступа; не трогать Cloudflare One, Mesh других проектов и общую инфраструктуру.

До физической приёмки нового native install/replace/recover **система не 10/10**; только read-only preflight и статус. Изменения через устаревшие команды запрещены. [Нормативная архитектура](ARCHITECTURE.md), [единственный план](FINALIZATION-PLAN.md), [живой курсор](https://github.com/iamaman11/sing-box/issues/26).
