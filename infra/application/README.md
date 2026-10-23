# VM application inputs — implementation reference

**Не отдельный план и не операторский интерфейс.** Нормативный [ARCHITECTURE.md](../../edge-platform/ARCHITECTURE.md), единственный [FINALIZATION-PLAN.md](../../edge-platform/FINALIZATION-PLAN.md), действующие [три /host-команды](../../edge-platform/COMMAND-INVENTORY.md).

## Действующий desired и владельцы

Git `infra/hosts/hosts.textproto` определяет host/target и пути typed spec (например `infra/hosts/specs/application-acceptance-3.textproto`). Immutable ReleaseSet содержит digest установочного bundle/image/executable. Worker владеет секретами и signer; self-hosted runner — доставка, установленный VM root Agent — единственный mutating owner Docker/sing-box. Ни provider key, ни private receipt key, ни runtime secret не являются Git desired.

Наблюдение контейнеров — нативный Bollard/host readback. Изменения — только known scoped handler `host_native.rs` по подписанному intent, локальному lock/журналу и exact owner; не прямые Compose CLI команды оператора.

Для `application-acceptance-3` целевой Git состав — `line1-gateway`, `line2-proxy`, `warp-egress` (**3 контейнера**, Compose project `vultr-edge`). Сетевые endpoints, TLS/auth, DIRECT/WARP, DNS и firewall требуют независимого физического witness: `running`/NOOP не равен readiness.

## Форматы и устаревшие inputs

Protobuf/textproto — внутреннее управляемое состояние. JSON допустим как обязательный внешний формат (sing-box config, GitHub REST/Actions matrix) и в явно ещё потребляемых исторических input-файлах: они не становятся альтернативным desired. `infra/application/disposable-acceptance.json` и старые A/B snapshot/proof-slot notes — **не новый авторизованный путь** установки/credential mutation.

Сгенерированные Docker/Compose/sing-box файлы и локальные секретные projections — результат рендера native owner, а не самостоятельная база состояния. Удаление/замена устаревших inputs допустимы только после проверки реальных зависимостей first-use и тестов.

## Диагностика и эксплуатация

Использовать только `/host status <machine-id> --deep`, `/host apply <machine-id>` (включая ограниченный config resource), `/host recover <machine-id>` (сейчас read-only). Никаких устаревших `/vm diagnose`, `/production rollback`, A/B first-use, SSH runtime mutation, второго агента или generic Docker control. При неопределённом результате — `UNKNOWN_NO_REPLAY`.

Свежая VM, 3/3 контейнера и 10/10 Line1/Line2 не имеют физической приёмки только на основании исходников, GitHub CI или legacy свидетельств. Критерии и очередность — исключительно в [плане](../../edge-platform/FINALIZATION-PLAN.md).
