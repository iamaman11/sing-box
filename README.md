# sing-box

**Единственный канонический источник истины:** защищённый [GitHub main](https://github.com/iamaman11/sing-box/tree/main). Старые чаты, локальные копии, issue и PR не заменяют этот репозиторий.

| Назначение | Источник |
| --- | --- |
| **Архитектурный контракт и роли** | [edge-platform/ARCHITECTURE.md](edge-platform/ARCHITECTURE.md) |
| **Единственный текущий план завершения и физической приёмки** | [edge-platform/FINALIZATION-PLAN.md](edge-platform/FINALIZATION-PLAN.md) |
| **Единственный интерфейс и фактически поддерживаемые команды** | [edge-platform/COMMAND-INVENTORY.md](edge-platform/COMMAND-INVENTORY.md) |
| Исторические события, текущие readback и journal | [Issue #26](https://github.com/iamaman11/sing-box/issues/26) |
| Единственный операторский вход | [Issue #1](https://github.com/iamaman11/sing-box/issues/1) |

## Что представляет собой приложение

Git desired + Protobuf/Rust DAG planner → immutable ReleaseSet → Cloudflare Worker signed HostIntent/CredentialRef → один native owner (VM root Agent / Windows SYSTEM Controller) → durable journal → authenticated receipt и независимый physical readback. GitHub Actions/runner — транспорт, не root/SCM authority.

Единственный публичный операторский язык: `/host status|apply|recover`; `recover` пока только read-only preflight. Старые `/vm`, `/windows`, `/credentials`, `/production`, SSH/docker exec и прямые системные команды не являются путями управления.

## Реальная готовность

Кодовый срез криптографии/Worker PR [#473](https://github.com/iamaman11/sing-box/pull/473) слит и принят CI. **Физическая приёмка VM/Windows не завершена.** По последнему read-only Cloudflare witness Worker находится в состоянии старый `active` / новый `pending` после незавершённого upload, а VM `application-acceptance-3` показывает `VM_RELEASE_ABSENT_LOCAL_ONLY`, 0/3 контейнера. Точные идентификаторы, запреты на replay, незавершённый owner transition и критерии завершения — в [единственном плане](edge-platform/FINALIZATION-PLAN.md). Перед действием заново сверять GitHub и provider.

CI, source code, опубликованный ReleaseSet, runner-copied Protobuf и `content/v2` без version-bound proof не являются доказательством установленного или работающего приложения. Windows `STOPPED/PROXY_ONLY`; TUN/SYSTEM без нового Git desired и допуска не запускать. Чужой Cloudflare One/Mesh не изменять.

Остальные README в каталоге — только краткие технические примечания; они не задают планы, новые команды или разрешения на мутацию.
