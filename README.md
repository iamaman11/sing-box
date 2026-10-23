# sing-box

**Единственный канонический источник:** защищённый [GitHub main](https://github.com/iamaman11/sing-box/tree/main). Старые чаты, старые issue/PR, локальные копии и прошлые SHA не определяют текущее состояние.

## Где смотреть

| Назначение | Единственный источник |
| --- | --- |
| Архитектурные инварианты и роли | [ARCHITECTURE.md](edge-platform/ARCHITECTURE.md) |
| **План оставшихся работ и критерии приёмки** | [FINALIZATION-PLAN.md](edge-platform/FINALIZATION-PLAN.md) |
| Реальный поддерживаемый операторский интерфейс | [COMMAND-INVENTORY.md](edge-platform/COMMAND-INVENTORY.md) |
| Текущий физический статус и исторические свидетельства | [Issue #26](https://github.com/iamaman11/sing-box/issues/26) |
| **Единственный вход** операторских команд | [Issue #1](https://github.com/iamaman11/sing-box/issues/1) |

Другие README, runbook, технические notes и история PR не являются самостоятельными планами либо разрешениями на мутацию.

## Продукт и состояние

Git desired + Protobuf/Rust planner → immutable ReleaseSet → подписанный Worker HostIntent → единственный native owner (VM root Agent / Windows SYSTEM Controller) → durable journal → физический readback и аутентифицированный receipt. GitHub Actions — транспорт, не root/SCM authority.

Три оператора: `/host status`, `/host apply`, `/host recover`. Никаких старых `/vm`, `/windows`, `/credentials`, `/production` как обходных пользовательских команд.

**Кодовый hard cut PR #448–451 и точный ReleaseSet опубликованы. Физическая приёмка нового VM и Windows ещё не выполнена.** Отдельный зелёный CI, release asset или runner-copied Protobuf не доказывают установку. Дальнейшие действия и точные gates — только в [плане](edge-platform/FINALIZATION-PLAN.md).

Не выполнять replay `UNKNOWN_NO_REPLAY`, не продолжать историческую A/B, не изменять независимый Cloudflare One/Mesh. Windows остаётся STOPPED/PROXY_ONLY до отдельного принятого desired и физического допуска.
