# Native host lifecycle — implementation boundary

Нормативная цепочка — [ARCHITECTURE.md](ARCHITECTURE.md); единственный план и критерии — [FINALIZATION-PLAN.md](FINALIZATION-PLAN.md). Этот файл **не отдельный план**.

`/host status|apply|recover` → exact Git desired/ReleaseSet → Rust planner → Worker-signed HostIntent → GitHub Actions transport → native root Agent / SYSTEM Controller → local durable BEGIN → bounded mutation → readback → authenticated receipt.

- Новый VM first-use разрешает существующий Vultr provider CREATE/bootstrap с ограниченным SSH только до установки native owner и регистрации его отдельного public receipt key в защищённом Git. Worker signer и CredentialRef сверяются до provider CREATE; не переносить прежние private/receipt keys.
- После первого развёртывания VM штатный root `local host-refresh` (без аргументов) получает exact protected release сам; `local host-apply` — единственный VM resource effector. Hosted SSH, `docker exec`, старые bundle/credential RPC и historical A/B не являются путями восстановления.
- Перед BEGIN нужен точный owner/Git/Worker/scope proof. После неизвестного эффекта — `UNKNOWN_NO_REPLAY` и только адресная read-only диагностика. Runner-copied observation/CI не заменяют native receipt.
- Кодовая очистка принята через PR #448–451. Физическая VM, Windows SYSTEM/TUN и внешние endpoints остаются `UNPROVEN` до gates в плане.
