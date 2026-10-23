# Продолжение работы над sing-box

**Не второй план.** Всегда читать актуальный защищённый [main](https://github.com/iamaman11/sing-box), [архитектуру](ARCHITECTURE.md), [единственный план и acceptance gates](FINALIZATION-PLAN.md), [команды](COMMAND-INVENTORY.md), [фактический курсор](https://github.com/iamaman11/sing-box/issues/26) и [операторский вход](https://github.com/iamaman11/sing-box/issues/1). Не принимать прошлый SHA, PR или этот handoff за актуальную истину.

Работать большими закончеными срезами без новых служб, SSH fallback, второго desired/secret store, generic root commands, A/B, replay или совместимости со старыми мутациями. Не повторять удаление ingress из PR #448–451. Не принимать CI за физическую установку.

При отсутствии факта — один точный read-only запрос существующему native/local agent (machine, owner, resource, digest, journal, reason, next action), `MUTATIONS=0`; зафиксировать `UNPROVEN/BLOCKED`. Приватные ключи и секреты не читать в чат/Issues. Windows STOPPED/PROXY_ONLY, TUN и чужой Cloudflare One/Mesh не трогать без явного Git desired и физического допуска.

Выполненные работы, новые блокеры и критерии должны отражаться **в [FINALIZATION-PLAN.md](FINALIZATION-PLAN.md)**; Issue #26 хранит короткое состояние/ссылки на доказательства, а не второй roadmap.
