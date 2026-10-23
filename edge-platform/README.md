# edge-platform

Единое Rust/Protobuf управление sing-box: Git desired → Rust planner → Worker-signed intent → VM root Agent или Windows SYSTEM Controller → native readback/receipt.

**См. ровно три действующих документа:** [архитектура](ARCHITECTURE.md), [план и критерии приёмки](FINALIZATION-PLAN.md), [команды и текущие ограничения](COMMAND-INVENTORY.md). [Issue #26](https://github.com/iamaman11/sing-box/issues/26) хранит фактический статус и историю; [Issue #1](https://github.com/iamaman11/sing-box/issues/1) принимает команды.

Принятый код и ReleaseSet не равны физической готовности VM/Windows. Старые A/B и прямые mutation-маршруты не являются альтернативным восстановлением. Не создавать второй план, транспорт, сервис или владелец состояния.
