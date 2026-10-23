# Vultr WAW stack — repository inputs

Это каталог существующих bootstrap/runtime файлов, **не второй control plane**. Действующая [архитектура](../../edge-platform/ARCHITECTURE.md), [план](../../edge-platform/FINALIZATION-PLAN.md), [операторские команды](../../edge-platform/COMMAND-INVENTORY.md).

В `stack/docker-compose.yml` могут оставаться профили `tunnel` (`line1-gateway`, `line2-proxy`, `warp-egress`) и `mesh` (`cloudflare-mesh`). Физическая новая VM `application-acceptance-3` принимает **3/3** контейнера Line1/Line2/WARP по typed Git desired. Mesh имеет отдельное ownership: не затрагивать его без отдельного Git scope. Образ/конфиг — exact ReleaseSet, секреты — только Worker/native private owner.

**Единственный штатный путь:** `/host status|apply|recover` через GitHub Issue #1; first-use Vultr engine, затем signed Root Agent с журналом и receipt. Self-hosted runner — ограниченный транспорт. Нет прямого PowerShell/SSH/docker/Compose mutation, `/production rollback`, старых `bundle-converge` команд или legacy A/B как способа восстановления.

Физическая готовность определяется независимыми native readback + signed receipt + TLS/auth/DIRECT/WARP 4/4 и 6/6, не исходным Docker Compose файлом. Без подтверждения `UNPROVEN`.
