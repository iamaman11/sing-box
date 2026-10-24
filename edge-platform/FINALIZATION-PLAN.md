# sing-box — единственный план завершения и приёмки

**Канон:** защищённый [GitHub `main`](https://github.com/iamaman11/sing-box/tree/main). Нормативные ограничения — [ARCHITECTURE.md](ARCHITECTURE.md), реальные команды — [COMMAND-INVENTORY.md](COMMAND-INVENTORY.md). [Issue #26](https://github.com/iamaman11/sing-box/issues/26) — архив физических доказательств, **не второй план**; [Issue #1](https://github.com/iamaman11/sing-box/issues/1) — единственный операторский вход. Всегда сверять текущий SHA и локальный owner до операции.

## Текущий блокер — частичная VM INSTALL и неизученный native journal

Контрольный снимок 2026-10-24T23:09:49Z: protected `main=9f36677a0edd9419e36e04960c4db2c336da8aec`, ReleaseSet `865aa8103edc1f32c2f30d5c0f75c39420c32707a18b02c0c7e091400ff5581e`. Это **историческая точка доказательств**, не разрешение на повтор. Проверять fresh protected `main` при каждой операции.

- **Worker — ACCEPTED:** [PR #475](https://github.com/iamaman11/sing-box/pull/475) MERGED; [#40140245577](https://github.com/iamaman11/sing-box/actions/runs/40140245577) один source/version-bound deployment существующей версии `12286a19-8130-4d31-bb1d-5c7831016cdb`. Upload=0, secret writes=0. Worker pending mismatch **закрыт**, не возвращаться к старому PR/code-only gate.
- **VM — UNKNOWN_NO_REPLAY:** [INSTALL #40140549929](https://github.com/iamaman11/sing-box/actions/runs/40140549929) обновил root owner из exact ReleaseSet, но `host-apply` завершился `HOST_NATIVE_POSTSTATE_UNPROVEN` после возможных native effects. Подписанный terminal receipt не доказан.
- **Concurrent apply — FAILED PRE-APPLY:** [#40140582883](https://github.com/iamaman11/sing-box/actions/runs/40140582883) отказал на `HOST_NATIVE_JOURNAL_FILE_UNTRUSTED` при root refresh; host-apply не выполнялся. Оба HostIntent запрещено повторять.
- **Native readback — partial:** [#40140857338](https://github.com/iamaman11/sing-box/actions/runs/40140857338): три owned контейнера существуют, Line1/WARP running без полной приёмки, Line2 not running с 12 restarts. `UNPROVEN_NATIVE_OWNER_OR_RUNTIME`, 3/3 resource problems, TLS/auth/DIRECT/WARP, DNS, firewall, routes, 4/4+6/6 и signed receipt **не приняты**.
- **Read-only local-agent diagnosis:** `SING_BOX_NATIVE_ROOT_CAUSE_V1`, 2026-10-24T23:09:49Z, MUTATIONS=0. Источник дефекта в коде подтверждён: `create_new(true)` без Unix `0600` в native journal, в то время как scanner требует root-owned private regular files; `umask 022` способен дать `0644`, но фактический offending файл/umask **UNPROVEN**. Scanner прекращает обход на первом pending; poststate объединяет причины отказа. Line2 exit/log reason **UNPROVEN**.

**Жёсткое правило:** никакого VM APPLY/RECOVER, ручного chmod/chown, снятия pending, перезапуска/пересоздания контейнеров, SSH-runtime или второго root-транспорта до доказанного protected-local metadata + typed journal/physical readback. Runner-copied status не равно authenticated native owner receipt.

## Срез 1 — адресное исправление диагностики → безопасная VM-приёмка

Срез выполняется **в существующем Rust owner**, без новых служб, workflows, JSON-маршрутов или отдельных планов. Принятый Worker больше не менять.

1. Атомарно создавать **новые** pending/BEGIN/terminal journal records с Unix mode `0600` до первого байта, независимо от umask. **Ни одной нормализации старых файлов**. Провести полный fail-closed scan всех файлов даже после первого pending, сохранить `UNKNOWN_NO_REPLAY`.
2. Через существующий root Agent `local diagnose` и `/host status application-acceptance-3 --deep` вернуть ограниченные метаданные файлов (имя/тип/uid/gid/mode/timestamp/size), без secret values. Независимо показывать конкретные typed poststate gate failures, текущие observation reason codes и для owned Line2 exit/restarts/OOM плюс безопасную классификацию log hint (не raw Docker logs). Промаркировать runner-copy как `UNAUTHENTICATED`.
3. Автотесты: `umask 022` → private 0600 при создании; scanner обнаруживает плохой файл **после** pending; no replay для pending/unknown, no mutation при диагностике, no secret leak. Exact candidate CI **6/6**, merge protected main, no-rebuild release promotion. CI подтверждает код, **не VM**.
4. Только через **новое read-only** observation получить физически доказанный offending journal entry и Line2 failure. Сопоставить immutable journal BEGIN/pending/terminal с новым installed owner ReleaseSet; запрещено объявлять старую операцию успешной по metadata. Если восстановление доказательств/неизменности невозможно, вернуть `BLOCKED` и подготовить отдельно допускаемое owner-controlled recovery, но не скрытый повтор.
5. Лишь после доказанного и авторизованного решения Root Agent выполнить новый однократный signed HostIntent в строго ограниченном scope; принять signed native terminal receipt, 3/3 owned Docker containers, independent Line1 4/4 и Line2 6/6 TLS/auth/DIRECT/WARP, DNS, network/firewall/routes, и отрицательные scope-тесты чужого Mesh/Cloudflare One.

**Срез 1 закрыт только при полном VM physical PASS.** Промежуточный кодовый merge или 2/3 running — не завершение. Дефект Line2 классифицировать независимо от дефекта journal. Ни одна диагностическая операция не снимает durable pending gate.

## Срез 2 — эксплуатация, recovery и Windows

После приёмки VM, не параллельным обходом:

1. **Эксплуатационный цикл VM:** Scoped config-only Line1/Line2 без чужих изменений; exact ReplaceRelease/reinstall, offline runner, crash/unknown ACK, drift и typed `/host recover`. Сейчас `recover` — **только read-only preflight**. Mutating recover добавлять лишь в существующий native owner с typed handler, журналом и отдельной проверенной транзакцией. Отсутствующие handlers host DNS/firewall/routes остаются `UNSUPPORTED`, не shell/docker exec.
2. **Windows:** защищённый SYSTEM Controller/SCM, ACL и точный release install/readback; безопасный ProxyOnly lifecycle, replace/reinstall/rollback/reboot с native receipt. Windows сейчас **STOPPED/PROXY_ONLY**, SYSTEM apply/TUN ещё не приняты. Managed TUN, DNS leak/IPv6, default routes и сосуществование с Cloudflare One — отдельная физическая матрица только после Git desired и разрешения; чужой адаптер/службу не изменять.
3. **Архитектурный долг, только с доказанным потребителем:** заменить оставшиеся исполняемые `grep/sed` admission-проверки на закрытый Rust/Protobuf verifier в том же owner и убрать действительно нулевых потребителей старых mutating helpers. Не запускать самостоятельную бесконечную «очистку» файлов. Новая capability: `Protobuf → Rust DAG/planner → существующий native handler → typed readback → signed receipt → physical acceptance`.

**Конечный PASS:** две платформы устанавливаются, диагностируются, ограниченно перенастраиваются, обновляются и восстанавливаются **исключительно** тремя `/host` командами, с единым Git/Worker/root|SYSTEM owner chain, без произвольных команд, повторов UNKNOWN, лишних transport/secret registries, скрытых rollback. Независимо приняты network/TLS/auth/egress и негативные тесты. До этого проект `NOT_ACCEPTED_10_10`.

## Постоянные правила

- Один канонический `main` и Git desired, один immutable ReleaseSet, один Rust decision owner, один Cloudflare Worker credential/signing plane, один VM root Agent / Windows SYSTEM Controller. GitHub Actions/runner — доставка, не физический mutation owner.
- Исторические PR, issue/runner logs, Windows/WSL старые runbook — **свидетельства**, не допуск операции. Issue #26 сохранять; **не повторять** failed/unknown BEGIN/HostIntent. Отсутствие факта → **один адресный read-only запрос** существующему локальному агенту (никакого секрета в чат/GitHub).
- Сохранить source/provenance и install/external gates раздельными. Новую физическую операцию разрешать только после точной независимой сверки текущего provider/journal poststate и с новым подписанным operation ID.
- Приоритет: закончить сквозную физическую приёмку, а не плодить новые планы/этапы/службы/адаптеры.
