# VM server architecture — implementation reference

**Не отдельная архитектура и не план.** Нормативная [архитектура](../../edge-platform/ARCHITECTURE.md), [единственный план](../../edge-platform/FINALIZATION-PLAN.md), [команды](../../edge-platform/COMMAND-INVENTORY.md). Этот текст описывает техническую сторону VM; Git desired/ReleaseSet и native readback всегда важнее старых README.

## Границы

| Компонент | Владелец |
| --- | --- |
| Machine/Resource identity, target, immutable input | Git `infra/hosts/hosts.textproto`, Rust/Protobuf + ReleaseSet |
| Провайдер Vultr, first-use до native ownership | существующий Rust Vultr engine на GitHub-hosted Actions; SSH только начальное enrollment |
| Подпись HostIntent / credential reference | защищённый VM Cloudflare Worker |
| VM application, Docker, конфиг и локальный network readback | установленный root `edge-agent` |
| Сообщение, runner evidence | GitHub self-hosted runner, без root/секретов/mutating authority |

Обычный VM runtime путь: `/host apply` → exact protected release → Worker-signed scoped HostIntent → runner bounded dispatch (`host-refresh` без аргументов / `host-apply`) → root lock + local journal BEGIN → native step → readback + signed receipt. Нет обычного SSH, старого TCP/gRPC mutation listener, `bundle-converge`/rollback sudo или `/production` команд.

## Resource scope

Принятая целевая конфигурация новой `application-acceptance-3` содержит ровно три управляемых контейнера Compose project `vultr-edge`: `line1-gateway`, `line2-proxy`, `warp-egress`. Приёмка отдельно требует Line1 4/4, Line2 6/6, TLS/auth, DIRECT/WARP и host DNS/firewall/routes readback. Существующий `cloudflare-mesh` в исторической production composition — **чужая отдельная область ownership**; не удалять/принимать её в управление ради числа контейнеров.

Docker observation — Bollard; изменения — только known native handler, а не произвольный Compose/docker/root shell. Images/configs должны быть закреплены exact ReleaseSet; рендеренные YAML/JSON/env — потребительский результат, не второй desired. Worker secrets и приватный receipt key не входят в Git.

## Recovery и приёмка

Нет replay после неизвестного BEGIN/ACK. `/host recover` сейчас только read-only. Отдельная операция допустима при доказанном owner и poststate с новым signed ID; host DNS/firewall/routes mutations без адресного native handler блокируются. Сравнение Git, Docker и release без аутентифицированного receipt или внешнего TLS/auth witness не означает PASS.

Состояние физической приёмки смотреть в [Issue #26](https://github.com/iamaman11/sing-box/issues/26), порядок работ и criteria — **только** в [FINALIZATION-PLAN.md](../../edge-platform/FINALIZATION-PLAN.md).
