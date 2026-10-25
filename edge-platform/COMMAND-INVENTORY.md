# sing-box — единственный операторский интерфейс

**Канон:** защищённый [`main`](https://github.com/iamaman11/sing-box). Команды публикуются только в [Issue #1](https://github.com/iamaman11/sing-box/issues/1) и исполняются существующим Rust owner/Actions workflow; это не прямое разрешение на Cloudflare/Docker/SCM/SSH mutation.

| Синтаксис | Поддерживаемый смысл и предел |
| --- | --- |
| `/host diagnose <machine-id> <read-only argv>` | VM only. Protobuf-validated, bounded unprivileged native `ip/ss/ps/uname/uptime/resolvectl/systemctl` observations via exact existing self-hosted runner and installed Root Agent. Example: `/host diagnose application-acceptance-4 ip -6 route show table all`. Never a shell/mutation; `RUNNER_COPIED_UNAUTHENTICATED` is NOT signed physical receipt. |
| `/host status [machine-id] [--deep]` | Только read-only: Git/ReleaseSet, runner, native owner и bounded ресурсы, DNS/network readback, reason/owner/scope; `UNPROVEN` не означает healthy |
| `/host apply <machine-id>` | Единственный типизированный однократный маршрут Git/ReleaseSet → owner-gated Worker/signature → VM root Agent / Windows SYSTEM Controller, журнал и signed native receipt. Может завершиться только кодовым Worker upgrade/first-use или `BLOCKED`: не утверждать, что VM установлена, пока это не доказано |
| `/host apply <machine-id> config/vultr-edge/line1-gateway` | Узкий signed config-only scope Line1; соседние ресурсы не изменять |
| `/host apply <machine-id> config/vultr-edge/line2-proxy` | Узкий signed config-only scope Line2 |
| `/host recover <machine-id>` | **VM: однократное code-only обновление действующего Root Agent/trust из exact protected Git ReleaseSet через штатный `host-refresh`, затем read-only диагностика.** Кодовое обновление меняет бинарник/trust, но не контейнеры, DNS, firewall, credentials и не снимает pending. Любой resource recovery, replay, reinstall и rollback остаётся **BLOCKED/UNSUPPORTED** без отдельного подписанного native handler. Windows пока read-only preflight |

Нет других пользовательских `/vm`, `/windows`, `/vultr`, `/production`, `/credentials` команд. Внутренние Rust build/read-only/first-use verbs и typed `HostWorkflowOperation → GitHub Actions operation` не создают новых операторских ingress. `HostIntent`, desired, result и receipt — Protobuf; JSON допускается на необходимых внешних API/renderer границах, не как второй dispatcher.

## Владелец и безопасность

- **VM:** первоначальная Vultr API/SSH подготовка допускается только для *первого bootstrap* штатного root Agent и ограниченного self-hosted runner. После enrollment никакого SSH-runtime, `docker exec`, Compose/root shell или нового mutation listener. Root `host-refresh` (без аргументов) сверяет exact protected release и обновляет собственный binary/trust **без** resource mutation, снятия pending и нормализации journal. Обновление кода не даёт права повторить UNKNOWN; `host-apply` — отдельный resource effector под root lock и полным journal admission. Runner доставляет только типизированные операции, не владеет Docker socket.
- **Windows:** SCM `EdgePlatformController` и SYSTEM activation boundary — целевой единственный owner. Текущий `sing-box-windows-lab` **STOPPED/PROXY_ONLY**, signed SYSTEM apply/TUN/reboot/rollback **НЕ ПРИНЯТЫ**. Нельзя включать TUN, менять DNS/routes, трогать Cloudflare One.
- **VM network:** Docker observation и nft/DNS/route readback существуют, однако самостоятельные native handlers для host DNS/firewall/routes не приняты. При `UNSUPPORTED` не переключаться на shell/SSH.
- **Cloudflare Worker:** версия `latest` не обязательно является активной. Pending upload и legacy journal BEGIN не дают права на повтор или deploy. Worker pending source issue закрыт PR #475. Текущий блокер — старый установленный VM Root Agent и его недоверенный native journal; см. [единственный план](FINALIZATION-PLAN.md). Значения восьми Worker secrets не публиковать.
- **Физическое доказательство:** после любого apply требовать exact installed release, authenticated native receipt, 3/3 VM контейнера, независимые Line1 4/4 + Line2 6/6 TLS/auth/DIRECT/WARP, DNS/firewall/routes, negative scope и отдельную Windows матрицу. CI, `NOOP`, copied runner protobuf и «container running» не равны PASS.

## Операторский порядок

Прочитать текущий `main` и [единый план](FINALIZATION-PLAN.md) → `/host status --deep` и точный read-only provider/journal witness → подтвердить fresh Git/ReleaseSet/owner/scope/NO_REPLAY → только затем новая `/host apply` через Issue #1 → прочитать Actions/native signed receipt и независимо проверить poststate.

При неизвестном ACK либо недоказанном результате — `UNKNOWN_NO_REPLAY`: нельзя ни повторять исходный Issue comment/HostIntent, ни устранять блокировку chmod/delete, ни создавать второй транспорт. Старый установленный owner может блокировать свой же refresh; новая Git-версия сама по себе не заменяет его. Разрешён один адресный **read-only** запрос существующему локальному агенту с конкретным недостающим полем; секреты, ключи, raw configs и JWT не переносить в issue/чат. Только защищённый Rust owner может принять дальнейшее новое решение.
