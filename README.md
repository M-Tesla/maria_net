# maria_net

Asynchronous HTTP queue for MariaDB, the same kind of tool as `pg_net`, built for this engine. The `INSERT` returns before the call, and a separate process delivers it. `mysqld` does not speak HTTP. The only database is MariaDB 11.4 with TidesDB.

The switch is a small plugin. `INSTALL SONAME 'maria_net'` marks it on. `UNINSTALL SONAME 'maria_net'` marks it off. The `maria-net` binary stays outside the server and claims the queue only while that plugin is `ACTIVE`.

## What this server needs

- MariaDB 11.4 with `mariadb-plugin-tidesdb`. The plugin is beta, so set `plugin-maturity=beta`.
- The 12.3 line does not ship TidesDB.
- Durability follows `tidesdb_memtable_sync_mode=FULL`, which is already the default. This package has no per-table `SYNC_MODE`.
- The daemon session leaves `tidesdb_single_delete_primary` at 0. Claim updates columns that are not the primary key.
- Zig 0.16 to compile the daemon.
- `gcc` and the 11.4 server headers for the `.so`.

Tables in `net` use `ENGINE=TidesDB`. Keep that engine.

## Build

```sh
zig build -Doptimize=ReleaseSafe
plugin/build.sh /usr/lib/mysql/plugin/maria_net.so
```

`plugin/build.sh` uses `/usr/include/mariadb/server`. If the headers live somewhere else, set `MARIA_NET_PLUGIN_INCLUDE`.

From an account that can install plugins:

```sql
INSTALL SONAME 'maria_net';
```

## Schema and accounts

The installing account must be able to create users and `GRANT`. Passwords stay in files, not on the command line. The system user `maria-net` only runs the process. The SQL user `maria_net` is a different account.

```sh
useradd --system --home /var/lib/maria-net --shell /usr/sbin/nologin maria-net
install -d -m 0750 -o root -g maria-net /etc/maria-net
install -m 0640 -o root -g maria-net daemon.password /etc/maria-net/daemon.password
install -m 0640 -o root -g maria-net tenant.password /etc/maria-net/tenant.password

maria-net apply --host 127.0.0.1 --user root --password-file /etc/maria-net/root.password
maria-net accounts \
  --host 127.0.0.1 --user root --password-file /etc/maria-net/root.password \
  --daemon-user maria_net --daemon-password-file /etc/maria-net/daemon.password \
  --tenant-user app_user --tenant-password-file /etc/maria-net/tenant.password \
  --tenant-schema app --tenant-host '%'
```

`maria_net`@`127.0.0.1` reads and writes `net.*` and creates the trigger in the tenant schema. `app_user` has DML and DDL only on `app`. It does not receive `net.*`. Anyone who can read `net.webhook` can forge `X-Maria-Signature`.

The system service does not pass `--allow-loopback`. That flag is for local tests.

```sh
install -m 0755 zig-out/bin/maria-net /usr/local/bin/maria-net
install -m 0644 deploy/maria-net.service /etc/systemd/system/maria-net.service
systemctl enable --now maria-net
```

The unit reads `/etc/maria-net/daemon.password` and connects to `127.0.0.1`.

## Queue

Claim is an `UPDATE` inside a transaction. Two daemons on the same id: one `COMMIT` wins, the other gets a deadlock (`1180` or `1213`) and does not call HTTP. If the conflict continues after the retries, the row stays `processing` and the process keeps running. Reclaim returns the row after the lock is older than the timeout plus 30 seconds. Delivery is at least once.

Redirects are not followed. An internal address is refused before the socket. The response body stops at 64 KiB. History in `net.http_response` expires after 7 days (`TTL=604800`).

## What was measured

On 25 Sep 2026, one local MariaDB 11.4.13 with TidesDB delivered 36,000 loopback requests. The listener received 36,000 responses, one per call. `Memory_used` inside MariaDB stayed at 454 MB. That figure already includes the 256 MB block cache and the 256 MB write buffer.

Daemon RSS of the test process, from `/proc`:

| Deliveries | Daemon RSS |
| --- | --- |
| Start | 21.0 MB |
| 10,000 | 25.6 MB |
| 20,000 | 25.6 MB |
| 30,000 | 25.6 MB |
| 35,000 | 25.6 MB |
| 36,000 | 25.7 MB |

`mariadbd` RSS on the same run. The process was already warm at the start.

| Deliveries | mariadbd RSS |
| --- | --- |
| Start | 195.7 MB |
| 10,000 | 212.4 MB |
| 20,000 | 233.3 MB |
| 25,000 | 241.4 MB |
| 30,000 | 248.0 MB |
| 36,000 | 259.7 MB |

An earlier pass the same day delivered 11,999 calls and left one row `processing` after a commit deadlock. The process did not exit. That row was not delivered again before the test stopped, because reclaim waits for the timeout plus 30 seconds. The 36,000 run did not hit that deadlock, so it does not prove the redelivery.

There is no throughput number for `pg_net` from this machine. `pg_net` is not installed here and is not a dependency. The table below is behavior, from the `pg_net` worker and from tests on `maria_net`.

| Behavior | pg_net | maria_net |
| --- | --- | --- |
| Where HTTP runs | Inside the Postgres worker | Separate process. `mysqld` only loads the on/off plugin |
| When the caller returns | After the queue insert commits | After the queue insert commits |
| Crash after the row leaves the live queue | The request is deleted before HTTP, so a crash drops it | The row stays until finish. A crash redelivers later |
| Redirects | Followed | Refused. The first response is kept |
| Private addresses and metadata names | No filter before the socket | Refused before the socket. Tested against curl forms that dial internal addresses |
| Response body | Not capped in the worker | Stopped at 64 KiB |
| Two workers, same id | One in-process worker | One commit wins. The other gets 1180 or 1213 and does not call HTTP |
| Webhook secret | Not applicable | `X-Maria-Signature` from `net.webhook`. A tenant account that can `SELECT` that table can forge the signature. Tested: the tenant account received error 1142 |

## Test

```sh
MARIA_NET_TEST_HOST=127.0.0.1 \
MARIA_NET_TEST_USER=root \
MARIA_NET_TEST_PASSWORD=... \
MARIA_NET_TEST_PORT=3306 \
zig build test
```

Without `MARIA_NET_TEST_HOST`, the suite that talks to the server does not run.

## License

GNU GPL v3. The plugin loaded by MariaDB is `PLUGIN_LICENSE_GPL`. See `LICENSE`.
