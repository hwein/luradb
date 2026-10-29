# Installing LuraDB (Debian package)

## Requirements

Linux kernel 6.1 or newer: LuraDB's io_uring rings use `DEFER_TASKRUN`. On an older kernel the service does not start and logs `LuraDB requires Linux kernel 6.1 or newer (io_uring DEFER_TASKRUN)`. Check with `uname -r`.

## Building the package

```sh
cargo deb
```

Produces `target/debian/luradb_<version>-1_amd64.deb`. Requires `cargo-deb` (`cargo install cargo-deb`) and `dpkg-dev` (`sudo apt install dpkg-dev`) to be installed.

## Installing

```sh
sudo apt install ./target/debian/luradb_*.deb
```

`apt` resolves the runtime dependencies automatically. On first install, the following happens:

- The system user `luradb` is created (no login, no home directory).
- `/etc/luradb/luradb.toml` is owned by `root:luradb`, mode `640` (contains the admin API key).
- A random admin API key is generated (see below).
- The systemd service is enabled but not started, so you can review the config (bind address, data paths, admin API key) before LuraDB first runs and creates its data files. A notice at the end of the install says where the config lives and how to start.

Start the service once the config is ready (being enabled, it also starts on the next boot):

```sh
sudo systemctl start luradb
```

## Service status & logs

```sh
systemctl status luradb
journalctl -u luradb
journalctl -u luradb -f    # follow live
```

## Reading the admin API key

```sh
sudo grep api_key /etc/luradb/luradb.toml
```

The key starts with `lura_`. It is generated only on first install (placeholder `@GENERATED_ON_INSTALL@`) and stays unchanged across updates and reinstalls.

## Smoke test

```sh
curl -fs http://127.0.0.1:3000/health
```

## Changing the config

```sh
sudoedit /etc/luradb/luradb.toml
sudo systemctl restart luradb
```

`luradb.toml` is a dpkg conffile: local changes survive updates (dpkg prompts on conflicts between a local change and the new package version).

Disabling authentication (`auth.enabled = false`) only starts if `server.bind_address` is loopback (`127.0.0.1` / `::1`) — binding wider than loopback with auth off is refused at startup, so an unauthenticated listener can never end up reachable from the network. Enable auth, or keep the bind on loopback.

## Multicore

LuraDB spreads its domains over several data shards; each shard is one thread with its own storage engines. Reads of a domain scale across cores (the connection threads and the reader pool); the writes of one domain run on exactly one core, so write parallelism is at most the number of domains written at the same time.

The `[multicore]` keys size each part; `0` is automatic:

- `frontend_workers`: cores / 6, 2 to 4 (1 below 4 cores).
- `shards`: the count an existing data directory was written with; for a new one cores / 4, 1 to 8.
- `reader_threads`: cores − 2 − frontend workers − shards, at least 1.

On 12 cores with a new data directory that is 2 frontend workers, 3 data shards and 5 reader threads; the start log (`journalctl -u luradb`) reports the split and the memory of each shard.

Memory: the block cache of each engine (64 MiB) and the buffer pool (`buffer_pool.pool_size`) are split evenly across the shards; the MemTable threshold (`lsm.memtable_size_threshold`) applies per engine and shard, so MemTable memory grows to engines × shards × threshold (plus MemTables being flushed).

The shard count belongs to the data directory: with `shards = 0` the service keeps the count the data was written with, also after an upgrade or a move to a host with another core count; a different count set explicitly refuses the start. Only the migration tool changes it.

## Changing the shard count

After an update the service keeps the shard count the data directory was written with. If this host would use a different count, the start log (`journalctl -u luradb`) warns and prints the migration command.

The migration tool rewrites the data directory for another number of data shards, more or fewer, down to 1. It works offline, on a stopped service, and moves the key-value, JSON and relational data alike:

```bash
sudo systemctl stop luradb
sudo -u luradb sh -c 'cd /var/lib/luradb && exec /usr/bin/luradb --config /etc/luradb/luradb.toml --migrate-shards 4'
sudo systemctl start luradb
```

- Relative paths in the config count from the current directory, and the service runs in `/var/lib/luradb`; run the tool from there, as above, or it does not find the JSON and relational data and stops without changing anything.
- The service must have been shut down cleanly. If the tool reports writes that are not flushed yet, start the service once, stop it again and rerun the tool.
- It refuses to run while the service runs on the same data directory: the service holds a lock on `<system_dir>/lock` for as long as it runs, so a second LuraDB process on the same data directory does not start, and the tool runs only while the service is stopped.
- It needs free disk space for a second copy of the data next to the first: the new layout is built in a `migrate_<timestamp>/` directory inside each data directory and only then moved into place. The old layout is removed once the move has finished.
- Leave `shards = 0` in `[multicore]`, or set it to the new count; any other explicit value refuses the start.
- If the tool stops while it moves the new layout into place, the service refuses to start with "shard migration incomplete — rerun the migration tool"; running the same command again finishes the change. A tool stopped earlier leaves the old layout untouched.
- Backups are not affected: an archive restores into any shard count. Write-ahead-log positions (`lsn_cut` in a backup manifest) go on across the change.

## Enabling HTTPS (quickstart)

LuraDB can terminate TLS itself, on its own port (`tls_port`, default `3443`), in parallel to the plain HTTP listener. This is a quick start with a self-signed certificate; for a certificate from a public or internal CA (e.g. via `certbot`), just point `tls_cert_path`/`tls_key_path` at those files instead — or keep operating behind a reverse proxy.

1. Generate a self-signed certificate:

   ```sh
   sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
       -keyout /etc/luradb/tls/server.key -out /etc/luradb/tls/server.crt \
       -days 365 -nodes -subj "/CN=localhost" \
       -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
       -addext "basicConstraints=critical,CA:FALSE"
   ```

2. Restrict access to the private key (LuraDB does not enforce this — it's on the operator):

   ```sh
   sudo chown root:luradb /etc/luradb/tls/server.key
   sudo chmod 640 /etc/luradb/tls/server.key
   ```

3. Enable TLS and restart:

   ```sh
   sudoedit /etc/luradb/luradb.toml   # tls_enabled = true
   sudo systemctl restart luradb
   ```

4. Test:

   ```sh
   curl --cacert /etc/luradb/tls/server.crt https://127.0.0.1:3443/health
   curl -k https://127.0.0.1:3443/health   # without pinning the self-signed cert
   ```

5. Certificate rotation has no hot-reload — replace the files under `/etc/luradb/tls/` and run `sudo systemctl restart luradb`. For a CA-issued certificate, keep it renewed there (e.g. via `certbot`), or continue terminating TLS at a reverse proxy instead.

## Enabling CORS for browser clients

Off by default — a plain config change, no restart quirks. A browser-based client running on a different origin (e.g. a web console) needs `Access-Control-*` response headers, or the browser blocks every response regardless of whether the request succeeded server-side.

```toml
[cors]
enabled = true
allowed_origins = ["https://console.example.com", "http://localhost:5173"]
```

`allowed_origins` takes exact origins (`scheme://host[:port]`, lowercase, no path/query) — or the single entry `"*"` to allow any origin. `"*"` does not weaken authentication: `Authorization: Bearer` is still required as usual, it only means the origin allow-list stops being an extra line of defense. Methods, headers and cache lifetime are fixed by the server, not configurable. Apply with:

```sh
sudoedit /etc/luradb/luradb.toml   # [cors] enabled = true
sudo systemctl restart luradb
```

## UDS access

Local clients can also reach LuraDB via the Unix domain socket `/run/luradb/luradb.sock` (mode `0660`, group `luradb`; the directory `/run/luradb` is created by systemd via `RuntimeDirectory=`). To grant another system user access:

```sh
sudo usermod -aG luradb <username>
```

Log in again for the group membership to take effect.

## Disk and memory shortage

Once a second LuraDB reads the free space of every volume its data paths lie on (data files, write-ahead logs, log and backup directories) and its own anonymous memory (`RssAnon`), and compares them with `[resources]` in `/etc/luradb/luradb.toml`:

- **Warning:** a volume has less free space than `disk_free_warn` (default 15 % of the volume, at most 10 GB), or the memory reaches 80 % of `memory_budget`. The log shows a WARN line naming the volume or the memory, and `/health` answers 200 with `status: "degraded"` and the numbers in `resources`. Nothing is refused yet.
- **Writes refused:** a volume has less free space than `disk_free_block` (default 5 %, at most 2 GB), or the memory reaches 95 %. The log shows an ERROR line, repeated every minute while this lasts. Every write answers `507 Insufficient Storage` with `Retry-After: 5`, deletes, DDL, imports, restores and the write tools of MCP included; shared-memory clients get the same error. Reads, searches, SQL `SELECT`, `/health`, the metrics, backup downloads and deletions and sign-ins go on. A new backup runs only into a `backup.dir` on another volume above its warn threshold, and not while memory is short. Compaction and the cleanups of the value log and the write-ahead log go on and free space where they can.
- **Back to normal:** once every volume has more free space than `disk_free_resume` (default 10 %, at most 4 GB) and the memory is below 90 % for two seconds in a row, writes are accepted again, with an INFO line.

A delete does not free space at once: it writes a marker that compaction removes later. Faster ways out are deleting old backups (`DELETE /store-api/backups/{id}`), moving files off the volume or growing it. To cap the memory of the service on the system side as well, set `MemoryHigh=` in a drop-in (`sudo systemctl edit luradb`).

The service stops with its own exit code in two cases:

- **3:** the disk reported an error while making written data durable (`fsync`). The log shows `data sync failed on <path>`; systemd starts the service again, and the start recovers every confirmed write from the write-ahead log.
- **4:** at the start, a volume has less free space than the recovery needs (`not enough free disk space to recover`). systemd does not restart the service; free space, then run `sudo systemctl start luradb`. A start below `disk_free_block` with room for the recovery does not stop: the service starts with writes refused (`507`) and reads going on.

The unit allows three starts within five minutes, manual ones included; after that systemd refuses further starts until `sudo systemctl reset-failed luradb`.

## Update

```sh
sudo apt reinstall ./target/debian/luradb_*.deb
```

Updates the binary and systemd unit — even for the same package version, for which `apt install` would be a no-op. The conffile `/etc/luradb/luradb.toml` stays unchanged (standard dpkg behavior for conffiles), the existing admin API key is kept, and a running service is restarted afterward; a stopped service stays stopped.

Each write-ahead log of this version is a directory of segment files at its configured path (`wal_path` of `[storage]`, `[json]` and `[rel]`, and `wal` in `system_dir`). The first start of this version replays a write-ahead log file an earlier version left there and puts the directory in its place; the change is one-way. Once this version has started on a data directory, an earlier version refuses to start on it, with an error that the write-ahead log is a directory, and changes no data. To go back to an earlier version, either restore a backup into it, or stop this version cleanly, which leaves each write-ahead log directory with one segment that holds its 16-byte header alone, and delete these directories before the earlier version starts. The next update to this version then replays the logs the earlier version wrote once in full.

## Uninstallation

```sh
sudo apt remove luradb    # binary + systemd unit gone, conffile stays
sudo apt purge luradb     # additionally removes the conffile /etc/luradb/luradb.toml
```

`/var/lib/luradb` (database files: WAL, VLog, SSTables) and the system user `luradb` are **never deleted automatically** — that's deliberately destructive and stays manual:

```sh
sudo rm -rf /var/lib/luradb
sudo deluser luradb
```
