# Installing LuraDB (Debian package)

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
- The systemd service is enabled and started.

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

## UDS access

Local clients can also reach LuraDB via the Unix domain socket `/run/luradb/luradb.sock` (mode `0660`, group `luradb`; the directory `/run/luradb` is created by systemd via `RuntimeDirectory=`). To grant another system user access:

```sh
sudo usermod -aG luradb <username>
```

Log in again for the group membership to take effect.

## Update

```sh
sudo apt reinstall ./target/debian/luradb_*.deb
```

Updates the binary and systemd unit — even for the same package version, for which `apt install` would be a no-op. The conffile `/etc/luradb/luradb.toml` stays unchanged (standard dpkg behavior for conffiles), the existing admin API key is kept, and the service is restarted afterward.

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
