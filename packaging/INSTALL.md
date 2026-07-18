# LuraDB installieren (Debian-Paket)

## Paket bauen

```sh
cargo deb
```

Erzeugt `target/debian/luradb_<version>-1_amd64.deb`. Voraussetzung: `cargo-deb` (`cargo install cargo-deb`) und `dpkg-dev` (`sudo apt install dpkg-dev`) sind installiert.

## Installieren

```sh
sudo apt install ./target/debian/luradb_*.deb
```

`apt` löst die Laufzeitabhängigkeiten automatisch auf. Beim Erstinstall passiert Folgendes:

- Der Systembenutzer `luradb` wird angelegt (kein Login, kein Home-Verzeichnis).
- `/etc/luradb/luradb.toml` gehört `root:luradb`, Modus `640` (enthält den Admin-API-Key).
- Ein zufälliger Admin-API-Key wird generiert (siehe unten).
- Der systemd-Dienst wird aktiviert und gestartet.

## Dienststatus & Logs

```sh
systemctl status luradb
journalctl -u luradb
journalctl -u luradb -f    # live mitlesen
```

## Admin-API-Key auslesen

```sh
sudo grep api_key /etc/luradb/luradb.toml
```

Der Key beginnt mit `lura_`. Er wird nur beim Erstinstall generiert (Platzhalter `@GENERATED_ON_INSTALL@`) und bleibt über Updates und Reinstalls hinweg unverändert erhalten.

## Smoke-Test

```sh
curl -fs http://127.0.0.1:3000/health
```

## Konfig ändern

```sh
sudoedit /etc/luradb/luradb.toml
sudo systemctl restart luradb
```

`luradb.toml` ist ein dpkg-Conffile: lokale Änderungen bleiben bei Updates erhalten (dpkg fragt bei Konflikten zwischen lokaler Änderung und neuer Paketversion nach).

## UDS-Zugriff

Lokale Clients erreichen LuraDB auch über den Unix-Domain-Socket `/run/luradb/luradb.sock` (Modus `0660`, Gruppe `luradb`; das Verzeichnis `/run/luradb` legt systemd über `RuntimeDirectory=` an). Einen weiteren Systembenutzer für den Zugriff freischalten:

```sh
sudo usermod -aG luradb <benutzer>
```

Neu anmelden, damit die Gruppenmitgliedschaft wirksam wird.

## Update

```sh
sudo apt install ./target/debian/luradb_*.deb
```

Erneutes Installieren (gleiche oder neuere Paketversion) aktualisiert Binary und systemd-Unit. Das Conffile `/etc/luradb/luradb.toml` bleibt unverändert (dpkg-Standardverhalten für Conffiles), der bestehende Admin-API-Key bleibt erhalten, der Dienst wird danach neu gestartet.

## Deinstallation

```sh
sudo apt remove luradb    # Binary + systemd-Unit weg, Conffile bleibt
sudo apt purge luradb     # zusätzlich das Conffile /etc/luradb/luradb.toml weg
```

`/var/lib/luradb` (Datenbankdateien: WAL, VLog, SSTables) und der Systembenutzer `luradb` werden **nie automatisch gelöscht** — das ist beabsichtigt destruktiv und bleibt manuell:

```sh
sudo rm -rf /var/lib/luradb
sudo deluser luradb
```
