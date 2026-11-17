# Deploying sot-validator as a systemd timer

`deploy/systemd/` holds two unit templates:

- `sot-validator.service` — a hardened `Type=oneshot` run as the `sot-validator` user.
- `sot-validator.timer` — starts the service daily at 02:00 (`Persistent=true`, up to 15 minutes of random delay).

Every path and the `ExecStart=` command line are placeholders, marked with comments in the units. Adjust them for your host before installing.

> **Not yet wired in.** The `sot_validator.ops` run lock (`RunLock`), run manifest (`RunManifest`, `run_manifest.json`) and exit-code contract (`ExitCode`, `select_exit_code`) are not used by the CLI yet. Until a later integration change wires them into `run` and `campaign`, the service exit status is whatever the CLI returns today, and no lock or manifest is written.
>
> **POSIX-only.** `sot_validator.ops` uses `fcntl.flock`, so it works on Linux and other POSIX systems only.

## 1. Create the service user and group

```bash
sudo groupadd --system sot-validator
sudo useradd --system --gid sot-validator --home-dir /var/lib/sot-validator \
  --no-create-home --shell /usr/sbin/nologin sot-validator
```

## 2. Create the directories

```bash
sudo install -d -o root -g root -m 0755 /etc/sot-validator
sudo install -d -o sot-validator -g sot-validator -m 0750 /var/lib/sot-validator
sudo install -d -o sot-validator -g sot-validator -m 0750 /var/lib/sot-validator/output
sudo install -d -o sot-validator -g sot-validator -m 0750 /var/lib/sot-validator/state
```

The service can write only to `/var/lib/sot-validator/output` and `/var/lib/sot-validator/state` (`ProtectSystem=strict` with `ReadWritePaths=`).

## 3. Install the package into a virtualenv

```bash
sudo python3 -m venv /opt/sot-validator/venv
sudo /opt/sot-validator/venv/bin/pip install /path/to/sot-validator-checkout
```

## 4. Create the secrets env file

The TOML fleet config refers to secrets as `${env:NAME}` (see `examples/sot-validator.example.toml`). Put one `NAME=value` line per reference in the env file, owned by `root` with `0600` permissions. systemd reads it as root before dropping to the service user, so the service user never needs to read the file itself.

```bash
sudo install -o root -g root -m 0600 /dev/null /etc/sot-validator/sot-validator.env
sudoedit /etc/sot-validator/sot-validator.env
```

Example contents (replace the values; never commit this file):

```
SOT_VCENTER_PASSWORD=change-me
SOT_SNMP_COMMUNITY=change-me
SOT_PROXMOX_TOKEN_SECRET=change-me
```

Secret values never go in the unit files.

## 5. Install and enable the units

```bash
sudo cp deploy/systemd/sot-validator.service deploy/systemd/sot-validator.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sot-validator.timer
```

## 6. Check the timer and the runs

```bash
systemctl list-timers sot-validator.timer
systemctl status sot-validator.service
journalctl -u sot-validator
```

To run once immediately: `sudo systemctl start sot-validator.service`.

## Exit codes

`sot_validator.ops.ExitCode` defines this contract (not yet returned by the CLI):

| Code | Name | Meaning |
|------|------|---------|
| `0` | `SUCCESS` | Every site was ok or skipped, with no actionable findings. |
| `1` | `ACTIONABLE` | The run completed and produced findings an operator should act on. |
| `2` | `PARTIAL` | At least one site failed while others succeeded or were skipped. |
| `3` | `FAILED` | The run failed as a whole, or every site failed. |
| `4` | `LOCK_HELD` | Another run held the lock, so this run did nothing. |

Skipped sites never count as failures.
