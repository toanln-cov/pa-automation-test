# PA Automation Tool

An automation tool with a web interface that helps administrators deploy configuration to Palo Alto Networks firewalls automatically from an Excel template, through the PAN-OS XML / REST API. Its features are completely different from Panorama, so it is not a replacement for Panorama. Panorama is a native Palo Alto product that provides a very comprehensive centralized management solution, with a strong binding between Panorama and the firewalls. This tool is only a helper for automated configuration, not a centralized management system for Palo Alto firewalls. In the future, I may add automated configuration for Panorama.

[Features](#features) · [Limits](#what-the-tool-does-not-do) · [Build](#build-the-tool) · [Recommendations](#recommendations-for-setting-up-the-tool) · [Configuration](#initial-configuration-settings)

## Purpose

The tool comes from the need to manage many Palo Alto firewalls in an infrastructure without a centralized management tool such as Panorama. Also, manual configuration in the firewall GUI is slow and error-prone. This tool makes the daily operations of the firewall team easier:

- It supports the core, basic features such as security / NAT rules, objects, object groups..., which covers most of the daily needs of administrators.
- It has a Dry-run feature that checks the configuration file against the real firewalls **before** deploying to them.
- The goal is a convenient tool that keeps the impact on services as low as possible, so it only supports creating and editing, with no delete. It also never commits automatically: it only writes the changes to the **candidate config**. The admin runs commit check and commit manually (also in this tool).
- It configures several firewalls / vsys at once.
- Because it is a web-based tool whose input is an Excel template, it can be integrated more easily with the organization's rule-request ticketing system.

Typical use: change requests that add or edit address objects, services, groups, security rules and NAT rules on standalone or HA firewalls.

## Features

- **One template with add and edit sheets**: tags, address objects / groups, service objects / groups, security rules, NAT rules.
- **Dry-run**: checks every row (name, values, references, duplicates, rule position) by only reading information from the firewall. Nothing is written to the firewall.
- **Install**: writes to the candidate config only. Before writing, the configuration of each firewall is locked for the time the tool configures it, and a named backup (`Auto-<date>.xml`) is created.
- **Commit page**: commit check and commit, separate from Install, used after the candidate config has been reviewed.
- **Multiple firewalls, multiple vsys, shared**: configures several firewalls at once, with several vsys and the shared location.
- **Job history**: follow running configuration jobs in real time, and review past jobs.
- **User Guide** (English / Vietnamese): every sheet, column and value rule, with examples, for reference while using the tool.

## What the tool does not do

- No delete.
- Static address groups only.
- Services with tcp / udp only.
- NAT with ipv4 only.
- It does not create or edit these components: EDL, application, profile, zone, interface, schedule...
- **Install** does not commit automatically.
- Not for firewalls managed by Panorama (to avoid configuration conflicts).
- HA: fill only the IP of the active firewall.
- Dry-run catches most errors but not all; some cases are only known at Install.

## PAN-OS compatibility

| PAN-OS                         | Status                                                                         |
| ------------------------------ | ------------------------------------------------------------------------------ |
| 11.1 and later                 | Supported. Tested on 11.1.4 and 11.1.10.                                       |
| 10.2, 10.1                     | Supported; use the 11.1 behavior until the differences are checked.            |
| 10.0, 9.1, 9.0 and older (EoL) | Not supported. May fail (for example the 9.0 REST URL has a different format). |

## Requirements

- Linux host with Docker and Docker Compose v2.
- Open connections from the tool to the firewall management interfaces on port 443 (HTTPS).
- (Recommended) Plan a dedicated firewall admin account for the tool, with API access, not shared with other accounts.

## Build the tool

```sh
git clone https://github.com/toanln-cov/pa-automation-test.git
cd pa-automation-test
docker compose up -d --build
```

Then open the tool at `https://<server-ip>:9198/` and sign in the first time with **admin / admin**.

The tool requires a password change at first login. The TLS certificate is generated automatically.

How to use the tool is described in the tool's Guide page.

## Recommendations for setting up the tool

Already set up in the tool:

- HTTPS (TLS 1.2 / 1.3) with security headers.
- Login lockout after repeated failures, forced change of weak passwords, session timeout.
- Container runs as `www-data` with a read-only filesystem and no capabilities.
- Pinned base image / Ubuntu snapshot / Python hashes, for compatible and stable installation and use.
- Audit log in `docker logs` for audit and troubleshooting.

Recommendations for the environment that hosts the tool:

1. **Restrict access** to port 9198 to the admin network only (network firewall or host firewall), or bind one address only: `'<host-ip>:9198:8443'`.
2. **Use a trusted certificate**: replace `data/ssl/server.crt` and `server.key`, restart, then you can set `APP_HSTS_SECONDS=31536000`.
3. **Set `APP_ALLOWED_HOSTS`** to the real names / IPs of the tool.
4. **Use a dedicated firewall account** for the tool, not a superuser: XML API Configuration, Operational Requests (read version, lock, backup), Commit. REST API for the objects and policies used.
5. **Set the API key lifetime** on the firewalls (Device > Setup > Management > Authentication Settings): each job creates a new key.
6. **Verify the firewall certificates** with `APP_PANOS_CA_BUNDLE`.
7. **Forward the audit log** to syslog / SIEM (`docker logs` is configured by default to keep only about 1 GB).
8. **Update regularly**: new `ubuntu:24.04` digest, newer `APT_SNAPSHOT` in the Dockerfile, but `requirements.txt` must be regenerated, then rebuild and retest.
9. **Back up** the data folders `./data/` and `./jobs/`.

## Initial configuration settings

Set in `docker-compose.yml` under `environment:`, then run `docker compose up -d`.

| Variable                      | Default           | Meaning                                                                                                    |
| ----------------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------- |
| `APP_DEBUG`                 | `0`             | `1` turns on the Django debug page. Not recommended; only for debugging while developing the tool.       |
| `APP_ALLOWED_HOSTS`         | `*`             | Domain names / IPs used to access the tool, comma separated (for example `10.0.0.5`, `pa-auto.local`). |
| `APP_TZ_OFFSET_HOURS`       | `7`             | Time zone for job times (7 = GMT+7).                                                                       |
| `APP_CERT_CN`               | `pa-automation` | Name in the auto-generated certificate.                                                                    |
| `APP_LOGIN_FAILURE_LIMIT`   | `5`             | Failed logins (per username + IP) before lockout.                                                          |
| `APP_LOGIN_COOLOFF_MINUTES` | `15`            | Lockout duration.                                                                                          |
| `APP_HSTS_SECONDS`          | `0`             | HSTS max-age. Keep `0` with the self-signed certificate.                                                 |
| `APP_PANOS_CA_BUNDLE`       | (empty)           | CA bundle path in the container, used to verify the firewall certificates.                                 |
| `APP_MIN_FREE_DISK_MB`      | `100`           | New jobs are refused when the free space of the jobs disk is below this value.                             |
| `APP_JOB_MAX_SIZE_MB`       | `1024`          | Above this size, the oldest job results are deleted. `0` = no limit.                                     |

## Troubleshooting

The container has `curl`, `nc`, `dig` and `traceroute` (no `ping`, because it has no NET_RAW capability). Commands to debug from the container:

```sh
docker exec pa-automation curl -sk -o /dev/null -w '%{http_code}\n' https://<firewall-ip>/
docker exec pa-automation nc -zv -w 3 <firewall-ip> 443
docker exec pa-automation dig +short <firewall-name>
docker exec pa-automation traceroute -n <firewall-ip>
```

## Support

Community project, not affiliated with or supported by Palo Alto Networks. Please report bugs and questions in GitHub Issues.

## Disclaimer

Provided as is, without warranty. Always run Dry-run, review the candidate config and keep a backup before committing on production firewalls.
