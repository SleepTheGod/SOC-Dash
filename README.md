```markdown
# SOC Dash

A lightweight, single host Security Operations Center dashboard that runs entirely in the browser and renders live server telemetry from a single PHP file.

Repo `https://github.com/SleepTheGod/SOC-Dash`

## Overview

SOC Dash gives you an at a glance view of the health, security posture, and activity of a Linux server. It is designed for analysts, sysadmins, and hobbyists who want a fast, self hosted monitoring page without any agents, databases, or external services.

Everything is served from a single PHP file that reads directly from the host using standard Linux tooling. No background daemon, no database, no third party API, no JavaScript build step.

## Features

A full page refresh every ten seconds keeps the dashboard current.

Top level KPI strip showing memory usage, root filesystem usage, load average, listening sockets, failed SSH logins over the last twenty four hours, and active user sessions.

System information panel with hostname, operating system, kernel, architecture, distribution, PHP version, uptime, and server time.

Resource utilization meters for RAM and swap with color coded severity bars.

Filesystem usage table covering every mounted volume, with per mount severity tags and volume bars.

Top processes table ranked by CPU usage, showing PID, parent PID, user, command, percent memory, and percent CPU, each tagged by severity.

Active sessions panel listing every logged in user along with their TTY, source address, and login time.

Failed SSH login panel that aggregates attempts by source IP, ranks them by volume, and tags each IP by severity.

Listening ports panel showing protocol, local address, peer address, and owning process for every open socket.

Global status pill in the header that reports NOMINAL, WARNING, or CRITICAL based on configurable thresholds across disks, memory, load, and failed logins.

Automatic refresh cadence adjustable in one constant at the top of the file.

IP allowlist enforced inside the PHP file for defense in depth, on top of whatever your web server already enforces.

Hardened response headers including X Frame Options, X Content Type Options, and Referrer Policy.

Every value rendered into the page is escaped, so log contents, process command lines, and usernames cannot inject markup.

Graceful degradation, meaning that if a command is missing or the shell is disabled, that panel simply shows an unavailable message while the rest of the dashboard continues to render.

## Files

`index.php` is the primary entry point. It collects live data from the host and renders the full dashboard.

`index.html` is a static fallback page. Use it when you want to preview the interface without PHP, or as a landing page when PHP is unavailable.

`deploy.sh` is an automated installer for Debian, Ubuntu, RHEL, Alma, Rocky, and Arch Linux. It installs the web stack, clones the repo, configures the virtual host, and applies the recommended hardening.

## Requirements

A Linux host running PHP 7.4 or newer.

A web server such as Nginx or Apache with PHP support.

Read access to system files under `/proc`.

The `df`, `ps`, and `who` commands available on the system.

Optional but recommended for the failed login panel, either `journalctl` with the PHP user in the `systemd-journal` group, or readable `/var/log/auth.log` on Debian based systems, or readable `/var/log/secure` on Red Hat based systems.

Optional for the listening ports panel, either the `ss` command from iproute2, or the older `netstat` command from net tools.

## Quick Start

Clone the repository.

```bash
git clone https://github.com/SleepTheGod/SOC-Dash.git
cd SOC-Dash
```

Run the deploy script as root.

```bash
sudo bash deploy.sh
```

The script will install the web stack, place the application under `/var/www/soc-dash`, configure the virtual host, set permissions, tune PHP FPM, and print the URL you should visit.

## Manual Installation

Copy `index.php` and `index.html` into your web root, for example `/var/www/html`.

Set ownership so the web server user can read them.

```bash
sudo chown www-data www-data /var/www/html/index.php /var/www/html/index.html
```

Grant the web server user access to system logs so the failed login panel populates.

```bash
sudo usermod aG systemd-journal www-data
sudo usermod aG adm www-data
sudo systemctl restart php8.2-fpm
```

Adjust the PHP FPM version in the last command to match your system.

Open the site in a browser.

## Configuration

All tunable settings live at the top of `index.php` inside a single configuration block.

`REFRESH_SECONDS` controls how often the page reloads. The default is ten seconds.

`THRESH_DISK_WARN` and `THRESH_DISK_CRIT` set the warning and critical percentages for filesystem usage. Defaults are seventy five and ninety.

`THRESH_MEM_WARN` and `THRESH_MEM_CRIT` set the warning and critical percentages for memory usage. Defaults are seventy five and ninety.

`THRESH_LOAD_WARN` sets the load average threshold for a warning. The default is four.

`THRESH_FAIL_WARN` and `THRESH_FAIL_CRIT` set the warning and critical thresholds for failed SSH logins over the collection window. Defaults are twenty and one hundred.

`FAIL_WINDOW` is the lookback window for failed logins. The default is twenty four hours.

`FAIL_LIMIT` is the maximum number of source IPs shown. The default is fifteen.

`PROC_LIMIT` is the maximum number of processes listed. The default is fifteen.

`ALLOWED_CIDRS` is an array of CIDR blocks permitted to load the page. Leave the array empty to disable the check and rely entirely on your web server for access control.

## Security Notes

This dashboard exposes sensitive host information including process command lines, logged in usernames, network sockets, and authentication failure sources. Treat it as an internal tool.

Never expose it directly to the public internet.

Place it behind a VPN, an IP allowlist, HTTP basic authentication, or a reverse proxy that enforces authentication.

Even though the PHP file ships with its own allowlist, that is a second layer of defense, not a replacement for proper network level controls.

If you want an application level token on top of the allowlist, add a check near the top of `index.php` that compares a query parameter against a long random string using `hash_equals`.

Rotate the allowlist whenever an administrator leaves your team.

Review the file after every upstream update to confirm the allowlist and thresholds still match your environment.

## Customization

The visual language is defined in a single CSS block inside `index.php`. Colors are declared as CSS custom properties at the top of the style block, so changing the palette means editing a handful of variables rather than hunting through the file.

Column layout is driven by a twelve column grid. Panels are assigned classes such as `c-4`, `c-6`, and `c-8` to control their width. Changing a panel from `c-6` to `c-4` narrows it, and changing it to `c-12` makes it full width.

Severity colors are exposed as CSS variables named `--good`, `--warn`, and `--crit`. Override them if you want a different palette.

To add a new panel, add a collector function near the top of the file, call it in the collection section, and render a card for it in the body. Follow the existing pattern of escaping every value with the helper function before outputting it.

## Troubleshooting

If the failed login panel says the log is unreadable or empty, confirm the PHP FPM user belongs to the `systemd-journal` group and restart PHP FPM. On systems without journald, confirm that `/var/log/auth.log` or `/var/log/secure` exists and is readable by the web server user.

If the top processes panel is empty, confirm that `shell_exec` is not disabled in your PHP configuration. You can check with `php i` and look for `disable_functions`.

If the listening ports panel is empty, confirm that either `ss` or `netstat` is installed and available in the PATH of the PHP FPM user.

If the page returns a forbidden message, your client IP is not in the `ALLOWED_CIDRS` array. Add it or remove the array to disable the check.

If the whole page fails to load and shows raw PHP, your web server is not handing PHP files to PHP FPM. Review the virtual host configuration.

If metrics look stale, remember that the page reloads every `REFRESH_SECONDS`. Reduce the value if you want a faster cadence, but be aware that each reload spawns several shell commands.

## Performance

Each page load runs roughly six short lived commands, which together complete in well under one hundred milliseconds on a typical virtual machine. The page is intentionally server rendered, so there is no client side polling loop and no background daemon.

If you host this on a very small instance or a device with slow storage, consider raising `REFRESH_SECONDS` to thirty or sixty to reduce load.

## Contributing

Fork the repository, create a feature branch, make your change, and open a pull request. Keep the single file philosophy intact where possible. If a change requires a new dependency, explain why in the pull request description.

## License

The repository does not currently declare a license. Until one is added, all rights are reserved by the author. If you intend to redistribute or embed this dashboard in another product, please open an issue to discuss licensing.

## Acknowledgments

Built for people who want a clear view of a server without installing a full monitoring stack. Inspired by the SOC dashboards that analysts stare at all day, distilled into a single file.
```
