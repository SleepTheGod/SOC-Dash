<?php
/**
 * SOC Analyst Dashboard — single-file PHP, server-side rendered.
 *
 * WARNING: exposes sensitive host info. Restrict access before deploying.
 * Edit the CONFIG block below, then place behind VPN / IP allowlist / auth.
 */

declare(strict_types=1);

/* ==================================================================
 * CONFIG
 * ================================================================== */
const REFRESH_SECONDS = 10;                 // auto-refresh interval
const THRESH_DISK_WARN = 75;
const THRESH_DISK_CRIT = 90;
const THRESH_MEM_WARN  = 75;
const THRESH_MEM_CRIT  = 90;
const THRESH_LOAD_WARN = 4.0;
const THRESH_FAIL_WARN = 20;
const THRESH_FAIL_CRIT = 100;
const FAIL_WINDOW      = '24 hours ago';
const FAIL_LIMIT       = 15;
const PROC_LIMIT       = 15;

// CIDR allowlist for extra safety. Leave empty to disable.
const ALLOWED_CIDRS = [
    '127.0.0.1/32',
    '::1/128',
    '10.0.0.0/8',
    '192.168.0.0/16',
    '172.16.0.0/12',
];

/* ==================================================================
 * ACCESS CONTROL
 * ================================================================== */
function ipInCidr(string $ip, string $cidr): bool {
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    [$subnet, $bits] = explode('/', $cidr, 2);
    $bits = (int)$bits;

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ipL = ip2long($ip);
        $subL = ip2long($subnet);
        if ($ipL === false || $subL === false) return false;
        $mask = $bits === 0 ? 0 : (-1 << (32 - $bits));
        return ($ipL & $mask) === ($subL & $mask);
    }

    $ipB  = @inet_pton($ip);
    $subB = @inet_pton($subnet);
    if ($ipB === false || $subB === false) return false;
    $bytes = intdiv($bits, 8);
    $rem   = $bits % 8;
    if ($bytes > 0 && substr($ipB, 0, $bytes) !== substr($subB, 0, $bytes)) return false;
    if ($rem === 0) return true;
    $m = chr((0xFF << (8 - $rem)) & 0xFF);
    return (($ipB[$bytes] & $m) === ($subB[$bytes] & $m));
}

$remoteIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
if (ALLOWED_CIDRS) {
    $allowed = false;
    foreach (ALLOWED_CIDRS as $cidr) {
        if (ipInCidr($remoteIp, $cidr)) { $allowed = true; break; }
    }
    if (!$allowed) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        exit("Forbidden: your IP ($remoteIp) is not allowed.\n");
    }
}

/* ==================================================================
 * HELPERS
 * ================================================================== */
function h($v): string {
    return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function run(string $cmd): ?string {
    if (!function_exists('shell_exec')) return null;
    $out = @shell_exec($cmd . ' 2>/dev/null');
    if (!is_string($out)) return null;
    $out = trim($out);
    return $out === '' ? null : $out;
}

function fmtBytes(int $b): string {
    $u = ['B','KB','MB','GB','TB','PB'];
    $i = 0;
    while ($b >= 1024 && $i < count($u) - 1) { $b /= 1024; $i++; }
    return (round($b * 100) / 100) . ' ' . $u[$i];
}

function sevClass(int $pct, int $warn, int $crit): string {
    if ($pct >= $crit) return 'crit';
    if ($pct >= $warn) return 'warn';
    if ($pct >= 50)   return 'ok';
    return 'good';
}

function sevForLoad(float $l): string {
    if ($l >= 8) return 'crit';
    if ($l >= THRESH_LOAD_WARN) return 'warn';
    return '';
}

function uptimeHuman(): string {
    $up = @file_get_contents('/proc/uptime');
    if (!$up) return 'unknown';
    $sec = (int)explode(' ', $up)[0];
    $d = intdiv($sec, 86400); $sec %= 86400;
    $hh = intdiv($sec, 3600); $sec %= 3600;
    $m = intdiv($sec, 60);
    return "{$d}d {$hh}h {$m}m";
}

/* ==================================================================
 * COLLECTORS
 * ================================================================== */

/* ---- Host ---- */
function collectHost(): array {
    $distro = 'unknown';
    $osr = @file_get_contents('/etc/os-release');
    if ($osr && preg_match('/^PRETTY_NAME="?([^"\n]+)"?/m', $osr, $m)) {
        $distro = $m[1];
    }
    return [
        'Hostname'     => gethostname() ?: 'unknown',
        'OS'           => PHP_OS,
        'Kernel'       => php_uname('r'),
        'Architecture' => php_uname('m'),
        'Distro'       => $distro,
        'PHP Version'  => PHP_VERSION,
        'Uptime'       => uptimeHuman(),
        'Server Time'  => date('Y-m-d H:i:s T'),
    ];
}

/* ---- Memory ---- */
function collectMemory(): array {
    $raw = @file_get_contents('/proc/meminfo') ?: '';
    $m = [];
    foreach (explode("\n", $raw) as $line) {
        if (preg_match('/^(\w+):\s+(\d+)/', $line, $x)) {
            $m[$x[1]] = (int)$x[2] * 1024;
        }
    }
    $total = $m['MemTotal'] ?? 0;
    $avail = $m['MemAvailable'] ?? ($m['MemFree'] ?? 0);
    return [
        'total'     => $total,
        'used'      => max(0, $total - $avail),
        'avail'     => $avail,
        'swapTotal' => $m['SwapTotal'] ?? 0,
        'swapUsed'  => max(0, ($m['SwapTotal'] ?? 0) - ($m['SwapFree'] ?? 0)),
    ];
}

/* ---- Load ---- */
function collectLoad(): array {
    $la = @file_get_contents('/proc/loadavg');
    if (!$la) return ['?','?','?'];
    $p = explode(' ', trim($la));
    return [$p[0] ?? '?', $p[1] ?? '?', $p[2] ?? '?'];
}

/* ---- Disks ---- */
function collectDisks(): array {
    $out = run("df -P -B1 -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2");
    if (!$out) return [];
    $rows = [];
    foreach (explode("\n", $out) as $line) {
        $p = preg_split('/\s+/', trim($line));
        if (count($p) < 6) continue;
        $rows[] = [
            'fs'    => $p[0],
            'size'  => (int)$p[1],
            'used'  => (int)$p[2],
            'avail' => (int)$p[3],
            'pct'   => (int)rtrim($p[4], '%'),
            'mount' => $p[5],
        ];
    }
    return $rows;
}

/* ---- Processes ---- */
function collectProcesses(int $n): array {
    $out = run("ps -eo pid,ppid,user,comm,%mem,%cpu --sort=-%cpu 2>/dev/null | head -n " . ($n + 1));
    if (!$out) return [];
    $lines = explode("\n", $out);
    array_shift($lines);
    $rows = [];
    foreach ($lines as $line) {
        $p = preg_split('/\s+/', trim($line), 6);
        if (count($p) < 6) continue;
        $tail = $p[5];
        if (!preg_match('/^(.*)\s+([\d\.]+)\s+([\d\.]+)$/', $tail, $m)) continue;
        $rows[] = [
            'pid'  => (int)$p[0],
            'ppid' => (int)$p[1],
            'user' => $p[2],
            'cmd'  => $m[1],
            'mem'  => (float)$m[2],
            'cpu'  => (float)$m[3],
        ];
    }
    return $rows;
}

/* ---- Active users ---- */
function collectUsers(): array {
    $out = run("who 2>/dev/null");
    if (!$out) return [];
    $rows = [];
    foreach (explode("\n", $out) as $line) {
        $p = preg_split('/\s+/', trim($line));
        if (count($p) < 5) continue;
        $rows[] = [
            'user' => $p[0],
            'tty'  => $p[1],
            'when' => $p[2] . ' ' . $p[3],
            'from' => $p[4],
        ];
    }
    return $rows;
}

/* ---- Failed SSH logins ---- */
function collectFailedLogins(int $limit): array {
    $raw = run("journalctl -u ssh -u sshd --since '" . FAIL_WINDOW . "' 2>/dev/null | grep -i 'failed password' | tail -n 1000");
    if (!$raw) $raw = run("tail -n 1000 /var/log/auth.log 2>/dev/null | grep -i 'failed password'");
    if (!$raw) $raw = run("tail -n 1000 /var/log/secure 2>/dev/null | grep -i 'failed password'");
    if (!$raw) return [];

    $byIp = [];
    foreach (explode("\n", $raw) as $line) {
        if (preg_match('/from\s+([0-9a-fA-F:\.]+)\s+port/i', $line, $m)) {
            $ip = $m[1];
            $byIp[$ip] = ($byIp[$ip] ?? 0) + 1;
        }
    }
    arsort($byIp);
    $out = [];
    foreach (array_slice($byIp, 0, $limit, true) as $ip => $n) {
        $out[] = ['ip' => $ip, 'count' => $n];
    }
    return $out;
}

/* ---- Listening sockets ---- */
function collectListeners(): array {
    $out = run("ss -tulnH 2>/dev/null");
    if (!$out) $out = run("ss -tuln 2>/dev/null | tail -n +2");
    if (!$out) $out = run("netstat -tuln 2>/dev/null | tail -n +3");
    if (!$out) return [];

    $rows = [];
    foreach (explode("\n", $out) as $line) {
        $p = preg_split('/\s+/', trim($line));
        if (count($p) < 5) continue;
        $proto = strtolower($p[0]);
        if (!in_array($proto, ['tcp','udp','tcp6','udp6'], true)) continue;
        // ss -H layout: Netid State Recv-Q Send-Q Local Peer [Process]
        // netstat:      Proto Recv-Q Send-Q Local Foreign State
        $local = $p[4] ?? '';
        $peer  = $p[5] ?? '';
        $proc  = $p[6] ?? ($p[7] ?? '');
        if (strpos($local, ':') === false && isset($p[3])) {
            // netstat variant: local is index 3
            $local = $p[3];
            $peer  = $p[4];
            $proc  = $p[5] ?? '';
        }
        $rows[] = [
            'proto' => $proto,
            'local' => $local,
            'peer'  => $peer,
            'proc'  => trim($proc, '()'),
        ];
    }
    return $rows;
}

/* ==================================================================
 * COLLECT
 * ================================================================== */
$host      = collectHost();
$memory    = collectMemory();
$load      = collectLoad();
$disks     = collectDisks();
$processes = collectProcesses(PROC_LIMIT);
$users     = collectUsers();
$failures  = collectFailedLogins(FAIL_LIMIT);
$listeners = collectListeners();

$memPct  = $memory['total'] > 0 ? (int)round($memory['used'] / $memory['total'] * 100) : 0;
$swapPct = $memory['swapTotal'] > 0 ? (int)round($memory['swapUsed'] / $memory['swapTotal'] * 100) : 0;
$failTotal = array_sum(array_column($failures, 'count'));

$rootDisk = null;
foreach ($disks as $d) { if ($d['mount'] === '/') { $rootDisk = $d; break; } }
if (!$rootDisk && $disks) $rootDisk = $disks[0];

/* ---- Global status ---- */
$critCount = 0; $warnCount = 0;
foreach ($disks as $d) {
    if ($d['pct'] >= THRESH_DISK_CRIT) $critCount++;
    elseif ($d['pct'] >= THRESH_DISK_WARN) $warnCount++;
}
if ($memPct >= THRESH_MEM_CRIT) $critCount++;
elseif ($memPct >= THRESH_MEM_WARN) $warnCount++;
if ((float)$load[0] > THRESH_LOAD_WARN) $warnCount++;
if ($failTotal >= THRESH_FAIL_CRIT) $critCount++;
elseif ($failTotal >= THRESH_FAIL_WARN) $warnCount++;

if ($critCount > 0)     { $status = 'CRITICAL'; $statusCls = 'crit'; }
elseif ($warnCount > 0) { $status = 'WARNING';  $statusCls = 'warn'; }
else                    { $status = 'NOMINAL';  $statusCls = 'good'; }

/* ==================================================================
 * RENDER
 * ================================================================== */
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="<?= REFRESH_SECONDS ?>">
<title>SOC Dashboard · <?= h($host['Hostname']) ?></title>
<style>
:root {
    --bg:#0a0e14; --panel:#111721; --panel-2:#0d131c; --border:#1e2836;
    --text:#c8d3e0; --muted:#6b7a8f; --accent:#00e5a0; --accent-2:#38bdf8;
    --good:#22c55e; --warn:#f59e0b; --crit:#ef4444; --info:#38bdf8;
    --shadow:0 4px 20px rgba(0,0,0,.5);
}
* { box-sizing: border-box; }
body {
    margin:0;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    background: radial-gradient(1200px 600px at 20% -10%, #0d1a24 0%, var(--bg) 60%);
    color: var(--text); font-size: 13px; line-height: 1.45; min-height: 100vh;
}
.topbar {
    display:flex; align-items:center; justify-content:space-between;
    padding:14px 22px; border-bottom:1px solid var(--border);
    background:rgba(10,14,20,.85); backdrop-filter:blur(8px);
    position:sticky; top:0; z-index:10;
}
.brand { display:flex; align-items:center; gap:12px; }
.brand .logo {
    width:30px; height:30px; border-radius:8px;
    background:linear-gradient(135deg,var(--accent),var(--accent-2));
    display:flex; align-items:center; justify-content:center;
    color:#001; font-weight:800; font-size:14px;
    box-shadow:0 0 20px rgba(0,229,160,.4);
}
.brand h1 { font-size:15px; margin:0; letter-spacing:.5px; }
.brand small { color:var(--muted); font-size:11px; }
.topbar .meta { color:var(--muted); font-size:11px; text-align:right; }
.topbar .meta b { color:var(--text); }

.status-pill { padding:4px 12px; border-radius:999px; font-weight:700; letter-spacing:.8px; font-size:11px; text-transform:uppercase; }
.status-pill.good { background:rgba(34,197,94,.12); color:var(--good); border:1px solid rgba(34,197,94,.4); }
.status-pill.warn { background:rgba(245,158,11,.12); color:var(--warn); border:1px solid rgba(245,158,11,.4); }
.status-pill.crit { background:rgba(239,68,68,.14); color:var(--crit); border:1px solid rgba(239,68,68,.5); animation:pulse 1.6s infinite; }
@keyframes pulse { 0%,100% { box-shadow:0 0 0 0 rgba(239,68,68,.5); } 50% { box-shadow:0 0 0 8px rgba(239,68,68,0); } }

.grid { display:grid; grid-template-columns:repeat(12,1fr); gap:16px; padding:20px 22px 60px; max-width:1600px; margin:0 auto; }
.card { grid-column:span 12; background:linear-gradient(180deg,var(--panel),var(--panel-2)); border:1px solid var(--border); border-radius:12px; box-shadow:var(--shadow); overflow:hidden; }
.card .hd { display:flex; justify-content:space-between; align-items:center; padding:12px 16px; border-bottom:1px solid var(--border); background:rgba(255,255,255,.02); }
.card .hd h2 { font-size:12px; letter-spacing:1.2px; text-transform:uppercase; color:var(--muted); margin:0; }
.card .hd .count { font-size:11px; color:var(--muted); }
.card .bd { padding:14px 16px; }

.kpis { display:grid; grid-template-columns:repeat(6,1fr); gap:16px; grid-column:span 12; }
.kpi { background:linear-gradient(180deg,var(--panel),var(--panel-2)); border:1px solid var(--border); border-radius:12px; padding:14px 16px; position:relative; overflow:hidden; box-shadow:var(--shadow); }
.kpi::before { content:''; position:absolute; left:0; top:0; bottom:0; width:3px; background:var(--accent); }
.kpi.warn::before { background:var(--warn); }
.kpi.crit::before { background:var(--crit); }
.kpi .label { color:var(--muted); font-size:10.5px; letter-spacing:1px; text-transform:uppercase; }
.kpi .value { font-size:24px; font-weight:700; margin-top:6px; }
.kpi .sub { color:var(--muted); font-size:11px; margin-top:4px; }

.meter { height:8px; background:#0a0f16; border-radius:999px; overflow:hidden; border:1px solid var(--border); }
.meter > span { display:block; height:100%; background:var(--good); transition:width .4s; }
.meter > span.ok   { background:linear-gradient(90deg,#0ea5e9,#22c55e); }
.meter > span.warn { background:linear-gradient(90deg,#f59e0b,#ef4444); }
.meter > span.crit { background:linear-gradient(90deg,#ef4444,#b91c1c); }

table { width:100%; border-collapse:collapse; font-size:12.5px; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:11px; letter-spacing:.8px; text-transform:uppercase; background:rgba(255,255,255,.02); }
tbody tr:hover { background:rgba(56,189,248,.05); }
td.k { color:var(--muted); width:220px; }
td.num { text-align:right; font-variant-numeric:tabular-nums; }

.tag { display:inline-block; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:600; letter-spacing:.4px; border:1px solid transparent; }
.tag.good { color:var(--good); background:rgba(34,197,94,.1); border-color:rgba(34,197,94,.3); }
.tag.warn { color:var(--warn); background:rgba(245,158,11,.1); border-color:rgba(245,158,11,.3); }
.tag.crit { color:var(--crit); background:rgba(239,68,68,.1); border-color:rgba(239,68,68,.4); }
.tag.info { color:var(--info); background:rgba(56,189,248,.1); border-color:rgba(56,189,248,.3); }
.tag.mute { color:var(--muted); background:rgba(107,122,143,.08); border-color:var(--border); }

.muted { color:var(--muted); } .right { text-align:right; } .mono { font-family:ui-monospace,monospace; }
.bar { display:flex; align-items:center; gap:8px; } .bar .meter { flex:1; }
.c-3 { grid-column:span 3; } .c-4 { grid-column:span 4; } .c-6 { grid-column:span 6; } .c-8 { grid-column:span 8; } .c-12 { grid-column:span 12; }
@media (max-width:1100px){ .kpis{grid-template-columns:repeat(3,1fr);} .c-3,.c-4,.c-6,.c-8{grid-column:span 12;} }
@media (max-width:600px){ .kpis{grid-template-columns:repeat(2,1fr);} }
</style>
</head>
<body>

<!-- ============ TOP BAR ============ -->
<div class="topbar">
    <div class="brand">
        <div class="logo">SOC</div>
        <div>
            <h1>Server SOC Dashboard</h1>
            <small><?= h($host['Hostname']) ?> · <?= h($host['OS']) ?> · <?= h($host['Kernel']) ?></small>
        </div>
    </div>
    <div class="meta">
        <span class="status-pill <?= h($statusCls) ?>"><?= h($status) ?></span>
        <div style="margin-top:4px">Updated <b><?= h($host['Server Time']) ?></b> · auto-refresh <?= REFRESH_SECONDS ?>s</div>
    </div>
</div>

<div class="grid">

    <!-- ============ KPI STRIP ============ -->
    <div class="kpis">
        <div class="kpi <?= h(sevClass($memPct, THRESH_MEM_WARN, THRESH_MEM_CRIT)) ?>">
            <div class="label">Memory</div>
            <div class="value"><?= h($memPct) ?>%</div>
            <div class="sub"><?= h(fmtBytes($memory['used'])) ?> / <?= h(fmtBytes($memory['total'])) ?></div>
        </div>

        <div class="kpi <?= h($rootDisk ? sevClass($rootDisk['pct'], THRESH_DISK_WARN, THRESH_DISK_CRIT) : '') ?>">
            <div class="label">Root FS</div>
            <div class="value"><?= h($rootDisk['pct'] ?? 0) ?>%</div>
            <div class="sub"><?= $rootDisk ? h(fmtBytes($rootDisk['used']) . ' / ' . fmtBytes($rootDisk['size'])) : 'n/a' ?></div>
        </div>

        <div class="kpi <?= h(sevForLoad((float)$load[0])) ?>">
            <div class="label">Load (1 / 5 / 15)</div>
            <div class="value" style="font-size:18px"><?= h($load[0]) ?> / <?= h($load[1]) ?> / <?= h($load[2]) ?></div>
            <div class="sub">uptime <?= h($host['Uptime']) ?></div>
        </div>

        <div class="kpi">
            <div class="label">Listening Ports</div>
            <div class="value"><?= h(count($listeners)) ?></div>
            <div class="sub">tcp + udp sockets</div>
        </div>

        <div class="kpi <?= h($failTotal >= THRESH_FAIL_CRIT ? 'crit' : ($failTotal >= THRESH_FAIL_WARN ? 'warn' : '')) ?>">
            <div class="label">Failed SSH (24h)</div>
            <div class="value"><?= h($failTotal) ?></div>
            <div class="sub"><?= h(count($failures)) ?> unique source IPs</div>
        </div>

        <div class="kpi">
            <div class="label">Active Users</div>
            <div class="value"><?= h(count($users)) ?></div>
            <div class="sub">via `who`</div>
        </div>
    </div>

    <!-- ============ SYSTEM INFO ============ -->
    <div class="card c-6">
        <div class="hd"><h2>System Information</h2><span class="count">host telemetry</span></div>
        <div class="bd">
            <table>
                <tbody>
                <?php foreach ($host as $k => $v): ?>
                    <tr><td class="k"><?= h($k) ?></td><td class="mono"><?= h($v) ?></td></tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- ============ RESOURCE UTILIZATION ============ -->
    <div class="card c-6">
        <div class="hd"><h2>Resource Utilization</h2><span class="count">memory &amp; swap</span></div>
        <div class="bd">
            <div style="margin-bottom:14px">
                <div class="bar">
                    <div style="width:80px" class="muted">RAM</div>
                    <div class="meter"><span class="<?= h(sevClass($memPct, THRESH_MEM_WARN, THRESH_MEM_CRIT)) ?>" style="width:<?= h($memPct) ?>%"></span></div>
                    <div class="num mono" style="width:60px;text-align:right"><?= h($memPct) ?>%</div>
                </div>
                <div class="muted" style="font-size:11px;margin-top:4px">
                    used <?= h(fmtBytes($memory['used'])) ?> · avail <?= h(fmtBytes($memory['avail'])) ?> · total <?= h(fmtBytes($memory['total'])) ?>
                </div>
            </div>
            <div>
                <div class="bar">
                    <div style="width:80px" class="muted">SWAP</div>
                    <div class="meter"><span class="<?= h(sevClass($swapPct, THRESH_MEM_WARN, THRESH_MEM_CRIT)) ?>" style="width:<?= h($swapPct) ?>%"></span></div>
                    <div class="num mono" style="width:60px;text-align:right"><?= h($swapPct) ?>%</div>
                </div>
                <div class="muted" style="font-size:11px;margin-top:4px">
                    used <?= h(fmtBytes($memory['swapUsed'])) ?> · total <?= h(fmtBytes($memory['swapTotal'])) ?>
                </div>
            </div>
        </div>
    </div>

    <!-- ============ FILESYSTEMS ============ -->
    <div class="card c-12">
        <div class="hd"><h2>Filesystem Usage</h2><span class="count"><?= h(count($disks)) ?> mounts</span></div>
        <div class="bd">
            <?php if (!$disks): ?>
                <div class="muted">No filesystem data available.</div>
            <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>Mount</th><th>Device</th>
                        <th class="right">Size</th><th class="right">Used</th><th class="right">Avail</th>
                        <th style="width:30%">Usage</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($disks as $d): $c = sevClass($d['pct'], THRESH_DISK_WARN, THRESH_DISK_CRIT); ?>
                    <tr>
                        <td class="mono"><?= h($d['mount']) ?></td>
                        <td class="mono muted"><?= h($d['fs']) ?></td>
                        <td class="num mono"><?= h(fmtBytes($d['size'])) ?></td>
                        <td class="num mono"><?= h(fmtBytes($d['used'])) ?></td>
                        <td class="num mono"><?= h(fmtBytes($d['avail'])) ?></td>
                        <td>
                            <div class="bar">
                                <div class="meter"><span class="<?= h($c) ?>" style="width:<?= h($d['pct']) ?>%"></span></div>
                                <span class="tag <?= h($c) ?>"><?= h($d['pct']) ?>%</span>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>

    <!-- ============ TOP PROCESSES ============ -->
    <div class="card c-8">
        <div class="hd"><h2>Top Processes by CPU</h2><span class="count"><?= h(count($processes)) ?> shown</span></div>
        <div class="bd" style="padding:0">
            <?php if (!$processes): ?>
                <div class="bd muted">Process list unavailable (shell_exec disabled?).</div>
            <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th class="right">PID</th><th class="right">PPID</th><th>User</th>
                        <th>Command</th>
                        <th class="right">%MEM</th><th class="right">%CPU</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($processes as $p):
                    $cpuCls = $p['cpu'] >= 50 ? 'crit' : ($p['cpu'] >= 10 ? 'warn' : 'mute');
                    $memCls = $p['mem'] >= 25 ? 'crit' : ($p['mem'] >= 10 ? 'warn' : 'mute');
                ?>
                    <tr>
                        <td class="num mono"><?= h($p['pid']) ?></td>
                        <td class="num mono muted"><?= h($p['ppid']) ?></td>
                        <td class="mono"><?= h($p['user']) ?></td>
                        <td class="mono" style="max-width:560px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?= h($p['cmd']) ?></td>
                        <td class="num"><span class="tag <?= h($memCls) ?>"><?= h(number_format($p['mem'],1)) ?></span></td>
                        <td class="num"><span class="tag <?= h($cpuCls) ?>"><?= h(number_format($p['cpu'],1)) ?></span></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>

    <!-- ============ ACTIVE SESSIONS ============ -->
    <div class="card c-4">
        <div class="hd"><h2>Active Sessions</h2><span class="count"><?= h(count($users)) ?> logged in</span></div>
        <div class="bd" style="padding:0">
            <?php if (!$users): ?>
                <div class="bd muted">No active sessions.</div>
            <?php else: ?>
            <table>
                <thead><tr><th>User</th><th>TTY</th><th>From</th><th>When</th></tr></thead>
                <tbody>
                <?php foreach ($users as $u): ?>
                    <tr>
                        <td class="mono"><?= h($u['user']) ?></td>
                        <td class="mono muted"><?= h($u['tty']) ?></td>
                        <td class="mono"><?= h($u['from']) ?></td>
                        <td class="muted"><?= h($u['when']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>

    <!-- ============ FAILED SSH LOGINS ============ -->
    <div class="card c-6">
        <div class="hd"><h2>Failed SSH Logins · 24h</h2><span class="count"><?= h(count($failures)) ?> IPs · <?= h($failTotal) ?> attempts</span></div>
        <div class="bd" style="padding:0">
            <?php if (!$failures): ?>
                <div class="bd muted">No failed-login data (journald/auth.log unreadable or empty).</div>
            <?php else:
                $max = max(array_column($failures, 'count'));
            ?>
            <table>
                <thead><tr><th>Source IP</th><th>Attempts</th><th style="width:40%">Volume</th><th>Severity</th></tr></thead>
                <tbody>
                <?php foreach ($failures as $f):
                    $cls = $f['count'] >= THRESH_FAIL_WARN ? 'crit' : ($f['count'] >= 5 ? 'warn' : 'mute');
                    $pct = $max > 0 ? (int)round($f['count'] / $max * 100) : 0;
                    $label = $cls === 'mute' ? 'LOW' : strtoupper($cls);
                ?>
                    <tr>
                        <td class="mono"><?= h($f['ip']) ?></td>
                        <td class="num mono"><?= h($f['count']) ?></td>
                        <td><div class="meter"><span class="<?= h($cls === 'mute' ? 'ok' : $cls) ?>" style="width:<?= h($pct) ?>%"></span></div></td>
                        <td><span class="tag <?= h($cls) ?>"><?= h($label) ?></span></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>

    <!-- ============ LISTENING PORTS ============ -->
    <div class="card c-6">
        <div class="hd"><h2>Listening Ports</h2><span class="count"><?= h(count($listeners)) ?> sockets</span></div>
        <div class="bd" style="padding:0">
            <?php if (!$listeners): ?>
                <div class="bd muted">No listening sockets detected (ss/netstat unavailable).</div>
            <?php else: ?>
            <table>
                <thead><tr><th>Proto</th><th>Local Address</th><th>Peer</th><th>Process</th></tr></thead>
                <tbody>
                <?php foreach ($listeners as $l): ?>
                    <tr>
                        <td><span class="tag info"><?= h(strtoupper($l['proto'])) ?></span></td>
                        <td class="mono"><?= h($l['local']) ?></td>
                        <td class="mono muted"><?= h($l['peer']) ?></td>
                        <td class="mono muted" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?= h($l['proc']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>

</div>
</body>
</html>
