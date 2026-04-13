<?php
/*
 *  Reporting page for nginx/modsecurity log file database - Garrett Wiedmeier - 2026
 *  Shout-out to inspiration from Tommy Mühle's Simple PHP library to parse Apache or Nginx error-log file entries for further usage. https://github.com/tommy-muehle/error-log-parser 
 *  Created based on many prompts from copilot AI help
 */

#Should be commented out on production
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

#Set to your desired time zone
date_default_timezone_set('America/Los_Angeles');

/* ============================================================
   DATABASE - be sure to set your own variables
   I store them in files outside the web root
   Change as appropriate
   ============================================================ */

$dbHost = file_get_contents("/path/to/config/dbserver.cfg");
$dbUser = file_get_contents("/path/to/config/dbuser.cfg");
$dbPass = file_get_contents("/path/to/config/dbpass.cfg");
$dbName = file_get_contents("/path/to/config/dbname.cfg");

$mysqli = new mysqli($dbHost, $dbUser, $dbPass, $dbName);
if ($mysqli->connect_error) {
    die("Database connection failed");
}
$mysqli->set_charset('utf8mb4');

// Simple helper
function fetchAll($mysqli, $sql) {
    $res = $mysqli->query($sql);
    return $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>ModSecurity Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f6f8; }
        h1, h2 { color: #333; }
        table { border-collapse: collapse; width: 100%; background: #fff; margin-bottom: 30px; }
        th, td { padding: 8px 12px; border: 1px solid #ddd; font-size: 13px; }
        th { background: #2c3e50; color: #fff; text-align: left; }
        tr:nth-child(even) { background: #f9f9f9; }
        .container { width: 95%; margin: auto; }
        .stat-box { display: inline-block; padding: 15px; margin: 10px; background: #fff; border: 1px solid #ddd; }
    </style>
</head>
<body>
<div class="container">

<h1>🛡️ ModSecurity Dashboard</h1>

<?php
// ================= OVERALL STATS =================
$stats = fetchAll($mysqli, "
    SELECT
        COUNT(*) total_events,
        COUNT(DISTINCT client_ip) unique_ips,
        COUNT(DISTINCT rule_id) unique_rules,
        COUNT(DISTINCT server_name) servers
    FROM modsecurity_events
");
$s = $stats[0];
?>

<div class="stat-box"><strong>Total Events</strong><br><?= number_format($s['total_events']) ?></div>
<div class="stat-box"><strong>Unique IPs</strong><br><?= number_format($s['unique_ips']) ?></div>
<div class="stat-box"><strong>Rules Triggered</strong><br><?= number_format($s['unique_rules']) ?></div>
<div class="stat-box"><strong>Servers</strong><br><?= number_format($s['servers']) ?></div>

---

<h2>🔝 Top Client IPs Triggering ModSecurity</h2>
<table>
<tr><th>Client IP</th><th>Hits</th></tr>
<?php
$rows = fetchAll($mysqli, "
    SELECT client_ip, COUNT(*) hits
    FROM modsecurity_events
    GROUP BY client_ip
    ORDER BY hits DESC
    LIMIT 20
");
foreach ($rows as $r): ?>
<tr>
    <td><?= htmlspecialchars($r['client_ip']) ?></td>
    <td><?= number_format($r['hits']) ?></td>
</tr>
<?php endforeach; ?>
</table>

---

<h2>🚨 Top Triggered Rules</h2>
<table>
<tr><th>Rule ID</th><th>Message</th><th>Hits</th></tr>
<?php
$rows = fetchAll($mysqli, "
    SELECT rule_id, message, COUNT(*) hits
    FROM modsecurity_events
    GROUP BY rule_id, message
    ORDER BY hits DESC
    LIMIT 20
");
foreach ($rows as $r): ?>
<tr>
    <td><?= htmlspecialchars($r['rule_id']) ?></td>
    <td><?= htmlspecialchars($r['message']) ?></td>
    <td><?= number_format($r['hits']) ?></td>
</tr>
<?php endforeach; ?>
</table>


---

<h2>📌 Top Requests Triggering ModSecurity</h2>
<table>
<tr>
    <th>Website</th>
    <th>Request</th>
    <th>Hits</th>
</tr>
<?php
$rows = fetchAll($mysqli, "
    SELECT
        server_name,
        request_line,
        COUNT(*) AS hits
    FROM modsecurity_events
    WHERE request_line IS NOT NULL
    GROUP BY server_name, request_line
    ORDER BY hits DESC
    LIMIT 25
");
foreach ($rows as $r): ?>
<tr>
    <td><?= htmlspecialchars($r['server_name']) ?></td>
    <td><?= htmlspecialchars($r['request_line']) ?></td>
    <td><?= number_format($r['hits']) ?></td>
</tr>
<?php endforeach; ?>
</table>

---

<h2>🏷️ Server → Request → Rule Breakdown ✅</h2>
<table>
<tr>
    <th>Server</th>
    <th>Request URI</th>
    <th>Rule ID</th>
    <th>Message</th>
    <th>Hits</th>
</tr>
<?php
$rows = fetchAll($mysqli, "
    SELECT
        server_name,
        request_line,
        rule_id,
        message,
        COUNT(*) hits
    FROM modsecurity_events
    GROUP BY server_name, request_line, rule_id, message
    ORDER BY hits DESC
    LIMIT 50
");
foreach ($rows as $r): ?>
<tr>
    <td><?= htmlspecialchars($r['server_name']) ?></td>
    <td><?= htmlspecialchars($r['request_line']) ?></td>
    <td><?= htmlspecialchars($r['rule_id']) ?></td>
    <td><?= htmlspecialchars($r['message']) ?></td>
    <td><?= number_format($r['hits']) ?></td>
</tr>
<?php endforeach; ?>
</table>

---


<h2>📈 Top Requests Triggering ModSecurity Per Server</h2>
<table>
<tr><th>Server</th><th>Request</th><th>Hits</th></tr>
<?php
$rows = fetchAll($mysqli, "
    SELECT server_name, request_line, COUNT(*) hits
    FROM modsecurity_events
    WHERE request_line IS NOT NULL
    GROUP BY server_name, request_line
    ORDER BY hits DESC
    LIMIT 30
");
foreach ($rows as $r): ?>
<tr>
    <td><?= htmlspecialchars($r['server_name']) ?></td>
    <td><?= htmlspecialchars($r['request_line']) ?></td>
    <td><?= number_format($r['hits']) ?></td>
</tr>
<?php endforeach; ?>
</table>


---

<h2>🕒 Most Recent ModSecurity Events</h2>
<table>
<tr>
    <th>Time</th><th>Server</th><th>Client IP</th>
    <th>Rule</th><th>Message</th><th>Request</th>
</tr>
<?php
$rows = fetchAll($mysqli, "
    SELECT event_time, server_name, client_ip, rule_id, message, request_line
    FROM modsecurity_events
    ORDER BY event_time DESC
    LIMIT 50
");
foreach ($rows as $r): ?>
<tr>


<?php
$dt = new DateTime($r['event_time'], new DateTimeZone('UTC'));
$dt->setTimezone(new DateTimeZone('America/Los_Angeles'));
?>
<td><?= htmlspecialchars($dt->format('Y-m-d H:i:s T')) ?></td>



    
    <td><?= htmlspecialchars($r['server_name']) ?></td>
    <td><?= htmlspecialchars($r['client_ip']) ?></td>
    <td><?= htmlspecialchars($r['rule_id']) ?></td>
    <td><?= htmlspecialchars($r['message']) ?></td>
    <td><?= htmlspecialchars($r['request_line']) ?></td>
</tr>
<?php endforeach; ?>
</table>

</div>
</body>
</html>