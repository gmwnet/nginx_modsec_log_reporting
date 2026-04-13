
<?php
/**
 *  NGINX error log + embedded ModSecurity parser - Garrett Wiedmeier - 2026
 *  Shout-out to inspiration from Tommy Mühle's Simple PHP library to parse Apache or Nginx error-log file entries for further usage. https://github.com/tommy-muehle/error-log-parser 
 *  Created based on many prompts from copilot AI help
 *  Be sure to run the create DB script in this project and set appropriate permissions and set the credentials below
 *  Suggest running from CLI as cron job every x minutes
 *  And protecting to run from localhost only
 * - CLI and Web compatible
 * - Batch inserts (mysqli)
 * - File offset tracking (no duplicates)
 * * php parse_nginx_modsec.php /var/log/nginx/error.log  --batch=1000 --dryrun --debug
 * * https://yourserver/parse_nginx_modsec.php?file=/var/log/nginx/error.log&batch=1000&dryrun=1&debug=1
 */

#Should be commented out on production
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

/* ============================================================
   ENV DETECTION
   ============================================================ */
$isCli = (PHP_SAPI === 'cli');

/* ============================================================
   INPUT
   ============================================================ */
if ($isCli) {
    $logFile = $argv[1] ?? null;
    $batchSize = 500;
    $dryRun = false;
    $debug = false;

    foreach ($argv as $arg) {
        if (preg_match('/--batch=(\d+)/', $arg, $m)) $batchSize = (int)$m[1];
        if ($arg === '--dryrun') $dryRun = true;
        if ($arg === '--debug') $debug = true;
    }
} else {
    $logFile   = $_GET['file'] ?? null;
    $batchSize = (int)($_GET['batch'] ?? 500);
    $dryRun    = isset($_GET['dryrun']);
    $debug     = isset($_GET['debug']);
}

if (!$logFile) {
    die("No log file specified\n");
}

/* ============================================================
   SECURITY: restrict file access
   ============================================================ */
$allowedBaseDir = '/var/log/nginx/';
$realLog = realpath($logFile);
if (!$realLog || strpos($realLog, realpath($allowedBaseDir)) !== 0) {
    die("Unauthorized log file\n");
}

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
    die("DB connection failed\n");
}
$mysqli->set_charset('utf8mb4');

/* ============================================================
   FILE OFFSET FUNCTIONS
   ============================================================ */
function loadLogOffset(mysqli $db, string $file, int $inode, int $size): int
{
    $stmt = $db->prepare(
        "SELECT inode, last_position
         FROM log_file_offsets
         WHERE file_path = ?"
    );
    $stmt->bind_param('s', $file);
    $stmt->execute();
    $stmt->bind_result($savedInode, $pos);

    if ($stmt->fetch()) {
        $stmt->close();
        if ($savedInode != $inode || $pos > $size) {
            return 0; // rotated or truncated
        }
        return (int)$pos;
    }

    $stmt->close();
    return 0; // first run
}

function saveLogOffset(mysqli $db, string $file, int $inode, int $position): void
{
    $stmt = $db->prepare(
        "INSERT INTO log_file_offsets (file_path, inode, last_position)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE
           inode = VALUES(inode),
           last_position = VALUES(last_position)"
    );
    $stmt->bind_param('sii', $file, $inode, $position);
    $stmt->execute();
    $stmt->close();
}

/* ============================================================
   PARSER
   ============================================================ */
function parseNginxErrorWithModSec(string $line): ?array
{
    if (!preg_match(
        '/^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) ' .
        '\[(\w+)\] (\d+)#(\d+): ' .
        '\*(\d+) \[client ([^\]]+)\] (.+)$/',
        $line,
        $m
    )) {
        return null;
    }

    $event = [
        'nginx' => [
            'event_time'    => $m[1],
            'nginx_level'   => $m[2],
            'nginx_pid'     => (int)$m[3],
            'nginx_tid'     => (int)$m[4],
            'connection_id' => (int)$m[5],
            'client_ip'     => $m[6]
        ],
        'modsecurity' => null
    ];

    $rest = $m[7];

    if (strpos($rest, 'ModSecurity:') === false) {
        return $event;
    }

    if (!preg_match('/ModSecurity:\s*(.*?)\s*(, client:|$)/', $rest, $mm)) {
        return $event;
    }

    $payload = $mm[1];
    $mod = [];

    if (preg_match('/code (\d+) \(phase (\d+)\)/', $payload, $x)) {
        $mod['http_code'] = (int)$x[1];
        $mod['phase'] = (int)$x[2];
    }

    if (preg_match('/Matched "([^"]+)"/', $payload, $x)) {
        $mod['matched'] = $x[1];
    }

    preg_match_all('/\[(\w+)\s+"([^"]*)"\]/', $payload, $pairs, PREG_SET_ORDER);
    foreach ($pairs as $p) {
        [, $k, $v] = $p;
        if (isset($mod[$k])) {
            if (!is_array($mod[$k])) $mod[$k] = [$mod[$k]];
            $mod[$k][] = $v;
        } else {
            $mod[$k] = $v;
        }
    }

    preg_match('/request:\s*"([^"]+)"/', $line, $x) && $event['nginx']['request_line'] = $x[1];
    preg_match('/server:\s*([^,]+)/', $line, $x) && $event['nginx']['server_name'] = trim($x[1]);
    preg_match('/host:\s*"([^"]+)"/', $line, $x) && $event['nginx']['host'] = $x[1];

    $event['modsecurity'] = $mod;
    return $event;
}

/* ============================================================
   PREPARED STATEMENTS
   ============================================================ */
$eventStmt = $mysqli->prepare(
    "INSERT INTO modsecurity_events
     (event_time, nginx_level, nginx_pid, nginx_tid, connection_id,
      client_ip, server_name, host, request_line,
      http_code, phase, rule_id, rule_file, rule_line,
      rule_rev, rule_ver, message, matched, data,
      severity, maturity, accuracy, unique_id)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
);

$tagAdd = $mysqli->prepare("INSERT IGNORE INTO modsecurity_tags (tag) VALUES (?)");
$tagGet = $mysqli->prepare("SELECT id FROM modsecurity_tags WHERE tag=?");
$link   = $mysqli->prepare("INSERT IGNORE INTO modsecurity_event_tags (event_id, tag_id) VALUES (?,?)");

/* ============================================================
   PROCESS FILE
   ============================================================ */
$stat = stat($realLog);
$inode = $stat['ino'];
$fileSize = $stat['size'];

$offset = loadLogOffset($mysqli, $realLog, $inode, $fileSize);

$fh = fopen($realLog, 'r');
fseek($fh, $offset);

$processed = $inserted = 0;
$mysqli->begin_transaction();

while (($line = fgets($fh)) !== false) {
    $parsed = parseNginxErrorWithModSec($line);
    if (!$parsed || !$parsed['modsecurity']) continue;

    $processed++;

    if ($debug) {
        echo ($isCli ? print_r($parsed, true)
                     : '<pre>'.htmlspecialchars(print_r($parsed, true)).'</pre>');
    }

    if ($dryRun) continue;

    $n = $parsed['nginx'];
    $m = $parsed['modsecurity'];

// NGINX values
$event_time    = $n['event_time'];
$nginx_level   = $n['nginx_level'];
$nginx_pid     = $n['nginx_pid'];
$nginx_tid     = $n['nginx_tid'];
$connection_id = $n['connection_id'];
$client_ip     = $n['client_ip'];
$server_name   = $n['server_name'] ?? null;
$host          = $n['host'] ?? null;
$request_line  = $n['request_line'] ?? null;

// ModSecurity values
$http_code = $m['http_code'] ?? null;
$phase     = $m['phase'] ?? null;
$rule_id   = $m['id'] ?? null;
$rule_file = $m['file'] ?? null;
$rule_line = $m['line'] ?? null;
$rule_rev  = $m['rev'] ?? null;
$rule_ver  = $m['ver'] ?? null;
$message   = $m['msg'] ?? null;
$matched   = $m['matched'] ?? null;
$data_val  = $m['data'] ?? null;
$severity  = $m['severity'] ?? null;
$maturity  = $m['maturity'] ?? null;
$accuracy  = $m['accuracy'] ?? null;
$unique_id = $m['unique_id'] ?? null;


$eventStmt->bind_param(
    'ssiiissssiississsssiiis',
    $event_time,
    $nginx_level,
    $nginx_pid,
    $nginx_tid,
    $connection_id,
    $client_ip,
    $server_name,
    $host,
    $request_line,
    $http_code,
    $phase,
    $rule_id,
    $rule_file,
    $rule_line,
    $rule_rev,
    $rule_ver,
    $message,
    $matched,
    $data_val,
    $severity,
    $maturity,
    $accuracy,
    $unique_id
);


    $eventStmt->execute();
    $eventId = $mysqli->insert_id;
    $inserted++;

    $tags = $m['tag'] ?? [];
    if (!is_array($tags)) $tags = [$tags];

    foreach ($tags as $tag) {
        $tagAdd->bind_param('s', $tag);
        $tagAdd->execute();

        $tagGet->bind_param('s', $tag);
        $tagGet->execute();
        $tagGet->bind_result($tid);
        $tagGet->fetch();
        $tagGet->free_result();

        if ($tid) {
            $link->bind_param('ii', $eventId, $tid);
            $link->execute();
        }
    }

    if ($inserted % $batchSize === 0) {
        $mysqli->commit();
        $mysqli->begin_transaction();
    }
}

$mysqli->commit();
$finalPos = ftell($fh);
fclose($fh);

saveLogOffset($mysqli, $realLog, $inode, $finalPos);

/* ============================================================
   OUTPUT
   ============================================================ */
$response = [
    'file'      => $realLog,
    'processed' => $processed,
    'inserted'  => $dryRun ? 0 : $inserted,
    'offset'    => $finalPos,
    'batch'     => $batchSize,
    'dryrun'    => $dryRun,
    'mode'      => $isCli ? 'cli' : 'web'
];

if ($isCli) {
    print_r($response);
} else {
    header('Content-Type: application/json');
    echo json_encode($response, JSON_PRETTY_PRINT);
}
