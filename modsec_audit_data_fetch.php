
<?php

# DB credentials - adjust to your own needs
$dbHost = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$dbuser = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$dbpass = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$dbname = 'security_logs';

$host = $dbHost;
$db   = $dbname;
$user = $dbuser;
$pass = $dbpass;
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (Exception $e) {
    http_response_code(500);
    echo 'Database connection failed';
    exit;
}

// DataTables parameters
$draw  = intval($_POST['draw']);
$start = intval($_POST['start']);
$length = intval($_POST['length']);
$searchValue = $_POST['search']['value'] ?? '';

// Column mapping (must match DataTables columns order)
$columns = [
    0 => 'id',
    1 => 'rule_id',
    2 => 'txid',
    3 => 'event_time',
    4 => 'client_ip',
    5 => 'hostname',
    6 => 'uri'

];

// Ordering
$orderColumnIndex = intval($_POST['order'][0]['column']);
$orderColumn = $columns[$orderColumnIndex] ?? 'id';
$orderDir = $_POST['order'][0]['dir'] === 'asc' ? 'ASC' : 'DESC';

// Base query
$where = '';
$params = [];

if (!empty($searchValue)) {
    $where = "WHERE 
        txid LIKE :search OR
        client_ip LIKE :search OR
        hostname LIKE :search OR
        uri LIKE :search OR
        rule_id LIKE :search
    ";
    $params[':search'] = "%$searchValue%";
}

// Total records
$totalRecords = $pdo->query("SELECT COUNT(*) FROM modsec_hits")->fetchColumn();

// Filtered records
$stmt = $pdo->prepare("SELECT COUNT(*) FROM modsec_hits $where");
$stmt->execute($params);
$filteredRecords = $stmt->fetchColumn();

// Data query
$sql = "
    SELECT id, txid, event_time, client_ip, hostname, uri, rule_id
    FROM modsec_hits
    $where
    ORDER BY $orderColumn $orderDir
    LIMIT :start, :length
";

$stmt = $pdo->prepare($sql);

// Bind params
foreach ($params as $key => $value) {
    $stmt->bindValue($key, $value);
}
$stmt->bindValue(':start', $start, PDO::PARAM_INT);
$stmt->bindValue(':length', $length, PDO::PARAM_INT);

$stmt->execute();
$data = $stmt->fetchAll();

// Output
echo json_encode([
    "draw" => $draw,
    "recordsTotal" => $totalRecords,
    "recordsFiltered" => $filteredRecords,
    "data" => $data
]);