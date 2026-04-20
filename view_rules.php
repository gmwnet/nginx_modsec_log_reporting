<?php
/**
 * View ModSecurity rules (paginated, Bootstrap styled)
 */

# DB credentials
$DB_HOST = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$DB_USER = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$DB_PASS = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$DB_NAME = 'security_logs';

define('PAGE_SIZE', 50);

$pdo = new PDO(
    "mysql:host=$DB_HOST;dbname=$DB_NAME;charset=utf8mb4",
    $DB_USER,
    $DB_PASS,
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => true,
    ]
);

/* ================= Filters ================= */

$where = [];
$params = [];

if (!empty($_GET['rule_id'])) {
    $where[] = "rule_id = :rid";
    $params[':rid'] = (int)$_GET['rule_id'];
    $SingleRule = 1;
}

if (!empty($_GET['severity'])) {
    $where[] = "severity = :sev";
    $params[':sev'] = $_GET['severity'];
}

if (!empty($_GET['tag'])) {
    $where[] = "JSON_CONTAINS(tags, :tag)";
    $params[':tag'] = json_encode($_GET['tag']);
}

if (!empty($_GET['file'])) {
    $where[] = "source_file = :file";
    $params[':file'] = $_GET['file'];
}

$whereSql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

/* ================= Pagination ================= */

$page = max(1, (int)($_GET['page'] ?? 1));
$offset = ($page - 1) * PAGE_SIZE;

$countStmt = $pdo->prepare("SELECT COUNT(*) FROM modsec_rules $whereSql");
$countStmt->execute($params);
$totalRows = (int)$countStmt->fetchColumn();
$totalPages = max(1, ceil($totalRows / PAGE_SIZE));

$sql = "
SELECT *
FROM modsec_rules
$whereSql
ORDER BY rule_id ASC
LIMIT :limit OFFSET :offset
";

$stmt = $pdo->prepare($sql);

foreach ($params as $k => $v) {
    $stmt->bindValue($k, $v);
}
$stmt->bindValue(':limit', PAGE_SIZE, PDO::PARAM_INT);
$stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
$stmt->execute();

$rules = $stmt->fetchAll();

/* ================= Helper ================= */

function pageUrl(int $page): string {
    $q = $_GET;
    $q['page'] = $page;
    return '?' . http_build_query($q);
}

header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="en">
<head>
    <title>ModSecurity Rules</title>

    <!-- Bootstrap 5 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">

<div class="container my-4">
    
    <?php if (!isset($SingleRule)): ?>
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h2 class="mb-0">ModSecurity Rules</h2>
                <span class="text-muted">
                    <?= $totalRows ?> total • page <?= $page ?> of <?= $totalPages ?>
                    <hr>
                </span>
        </div>


    <!-- Pagination -->
    <nav class="mb-4">
        <ul class="pagination">
            <li class="page-item <?= $page <= 1 ? 'disabled' : '' ?>">
                <a class="page-link" href="<?= htmlspecialchars(pageUrl($page - 1)) ?>">&laquo; Prev</a>
            </li>
            <li class="page-item <?= $page >= $totalPages ? 'disabled' : '' ?>">
                <a class="page-link" href="<?= htmlspecialchars(pageUrl($page + 1)) ?>">Next &raquo;</a>
            </li>
        </ul>
    </nav>

    <?php else: ?>
    <?php endif; ?>

    <?php if (!$rules): ?>
        <div class="alert alert-warning">No rules found.</div>
    <?php endif; ?>

    <?php foreach ($rules as $r): ?>
        <div class="card mb-4 shadow-sm">
            <div class="card-header d-flex justify-content-between">
                <div>
                    <strong>Rule ID:</strong> <?= htmlspecialchars($r['rule_id']) ?>
                    <span class="ms-3">
                        <strong>File:</strong> <?= htmlspecialchars($r['source_file']) ?>
                    </span>
                </div>
                <span class="badge bg-danger">
                    <?= htmlspecialchars($r['severity'] ?? 'UNKNOWN') ?>
                </span>
            </div>

            <div class="card-body">
                <pre class="bg-white border rounded p-3 mb-0"><?= htmlspecialchars($r['raw_rule']) ?></pre>
            </div>
        </div>
    <?php endforeach; ?>

</div>

</body>
</html>