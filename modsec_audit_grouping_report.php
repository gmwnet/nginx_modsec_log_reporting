<?php

# DB credentials - adjust to your own needs
$dbHost = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$dbUser = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$dbPass = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$dbName = 'security_logs';


try {
    $pdo = new PDO(
        "mysql:host=$dbHost;dbname=$dbName;charset=utf8mb4",
        $dbUser,
        $dbPass,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]
    );
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

function fetchTop10(PDO $pdo, string $column) {
    $sql = "
        SELECT $column AS label, COUNT(*) AS hit_count
        FROM modsec_hits
        GROUP BY $column
        ORDER BY hit_count DESC
        LIMIT 10
    ";
    return $pdo->query($sql)->fetchAll();
}

$topClientIps = fetchTop10($pdo, 'client_ip');
$topHostnames = fetchTop10($pdo, 'hostname');
$topUris      = fetchTop10($pdo, 'uri');
$topRuleIds   = fetchTop10($pdo, 'rule_id');

function e(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ModSecurity Audit Logs Grouping Report</title>

    <!-- Bootstrap -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">


    <style>
        body {
            background-color: #f5f7fa;
        }

        .report-section {
            margin-bottom: 3rem;
            background: #ffffff;
            padding: 1.5rem;
            border-radius: 0.5rem;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
        }

        .section-title {
            margin-bottom: 1rem;
            padding-bottom: 0.25rem;
            border-bottom: 2px solid #0d6efd;
        }

        .table td {
            word-break: break-all;
        }
    </style>
</head>

<body>
<div class="container my-5">

    <h2 class="mb-4"><a href="index.php">🛡️</a> ModSecurity Audit Logs Grouping Report</h2>
    <p class="text-muted mb-4">Top 10 grouped results</p>

    <!-- Client IPs -->
    <div class="report-section">
        <h4 class="section-title">Top 10 Client IPs</h4>
        <table class="table table-striped table-bordered align-middle">
            <thead class="table-light">
                <tr>
                    <th>Client IP</th>
                    <th>Hit Count</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($topClientIps as $row): ?>
                <tr>
                    <td><?= e($row['label']) ?></td>
                    <td><?= $row['hit_count'] ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- Hostnames -->
    <div class="report-section">
        <h4 class="section-title">Top 10 Hostnames</h4>
        <table class="table table-striped table-bordered align-middle">
            <thead class="table-light">
                <tr>
                    <th>Hostname</th>
                    <th>Hit Count</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($topHostnames as $row): ?>
                <tr>
                    <td><?= e($row['label']) ?></td>
                    <td><?= $row['hit_count'] ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- URIs -->
    <div class="report-section">
        <h4 class="section-title">Top 10 URIs</h4>
        <table class="table table-striped table-bordered align-middle">
            <thead class="table-light">
                <tr>
                    <th>URI</th>
                    <th>Hit Count</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($topUris as $row): ?>
                <tr>
                    <td><?= e($row['label']) ?></td>
                    <td><?= $row['hit_count'] ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- Rule IDs -->
    <div class="report-section">
        <h4 class="section-title">Top 10 Rule IDs</h4>
        <table class="table table-striped table-bordered align-middle">
            <thead class="table-light">
                <tr>
                    <th>Rule ID</th>
                    <th>Hit Count</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($topRuleIds as $row): ?>
                <tr>
                    <td><a href="view_rules.php?rule_id=<?= e($row['label']) ?>" data-modal><?= e($row['label']) ?></a></td>
                    <td><?= $row['hit_count'] ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

</div>

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>


<script>
document.addEventListener('DOMContentLoaded', function () {

    document.body.addEventListener('click', function (e) {
        const link = e.target.closest('a[data-modal]');
        if (!link) return;

        e.preventDefault();

        const url = link.getAttribute('href');
        const modalEl = document.getElementById('linkModal');
        const contentEl = document.getElementById('modalContent');

        contentEl.textContent = 'Loading…';

        fetch(url, { credentials: 'same-origin' })
            .then(res => res.text())
            .then(html => {
                contentEl.innerHTML = html;
            })
            .catch(() => {
                contentEl.innerHTML = '<div class="alert alert-danger">Failed to load content.</div>';
            });

        const modal = new bootstrap.Modal(modalEl);
        modal.show();
    });

});
</script>


<!-- Modal -->
<div class="modal fade" id="linkModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-xl modal-dialog-scrollable">
    <div class="modal-content">

      <div class="modal-header">
        <h5 class="modal-title">Details</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>

      <div class="modal-body">
        <div id="modalContent" class="text-right text-muted">
          Loading…
        </div>
      </div>

    </div>
  </div>
</div>




</body>
</html>