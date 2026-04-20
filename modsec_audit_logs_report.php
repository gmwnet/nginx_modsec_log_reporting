<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ModSecurity Hits</title>

    <!-- Bootstrap -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">

    <!-- DataTables -->
    <link href="https://cdn.datatables.net/1.13.8/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.datatables.net/responsive/2.5.0/css/responsive.dataTables.min.css">


    <style>
        body {
            padding: 20px;
        }
        table.dataTable td {
            vertical-align: middle;
        }
    </style>
</head>
<body>

<div class="container-fluid">
    <h2 class="mb-4"><a href="index.php">🛡️</a> ModSecurity Audit Logs</h2>

    <div class="table-responsive">
        <table id="modsecTable" class="table table-striped table-bordered w-100">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Rule ID</th>
                    <th>TXID</th>
                    <th>Event Time</th>
                    <th>Client IP</th>
                    <th>Hostname</th>
                    <th>URI</th>
                </tr>
            </thead>
        </table>
    </div>
</div>

<!-- JS -->
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>

<script src="https://cdn.datatables.net/1.13.8/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.8/js/dataTables.bootstrap5.min.js"></script>
<script src="https://cdn.datatables.net/responsive/2.5.0/js/dataTables.responsive.min.js"></script>



<script>
$(document).ready(function () {
    $('#modsecTable').DataTable({

        processing: true,
        serverSide: true,

        
        responsive: {
            details: {
                type: 'inline',   // rows expand inline
                target: 'tr'
            }
        },

        pageLength: 100,
        lengthMenu: [25, 50, 100, 250, 500],

        order: [[0, 'desc']], // id DESC

        ajax: {
            url: 'modsec_audit_data_fetch.php',
            type: 'POST'
        },

        columns: [
            { data: 'id', responsivePriority: 1},
            {
                data: 'rule_id', responsivePriority: 2, 
                render: function (data, type, row) {

                    // IMPORTANT: return raw data for sort/search
                    if (type !== 'display') {
                        return data;
                    }

                    // Display mode: render link
                    if (!data) {
                        return '';
                    }

                    return '<a href="view_rules.php?rule_id=' + encodeURIComponent(data) + '" data-modal>' + data + '</a>';
                },
            },
            { data: 'txid', responsivePriority: 4 },
            { data: 'event_time', responsivePriority: 3 },
            { data: 'client_ip', responsivePriority: 5 },
            { data: 'hostname', responsivePriority: 6 },
            { data: 'uri', responsivePriority: 7 }

        ]
    });
});
</script>


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