<?php
/**
 * ModSecurity Rule Importer
 * Run via cron
 */

/* ================= CONFIG ================= */

# DB credentials - adjust to your own needs.  I use files utside the www root per usual.
$DB_HOST = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$DB_USER = file_get_contents("/path/to/a/plain/test/file/with/this/variable/filename.cfg");
$DB_PASS = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$DB_NAME = 'security_logs';


$RULES_DIR = '/path/to/your/modsec/coreruleset/rules';   // directory with .conf files

/*
$DB_HOST   = 'localhost';
$DB_NAME   = 'modsecurity';
$DB_USER   = 'dbuser';
$DB_PASS   = 'dbpass';
*/

/* ================= DB ================= */

$pdo = new PDO(
    "mysql:host=$DB_HOST;dbname=$DB_NAME;charset=utf8mb4",
    $DB_USER,
    $DB_PASS,
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]
);

/* ================= CLASSES ================= */

class SecRule
{
    public string $variables;
    public string $operator;
    public array  $actions;
    public string $raw;

    public static function parse(string $block): ?self
    {
        $raw = trim($block);
        $flat = preg_replace("/\\\\\s*\n/", "", $block);

        if (!preg_match('/^SecRule\s+(.+?)\s+"([^"]+)"\s+"(.+)"$/s', trim($flat), $m)) {
            return null;
        }

        $r = new self();
        $r->raw       = $raw;
        $r->variables = $m[1];
        $r->operator  = $m[2];
        $r->actions   = self::splitActions($m[3]);
        return $r;
    }

    private static function splitActions(string $raw): array
    {
        $parts = [];
        $buf = '';
        $quoted = false;

        for ($i = 0; $i < strlen($raw); $i++) {
            $c = $raw[$i];
            if ($c === "'" && ($i === 0 || $raw[$i - 1] !== '\\')) {
                $quoted = !$quoted;
            }
            if ($c === ',' && !$quoted) {
                $parts[] = trim($buf);
                $buf = '';
            } else {
                $buf .= $c;
            }
        }

        if ($buf !== '') {
            $parts[] = trim($buf);
        }

        return $parts;
    }

    public function actionValue(string $key): ?string
    {
        foreach ($this->actions as $a) {
            if (str_starts_with($a, "$key:")) {
                return trim(substr($a, strlen($key) + 1), "'");
            }
        }
        return null;
    }

    public function tags(): array
    {
        return array_values(array_map(
            fn($a) => trim(substr($a, 4), "'"),
            array_filter($this->actions, fn($a) => str_starts_with($a, 'tag:'))
        ));
    }
}

/* ================= FUNCTIONS ================= */

function extractRules(string $file): array
{
    $rules = [];
    $buf = '';

    foreach (file($file) as $line) {
        $buf .= $line;
        if (!str_ends_with(trim($line), '\\')) {
            if (str_starts_with(trim($buf), 'SecRule')) {
                if ($r = SecRule::parse($buf)) {
                    $rules[] = $r;
                }
            }
            $buf = '';
        }
    }

    return $rules;
}

/* ================= INSERT ================= */

$stmt = $pdo->prepare("
INSERT INTO modsec_rules
(rule_id, variables, operator, actions, severity, msg, tags, source_file, raw_rule)
VALUES
(:id, :vars, :op, :actions, :severity, :msg, :tags, :file, :raw)
ON DUPLICATE KEY UPDATE
variables = VALUES(variables),
operator = VALUES(operator),
actions = VALUES(actions),
severity = VALUES(severity),
msg = VALUES(msg),
tags = VALUES(tags),
raw_rule = VALUES(raw_rule)
");

/* ================= RUN ================= */

$total = 0;

foreach (glob("$RULES_DIR/*.conf") as $file) {
    foreach (extractRules($file) as $rule) {
        $stmt->execute([
            ':id'      => (int)$rule->actionValue('id'),
            ':vars'    => $rule->variables,
            ':op'      => $rule->operator,
            ':actions' => implode(',', $rule->actions),
            ':severity'=> $rule->actionValue('severity'),
            ':msg'     => $rule->actionValue('msg'),
            ':tags'    => json_encode($rule->tags(), JSON_UNESCAPED_SLASHES),
            ':file'    => basename($file),
            ':raw'     => $rule->raw
        ]);
        $total++;
    }
}

echo date('c') . " Imported {$total} rules\n";