<?php
$logFile = '/var/log/modsec/modsec_audit.json';


# DB credentials - adjust to your own needs
$dbHost = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$dbuser = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$dbpass = file_get_contents("/path/to/a/plain/text/file/with/this/variable/filename.cfg");
$dbname = 'security_logs';

$db = new mysqli($dbHost, $dbuser, $dbpass, $dbname);
if ($db->connect_error) {
    die("DB connection failed\n");
}

#Select the last position read in the log file
$LastPositionSQL = sprintf("SELECT last_position FROM log_file_offsets WHERE file_path = '$logFile'");
$LastPositionResult = mysqli_query($db, $LastPositionSQL);
$LPnumberofrows = $LastPositionResult->num_rows;
    if ($LPnumberofrows == 0 || $LPnumberofrows > 1) {
        die("Last Position Not Found or multiple found");
    } else {
        while($row = $LastPositionResult->fetch_assoc()) {
                $StartFilePosition = $row["last_position"];
        } 
    }
$LastFilePosition = $StartFilePosition;

#Clear caches to make sure we're good
clearstatcache(true, $logFile);
$currentSize = filesize($logFile);

#If the log has rotated, start at 0
if ($currentSize < $LastFilePosition) {
    $LastFilePosition = 0; 
}

#Read the file
if ($handle = fopen($logFile, 'r')) {
    fseek($handle, $LastFilePosition);

    # Read only the new lines
    while (($line = fgets($handle)) !== false) {

            # only lines that definitely contain a rule hit
            if (strpos($line, '"ruleId"') === false) {
                continue;
            }

            #The magical regex parsing the line
            preg_match('/"unique_id":"([^"]+)"/', $line, $txid);
            preg_match('/"time_stamp":"([^"]+)"/', $line, $time);
            preg_match('/"client_ip":"([^"]+)"/', $line, $ip);
            preg_match('/"hostname":"([^"]+)"/', $line, $host);
            preg_match('/"uri":"([^"]+)"/', $line, $uri);
            preg_match_all('/"ruleId":"([^"]+)"/', $line, $rules);

            if (empty($rules[1])) {
                continue;
            }

            foreach ($rules[1] as $ruleId) {

                #Parse the text time value and make into a proper datetime object
                $dateString = $time[1] ?? '';

                if ($dateString == '') {
                    #if date missing, just put in the start of unix time to flag it and not throw an error.  Easily noticed in reporting.
                    $parseddate = new DateTime('1970-01-01');
                    $mysqlDate = $parseddate->format('Y-m-d H:i:s');
                } else {
                    $parseddate = DateTime::createFromFormat('D M d H:i:s Y', $dateString);
                    $mysqlDate = $parseddate->format('Y-m-d H:i:s');
                }

                #I like to make good looking variables in code before database statements - whip me if you must.  Makes debugging easier for me.
                $insert_txid = htmlspecialchars($txid[1] ?? '');
                $insert_time = $mysqlDate;
                $insert_client_ip = htmlspecialchars($ip[1] ?? '');
                $insert_hostname = htmlspecialchars($host[1] ?? '');
                $insert_uri = htmlspecialchars($uri[1] ?? '');
                $insert_rule_id = htmlspecialchars($ruleId ?? '');

                $stmt = $db->prepare(
                    "INSERT IGNORE INTO modsec_hits
                    (txid, event_time, client_ip, hostname, uri, rule_id)
                    VALUES (?, ?, ?, ?, ?, ?)"
                );
                $stmt->bind_param(
                    'ssssss',
                    $insert_txid,
                    $insert_time,
                    $insert_client_ip,
                    $insert_hostname,
                    $insert_uri,
                    $insert_rule_id
                );

                $stmt->execute();

            }

       
    }

    // Store the new position for the next run
    $LastFilePosition = ftell($handle);
    fclose($handle);
}

#Update the file position in DB
$positionsql = sprintf("UPDATE log_file_offsets SET last_position = $LastFilePosition WHERE file_path = '$logFile'");
$PositionResult = mysqli_query($db, $positionsql);



