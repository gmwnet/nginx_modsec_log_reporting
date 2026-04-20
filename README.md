# Exceedingly simple ModSecurity/Nginx error log reporting
## V2.0

###HEY!  Thanks for viweing my first github project.  I'm proud of it singularly, and I'm looking to add more!

V2.0 updates: Added ModSec audit log parsing and reporting, added a OWASP CRS rule import and detail page for the reports, added an index.php dashboard, misc fine tuning of code and design.  Updated Readme.

To do for v3.0:  Make this a proper app and do some stuff like a database object and other functions.

These simple PHP scripts are not much, but I found myself looking for a simple log report after installing ModSecurity with Nginx to see what the heck is going on. 

Sure, there's lots of neat dashboards and apps using elasticsearch, Grafana, etc - and that's cool.  I really searched for quite a while to find something simpler - but couldn't find anything current or to my liking as of 2026.  So thus, I found my own solution.  Super simple.  Same server. A handful of files.

This is my first public upload to github so have patience with me.  I present this as a **solution** - and not an example of code I write, as...

These scripts borrow heavily from Copilot AI prompts, and I'm not afraid to say so.  The ModSecurity log formats, embedded inside the nginx error log format - well - is *involved*. The ModSec JSON audit log is JSON *flavored* JSON.  I saved time, and I'm glad I did.  A couple hours, done.  No real dependancies other than your standard LEMP stack.  I did manually review all code, and found no huge issues.  On to the next thing I gotta do...

WHO YOU ARE: A SysAdmin looking for something exceedingly simple that will tell you what the heck Nginx/ModSecurity is doing without having to spin up another VM, container, deal with dozens of dependancies, etc, etc, etc.   It parses the nginx error logs, ModSecurity Audit logs, sticks them in a database and reports on them. Done.

YMMV

That said, I would highly recommend you restict these scripts to running on localhost or your local network only.  I run it on a separate vhost that nginx only allows from my networks, and doesn't have a public domain name.  

These scripts were inspired by Tommy Mühle's Simple PHP library to parse Apache or Nginx error-log file entries. https://github.com/tommy-muehle/error-log-parser .  His code still works.  I played with it, and was going to use it, but decided to go even simpler after looking at how to manually parse the ModSec stuff.

If you're curious, I finally got ModSecurity running thanks to inspiration from https://www.softworx.at/en/nginx-modsecurity-v3-owasp-crs-on-ubuntu-24-04-lts-step-by-step-part-1/  I had to ammend several things, including the newer sources for ModSecuirty and the OWASP rules.  I may post my install script if anyone desires - let me know.

## Requirements

* LEMP stack (I'm on Ubuntu 24 LTS with stock nginx)
* ModSecurity compiled with nginx and active and working to your liking (I'm on Nginx 1.24.0, ModSecurity-nginx v1.0.4, CRS v4.25.0 LTS)
* ModSecurity audit logging setup with the following options:

```
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogType Serial
SecAuditLog /var/log/modsec/modsec_audit.json #Or wherever you desire; adjust the parsing scripts
SecAuditLogFormat JSON
SecAuditLogParts ABHZ
```

## Optional
* [OWASP Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/) downloaded and in use.  This is needed to import the rules into the database for ease of use.
* My reports use [Bootstrap](https://https://getbootstrap.com/) and [Data Tables](https://datatables.net/).  If you don't like those, take them out in the scripts.
* I suggest you setup a log rotation for the CRS audit logs.  They can get big if you have a lot of traffic.  I set a file in /etc/logrotate.d/modsec that has the following:
```
    /var/log/modsec/*.json {
        daily
        missingok
        rotate 30
        compress
        notifempty
        copytruncate
    }
```


## Installation

* Place the files somewhere in your website file structure.
* Create the database in MySQL using the .sql script and assign user/permissions, etc.  The SQL script is in the sql folder.
* Adjust the database connection parameters in the PHP scripts, at the top of every file.
* Set a cron job to run parse_nginx_modsec.php and parse_modsec_audit_logs.php as frequently as you need.  They are in the cron folder.
* Optional:  Run the import_rules.php script once to import the OWASP CRS rules into the database.  This assumes you have already downloaded them via git or some other method and activated them via modsec.conf.  Check the RULES_DIR variable at the top of the script and adjust as necessary.  This makes lookups from the dashboard happen.  As you update the CRS rules, delete all the entries in the modsec_rules table and run the script again to update.
* View /index.php for the mini dashboard and check if your reports are OK
* (optional) protect the folder these scripts are in to your local network only. You could use some simple password protection, or I use a separate vhost with no public DNS and nginx rules to restrict access to my local net and localhost only.  
