# Exceedingly simple ModSecurity/Nginx error log reporting

These simple PHP scripts are not much, but I found myself looking for a simple log report after installing ModSecurity with Nginx to see what the heck is going on. 

Sure, there's lots of cool dashboards and apps using elasticsearch, Grafana, etc - and that's cool.  I really searched for quite a while to find something simpler - but couldn't find anything current or to my liking as of 2026.  So thus, I found my own solution.  Super simple.  Same server. Three files.

This is my first public upload to github so have patience with me.  I present this as a *solution* - and not an example of code I write, as...

These scripts borrow heavily from Copilot AI prompts, and I'm not afraid to say so.  The ModSecurity log format, embedded inside the nginx error log format - well - is involved.  I saved time, and I'm glad I did.  1 hour, done.  No dependancies other than your standard LEMP stack.  I did manually review all code, and found no huge issues.  On to the next thing I gotta do...

WHO YOU ARE: A SysAdmin looking for something exceedingly simple that will tell you what the heck Nginx/ModSecurity is doing without having to spin up another VM, container, deal with dependancies, etc, etc, etc.   It parses the nginx error logs, sticks them in a database and reports on them. Done.

YMMV

That said, I would highly recommend you restict these scripts to running on localhost or your local network only.  I run it on a separate vhost that nginx only allows from my networks, and doesn't have a public domain name.  

These scripts were inspired by Tommy Mühle's Simple PHP library to parse Apache or Nginx error-log file entries. https://github.com/tommy-muehle/error-log-parser .  His code still works.  I played with it, and was going to use it, but decided to go even simpler after looking at how to manually parse the ModSec stuff.

If you're curious, I finally got ModSecurity running thanks to inspiration from https://www.softworx.at/en/nginx-modsecurity-v3-owasp-crs-on-ubuntu-24-04-lts-step-by-step-part-1/  I had to ammend several things, including the newer sources for ModSecuirty and the OWASP rules.  I may post my install script if anyone desires - let me know.

## Requirements

* LEMP stack (I'm on Ubuntu 24 with stock nginx)
* ModSecurity compiled with nginx and active and working to your liking

## Installation

* Place the files somewhere in your website file structure.
* Create the database using the .sql script and assign user/permissions, etc
* Adjust the database connection parameters in both PHP scripts.
* Set a cron job to run parse_nginx_modsec.php as frequently as you need.
* View report.php to see results
* (optional) protect the folder these scripts are in to your local network only. You could use some simple password protection, or I use a separate vhost with no public DNS and nginx rules to restrict access to my local net and localhost only.  
