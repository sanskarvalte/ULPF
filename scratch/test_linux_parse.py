from app.parsers.syslog_parser import parse_syslog_log
from app.normalization.engine import normalize_event

lines = [
    "Aug 25 00:30:03 Sanskars-MacBook-Air newsyslog[5617]: logfile turned over",
    "Jun 14 15:17:01 server CRON[24050]: (root) CMD (   test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))",
    "Oct 11 14:00:00 ubuntu systemd[1]: Started Daily apt upgrade and clean activities."
]

for l in lines:
    ev = normalize_event(parse_syslog_log(l))
    print(l[:35], "->", ev.product, "| cat:", ev.category_name, "| act:", ev.activity_name, "| sev:", ev.severity, "| user:", ev.user)
