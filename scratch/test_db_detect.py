from app.parsers.syslog_parser import parse_syslog_log

l = "2023-10-11T14:35:00.123456Z 12 [Note] Access denied for user 'root'@'192.168.1.100' (using password: YES)"
ev = parse_syslog_log(l)
print("MySQL:", ev.category_name, ev.activity_name, ev.user, ev.src_ip, ev.status)
