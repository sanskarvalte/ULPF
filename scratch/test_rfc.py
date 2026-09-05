from app.parsers.syslog_parser import _RFC5424_RE, _SYSLOG_RE, parse_syslog_log

line = '<134>1 2023-10-11T22:14:15.003Z web-gw nginx - - [audit@123] {"src_ip":"10.0.0.15","user":"admin","action":"login","status":"success"}'

print("_RFC5424_RE match:")
m = _RFC5424_RE.match(line)
if m:
    print(m.groupdict())
else:
    print("None")

print("\nparse_syslog_log:")
ev = parse_syslog_log(line)
print("src_ip:", ev.src_ip)
print("user:", ev.user)
print("activity_name:", ev.activity_name)
print("class_name:", ev.class_name)
print("unmapped:", ev.unmapped)
