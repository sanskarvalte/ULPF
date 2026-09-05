from app.ingestion.detector import match_format

m1 = '<134>1 2023-10-11T22:14:15.003Z web-gw nginx - - [audit@123] {"src_ip":"10.0.0.15"}'
m2 = 'Oct 11 22:15:00 fw-01 kernel: [12345.67] IPTables-Dropped: IN=eth0 OUT= SRC=192.168.1.99 DST=10.0.0.100 PROTO=TCP SPT=49876 DPT=22 ACTION=DROP'
m3 = '<165>1 2026-08-26T12:00:00.000Z myhost.example.com firewalld 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] Connection dropped from 192.168.1.50 port 54321'

print('m1:', match_format(m1)[:2])
print('m2:', match_format(m2)[:2])
print('m3:', match_format(m3)[:2])
