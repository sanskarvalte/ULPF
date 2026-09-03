"""
Unit tests for ULPF Parsers (JSON, Syslog, CEF, LEEF, XML, CSV, Generic, Drain).
"""

import unittest
from app.ingestion.detector import detect_format
from app.normalization.engine import normalize_event
from app.parsers.cef_parser import parse_cef_log
from app.parsers.csv_parser import parse_csv_log
from app.parsers.drain_service import SimpleDrainService
from app.parsers.generic_parser import parse_generic_log
from app.parsers.json_parser import parse_json_log
from app.parsers.leef_parser import parse_leef_log
from app.parsers.syslog_parser import parse_syslog_log
from app.parsers.xml_parser import parse_xml_log


class TestParsers(unittest.TestCase):

    def test_json_parser(self):
        raw = '{"timestamp": "2026-08-26T12:00:00Z", "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "user": "admin", "severity": "high", "message": "Failed login"}'
        ev = parse_json_log(raw)
        norm = normalize_event(ev)
        self.assertEqual(norm.src_ip, "192.168.1.10")
        self.assertEqual(norm.user, "admin")
        self.assertEqual(norm.severity_id, 4)
        self.assertEqual(norm.raw_event, raw)

    def test_cef_parser(self):
        raw = "CEF:0|CheckPoint|Firewall|R80.10|1|Drop|7|src=192.168.1.50 dst=10.0.0.5 spt=54321 dpt=443 proto=tcp msg=Blocked"
        ev = parse_cef_log(raw)
        norm = normalize_event(ev)
        self.assertEqual(norm.vendor, "CheckPoint")
        self.assertEqual(norm.src_ip, "192.168.1.50")
        self.assertEqual(norm.dst_ip, "10.0.0.5")
        self.assertEqual(norm.src_port, 54321)
        self.assertEqual(norm.dst_port, 443)
        self.assertEqual(norm.severity, "High")

    def test_leef_parser(self):
        raw = "LEEF:1.0|IBM|QRadar|7.3.1|LoginFailed|src=172.16.0.4\tdst=172.16.0.1\tusrName=john.doe\tproto=TCP\tsev=4"
        ev = parse_leef_log(raw)
        norm = normalize_event(ev)
        self.assertEqual(norm.vendor, "IBM")
        self.assertEqual(norm.src_ip, "172.16.0.4")
        self.assertEqual(norm.user, "john.doe")
        self.assertEqual(norm.severity_id, 4)

    def test_syslog_parser(self):
        raw = "Jan 04 15:16:01 combo sshd[24047]: authentication failure; rhost=218.188.2.4 user=root"
        ev = parse_syslog_log(raw)
        norm = normalize_event(ev)
        self.assertEqual(norm.src_ip, "218.188.2.4")
        self.assertEqual(norm.user, "root")
        self.assertEqual(norm.log_name, "combo")

    def test_xml_parser(self):
        raw = "<Event><EventID>4624</EventID><TargetUserName>svc_backup</TargetUserName><IpAddress>10.0.1.20</IpAddress></Event>"
        ev = parse_xml_log(raw)
        norm = normalize_event(ev)
        self.assertEqual(norm.src_ip, "10.0.1.20")
        self.assertEqual(norm.user, "svc_backup")

    def test_xml_unmapped_metadata(self):
        raw = """<?xml version="1.0" encoding="UTF-8"?>
<logEntry>
  <timestamp>2026-08-26T14:32:07Z</timestamp>
  <severity>WARNING</severity>
  <source>InventorySystem</source>
  <host>db-node-02</host>
  <message>Low stock threshold reached for SKU-48213</message>
  <metadata>
    <userId>svc_inventory</userId>
    <requestId>req-77213-a1</requestId>
    <sku>SKU-48213</sku>
    <currentQuantity>4</currentQuantity>
  </metadata>
</logEntry>"""
        ev = parse_xml_log(raw)
        norm = normalize_event(ev)

        self.assertEqual(norm.severity, "Medium")
        self.assertEqual(norm.severity_id, 3)
        self.assertEqual(norm.src_hostname, "db-node-02")
        self.assertEqual(norm.service_name, "InventorySystem")
        self.assertEqual(norm.user, "svc_inventory")
        self.assertEqual(norm.session_uid, "req-77213-a1")
        self.assertEqual(norm.message, "Low stock threshold reached for SKU-48213")
        self.assertEqual(norm.unmapped["sku"], "SKU-48213")
        self.assertEqual(norm.unmapped["currentQuantity"], "4")

    def test_xml_multi_record_audit_log(self):
        from app.parsers.xml_parser import parse_xml_log_all
        raw = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE log SYSTEM "logger.dtd">
<log>
<record>
  <date>2009-05-21T00:00:00</date>
  <millis>1242878400161</millis>
  <sequence>1</sequence>
  <logger>com.ibm.is.auditing</logger>
  <level>FINE</level>
  <class>com.ibm.is.security.auth.LoginService</class>
  <method>login</method>
  <thread>12</thread>
  <message>User InformationServerSystemUser logged in successfully</message>
  <key>info.audit.session.LOGIN</key>
  <catalog>com.ascential.acs.auditing.AuditLogResources</catalog>
  <param>InformationServerSystemUser</param>
  <param>InformationServerSystemUser</param>
  <param>Server client</param>
  <param>SwordIFS</param>
  <param>34BADF15-ABA5-4FA9-AA7D-68D26402C2D6</param>
</record>
<record>
  <date>2009-05-21T00:05:00</date>
  <millis>1242878700200</millis>
  <sequence>2</sequence>
  <logger>com.ibm.is.auditing</logger>
  <level>INFO</level>
  <class>com.ibm.is.security.auth.LoginService</class>
  <method>logout</method>
  <thread>12</thread>
  <message>User InformationServerSystemUser logged out</message>
  <key>info.audit.session.LOGOUT</key>
  <catalog>com.ascential.acs.auditing.AuditLogResources</catalog>
  <param>InformationServerSystemUser</param>
  <param>Server client</param>
  <param>34BADF15-ABA5-4FA9-AA7D-68D26402C2D6</param>
</record>
<record>
  <date>2009-05-21T00:15:00</date>
  <millis>1242879300500</millis>
  <sequence>4</sequence>
  <logger>com.ibm.is.auditing</logger>
  <level>WARNING</level>
  <class>com.ibm.is.security.directory.UserService</class>
  <method>addUser</method>
  <thread>14</thread>
  <message>Created new user account analyst01</message>
  <key>info.audit.user.ADD_USER</key>
  <catalog>com.ascential.acs.auditing.AuditLogResources</catalog>
  <param>analyst01</param>
  <param>dsadmin</param>
</record>
</log>"""
        events = parse_xml_log_all(raw)
        self.assertEqual(len(events), 3)

        # Record 1 (LOGIN)
        ev1 = normalize_event(events[0])
        self.assertTrue(ev1.raw_event.startswith("<record"))
        self.assertTrue(ev1.raw_event.endswith("</record>"))
        self.assertEqual(ev1.vendor, "IBM")
        self.assertEqual(ev1.product, "InfoSphere Information Server")
        self.assertEqual(ev1.category_name, "Identity & Access Management")
        self.assertEqual(ev1.class_name, "Authentication")
        self.assertEqual(ev1.activity_name, "Logon")
        self.assertEqual(ev1.severity, "Informational")
        self.assertEqual(ev1.severity_id, 1)
        self.assertEqual(ev1.user, "InformationServerSystemUser")
        self.assertEqual(len(ev1.unmapped["param"]), 5)
        self.assertIsNotNone(ev1.timestamp)
        self.assertEqual(ev1.timestamp.year, 2009)

        # Record 2 (LOGOUT)
        ev2 = normalize_event(events[1])
        self.assertEqual(ev2.category_name, "Identity & Access Management")
        self.assertEqual(ev2.class_name, "Authentication")
        self.assertEqual(ev2.activity_name, "Logoff")
        self.assertEqual(len(ev2.unmapped["param"]), 3)

        # Record 3 (ADD_USER)
        ev3 = normalize_event(events[2])
        self.assertEqual(ev3.category_name, "Identity & Access Management")
        self.assertEqual(ev3.class_name, "Account Change")
        self.assertEqual(ev3.activity_name, "Create")
        self.assertEqual(ev3.severity, "Medium")
        self.assertEqual(ev3.severity_id, 3)
        self.assertEqual(ev3.user, "analyst01")

    def test_csv_parser(self):
        raw = "timestamp,src_ip,dst_ip,user,severity\n2026-08-26 10:00:00,10.0.0.1,10.0.0.2,alice,low"
        ev = parse_csv_log(raw)
        norm = normalize_event(ev)
        self.assertEqual(norm.src_ip, "10.0.0.1")
        self.assertEqual(norm.user, "alice")
        self.assertEqual(norm.severity_id, 2)

    def test_generic_parser(self):
        raw = "2026-08-26 12:30:45 [WARN] client 192.168.10.55 disconnected unexpectedly bytes=4096"
        ev = parse_generic_log(raw)
        norm = normalize_event(ev)
        self.assertEqual(norm.src_ip, "192.168.10.55")
        self.assertEqual(norm.traffic_bytes, 4096)

    def test_format_detector(self):
        cef = "CEF:0|Vendor|Prod|1|1|Action|3|"
        fmt, _ = detect_format(cef)
        self.assertEqual(fmt, "cef")

        json_str = '{"test": 1}'
        fmt, _ = detect_format(json_str)
        self.assertEqual(fmt, "json")

    def test_android_parser(self):
        from app.parsers.android_parser import parse_android_log
        raw = "03-17 16:13:38.819  1702  8671 D PowerManagerService: acquire lock=233570404, flags=0x1, tag=\"View Lock\", name=com.android.systemui, ws=null, uid=10037, pid=2227"
        ev = parse_android_log(raw, default_year=2026)
        self.assertIsNotNone(ev.timestamp)
        self.assertEqual(ev.timestamp.month, 3)
        self.assertEqual(ev.timestamp.day, 17)
        self.assertEqual(ev.severity, "Informational")
        self.assertEqual(ev.severity_id, 1)
        self.assertEqual(ev.service_name, "PowerManagerService")
        self.assertEqual(ev.vendor, "Google")
        self.assertEqual(ev.product, "Android")
        self.assertEqual(ev.category_name, "System Activity")
        self.assertEqual(ev.class_name, "Operating System")
        self.assertEqual(ev.user_uid, "10037")
        self.assertEqual(ev.raw_event, raw)
        self.assertEqual(ev.unmapped["pid"], "1702")
        self.assertEqual(ev.unmapped["tid"], "8671")
        self.assertEqual(ev.unmapped["lock"], "233570404")

    def test_android_nested_braces(self):
        from app.parsers.android_parser import parse_android_log
        raw = "03-17 16:13:38.811  1702  2395 D WindowManager: printFreezingDisplayLogsopening app wtoken = AppWindowToken{9f4ef63 token=Token{a64f992 ActivityRecord{de9231d u0 com.tencent.qt.qtl/.activity.info.NewsDetailXmlActivity t761}}}, allDrawn= false, startingDisplayed =  false, startingMoved =  false, isRelaunching =  false"
        ev = parse_android_log(raw, default_year=2026)
        self.assertEqual(ev.severity, "Informational")
        self.assertEqual(ev.severity_id, 1)
        self.assertEqual(ev.service_name, "WindowManager")
        self.assertEqual(ev.category_name, "Application Activity")
        self.assertEqual(ev.class_name, "Application Lifecycle")
        self.assertEqual(ev.raw_event, raw)
        self.assertEqual(
            ev.unmapped["wtoken"],
            "AppWindowToken{9f4ef63 token=Token{a64f992 ActivityRecord{de9231d u0 com.tencent.qt.qtl/.activity.info.NewsDetailXmlActivity t761}}}"
        )
        self.assertEqual(ev.unmapped["allDrawn"], "false")
        self.assertEqual(ev.unmapped["startingDisplayed"], "false")

    def test_android_trailing_text_and_stray_delimiters(self):
        from app.parsers.android_parser import parse_android_log

        # 1. token with trailing "-- going to hide"
        raw1 = "03-17 16:13:38.839  1702  2113 V WindowManager: Skipping AppWindowToken{df0798e token=Token{78af589 ActivityRecord{3b04890 u0 com.tencent.qt.qtl/com.tencent.video.player.activity.PlayerActivity t761}}} -- going to hide"
        ev1 = parse_android_log(raw1, default_year=2026)
        self.assertEqual(
            ev1.unmapped["token"],
            "Token{78af589 ActivityRecord{3b04890 u0 com.tencent.qt.qtl/com.tencent.video.player.activity.PlayerActivity t761}}"
        )

        # 2. cmp with stray '}' and "from uid 10111 on display 0"
        raw2 = "03-17 16:13:47.113  1702 17622 I ActivityManager: START u0 {act=com.tencent.mobileqq.action.MAINACTIVITY flg=0x14000000 cmp=com.tencent.mobileqq/.activity.SplashActivity (has extras)} from uid 10111 on display 0"
        ev2 = parse_android_log(raw2, default_year=2026)
        self.assertEqual(
            ev2.unmapped["cmp"],
            "com.tencent.mobileqq/.activity.SplashActivity (has extras)"
        )

        # 3. bnds with stray '}' and "from uid 10057 on display 0"
        raw3 = "03-17 16:15:36.921  1702  2113 I ActivityManager: START u0 {act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] flg=0x10200000 cmp=com.example.android.notepad/.NotePadActivity bnds=[8,820][184,1011]} from uid 10057 on display 0"
        ev3 = parse_android_log(raw3, default_year=2026)
        self.assertEqual(
            ev3.unmapped["bnds"],
            "[8,820][184,1011]"
        )

    def test_android_zero_millisecond_timestamp_precision(self):
        from app.parsers.android_parser import parse_android_log
        raw = "03-17 16:15:06.000  1702  2113 I WindowManager: Screen frozen"
        ev = parse_android_log(raw, default_year=2026)
        dump = ev.model_dump(mode="json")
        self.assertEqual(dump["timestamp"], "2026-03-17T16:15:06.000000Z")

    def test_drain_service(self):
        miner = SimpleDrainService()
        res1 = miner.mine_template("Authentication failed for user root from 192.168.1.50")
        res2 = miner.mine_template("Authentication failed for user admin from 10.0.0.1")
        self.assertEqual(res1["cluster_id"], res2["cluster_id"])

    def test_log_to_json(self):
        from app.parsers.log_to_json import parse_log_to_json_records
        sample = "081109 203615 148 INFO dfs.DataNode$DataXceiver: Receiving block blk_-1608999814545162878 src: /10.250.19.102:54106 dest: /10.250.19.102:50010"
        records = parse_log_to_json_records(sample, format_name="HDFS")
        self.assertEqual(len(records), 1)
        self.assertIn("line_id", records[0])
        self.assertIn("event_template", records[0])


    def test_syslog_macos_context_header(self):
        # 1. sandboxd with PID and parenthetical context
        raw1 = "Jan  1 09:29:02 calvisitor-10-105-160-95 sandboxd[129] ([31211]): com.apple.Addres(31211) deny network-outbound /private/var/run/mDNSResponder"
        ev1 = parse_syslog_log(raw1, default_year=2017)
        norm1 = normalize_event(ev1)
        self.assertEqual(norm1.log_name, "calvisitor-10-105-160-95")
        self.assertEqual(norm1.product, "sandboxd")
        self.assertEqual(norm1.unmapped.get("pid"), "129")
        self.assertEqual(norm1.unmapped.get("context"), "[31211]")
        self.assertEqual(norm1.message, "com.apple.Addres(31211) deny network-outbound /private/var/run/mDNSResponder")
        self.assertEqual(norm1.vendor, "Apple")
        self.assertEqual(norm1.category_name, "Security Finding")
        self.assertEqual(norm1.class_name, "Security Finding")
        self.assertEqual(norm1.raw_event, raw1)

        # 2. com.apple.xpc.launchd with domain context
        raw2 = "Jan  2 16:55:53 calvisitor-10-105-163-202 com.apple.xpc.launchd[1] (com.apple.xpc.launchd.domain.pid.WebContent.32502): Path not allowed in target domain"
        ev2 = parse_syslog_log(raw2, default_year=2017)
        norm2 = normalize_event(ev2)
        self.assertEqual(norm2.log_name, "calvisitor-10-105-163-202")
        self.assertEqual(norm2.product, "com.apple.xpc.launchd")
        self.assertEqual(norm2.unmapped.get("pid"), "1")
        self.assertEqual(norm2.unmapped.get("context"), "com.apple.xpc.launchd.domain.pid.WebContent.32502")
        self.assertEqual(norm2.message, "Path not allowed in target domain")
        self.assertEqual(norm2.vendor, "Apple")
        self.assertEqual(norm2.category_name, "System Activity")
        self.assertEqual(norm2.class_name, "Process Activity")

    def test_syslog_user_not_fabricated_for_kernel_and_daemons(self):
        # Line containing "for route = 0x0"
        raw1 = "Jul  1 09:00:55 calvisitor-10-105-160-95 kernel[0]: IOThunderboltSwitch<0>(0x0)::listenerCallback - Thunderbolt HPD packet for route = 0x0 port = 11 unplug = 0"
        ev1 = parse_syslog_log(raw1)
        self.assertIsNone(ev1.user)

        # Line containing "for interface awdl0"
        raw2 = "Jul  1 09:03:11 calvisitor-10-105-160-95 mDNSResponder[91]: mDNS_DeregisterInterface: Frequent transitions for interface awdl0 (FE80:0000:0000:0000:D8A5:90FF:FEF5:7FFF)"
        ev2 = parse_syslog_log(raw2)
        self.assertIsNone(ev2.user)

        # Line containing "for 439034 seconds"
        raw3 = "Jul  1 09:19:13 calvisitor-10-105-160-95 com.apple.cts[258]: com.apple.icloud.fmfd.heartbeat: scheduler_evaluate_activity told me to run this job; however, but the start time isn't for 439034 seconds.  Ignoring."
        ev3 = parse_syslog_log(raw3)
        self.assertIsNone(ev3.user)

    def test_syslog_legitimate_user_extraction(self):
        # Explicit key-value user=
        raw_kv = "Jan 04 15:16:01 combo testproc[123]: session auth user=john_doe status=ok"
        ev_kv = parse_syslog_log(raw_kv)
        self.assertEqual(ev_kv.user, "john_doe")

        # SSH auth failure
        raw_ssh_fail = "Jan 04 15:16:01 combo sshd[24047]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"
        ev_ssh_fail = parse_syslog_log(raw_ssh_fail)
        self.assertEqual(ev_ssh_fail.user, "admin")
        self.assertEqual(ev_ssh_fail.src_ip, "192.168.1.100")

        # SSH auth success
        raw_ssh_ok = "Jan 04 15:16:01 combo sshd[24047]: Accepted publickey for alice from 10.0.0.5 port 54321 ssh2"
        ev_ssh_ok = parse_syslog_log(raw_ssh_ok)
        self.assertEqual(ev_ssh_ok.user, "alice")
        self.assertEqual(ev_ssh_ok.src_ip, "10.0.0.5")

        # Sudo execution
        raw_sudo = "Jan 04 15:16:01 combo sudo[500]:   charlie : TTY=pts/0 ; PWD=/home/charlie ; COMMAND=/bin/ls"
        ev_sudo = parse_syslog_log(raw_sudo)
        self.assertEqual(ev_sudo.user, "charlie")

        # User unknown
        raw_unknown = "Jan 04 15:16:01 combo sshd[24047]: check pass; user unknown"
        ev_unknown = parse_syslog_log(raw_unknown)
        self.assertEqual(ev_unknown.user, "unknown")

    def test_syslog_timestamp_year_inference(self):
        raw = "Jul  1 09:00:55 calvisitor-10-105-160-95 kernel[0]: System boot"
        ev_2017 = parse_syslog_log(raw, default_year=2017)
        self.assertIsNotNone(ev_2017.timestamp)
        self.assertEqual(ev_2017.timestamp.year, 2017)
        self.assertEqual(ev_2017.timestamp.month, 7)
        self.assertEqual(ev_2017.timestamp.day, 1)
        self.assertEqual(ev_2017.timestamp.hour, 9)
        self.assertEqual(ev_2017.timestamp.minute, 0)
        self.assertEqual(ev_2017.timestamp.second, 55)
        self.assertTrue(ev_2017.unmapped.get("timestamp_year_inferred"))

    def test_syslog_macos_subsystem_enrichment(self):
        test_cases = [
            ("kernel", "Apple", "System Activity", "Kernel Activity"),
            ("sandboxd", "Apple", "Security Finding", "Security Finding"),
            ("com.apple.CDScheduler", "Apple", "System Activity", "Scheduled Job Activity"),
            ("mDNSResponder", "Apple", "Network Activity", "DNS Activity"),
            ("networkd", "Apple", "Network Activity", "Network Activity"),
            ("WindowServer", "Apple", "System Activity", "System Activity"),
            ("Google Software Update", "Google", "Application Activity", "Application Lifecycle"),
        ]
        for proc, expected_vendor, expected_cat, expected_class in test_cases:
            raw = f"Jul  1 09:00:00 myhost {proc}[100]: message test"
            ev = parse_syslog_log(raw)
            norm = normalize_event(ev)
            self.assertEqual(norm.vendor, expected_vendor)
            self.assertEqual(norm.category_name, expected_cat)
            self.assertEqual(norm.class_name, expected_class)

    def test_tableau_hyper_severity_mapping(self):
        # 1. trace -> Informational (1)
        raw_trace = '{"ts":"2023-05-15T12:00:00.000Z","sev":"trace","k":"trace-start","v":{"detail":"initializing"}}'
        ev_trace = normalize_event(parse_json_log(raw_trace))
        self.assertEqual(ev_trace.severity, "Informational")
        self.assertEqual(ev_trace.severity_id, 1)

        # 2. info -> Informational (1), even when 'k' field contains keywords like 'error' or 'fatal'
        raw_info = '{"ts":"2023-05-15T12:00:01.000Z","sev":"info","k":"error-handler-initialized","v":{"code":0}}'
        ev_info = normalize_event(parse_json_log(raw_info))
        self.assertEqual(ev_info.severity, "Informational")
        self.assertEqual(ev_info.severity_id, 1)

        # 3. warning -> Medium (3)
        raw_warn = '{"ts":"2023-05-15T12:00:02.000Z","sev":"warning","k":"high-memory-warning","v":{"used_mb":8192}}'
        ev_warn = normalize_event(parse_json_log(raw_warn))
        self.assertEqual(ev_warn.severity, "Medium")
        self.assertEqual(ev_warn.severity_id, 3)

        # 4. error -> High (4)
        raw_err = '{"ts":"2023-05-15T12:00:03.000Z","sev":"error","k":"query-failed","v":{"error_code":"QUERY_CANCELED"}}'
        ev_err = normalize_event(parse_json_log(raw_err))
        self.assertEqual(ev_err.severity, "High")
        self.assertEqual(ev_err.severity_id, 4)

        # 5. fatal -> Fatal (6)
        raw_fatal = '{"ts":"2023-05-15T12:00:04.000Z","sev":"fatal","k":"unhandled-exception-shutdown","v":{"reason":"OOM"}}'
        ev_fatal = normalize_event(parse_json_log(raw_fatal))
        self.assertEqual(ev_fatal.severity, "Fatal")
        self.assertEqual(ev_fatal.severity_id, 6)

        # 6. Check unmapped fields and timestamp parsing
        self.assertEqual(ev_info.unmapped.get("k"), "error-handler-initialized")
        self.assertIsNotNone(ev_info.timestamp)
        self.assertEqual(ev_info.vendor, "Tableau")
        self.assertEqual(ev_info.product, "Hyper")

    def test_ollama_parser_offline_fallback(self):
        from app.parsers.ollama_parser import parse_with_ollama
        raw = "2026-08-31 22:45:00 [CUSTOM_APP] user=john_doe action=checkout status=success"
        ev = parse_with_ollama(raw)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.raw_event, raw)


if __name__ == "__main__":
    unittest.main()


