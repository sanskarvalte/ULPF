import re

apache_line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://example.com" "Mozilla/5.0"'
apache_re = re.compile(r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"]*)"\s+(\d{3})\s+(\S+)')
print('Apache match:', bool(apache_re.match(apache_line)))

hadoop_line1 = '2015-10-18 18:01:47,978 INFO [main] org.apache.hadoop.mapreduce.v2.app.MRAppMaster: Created MRAppMaster'
hadoop_line2 = '081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk terminating'
hadoop_re = re.compile(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d{3}|\d{6}\s+\d{6}(?:\s+\d+)?)\s+(INFO|WARN|ERROR|FATAL|DEBUG|TRACE)\s+(?:\[[^\]]+\]\s+)?(?:org\.apache\.|dfs\.)[^:]+:')
print('Hadoop 1 match:', bool(hadoop_re.match(hadoop_line1)))
print('Hadoop 2 match:', bool(hadoop_re.match(hadoop_line2)))
