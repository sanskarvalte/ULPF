import urllib.request
import json

raw_sample = '192.0.2.10 - - [24/Aug/2026:09:30:11 +0530] "GET /index.html HTTP/1.1" 200 5324 "-" "Mozilla/5.0"'
payload = {
    'raw_log': raw_sample,
    'source': '04_apache_access.log'
}

req = urllib.request.Request(
    'http://127.0.0.1:8000/api/ai/analyze',
    data=json.dumps(payload).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)

try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        print("Format Name:", data.get("format_name"))
        print("Grok Template:", data.get("grok_template"))
        print("Discovered Fields:")
        for f in data.get("discovered_fields", []):
            print(f"  {f.get('name')}: {f.get('type')} = {f.get('sample_value')}")
        print("Confidence:", data.get("confidence_percent"))
        val = data.get("validation_result", {})
        print("Validation Status:", val.get("status"), "Match %:", val.get("success_rate_percent"))
except Exception as e:
    print("Error:", e)
