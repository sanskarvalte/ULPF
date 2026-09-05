import urllib.request
import json
from pathlib import Path

file_path = Path('tests/real_unknown_logs/turbine_telemetry.log')
content = file_path.read_bytes()

def upload_file(label):
    boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
    body = []
    body.append(f'--{boundary}'.encode())
    body.append(f'Content-Disposition: form-data; name="files"; filename="{label}"'.encode())
    body.append(b'Content-Type: text/plain\r\n')
    body.append(content)
    body.append(f'--{boundary}--\r\n'.encode())
    payload = b'\r\n'.join(body)

    req = urllib.request.Request(
        'http://127.0.0.1:8000/api/ingest/upload?sync=true',
        data=payload,
        headers={'Content-Type': f'multipart/form-data; boundary={boundary}'},
        method='POST'
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

print('=== UPLOADING TURBINE RUN 1 ===')
res1 = upload_file('turbine_telemetry_run1.log')
job1 = res1.get('job', {})
print(f'Job ID: {job1.get("job_id")}')
print(f'Status: {job1.get("status")}')
print(f'Format: {job1.get("format")}')
print(f'Parser: {job1.get("parser")}')
print(f'Parser Source: {job1.get("parser_source")}')
print(f'Events Stored: {job1.get("events_stored")}')
print(f'Ollama Calls: {job1.get("ollama_calls")}')
print(f'Fingerprint: {job1.get("fingerprint")}')

print('\n=== UPLOADING TURBINE RUN 2 (EXACT SAME FORMAT) ===')
res2 = upload_file('turbine_telemetry_run2.log')
job2 = res2.get('job', {})
print(f'Job ID: {job2.get("job_id")}')
print(f'Status: {job2.get("status")}')
print(f'Format: {job2.get("format")}')
print(f'Parser: {job2.get("parser")}')
print(f'Parser Source: {job2.get("parser_source")}')
print(f'Events Stored: {job2.get("events_stored")}')
print(f'Ollama Calls: {job2.get("ollama_calls")}')
print(f'Fingerprint: {job2.get("fingerprint")}')
