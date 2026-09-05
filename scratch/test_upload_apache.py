import urllib.request
import json
import uuid

boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
filename = "04_apache_access.log"

with open("data/uploads/JOB-042195/04_apache_access.log", "rb") as f:
    content = f.read()

body = (
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
    f"Content-Type: text/plain\r\n\r\n"
).encode("utf-8") + content + f"\r\n--{boundary}--\r\n".encode("utf-8")

req = urllib.request.Request(
    "http://127.0.0.1:8000/api/ingest/upload",
    data=body,
    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    method="POST"
)

try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        print("Upload Status: SUCCESS")
        print("Job ID:", data.get("job_id"))
        print("Format:", data.get("format"))
        print("Parser:", data.get("parser"))
        print("Parser Source:", data.get("parser_source"))
        print("Ollama Calls:", data.get("ollama_calls"))
        print("Status:", data.get("status"))
        for l in data.get("logs", []):
            print("  ", l.get("level"), l.get("message"))
except Exception as e:
    print("Upload error:", e)
