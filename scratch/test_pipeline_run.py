from app.pipeline import run_pipeline

line = '203.0.113.5 - - [27/Aug/2026:02:14:15 +0000] "GET /api/v1/orders HTTP/1.1" 200 5324 "https://example.com/dashboard" "Mozilla/5.0"'
res = run_pipeline(line, save_to_db=False)
print("Keys:", list(res.keys()))
print("Events:", res.get("events"))
print("Unparsed:", res.get("unparsed_count"))
print("Format:", res.get("format"))
