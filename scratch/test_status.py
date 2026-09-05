from app.pipeline import run_pipeline

raw = 'timestamp="2023-10-11T12:00:00Z" level=info service=auth-svc client_ip=192.168.1.20 user=sam action=login status=success latency=12ms'
res = run_pipeline(raw, save_to_db=False)
ev = res['events'][0]
print("pipeline status:", ev.status)
print("pipeline category:", ev.category_name)
print("pipeline user:", ev.user)
print("pipeline src_ip:", ev.src_ip)
print("pipeline unmapped:", ev.unmapped)
