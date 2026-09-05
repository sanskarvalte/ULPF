import sys, os
sys.path.insert(0, os.path.abspath("."))
from app.ai.parser_resolver import resolve_parser_spec, generate_parser_spec, validate_parser_spec

sample = (
    '192.0.2.10 - - [24/Aug/2026:09:30:11 +0530] "GET /index.html HTTP/1.1" 200 5324 "-" "Mozilla/5.0"\n'
    '198.51.100.5 - - [24/Aug/2026:09:30:44 +0530] "POST /login HTTP/1.1" 401 342 "-" "curl/8.1.0"'
)

print("Testing generate_parser_spec...")
try:
    spec = generate_parser_spec(sample, timeout=30.0)
    print("Generated Spec:", spec)
    val = validate_parser_spec(spec, log_samples=sample)
    print("Validation:", val)
except Exception as e:
    print("Error in generation:", e)
