import re

test = '2023-10-11T22:14:15.003Z web-gw nginx - - [audit@123] {"src_ip":"10.0.0.15"}'
old_pat = r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+\S+\s+(?:\[.*\]|[^\[:\s]+(?:\[\d+\])?(?::|\s+\[|\s+\d+\s+))"
new_pat = r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+\S+\s+(?:\[.*\]|[^\[:\s]+(?:\[\d+\])?(?::|\s+\[|\s+\S+\s+))"

print("old:", bool(re.match(old_pat, test)))
print("new:", bool(re.match(new_pat, test)))
