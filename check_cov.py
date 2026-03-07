import json
with open('coverage.json') as f:
    cov = json.load(f)
for file_name, data in cov['files'].items():
    if data['summary']['percent_covered'] < 100:
        print(f"{file_name}: {data['missing_lines']}")
