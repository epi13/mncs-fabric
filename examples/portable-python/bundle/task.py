from pathlib import Path

result = b'{"status":"ok","value":42}\n'
Path("result.json").write_bytes(result)
print("portable example complete")
