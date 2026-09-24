with open(".env", "r", encoding="utf-8") as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")
for i, line in enumerate(lines):
    stripped = line.rstrip("\n").rstrip("\r")
    if "=" in stripped:
        key, val = stripped.split("=", 1)
        if len(val) > 12:
            masked = val[:6] + "..." + val[-4:]
        else:
            masked = val
        print(f"Line {i}: [{key}] = [{masked}]  (raw_repr={repr(stripped)})")
    else:
        print(f"Line {i}: {repr(stripped)}")
