import argparse
import hashlib
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--directory", required=True)
args = parser.parse_args()

directory = Path(args.directory).expanduser().resolve()
directory.mkdir(parents=True, exist_ok=True)

for number in range(1, 61):
    path = directory / f"demo-evidence-{number:03d}.log"
    expected = f"CyberShield synthetic evidence {number}".encode("utf-8")

    if path.is_symlink():
        raise SystemExit(f"Refusing symbolic link: {path}")

    if path.exists():
        if not path.is_file() or path.read_bytes() != expected:
            raise SystemExit(f"Existing file differs; not overwritten: {path}")
    else:
        with path.open("xb") as file:
            file.write(expected)

    actual = path.read_bytes()

    if actual != expected:
        raise SystemExit(f"Verification failed: {path}")

    print(
        f"{path.name} | {len(actual)} bytes | "
        f"{hashlib.sha256(actual).hexdigest()}"
    )

print(f"SUCCESS: 60 demo evidence files verified in {directory}")