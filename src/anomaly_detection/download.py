"""Download the chronological inside tcpdump archives from MIT Lincoln Laboratory."""

from pathlib import Path
from urllib.request import Request, urlopen
import shutil

BASE = "https://archive.ll.mit.edu/ideval/data/1999/training/week2"
DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday")


def paths(directory: Path) -> list[Path]:
    return [directory / day / "inside.tcpdump.gz" for day in DAYS]


def download(directory: Path) -> list[Path]:
    """Stream to temporary files; avoid keeping ~800 MB in RAM."""
    output = paths(directory)
    for day, dest in zip(DAYS, output):
        if dest.is_file() and dest.stat().st_size > 0:
            print(f"[skip] {dest}")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        partial = dest.with_name(dest.name + ".part")
        url = f"{BASE}/{day}/inside.tcpdump.gz"
        print(f"[download] {url}")
        try:
            req = Request(url, headers={"User-Agent": "DARPA-Research/0.1"})
            with urlopen(req, timeout=120) as stream, partial.open("wb") as out:
                shutil.copyfileobj(stream, out, length=1024 * 1024)
            if not partial.stat().st_size:
                raise IOError(f"Empty download from {url}")
            partial.replace(dest)
        except Exception:
            partial.unlink(missing_ok=True)
            raise
    return output
