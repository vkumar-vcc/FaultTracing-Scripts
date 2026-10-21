"""Stop only this WSL server when its Windows launcher signals shutdown."""

from pathlib import Path
import subprocess
import sys
import time


def main() -> int:
    stop_file = Path(sys.argv[1])
    child = subprocess.Popen([sys.executable, "-m", "streamlit", *sys.argv[2:]])
    try:
        while child.poll() is None and not stop_file.exists():
            time.sleep(0.5)
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    return child.returncode if not stop_file.exists() else 0


if __name__ == "__main__":
    raise SystemExit(main())
