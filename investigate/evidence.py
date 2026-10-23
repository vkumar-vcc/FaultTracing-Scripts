"""Read-only access to a job's files for the evidence viewer: list, read line ranges, search.

DLT text exports can be hundreds of MB, so files are streamed line by line and never loaded whole.
"""

import itertools
import re
from pathlib import Path

TEXT_SUFFIXES = {".md", ".txt", ".log", ".json", ".csv"}
MAX_LINES = 1000
MAX_MATCHES = 500
MAX_LINE_CHARS = 2000


def list_files(folder):
    """Readable text files in the job folder as ``{"name", "path", "size"}``; report files first."""
    folder = Path(folder).resolve()
    files = []
    for path in folder.rglob("*"):
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            files.append({"name": path.relative_to(folder).as_posix(), "path": path, "size": path.stat().st_size})

    def order(item):
        name = item["name"]
        if name.startswith("report"):
            group = 0
        elif "/" not in name:
            group = 1
        else:
            group = 2 if name.startswith("collected/readouts/") else 3
        return group, name

    return sorted(files, key=order)


def resolve(folder, name):
    """The file ``name`` inside ``folder``; refuses paths outside it."""
    folder = Path(folder).resolve()
    path = (folder / name).resolve()
    if path != folder and folder not in path.parents:
        raise ValueError(f"Not a file of this investigation: {name}")
    if not path.is_file():
        raise ValueError(f"No such file: {name}")
    return path


def clip(line):
    line = line.rstrip("\r\n")
    return line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + " …"


def read_lines(path, start, count):
    """Lines ``start``.. (1-based) as ``[(number, text)]``, at most ``MAX_LINES``."""
    start = max(1, int(start))
    count = max(1, min(int(count), MAX_LINES))
    with open(path, encoding="utf-8", errors="replace") as handle:
        selected = itertools.islice(handle, start - 1, start - 1 + count)
        return [(number, clip(line)) for number, line in enumerate(selected, start)]


def compile_pattern(text, regex=False, ignore_case=True):
    if not text:
        raise ValueError("Enter text to search for.")
    try:
        return re.compile(text if regex else re.escape(text), re.IGNORECASE if ignore_case else 0)
    except re.error as error:
        raise ValueError(f"Not a valid regular expression: {error}") from None


def search(path, pattern, limit=MAX_MATCHES, start=1):
    """Matching lines from line ``start`` as ``([(number, text)], truncated)``."""
    limit = max(1, min(int(limit), MAX_MATCHES))
    matches = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            if number >= start and pattern.search(line):
                if len(matches) == limit:
                    return matches, True
                matches.append((number, clip(line)))
    return matches, False


def format_lines(lines, mark=None):
    width = len(str(lines[-1][0])) if lines else 1
    return "\n".join(
        f"{'>' if number == mark else ' '}{number:>{width}} | {text}" for number, text in lines
    )
