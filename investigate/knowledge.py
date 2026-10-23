"""Team knowledge for the root-cause agent, stored as skills in the repository.

Each entry is ``.github/skills/<name>/SKILL.md``. The ``root-cause`` agent reads the description of
every skill and loads the ones that match the problem, so knowledge saved here is used in later
investigations. Commit the new files to share them with the team.
"""

import json
import os
import re
from pathlib import Path

from jobs import iso, utc_now

ROOT = Path(__file__).resolve().parent.parent
NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_NAME = 64
MAX_TEXT = 20000
ADDENDUM_HEADING = "## Engineer notes"


def skills_root():
    configured = os.environ.get("FAULT_TRACING_SKILLS_DIR")
    return Path(configured).expanduser().resolve() if configured else ROOT / ".github" / "skills"


def slugify(title):
    slug = re.sub(r"[^a-z0-9]+", "-", (title or "").lower()).strip("-")
    return slug[:MAX_NAME].rstrip("-")


def one_line(text):
    return " ".join((text or "").split())


def skill_path(name, root=None):
    if not NAME_PATTERN.match(name or "") or len(name) > MAX_NAME:
        raise ValueError(f"Not a knowledge name: {name!r}")
    return (root or skills_root()) / name / "SKILL.md"


def read_frontmatter(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    fields = {}
    if text.startswith("---"):
        end = text.find("\n---", 3)
        for line in text[3:end if end > 0 else 0].splitlines():
            key, separator, value = line.partition(":")
            if separator:
                value = value.strip()
                if value.startswith('"'):
                    try:
                        value = json.loads(value)
                    except ValueError:
                        value = value.strip('"')
                fields[key.strip()] = value
    return fields


def list_knowledge(root=None):
    """Every skill as ``{"name", "description", "path"}``, sorted by name."""
    root = root or skills_root()
    if not root.is_dir():
        return []
    entries = []
    for path in sorted(root.glob("*/SKILL.md")):
        fields = read_frontmatter(path)
        entries.append({
            "name": fields.get("name") or path.parent.name,
            "description": fields.get("description", ""),
            "path": path,
        })
    return entries


def source_line(submitted_by="", job_id=""):
    parts = [f"Added {iso(utc_now())[:10]}"]
    if submitted_by:
        parts.append(f"by {one_line(submitted_by)}")
    if job_id:
        parts.append(f"from investigation `{job_id}`")
    return "_" + " ".join(parts) + "._"


def check_text(content):
    content = (content or "").strip()
    if not content:
        raise ValueError("Write the knowledge itself.")
    if len(content) > MAX_TEXT:
        raise ValueError(f"The knowledge is too long ({len(content):,} characters, at most {MAX_TEXT:,}).")
    return content


def save_knowledge(title, applies_when, content, submitted_by="", job_id="", root=None):
    """Create a new skill and return its path. Never overwrites an existing skill."""
    title = one_line(title)
    applies_when = one_line(applies_when)
    content = check_text(content)
    name = slugify(title)
    if not name:
        raise ValueError("Give the knowledge a title with letters or digits.")
    if not applies_when:
        raise ValueError("Say when the agent should use this knowledge (symptom, ECU, keywords).")
    path = skill_path(name, root)
    if path.exists():
        raise ValueError(f"Knowledge named '{name}' already exists. Add to it instead, or choose another title.")
    description = f"Use when: {applies_when} Team knowledge added from the investigation app."
    path.parent.mkdir(parents=True)
    path.write_text(
        "---\n"
        f"name: {name}\n"
        f"description: {json.dumps(description, ensure_ascii=False)}\n"
        "---\n\n"
        f"# {title}\n\n"
        f"{source_line(submitted_by, job_id)}\n\n"
        f"{content}\n",
        encoding="utf-8",
    )
    return path


def append_knowledge(name, content, submitted_by="", job_id="", root=None):
    """Add a dated note to an existing skill and return its path."""
    content = check_text(content)
    path = skill_path(name, root)
    if not path.is_file():
        raise ValueError(f"No knowledge named '{name}'.")
    text = path.read_text(encoding="utf-8").rstrip()
    if ADDENDUM_HEADING not in text:
        text += f"\n\n{ADDENDUM_HEADING}\n\nAdded by engineers from the investigation app. They refine the guidance above."
    text += f"\n\n### {source_line(submitted_by, job_id).strip('_')}\n\n{content}\n"
    path.write_text(text, encoding="utf-8")
    return path
