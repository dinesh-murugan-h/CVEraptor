from pathlib import Path
from datetime import datetime

# Project root = the folder where this script is placed
PROJECT_ROOT = Path(__file__).resolve().parent

# Output file on Ubuntu Desktop
OUTPUT_FILE = Path.home() / "Desktop" / "cveraptor_codebase_dump.txt"

# Folders to ignore
IGNORE_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "env",
    "dist",
    "build",
    ".next",
    ".vite",
    "coverage",
}

# File extensions to include
INCLUDE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".css",
    ".html",
    ".json",
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".dockerfile",
}

# Exact filenames to include even if they do not have normal extensions
INCLUDE_FILENAMES = {
    "Dockerfile",
    "docker-compose.yml",
    "requirements.txt",
    "package.json",
    "vite.config.js",
    "eslint.config.js",
    "README.md",
    ".gitignore",
}

# Optional: skip very large files
MAX_FILE_SIZE_MB = 2


def should_ignore(path: Path) -> bool:
    parts = set(path.parts)

    if parts & IGNORE_DIRS:
        return True

    if path.name == OUTPUT_FILE.name:
        return True

    if path.is_file():
        if path.name in INCLUDE_FILENAMES:
            return False

        if path.suffix.lower() in INCLUDE_EXTENSIONS:
            return False

        return True

    return False


def get_file_tree(files):
    tree_lines = []

    for file in files:
        relative = file.relative_to(PROJECT_ROOT)
        tree_lines.append(str(relative))

    return "\n".join(tree_lines)


def main():
    files_to_collate = []

    for path in PROJECT_ROOT.rglob("*"):
        if path.is_file() and not should_ignore(path):
            try:
                size_mb = path.stat().st_size / (1024 * 1024)
                if size_mb <= MAX_FILE_SIZE_MB:
                    files_to_collate.append(path)
            except OSError:
                continue

    files_to_collate.sort()

    with OUTPUT_FILE.open("w", encoding="utf-8") as output:
        output.write("CVERAPTOR CODEBASE DUMP\n")
        output.write("=" * 80 + "\n")
        output.write(f"Generated on: {datetime.now()}\n")
        output.write(f"Project root: {PROJECT_ROOT}\n")
        output.write(f"Total files included: {len(files_to_collate)}\n")
        output.write("=" * 80 + "\n\n")

        output.write("FILE TREE\n")
        output.write("=" * 80 + "\n")
        output.write(get_file_tree(files_to_collate))
        output.write("\n\n")

        for file_path in files_to_collate:
            relative_path = file_path.relative_to(PROJECT_ROOT)

            output.write("\n\n")
            output.write("=" * 80 + "\n")
            output.write(f"FILE: {relative_path}\n")
            output.write("=" * 80 + "\n\n")

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                output.write(content)
            except Exception as e:
                output.write(f"[ERROR READING FILE: {e}]")

    print(f"Done. Codebase dumped to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()