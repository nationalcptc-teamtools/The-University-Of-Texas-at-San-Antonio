"""Build the optional Burp extension using an explicit local Montoya API JAR."""

import argparse
import shutil
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-jar", type=Path, required=True)
    args = parser.parse_args()
    if not args.api_jar.is_file():
        parser.error("--api-jar must identify an installed Montoya API JAR")
    if not shutil.which("javac") or not shutil.which("jar"):
        parser.error("Install a Java 17+ JDK containing javac and jar")
    root = Path(__file__).resolve().parent
    classes, output = root / "build" / "classes", root / "dist" / "fieldkit-burp.jar"
    classes.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "javac",
            "--release",
            "17",
            "-cp",
            str(args.api_jar.resolve()),
            "-d",
            str(classes),
            *(str(p) for p in sorted((root / "src").rglob("*.java"))),
        ],
        check=True,
        timeout=60,
    )
    subprocess.run(
        ["jar", "--create", "--file", str(output), "-C", str(classes), "."],
        check=True,
        timeout=60,
    )
    print(output)


if __name__ == "__main__":
    main()
