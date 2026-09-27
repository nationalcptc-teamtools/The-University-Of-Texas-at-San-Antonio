"""Fixed networkless native scanner launcher; raw output leaves only via pipes."""
import base64
import json
import os
from pathlib import Path
import resource
import subprocess
import sys


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_CPU, (35, 35))
    # Reviewed ZAP add-ons unpack public dependency jars larger than 8 MiB.
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    # Parent verifies the live cgroup before allowing scanner startup.
    if sys.stdin.buffer.read(1) != b"G":
        return 2
    config = json.loads(Path("/config.json").read_bytes())
    if config == {"engine": "nuclei"}:
        command = ["/scanner", "-passive", "-u", "/capture.txt", "-t", "/rules",
                   "-duc", "-ni", "-silent", "-jsonl", "-omit-raw", "-omit-template",
                   "-disable-redirects", "-retries", "0", "-timeout", "3", "-max-time", "15s",
                   "-c", "1", "-bs", "1", "-no-stdin"]
        return subprocess.run(command, stdin=subprocess.DEVNULL, close_fds=True).returncode
    if config == {"engine": "zap"}:
        command = ["/jre/bin/java", "-Xmx384m", "-Djava.awt.headless=true", "-jar",
                   "/zap/zap-2.17.0.jar", "-cmd", "-silent", "-notel", "-dir", "/tmp/zap",
                   "-autorun", "/rules/zap-passive.yaml"]
        # Preserve native stdout/stderr identity. A final framed report is
        # appended only by this pinned launcher after the native process exits.
        code = subprocess.run(command, stdin=subprocess.DEVNULL, close_fds=True, cwd="/zap").returncode
        log = Path("/tmp/zap/zap.log")
        if log.is_file():
            sys.stderr.buffer.write(b"\n[CPTC ZAP internal log follows]\n")
            with log.open("rb") as stream:
                while chunk := stream.read(4096):
                    sys.stderr.buffer.write(chunk)
        if code:
            return code
        report = Path("/tmp/observations.json")
        if not report.is_file() or report.stat().st_size > 32768:
            return 3
        sys.stdout.buffer.write(b"\nCPTC_SCANNER_REPORT_V1:" + base64.b64encode(report.read_bytes()) + b"\n")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
