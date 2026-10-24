import re
import subprocess
from collections import Counter
from pathlib import Path

LOG_FILE = Path("samples/auth.log")
FAILED_LOGIN_THRESHOLD = 5
JOURNAL_TIMEOUT = 8

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

FAILURE_PATTERN = re.compile(
    r"failed password|authentication failure|"
    r"authentication failed|login failed|"
    r"invalid user|failed publickey",
    re.IGNORECASE,
)

def analyze_lines(lines):
    results = {
        "total_lines": 0,
        "failed_attempts": 0,
        "ip_counts": Counter(),
        "alerts": [],
        "errors": [],
        "source": "unknown",
    }

    for line in lines:
        results["total_lines"] += 1

        if not FAILURE_PATTERN.search(line):
            continue

        results["failed_attempts"] += 1
        match = IP_PATTERN.search(line)

        if match:
            results["ip_counts"][match.group()] += 1

    for ip, count in results["ip_counts"].most_common():
        if count >= FAILED_LOGIN_THRESHOLD:
            results["alerts"].append({
                "ip": ip,
                "attempts": count,
                "severity": "HIGH",
                "message": f"{count} intentos fallidos desde {ip}",
            })

    return results


def read_journal():
    command = [
        "journalctl",
        "--since", "24 hours ago",
        "--no-pager",
        "-o", "short-iso",
        "-q",
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=JOURNAL_TIMEOUT,
            check=False,
        )

        if completed.returncode != 0:
            message = completed.stderr.strip() or (
                f"journalctl terminó con código {completed.returncode}"
            )
            return None, message

        return completed.stdout.splitlines(), None

    except FileNotFoundError:
        return None, "No se encontró journalctl."

    except subprocess.TimeoutExpired:
        return None, "La lectura del diario superó el tiempo límite."

    except OSError as error:
        return None, f"No se pudo consultar el diario: {error}"


def read_sample():
    try:
        with LOG_FILE.open("r", encoding="utf-8") as file:
            return file.readlines(), None
    except (OSError, UnicodeError) as error:
        return None, f"No se pudo leer el archivo de pruebas: {error}"


def analyze_log(log_path=None):
    if log_path is not None:
        lines, error = read_sample_for_path(log_path)
        if error:
            return empty_report(error, "sample")
        report = analyze_lines(lines)
        report["source"] = "sample"
        return report

    lines, error = read_journal()

    if lines is not None:
        report = analyze_lines(lines)
        report["source"] = "journal"
        return report

    sample_lines, sample_error = read_sample()

    if sample_lines is not None:
        report = analyze_lines(sample_lines)
        report["source"] = "sample_fallback"
        report["errors"].append(
            f"El diario no estuvo disponible: {error}"
        )
        return report

    return empty_report(
        f"{error} {sample_error}",
        "unavailable",
    )


def read_sample_for_path(path):
    try:
        with Path(path).open("r", encoding="utf-8") as file:
            return file.readlines(), None
    except (OSError, UnicodeError) as error:
        return None, f"No se pudo leer el archivo: {error}"


def empty_report(message, source):
    return {
        "total_lines": 0,
        "failed_attempts": 0,
        "ip_counts": Counter(),
        "alerts": [],
        "errors": [message],
        "source": source,
    }


if __name__ == "__main__":
    report = analyze_log()

    print("=== DARK SENTINEL V1.1 ===")
    print(f"Fuente: {report['source']}")
    print(f"Eventos analizados: {report['total_lines']}")
    print(f"Intentos fallidos detectados: {report['failed_attempts']}")
    print(f"IPs con intentos fallidos: {len(report['ip_counts'])}")

    for error in report["errors"]:
        print(f"AVISO: {error}")

    for alert in report["alerts"]:
        print(f"[{alert['severity']}] {alert['message']}")

    if not report["alerts"] and not report["errors"]:
        print("No se detectaron alertas con el umbral actual.")
