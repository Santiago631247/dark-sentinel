# DARK SENTINEL V1.1 🛡️

**A Python-based security log monitoring dashboard.**

DARK SENTINEL is a defensive cybersecurity project designed to analyze system journal events, identify patterns associated with failed authentication attempts, and display security alerts through a local Flask dashboard.

## Features

- System journal analysis using `journalctl`.
- Detection of patterns associated with failed authentication.
- Configurable alert threshold.
- IP-based attempt counting.
- Flask dashboard with periodically refreshed metrics.
- Sample authentication logs for safe testing.
- Sample fallback when journal access is unavailable.

## Tech Stack

- Python
- Flask
- Linux systemd journal
- HTML, CSS and JavaScript

## Requirements

- Linux with `journalctl` available for system journal analysis.
- Python 3.
- Flask.

## Installation

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd dark-sentinel
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install Flask:

```bash
python -m pip install flask
```

## Run the Dashboard

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Test with Sample Logs

The project includes sample authentication events for testing the detector:

```bash
python -c "from sentinel import analyze_log; print(analyze_log('samples/auth.log'))"
```

The sample IP addresses are reserved for documentation and examples. They do not identify real attackers.

## Important Limitations

- Detection depends on the log events available to the process and the patterns configured in the detector.
- Missing matches do not prove that a system is free of threats.
- The dashboard is a local prototype, not a complete SIEM or a replacement for a production security monitoring system.
- Sample alerts are simulations, not evidence of real attacks.

## Security

Run the dashboard locally and do not expose it to untrusted networks without appropriate security controls.

## Project Status

**Version:** 1.1
**Status:** Development / Educational defensive security project.

Created by **DARK631247**.
