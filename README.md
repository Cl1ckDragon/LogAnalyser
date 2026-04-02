# Suspicious IP Detector

A simple Python CLI tool to detect suspicious IPs from failed login attempts in server logs.  
This project demonstrates core backend and cybersecurity concepts like log parsing, data aggregation, and threshold-based alerting.

## Features

- Parse log files for failed login attempts  
- Count failed attempts per IP  
- Flag IPs exceeding a configurable threshold  
- Command-line interface (CLI)  
- Modular and testable code  
- Unit tests using `pytest`  

## Concepts Demonstrated

- File handling (read logs)  
- String parsing and manipulation  
- Dictionaries for counting occurrences  
- CLI design with `argparse`  
- Threshold-based filtering for alerts  
- Unit testing and capturing stdout  

## How To Run

Run the script with a log file:

```bash
python log_analyzer.py sample.log
```

Set a custom threshold for suspicious activity:

```bash
python log_analyzer.py sample.log --threshold 5
```

Output example:

```bash
Suspicious IPs:
192.168.1.10 (3 attempts)
192.168.1.25 (5 attempts)
```

If no IP exceeds the threshold:

```bash
No suspicious activity detected!
```

## Testing

Run automated tests with pytest:

```bash
pytest -v
```

## Tech Used

- Python
- argparse
- pytest

## Purpose

This project demonstrates log parsing, data aggregation, and basic threat detection concepts such as identifying potential brute-force login attempts.