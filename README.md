## Problem

SSH servers can receive repeated failed login attempts. This tool analyzes SSH authentication logs and identifies IP addresses with suspicious login activity.

## Features

- Reads SSH authentication logs.
- Counts failed login attempts by IP address.
- Detects suspicious IP addresses using a configurable threshold.
- Exports analysis results to a JSON report.
- Supports command-line arguments using argparse.

## Technologies

- Python 3
- JSON
- argparse
- File Handling
- Dictionaries and Functions

## How to Run

1. Clone or download this repository.
2. Open the project directory.
3. Run the analyzer:

```bash
python analyzer.py --file sample_auth.log --threshold 5
```

You can change the detection threshold:

```bash
python analyzer.py --file sample_auth.log --threshold 2
```

## Example Output

```text
Failed login attempts: {'203.0.113.15': 5, '198.51.100.20': 2}
Suspicious IP addresses: ['203.0.113.15']
```


## Output

The program generates a `report.json` file containing:

- Failed login attempts by IP.
- A list of suspicious IP addresses.

## Disclaimer

This project uses sample log data for educational purposes. Detection results are indicators for further investigation, not proof of malicious activity.</WritingBlock>
