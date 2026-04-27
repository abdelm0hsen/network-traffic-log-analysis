# Network Traffic Log Analysis

A beginner-friendly Python project that inspects packet log CSV data and identifies suspicious patterns such as repeated failed access attempts and unusually large transfers.

## Features

- Parses CSV packet logs
- Summarizes top source IPs and targeted ports
- Flags suspicious ports and failed access behavior
- Detects high-volume data transfer events

## Project Structure

```
network-traffic-log-analysis/
  main.py
  sample_data/
    packets.csv
  requirements.txt
  README.md
```

## Usage

```bash
python main.py --input sample_data/packets.csv
```

## Learning Outcomes

- Traffic telemetry interpretation
- Security anomaly heuristics
- Report generation for SOC-style workflows
