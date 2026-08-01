# DNS Tunneling Detector

A Python-based network security tool that detects suspicious DNS activity using behavioral analysis. The detector analyzes DNS traffic from PCAP files or live network traffic and identifies potential DNS tunneling, data exfiltration, and command-and-control (C2) communication using multiple detection techniques.

## Features

- Offline analysis of PCAP files
- Live DNS traffic monitoring
- Shannon entropy analysis
- Query frequency detection
- Long subdomain detection
- Unique subdomain analysis
- Threat severity classification
- Interactive terminal dashboard using Rich

## Detection Techniques

The detector combines multiple behavioral indicators instead of relying on a single rule.

- High entropy subdomains
- Long subdomains
- High DNS query frequency
- Large number of unique subdomains
- Rule-based threat classification

## Technologies Used

- Python
- Scapy
- Pandas
- Rich

## Project Structure

```
DNS-Tunneling-Detector/
│
├── data/
├── src/
├── requirements.txt
└── README.md
```

## Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/DNS-Tunneling-Detector.git
cd DNS-Tunneling-Detector
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate the virtual environment:

**Windows**

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the application:

```bash
python src/main.py
```

Select one of the available modes:

- Offline PCAP Analysis
- Live DNS Monitoring

## Sample Output

Example screenshots of the detector can be added here.

```
screenshots/
├── offline-analysis.png
└── live-monitoring.png
```

## Limitations

- Uses heuristic-based detection and may produce false positives.
- Detection thresholds may require tuning for different network environments.
- Does not currently inspect encrypted DNS traffic (DoH/DoT).

## Future Improvements

- Machine learning-based detection
- Domain reputation lookups
- Export results to JSON/CSV
- Web dashboard for visualization

## License

This project is licensed under the MIT License.