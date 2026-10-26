# Malware Network Communication Analysis & Threat Detection

Điều tra traffic mạng từ PCAP của máy nghi nhiễm malware, tái dựng hành vi C2/beaconing/exfiltration, xây dựng detection rules và đánh giá độ chính xác.

---

## Dataset

**CTU-13** - Stratosphere Laboratory, Czech Technical University  
→ https://www.stratosphereips.org/datasets-ctu13

| Scenario | Botnet | Capture | Vai trò |
|----------|--------|---------|---------|
| Scenario 1 | Neris | CTU-Malware-Capture-Botnet-42 | Primary |
| Scenario 5 | Virut | CTU-Malware-Capture-Botnet-46 | Secondary |
| Scenario 13 | Virut | CTU-Malware-Capture-Botnet-54 | Secondary |

---

## Nhân sự

| Thành viên | Vai trò |
|-----------|---------|
| Thương | Network Forensics Analyst |
| Thi | Malware Communication Analyst |
| Quý | Traffic Analytics Engineer |
| Lâm | Threat Intelligence & Integration Analyst |

---

## Cấu trúc

```
malware-network-analysis/
│
├── data/
│   ├── raw/
│   │   ├── scenario-01-neris/
│   │   │   ├── pcap/
│   │   │   ├── labeled-flows/
│   │   │   └── metadata/
│   │   ├── scenario-05-virut/
│   │   ├── scenario-13-virut/
│   │   └── checksums.sha256
│   ├── processed/
│   └── labeled/
│
├── src/
│   ├── ingestion/
│   ├── analysis/
│   ├── detection/
│   │   ├── beaconing_detector.py
│   │   ├── dns_analyzer.py
│   │   └── outbound_detector.py
│   └── utils/
│
├── evidence/
├── notebooks/
├── reports/
│   ├── week1/
│   └── week2/
├── configs/
│   └── scenarios.yaml
├── docs/
│
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

---

## Setup

```bash
git clone <repo-url>
cd malware-network-analysis

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
# Điền giá trị trong .env
```

---

## Quy tắc làm việc

- Không push thẳng lên `main` - mọi thay đổi qua Pull Request
- Không commit file `.env`, PCAP, binetflow
- Finding ID format: `FND-NNN` · Evidence ID: `EVD-NNN` · IOC ID: `IOC-NNN`
- Xem [`docs/evidence_standards.md`](docs/evidence_standards.md) và [`docs/contribution_guide.md`](docs/contribution_guide.md)

---

## License

MIT · Xem [LICENSE](LICENSE)  
Dataset: Garcia et al., *"An empirical comparison of botnet detection methods"*, 2014
