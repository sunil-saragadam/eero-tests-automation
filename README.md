# Eero AP Test Automation

This repository contains scripts and tools to automate testing for Eero Access Points, including rate limiting, SQM (Smart Queue Management), CPU monitoring, and network performance testing using `iperf3` and `flent`.

## Features

- Automated SSH or serial-based interaction with crane and AP devices  
- Dynamic bandwidth shaping via `rate.sh` edits and execution  
- SQM enable/disable workflow integration  
- Real-time CPU stat collection using `mpstat -P ALL`  
- Automated `iperf3` and `flent` test orchestration  
- Wi-Fi station configuration via console  
- Manual pauses for test steps involving mobile app actions

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/eero-ap-test-automation.git
   cd eero-ap-test-automation
