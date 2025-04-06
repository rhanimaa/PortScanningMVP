# Internal Port Scanning Service MVP

This is an MVP for an internal port scanning service that helps identify endpoints with unusual ports open.

## Components

1. **Port Scanner**: Runs on each host, scans TCP/UDP ports, and sends results to receiver
2. **Port Receiver**: Receives and stores scan results with host information

## How to Run Locally

### Prerequisites
- Python 3.6+
- pip

### Setup

1. Clone this repository
2. Install dependencies:
   ```bash
   pip install flask requests


