# Basic scan (default scans TCP ports 1-1024)
python scanner_app.py

# Custom scan configuration
export TCP_PORTS_TO_SCAN="22,80,443,8000-9000"
export UDP_PORTS_TO_SCAN="53,67,68"
export RECEIVER_URL="http://localhost:5000/receive"
python scanner_app.py
