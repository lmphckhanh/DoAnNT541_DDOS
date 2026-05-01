#!/bin/bash
echo "=== Starting Ryu DDOS Controller - Dynamic Access Control ==="

# Activate Ryu virtual environment
source ~/ryu-env/bin/activate

# Vào thư mục dự án
cd ~/sdn-ddos

echo "Running DDOS Controller..."
ryu-manager --verbose ddos_controller.py