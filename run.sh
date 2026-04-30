#!/bin/bash

echo "=== CLEAN MININET ==="
sudo mn -c

echo "=== START RYU CONTROLLER ==="
gnome-terminal -- bash -c "python -m ryu.cmd.manager ddos_controller.py; exec bash"

sleep 3

echo "=== START MININET TOPOLOGY ==="
sudo mn --topo single,3 --controller remote --switch ovsk,protocols=OpenFlow13

echo "=== DONE ==="