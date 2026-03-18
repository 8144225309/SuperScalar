#!/bin/bash
# Launch the exhibition in background and capture PID
mkdir -p /tmp/ss_exhibit_v2
nohup bash /root/SuperScalar/run_all_exhibition.sh > /tmp/ss_exhibit_v2/master.log 2>&1 &
MASTER_PID=$!
echo $MASTER_PID > /tmp/ss_exhibit_v2/master.pid
echo "Exhibition started with PID $MASTER_PID"
