#!/bin/bash
cd /root/Khipu-vFHE/gpucc-vfhe/build
LOG=/root/Khipu-vFHE/tmp_test/logreg_test2.log
MR_TD=$(cat /root/Khipu-vFHE/scripts/expected_mrtd.txt)

echo "$(date): Starting test" > $LOG

./tee_server --port 8105 >> $LOG 2>&1 &
SRV=$!
echo "$(date): Server PID=$SRV" >> $LOG
sleep 3

echo "$(date): Starting client..." >> $LOG
./tee_client --port 8105 --workload logistic-regression --expected-mr-td "$MR_TD" >> $LOG 2>&1
RC=$?
echo "$(date): Client exit=$RC" >> $LOG

kill $SRV 2>/dev/null || true
echo "$(date): Test complete" >> $LOG
