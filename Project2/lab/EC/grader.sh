#!/bin/bash

ROUND=1
MAX_ROUNDS=60
MAX_TIME=1800 
SHARED_DIR="/shared"

rm -f $SHARED_DIR/coredump/*
rm -f $SHARED_DIR/config.data
rm -f $SHARED_DIR/exploit_done
rm -f $SHARED_DIR/success.txt

START_TIME=$(date +%s)

while [ $ROUND -le $MAX_ROUNDS ]; do
    echo "[*] Round $ROUND start"

    /exploit # create exploit_done
    
    while [ -f "$SHARED_DIR/exploit_done" ]; do # wait for IC delete exploit_done
        sleep 0.1
    done

    sleep 0.2 # wait for IC to process the exploit

    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    if [ $ELAPSED -ge $MAX_TIME ]; then
        echo "[-] Max grading time reached"
        break
    fi

    if [ -f "$SHARED_DIR/success.txt" ]; then
        echo "[+] Exploit successful! Grading ends."
        break
    fi    

    /triage 

    ROUND=$((ROUND + 1))
done

echo "[*] Grading done"
echo "Total time: $ELAPSED seconds"