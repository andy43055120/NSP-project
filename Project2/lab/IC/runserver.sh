#!/bin/bash
COREDUMP_DIR="/shared/coredump/"

mkdir -p "$COREDUMP_DIR"

echo "$COREDUMP_DIR/%e-%p.core" | tee /proc/sys/kernel/core_pattern

ulimit -c unlimited

while true; do
    /blogic
    sleep 0.1
done

