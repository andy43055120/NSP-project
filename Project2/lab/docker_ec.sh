#!/bin/bash
docker build -t my_ec ./EC

docker run -it --rm \
  -v $(pwd)/shared:/shared \
  my_ec