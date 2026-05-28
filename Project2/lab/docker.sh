#!/bin/bash

PHASE=${1:-3}  

IMAGE_NAME="ic_image"
CONTAINER_NAME="IC_PHASE${PHASE}"

if [ "$PHASE" -eq 1 ]; then
    SERVER="server_1"
else
    SERVER="server_2"
fi

echo "[*] Starting IC Phase $PHASE with $SERVER"

docker run -dit --name $CONTAINER_NAME \
  --platform linux/amd64 \
  --privileged \
  -v $(pwd)/shared:/shared \
  $IMAGE_NAME \
  bash

docker cp "./IC/$SERVER" "$CONTAINER_NAME:/blogic"
docker cp "./IC/$SERVER" "$CONTAINER_NAME:/shared/blogic"
docker cp "./IC/backdoor" "$CONTAINER_NAME:/backdoor"
docker cp "./IC/runserver.sh" "$CONTAINER_NAME:/runserver.sh"

docker exec -it $CONTAINER_NAME chmod +x /blogic /runserver.sh /backdoor
if [[ "$PHASE" -eq 1 || "$PHASE" -eq 2 ]]; then
    docker exec -it $CONTAINER_NAME sysctl -w kernel.randomize_va_space=0
else
    docker exec -it $CONTAINER_NAME sysctl -w kernel.randomize_va_space=2
fi
docker exec -d $CONTAINER_NAME /runserver.sh
echo "[*] Starting server inside container..."
