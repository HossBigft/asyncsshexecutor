#!/bin/bash

NUM_CONTAINERS=${1:-5}  # Default 5 containers
BASE_PORT=2222

echo "Starting $NUM_CONTAINERS SSH containers..."

for i in $(seq 1 "$NUM_CONTAINERS"); do
    PORT=$((BASE_PORT + i - 1))
    NAME="ssh-test-$i"
    
    echo "Starting $NAME on port $PORT"
    docker run -d \
    --name "$NAME" \
    -p "$PORT:22" \
    ssh-server
done

echo "Containers running on ports $BASE_PORT-$((BASE_PORT + NUM_CONTAINERS - 1))"