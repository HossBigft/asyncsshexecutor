#!/bin/bash

echo "Stopping and removing all ssh-test containers..."
docker ps -a --filter "name=ssh-test-" --format "{{.Names}}" | xargs -r docker rm -f
echo "Done!"