#!/bin/bash
USER="admin"
COMMAND="cd dave && ./restart.sh"

while IFS= read -r host
do
echo "Connecting to $host..."
ssh -n -o StrictHostKeyChecking=no $USER@$host "$COMMAND"
done < "hosts.txt"
