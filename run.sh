#!/bin/bash
USER="admin"
COMMAND=$1

while IFS= read -r host
do
echo "Connecting to $host..."
ssh -n -o StrictHostKeyChecking=no $USER@$host "$COMMAND"
done < "hostnames"
