#!/bin/bash

n=$1

for ((i=1; i<=n; i++)); do
  cp client.py "client${i}.py"
  echo "Created file: client${i}.py"
done

echo "created n files"

