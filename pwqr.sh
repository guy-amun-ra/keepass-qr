#!/bin/bash

# Get the absolute path of the input file
input_file=$(readlink -f "$1")

# Run the docker command with the absolute path
docker run -it --rm -v "$input_file:/app/your.kdbx" qr_passwords /app/your.kdbx
