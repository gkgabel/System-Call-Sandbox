#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

filename=$1

# Run the first Python script to generate a pikl file with the filename as an argument
python3 make_pikl.py "$filename"

# Run the second Python script for generating policy graph with the same filename
python3 generator.py "$filename"
