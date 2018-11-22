#!/bin/bash
exec >&2 # Redirect stdout to stderr so that it's captured for BOINC

echo "Results from a killerbeez run. This file ensures an empty zip file is not generated." > README.txt
for result_type in crashes hangs new_paths; do
  for file in $(ls output/$result_type); do
    cp output/$result_type/$file killerbeez_result_${result_type}_${file}
  done
done
