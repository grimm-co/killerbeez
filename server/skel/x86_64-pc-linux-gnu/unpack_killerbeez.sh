#!/bin/bash
exec >&2 # Redirect stdout to stderr so that it's captured for BOINC

# Ensure absolute paths
FROM=$(readlink -f $1)
INTO=$(readlink -f $2)

HASHFILE=$INTO/$(basename $FROM).sha256
EXTRACTED_NAME=$INTO/killerbeez-Linux

# Ensure only one copy of this script runs at a time
[ "${FLOCKER}" != "$0" ] && exec env FLOCKER="$0" flock -en "$0" "$0" "$@" || :

if [[ -e "$HASHFILE" ]]; then
  sha256sum -c "$HASHFILE"
  if [[ $? -eq 0 ]]; then
    echo >&2 "Already have a build of this version of Killerbeez, skipping"
    exit 0
  fi
fi

set -e

rm -rf $EXTRACTED_NAME
cd $INTO
unzip $FROM

sha256sum $FROM > $HASHFILE
