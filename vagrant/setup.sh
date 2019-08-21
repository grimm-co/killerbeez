#!/bin/bash
BRANCH="$1"

# Check out the code
git clone --recursive https://github.com/grimm-co/killerbeez

# Test a specific branch if necessary
if [[ "$BRANCH" != "" ]]; then
	cd killerbeez
	git checkout "$BRANCH"
	cd ..
fi

# build it & run some basic tests
./killerbeez/tests/smoke_test.sh
