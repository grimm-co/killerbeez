.PHONY=all clean docs

all: docs

docs:
	# Defer to the Makefile in the docs directory
	make -C docs
