.PHONY: build check

## Rebuild install.sh from src/
build:
	./build.sh

## Syntax + lint + build-integrity gate (run before committing)
check:
	./tools/check.sh
