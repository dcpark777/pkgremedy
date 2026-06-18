# Usage: make scan | envfix | native | build BASE=... | clean
BASE    ?= your.registry/spark-base:latest
FILE    ?= environment.yml
PYTHON  ?= python3

.PHONY: help envfix scan native build clean version
help:
	@echo "make envfix  BASE=<img>   one command: build from base, run envfix, write environment.fixed.yml"
	@echo "make scan    BASE=<img>   build from base, scan, fail on fixable (CI gate)"
	@echo "make native               run natively against the active env (no docker)"
	@echo "make build   BASE=<img>   just build the scanner image"
	@echo "make version              print pkgremedy version"

envfix:
	./pkgremedy-run.sh --base $(BASE) --file $(FILE)

scan:
	./pkgremedy-run.sh --base $(BASE) --file $(FILE) -- scan --fail-on fixable

native:
	./pkgremedy.sh native -- plan --fail-on fixable

build:
	docker build --build-arg BASE_IMAGE=$(BASE) -t pkgremedy:latest .

version:
	@$(PYTHON) pkgremedy.py --version

clean:
	rm -rf __pycache__ .pkgremedy environment.fixed.yml
