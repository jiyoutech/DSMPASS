.PHONY: test go-test frontend-install build-frontend docs-test package-dsm package-spk clean

test:
	scripts/test.sh all

go-test:
	scripts/test.sh go

frontend-install:
	cd frontend && npm ci

build-frontend:
	scripts/test.sh frontend

docs-test:
	scripts/test.sh docs

package-dsm:
	cd go && scripts/dsm/package-dsm.sh

package-spk:
	cd go && scripts/dsm/package-spk.sh

clean:
	rm -rf frontend/dist go/dist go/.gocache
