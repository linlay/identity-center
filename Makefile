VERSION ?= $(shell cat VERSION 2>/dev/null)
ARCH ?= $(shell uname -m | sed 's/^x86_64$$/amd64/' | sed 's/^aarch64$$/arm64/' | sed 's/^arm64$$/arm64/' | sed 's/^amd64$$/amd64/')

.PHONY: backend-build backend-test frontend-build docker-build docker-up docker-down size-check release release-program release-image clean

backend-build:
	cd backend && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w -buildid=' -o app ./cmd/server

backend-test:
	cd backend && go test ./...

frontend-build:
	cd frontend && npm ci && npm run build

docker-build:
	docker compose build

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

size-check:
	@echo "backend image size bytes:" && docker image inspect identity-center-backend --format '{{.Size}}'
	@echo "frontend image size bytes:" && docker image inspect identity-center-frontend --format '{{.Size}}'

release:
	$(MAKE) release-program VERSION=$(VERSION) ARCH=$(ARCH) PROGRAM_TARGETS="$(PROGRAM_TARGETS)" PROGRAM_TARGET_MATRIX="$(PROGRAM_TARGET_MATRIX)"

release-program:
	VERSION=$(VERSION) ARCH=$(ARCH) PROGRAM_TARGETS="$(PROGRAM_TARGETS)" PROGRAM_TARGET_MATRIX="$(PROGRAM_TARGET_MATRIX)" bash scripts/release-program.sh

release-image:
	VERSION=$(VERSION) ARCH=$(ARCH) bash scripts/release-image.sh

clean:
	rm -f backend/app
