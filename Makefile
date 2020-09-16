.PHONY: test clean qtest deploy dist
APP_VERSION:=$(shell cat VERSION | head -1)
GIT_COMMIT:=$(shell git describe --dirty --always)
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD -- | head -1)
BUILD_USER:=$(shell kongseokhwan)
BUILD_DATE:=$(shell date +"%Y-%m-%d")
BINARY:=helios-k8s-agent
VERBOSE:=-v
PROJECT=github.com/kongseokhwan/helios-k8s-agent.git
PKG_DIR=pkg/helios-k8s-agent

all:
	@echo "Version: $(APP_VERSION), Branch: $(GIT_BRANCH), Revision: $(GIT_COMMIT)"
	@echo "Build on $(BUILD_DATE) by $(BUILD_USER)"
	@mkdir -p bin/
	@rm -rf ./bin/*
	@CGO_ENABLED=0 go build -o ./bin/$(BINARY) $(VERBOSE) \
		-ldflags="-w -s \
		-X github.com/prometheus/common/version.Version=$(APP_VERSION) \
		-X github.com/prometheus/common/version.Revision=$(GIT_COMMIT) \
		-X github.com/prometheus/common/version.Branch=$(GIT_BRANCH) \
		-X github.com/prometheus/common/version.BuildUser=$(BUILD_USER) \
		-X github.com/prometheus/common/version.BuildDate=$(BUILD_DATE) \
		-X $(PROJECT)/$(PKG_DIR).appName=$(BINARY) \
		-X $(PROJECT)/$(PKG_DIR).appVersion=$(APP_VERSION) \
		-X $(PROJECT)/$(PKG_DIR).gitBranch=$(GIT_BRANCH) \
		-X $(PROJECT)/$(PKG_DIR).gitCommit=$(GIT_COMMIT) \
		-X $(PROJECT)/$(PKG_DIR).buildUser=$(BUILD_USER) \
		-X $(PROJECT)/$(PKG_DIR).buildDate=$(BUILD_DATE)" \
		-gcflags="all=-trimpath=$(GOPATH)/src" \
		-asmflags="all=-trimpath $(GOPATH)/src" \
		./cmd/helios-k8s-agent/*.go
	@echo "Done!"

test: all
	@go test -v ./$(PKG_DIR)/*.go
	@echo "PASS: core tests"
	@echo "OK: all tests passed!"

clean:
	@rm -rf bin/
	@rm -rf dist/
	@echo "OK: clean up completed"

deploy:
	@sudo rm -rf /usr/sbin/$(BINARY)
	@sudo cp ./bin/$(BINARY) /usr/sbin/$(BINARY)

qtest:
	@./bin/$(BINARY) -version

dist: all
	@mkdir -p ./dist
	@rm -rf ./dist/*
	@mkdir -p ./dist/$(BINARY)-$(APP_VERSION).linux-amd64
	@cp ./bin/$(BINARY) ./dist/$(BINARY)-$(APP_VERSION).linux-amd64/
	@cp ./README.md ./dist/$(BINARY)-$(APP_VERSION).linux-amd64/
	@cp LICENSE ./dist/$(BINARY)-$(APP_VERSION).linux-amd64/
	@cp assets/systemd/add_service.sh ./dist/$(BINARY)-$(APP_VERSION).linux-amd64/install.sh
	@chmod +x ./dist/$(BINARY)-$(APP_VERSION).linux-amd64/*.sh
	@cd ./dist/ && tar -cvzf ./$(BINARY)-$(APP_VERSION).linux-amd64.tar.gz ./$(BINARY)-$(APP_VERSION).linux-amd64
