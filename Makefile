# Sliver Implant Framework
# Copyright (C) 2022  Bishop Fox

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

GO ?= go
CGO_ENABLED ?= 0

GO_VERSION = $(shell $(GO) version)
GO_MAJOR_VERSION = $(shell $(GO) version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f1)
GO_MINOR_VERSION = $(shell $(GO) version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f2)
MIN_SUPPORTED_GO_MAJOR_VERSION = 1
MIN_SUPPORTED_GO_MINOR_VERSION = 18
GO_VERSION_VALIDATION_ERR_MSG = Golang version is not supported, please update to at least $(MIN_SUPPORTED_GO_MAJOR_VERSION).$(MIN_SUPPORTED_GO_MINOR_VERSION)

VERSION_HEADER ?= 1
API_PKG = github.com/sliverarmory/external-armory/api
LDFLAGS = "-s -w -X $(API_PKG).VersionHeader=$(VERSION_HEADER)"


.PHONY: external-armory
external-armory:
	$(GO) build -o external-armory -trimpath -ldflags $(LDFLAGS) .

.PHONY: release
release:
	mkdir -p ./release
	GOOS=linux GOARCH=amd64 $(GO) build -o ./release/external-armory_linux -trimpath -ldflags $(LDFLAGS) .
	GOOS=linux GOARCH=arm64 $(GO) build -o ./release/external-armory_linux-arm64 -trimpath -ldflags $(LDFLAGS) .
	GOOS=darwin GOARCH=amd64 $(GO) build -o ./release/external-armory_macos -trimpath -ldflags $(LDFLAGS) .
	GOOS=darwin GOARCH=arm64 $(GO) build -o ./release/external-armory_macos-arm64 -trimpath -ldflags $(LDFLAGS) .
	GOOS=windows GOARCH=amd64 $(GO) build -o ./release/external-armory_windows.exe -trimpath -ldflags $(LDFLAGS) .

clean:
	rm -f ./external-armory
	rm -rf ./release

validate-go-version:
	@if [ $(GO_MAJOR_VERSION) -gt $(MIN_SUPPORTED_GO_MAJOR_VERSION) ]; then \
		exit 0 ;\
	elif [ $(GO_MAJOR_VERSION) -lt $(MIN_SUPPORTED_GO_MAJOR_VERSION) ]; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	elif [ $(GO_MINOR_VERSION) -lt $(MIN_SUPPORTED_GO_MINOR_VERSION) ] ; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	fi