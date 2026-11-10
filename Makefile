BINARY := gitlab-mcp-plus
GO     := go

.PHONY: build install clean test check-schema smoke

build:
	$(GO) build -o $(BINARY) .

install: build
	@echo "Binary built at ./$(BINARY)"
	@echo "Add it to your Claude Code MCP settings or copy it to a directory in your PATH."

clean:
	rm -f $(BINARY)

test:
	$(GO) test ./...

check-schema:
	$(GO) test -tags live -run TestLiveSchema -count=1 ./...

smoke:
	$(GO) test -tags smoke -run TestSmoke -count=1 -v ./...
