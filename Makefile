BIN_DIR := bin
BINARY  := echtool

# Tool names symlinked to the echtool binary. Each symlink invokes echtool as a
# multi-call binary, dispatching to its matching subcommand (see cmd/echtool).
TOOLS := greasy dech echconn echtest

.PHONY: all build symlinks clean test deps licenses test-domains

all: build symlinks

# go build already resolves and downloads missing modules automatically; this
# target only pre-fetches them explicitly (handy for CI or offline builds).
deps:
	go mod download

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(BINARY) ./cmd/echtool

# Create a relative symlink per tool so the bin directory stays relocatable.
symlinks: build
	@for tool in $(TOOLS); do \
		ln -sf $(BINARY) $(BIN_DIR)/$$tool; \
		echo "$(BIN_DIR)/$$tool -> $(BINARY)"; \
	done

test:
	go test ./...

# Crash/robustness smoke test: sample real domains from a fresh Tranco list
# and fuzz greasy and conn (over TCP and QUIC) against each one, feeding any
# ECHConfigList either emits through dech. This does not check that ECH is
# actually accepted anywhere (most sampled domains won't support it, and
# conn's config is a fixed GREASE-style config that isn't valid for any real
# server) -- it only catches greasy/conn/dech misbehaving (crashing, or
# emitting a config dech can't decode) on real-world inputs. See
# scripts/domain-smoke-test.sh for exactly what counts as a failure.
TRANCO_URL      := https://tranco-list.eu/top-1m.csv.zip
DOMAIN_SAMPLE   := 1000
DOMAIN_PARALLEL := 25
# Fixed GREASE ECHConfigList (github.com/jmuecke/echtools/pkg/ech.Grease),
# reused as-is for every domain so conn always offers the same static config.
STATIC_ECH_CONFIG := AHD+DQBsTAAgACBsJVLEClmWycMiOo12cYgUDwClMY01yypj09rTMQvpTwAkAAEAAQABAAIAAQADAAIAAQACAAIAAgADAAMAAQADAAIAAwADAB1zdGF0aWMtZWNoLXNtb2tlLXRlc3QuaW52YWxpZAAA

test-domains: symlinks
	@mkdir -p $(BIN_DIR)
	@echo "Fetching Tranco list from $(TRANCO_URL)..."
	@curl -fsSL $(TRANCO_URL) -o $(BIN_DIR)/tranco.csv.zip
	@unzip -p $(BIN_DIR)/tranco.csv.zip | cut -d, -f2 | shuf -n $(DOMAIN_SAMPLE) > $(BIN_DIR)/tranco-sample.txt
	@echo "Probing $(DOMAIN_SAMPLE) sampled domains ($(DOMAIN_PARALLEL) in parallel)..."
	@rm -f $(BIN_DIR)/tranco-results.log
	@xargs -a $(BIN_DIR)/tranco-sample.txt -P $(DOMAIN_PARALLEL) -I{} \
		./scripts/domain-smoke-test.sh $(BIN_DIR) "$(STATIC_ECH_CONFIG)" {} \
		>> $(BIN_DIR)/tranco-results.log 2>&1 || true
	@processed=$$(grep -c '^DONE ' $(BIN_DIR)/tranco-results.log || true); \
	failures=$$(grep -c '^CRASH\|^DECH-FAIL' $(BIN_DIR)/tranco-results.log || true); \
	echo "Processed $$processed/$(DOMAIN_SAMPLE) domains, $$failures failure(s)"; \
	if [ "$$failures" -gt 0 ]; then \
		grep '^CRASH\|^DECH-FAIL' $(BIN_DIR)/tranco-results.log; \
		exit 1; \
	fi

clean:
	rm -rf $(BIN_DIR)

# Dependencies actually compiled into echtool (per `go list -deps ./cmd/echtool`),
# kept in sync by hand: google/go-licenses can't generate this automatically
# right now, it treats Go stdlib packages as fatal errors on Go 1.24+
# (https://github.com/google/go-licenses/issues/128, still open).
LICENSE_DEPS := \
	github.com/OmarTariq612/goech@v0.0.1 \
	github.com/cloudflare/circl@v1.3.3 \
	github.com/sirupsen/logrus@v1.9.4 \
	github.com/spf13/cobra@v1.10.2 \
	github.com/spf13/pflag@v1.0.10 \
	github.com/inconshreveable/mousetrap@v1.1.0 \
	golang.org/x/crypto@v0.51.0 \
	golang.org/x/sys@v0.45.0

licenses:
	@rm -rf THIRD_PARTY_LICENSES
	@mkdir -p THIRD_PARTY_LICENSES
	@for dep in $(LICENSE_DEPS); do \
		mod=$${dep%@*}; ver=$${dep#*@}; \
		esc=$$(echo "$$mod" | sed 's/\([A-Z]\)/!\L\1/g'); \
		src="$$(go env GOMODCACHE)/$$esc@$$ver"; \
		lic=$$(ls "$$src" | grep -iE '^licen|^copying' | head -1); \
		out="THIRD_PARTY_LICENSES/$$(echo "$$mod" | tr '/' '_')-LICENSE"; \
		cp "$$src/$$lic" "$$out"; \
	done
	@cp third_party/golang.org/x/net/LICENSE THIRD_PARTY_LICENSES/golang.org_x_net-LICENSE
