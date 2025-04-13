#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2025 Markus Stenberg
#
# Created:       Sun Apr 13 08:23:25 2025 mstenber
# Last modified: Sun Apr 13 08:52:04 2025 mstenber
# Edit time:     2 min
#
#

GO_TEST_TARGET=./...

.PHONY: ci
ci: lint test

.PHONY: test
test:
	go test $(GO_TEST_TARGET)

# See https://golangci-lint.run/usage/linters/
.PHONY: lint
lint:
	golangci-lint run --fix  # Externally installed, e.g. brew


.PHONY: references
references:
	rsync -a ~/share/1/rfcs/rfc{6206,7787}.txt reference
