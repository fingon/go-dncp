#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2025 Markus Stenberg
#
# Created:       Sun Apr 13 08:23:25 2025 mstenber
# Last modified: Sun Apr 13 08:32:30 2025 mstenber
# Edit time:     2 min
#
#

GO_TEST_TARGET=./...

.PHONY: test
test:
	go test $(GO_TEST_TARGET)


.PHONY: references
references:
	rsync -a ~/share/1/rfcs/rfc{6206,7787}.txt reference
