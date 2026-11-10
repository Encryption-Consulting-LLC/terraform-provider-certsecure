#!/usr/bin/env bash
# Fails if any Go file is not gofmt -s formatted.

echo "==> Checking that code complies with gofmt requirements..."
gofmt_files=$(gofmt -s -l $(find . -name '*.go' -not -path './vendor/*'))
if [[ -n ${gofmt_files} ]]; then
    echo 'gofmt needs running on the following files:'
    echo "${gofmt_files}"
    echo "You can use the command: \`make fmt\` to reformat code."
    exit 1
fi

exit 0
