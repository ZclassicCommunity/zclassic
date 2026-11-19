#!/bin/sh
exec "$(dirname "$1")/zcl-review-fixtures" "$1" "$(dirname "$0")/golden"
