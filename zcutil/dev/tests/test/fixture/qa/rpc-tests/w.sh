#!/bin/sh
# usage: w.sh --bin DIR --work DIR [--only N,N]
. ./w_scn?.sh
run_scn 1 "one" scn_one
run_scn 2 "two" scn_two
run_scn 11 "load" scn_load
