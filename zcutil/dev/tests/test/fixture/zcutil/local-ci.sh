#!/bin/sh
    step unit-a 600 t_a
    step dry-x 60 t_dry
# the scripts below run from the steps
    sh qa/rpc-tests/y.sh
    sh qa/rpc-tests/w.sh
    sh qa/rpc-tests/p.sh
