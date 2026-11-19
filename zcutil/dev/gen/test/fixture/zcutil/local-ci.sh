#!/bin/sh
step() { :; }
    step check-dev-tools 600 t_devtools
    step build-fixture 300 t_fixture
    step "$dyn" 1 t_x
