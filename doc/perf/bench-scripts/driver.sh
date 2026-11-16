#!/bin/sh
cd "$HOME/work/zc23-p0-bench" || exit 1
devbuild --wait --project z23 --class normal ./window.sh nowallet 900
echo "nowallet_rc=$?"
devbuild --wait --project z23 --class normal ./window.sh wallet 900
echo "wallet_rc=$?"
echo driver_done
