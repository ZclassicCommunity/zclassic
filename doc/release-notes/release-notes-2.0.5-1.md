Notable changes
===============

Fix signrawtransaction on mainnet
---------------------------------
Signrawtransaction was failing because APPROX_RELEASE_HEIGHT and Bubbles activation height were same.

Fix build error on mac os
-------------------------
Patched zcbenchmarks.cpp

Changelog
=========
Reduced the APPROX_RELEASE_HEIGHT to 582000 so that it is lower than the Bubbles activation height.
Patched zcbenchmarks.cpp to fix build error on mac os.
