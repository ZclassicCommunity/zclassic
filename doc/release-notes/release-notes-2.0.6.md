Notable changes
===============

This release fixes the security issues described at
https://z.cash/support/security/announcements/security-announcement-2019-09-24/
https://z.cash/support/security/announcements/security-announcement-2019-11-08/

Shrinking of debug.log files is temporarily disabled
----------------------------------------------------

In previous versions, `zclassicd` would shrink the `debug.log` file to 200 KB on
startup if it was larger than 10 MB. This behaviour, and the `-shrinkdebugfile`
option that controlled it, has been disabled.

Changelog
=========

Disable -shrinkdebugfile command
Fix of CVE-2017-18350

