Notable changes
===============

Fix for CVE-2019-16930 and CVE-2019-17048
-----------------------------------------
Included the fix for "Linking Anonymous Transactions via Remote Side-Channel Attacks"

Relay: Any sequence of pushdatas in OP_RETURN outputs now allowed
-----------------------------------------------------------------
Previously OP_RETURN outputs with a payload were only relayed and mined if they had a single pushdata. This restriction has been lifted to allow any combination of data pushes and numeric constant opcodes (OP_1 to OP_16) after the OP_RETURN. The limit on OP_RETURN output size is now applied to the entire serialized scriptPubKey, 223 bytes by default. (the new 220 bytes default plus three bytes overhead)

Changelog
=========
Fixes a Windows-specific compile bug
Increase the default setting for nMaxDatacarrierBytes to 223 bytes
Accept any sequence of PUSHDATAs in OP_RETURN outputs
Ignore exceptions when deserializing note plaintexts
Move mempool SyncWithWallets call into its own thread
