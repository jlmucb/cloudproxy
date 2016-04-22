This library contains support functions to add, retract or rotate keys or objects.  Functions in this
library can be used to change object statuses, and add objects with new epoch both by creating new
protecting or protector objects and encrypting or reencrypting portions of the key hierarchy to accommodate
these changes.  It can also find the status of all objects by name and epoch, status, type or validity period.
For example, when a protector key corresponding to a new epoch it can change the status of the earlier epochs
of this key and reencrypt the protected objects protected by the previous key epoch.
Finally, it can roll back epoch changes.

