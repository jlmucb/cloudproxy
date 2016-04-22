The protected_object library consists of a number of commonly used routines to maintain a key protection
hierarchy.  Key hierearchies are rooted in a master key (like the primary sealing key for a CloudProxy
Program).  

This library maintains an in memory (or serialized to storage protobuf) list of objects.
Objects represent things like files or keys.  All objects have universal names, object types,
validity periods, status, values and epochs.  Values are object dependent.  For keys, the value is the
key and parameters.  For files, the value may be the file contents or a pointer to a storage object.

The library also maintains a list of "protected objects" consisting of a protector name, epoch and type and
a protected object consisting of name, epoch and type as well a value for the protected object.  When the
protected object is a key, the value is the key object encrypted and integrity protected by the key of the
protector object.  When the protected object is a file, the value is (or points to) the file contents
encrypted and integrity protected with the protector key.

A chain of protected objects terminating, say, in a file object gives a recipie for decrypting an object
given the key at the top of a heierarchy.  For example, the top level program sealing key, may be the root
protector object, protecting a zone key which, in turn protects a file key which protects a file.

Library functions can construct a chain of such protected objects or find all descendent objects protected
directly or indirectly by a given object or all objects protecting, directly or indirectly by a given object.
This is useful when decrypting objects or adding or rotating keys.  The model is "active" objects can
encrypt or decrypt or be read or written, "retired" objects can decrypt or be read and "inactive" objects
can no longer be used.

