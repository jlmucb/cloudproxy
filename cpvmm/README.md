CloudProxy VMM
--------------

The CloudProxy VMM is derived from a hypervisor called eVMM written at Intel and
released under the Apache 2.0 license. To build the current version of the code
using cmake and ninja, create a build directory out of tree, e.g., at
../cprelease, and run

    cd cprelease
    cmake -G Ninja ../cpvmm -DCMAKE_BUILD_TYPE=Release
    ninja

This generates the files bin/bootstrap.bin and bin/evmm.bin.
