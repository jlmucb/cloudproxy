#

#
# This shell script builds the C++ support libraries, copies the library files to $LIBDEST and
# copies the include files to $INCLUDEDEST
#

#ifndef SRC_DIR
export SRC_DIR=$HOME
#endif
#ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
#endif
#ifndef LOCAL_LIB
export LOCAL_LIB=/usr/local/lib
#endif

export S= $(SRC_DIR)/src/github.com/jlmucb/cloudproxy/src
export O= $(OBJ_DIR)/tao_clib

export LIBDEST=/Domains
export INCLUDEDEST= $(S)/include

if [[ -e $INCLUDEDEST ]]
then
  echo "$INCLUDEDEST exists"
else
  mkdir $INCLUDEDEST
fi

if [[ -e $O ]]
then
  echo "$O exists"
else
  mkdir $O
fi

# copy include files
# cp ($S)/auth.h $(INCLUDEDEST)
# cp ($S)/third_party/include/*.h $(INCLUDEDEST)
# cp ($S)/tao/*.h $(INCLUDEDEST)
# cp ($S)/third_party/modp/include/*.h $(INCLUDEDEST)

# make each library
# make -f standalone/mmake.mak
# make -f standalone/cmake.mak
# make -f standalone/amake.mak
# make -f standalone/tmake.mak

