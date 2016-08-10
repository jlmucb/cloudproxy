#

#
# This shell script builds the C++ support libraries,
# copies the library files to $LIBDEST and
# copies the include files to $INCLUDEDEST
#

#ifndef SRC_DIR
export SRC_DIR=$HOME/src/github.com/jlmucb/cloudproxy
#endif
#ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
#endif
#ifndef LOCAL_LIB
export LOCAL_LIB=/usr/local/lib
#endif

export LIBDEST=/Domains
export INCLUDEDEST=$LIBDEST/include

export BINPATH=$HOME/bin
export S=$SRC_DIR/src
export O=$LIBDEST/tao_clib

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

if [[ -e $INCLUDEDEST/chromium ]]
then
  echo "$INCLUDEDEST/chromium exists"
else
  mkdir $INCLUDEDEST/chromium
fi

if [[ -e $INCLUDEDEST/chromium/base ]]
then
  echo "$INCLUDEDEST/chromium/base exists"
else
  mkdir $INCLUDEDEST/chromium/base
fi

$BINPATH/genauth -ast_file $SRC_DIR/go/tao/auth/ast.go \
-binary_file $SRC_DIR/go/tao/auth/binary.go \
-header_file $S/auth.h -impl_file $S/auth.cc

# copy include files
cp $S/tao/*.h $INCLUDEDEST
cp $S/auth.h $INCLUDEDEST
cp $S/third_party/chromium/include/chromium/base/*.h $INCLUDEDEST/chromium/base
cp $S/third_party/modp/include/modp/*.h $INCLUDEDEST

# make each library
make -f standalone/amake.mak
make -f standalone/mmake.mak
#make -f standalone/cmake.mak
# make -f standalone/tmake.mak

