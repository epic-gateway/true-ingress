#!/bin/bash
##############################
#usage: build.sh
echo "Install dependencies"
sudo apt-get install -y bc libssl-dev bison build-essential cmake flex git libedit-dev libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev llvm clang ethtool gdb curl
echo ""

KERNEL_VER=`uname -r | sed 's/-/ /g' | awk '{print $1}' | sed 's/\./ /g' | awk '{printf "v%s.%s", $1, $2}'`
echo "$KERNEL_VER"

case $KERNEL_VER in
"v5.9")
    SRC_TAG="v5.9-rc4"
#    LOCAL="v5.1"
    ;;
*)
    SRC_TAG=$KERNEL_VER
#    LOCAL=$KERNEL_VER
    ;;
esac

if [ -d linux ]; then
    echo "Kernel sources alredy downloaded"
else
    echo "Get kernel sources"
    git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
fi
echo ""

echo "Checkout running kernel version"
pushd linux
git fetch
echo "kernel version: $KERNEL_VER -> tag: $SRC_TAG"
git checkout $SRC_TAG
echo ""

echo "Install kernel headers"
make defconfig
sudo make headers_install
popd # linux
echo ""

#echo "Apply local changes"
#cp $LOCAL/* linux/samples/bpf/
#cp paio/* linux/samples/bpf/
#cd linux/samples/bpf/
#git apply Makefile.diff
##cd -
#echo ""

echo "Build kernel"
#cd linux
#sudo make -C samples/bpf/
sudo make
cd -
echo ""

echo "Build and install libbpf"
pushd linux/tools/lib/bpf
sudo make install_lib && sudo make install_headers
popd # linux/tools/lib/bpf
echo ""

echo "Create symbolic link to libbpf.so so ubuntu will find it"
sudo ln -sf /usr/local/lib64/libbpf.so   /usr/lib/libbpf.so
sudo ln -sf /usr/local/lib64/libbpf.so.0 /usr/lib/libbpf.so.0

# in newer kernels (5.3) if_xdp.h is not installed by make headers_install
# for some unkonwn reason, so install it manually
echo "Install if_xdp.h & bpf.h"
sudo cp linux/usr/include/linux/if_xdp.h /usr/include/linux/
sudo cp linux/usr/include/linux/bpf.h    /usr/include/linux/
echo ""
