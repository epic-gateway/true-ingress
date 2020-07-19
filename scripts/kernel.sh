#!/bin/bash
##############################
# install kernel version

echo "Download kernel packages"
case $1 in
"5.8")
    FOLDER="kernel.ubuntu.com/~kernel-ppa/mainline/v5.8-rc3/amd64"
    FILES="linux-headers-5.8.0-050800_5.8.0-050800.202006282330_all linux-headers-5.8.0-050800-generic_5.8.0-050800.202006282330_amd64 linux-image-unsigned-5.8.0-050800-generic_5.8.0-050800.202006282330_amd64 linux-modules-5.8.0-050800-generic_5.8.0-050800.202006282330_amd64"
    ;;
"5.7")
    FOLDER="kernel.ubuntu.com/~kernel-ppa/mainline/v5.7.6/amd64"
    FILES="linux-headers-5.7.6-050706_5.7.6-050706.202006241631_all linux-headers-5.7.6-050706-generic_5.7.6-050706.202006241631_amd64 linux-image-unsigned-5.7.6-050706-generic_5.7.6-050706.202006241631_amd64 linux-modules-5.7.6-050706-generic_5.7.6-050706.202006241631_amd64"
    ;;
"5.6")
    FOLDER="kernel.ubuntu.com/~kernel-ppa/mainline/v5.6.19/amd64"
    FILES="linux-headers-5.6.19-050619_5.6.19-050619.202006171132_all linux-headers-5.6.19-050619-generic_5.6.19-050619.202006171132_amd64 linux-image-unsigned-5.6.19-050619-generic_5.6.19-050619.202006171132_amd64 linux-modules-5.6.19-050619-generic_5.6.19-050619.202006171132_amd64"
    ;;
"5.5")
    FOLDER="kernel.ubuntu.com/~kernel-ppa/mainline/v5.5.19"
    FILES="linux-headers-5.5.19-050519_5.5.19-050519.202004210831_all linux-headers-5.5.19-050519-generic_5.5.19-050519.202004210831_amd64 linux-image-unsigned-5.5.19-050519-generic_5.5.19-050519.202004210831_amd64 linux-modules-5.5.19-050519-generic_5.5.19-050519.202004210831_amd64"
    ;;
"5.4")
    FOLDER="kernel.ubuntu.com/~kernel-ppa/mainline/v5.4.49/amd64"
    FILES="linux-headers-5.4.49-050449_5.4.49-050449.202006241630_all linux-headers-5.4.49-050449-generic_5.4.49-050449.202006241630_amd64 linux-image-unsigned-5.4.49-050449-generic_5.4.49-050449.202006241630_amd64 linux-modules-5.4.49-050449-generic_5.4.49-050449.202006241630_amd64"
    ;;
"5.3")
    FOLDER="kernel.ubuntu.com/~kernel-ppa/mainline/v5.3.18"
    FILES="linux-headers-5.3.18-050318_5.3.18-050318.201912181133_all linux-headers-5.3.18-050318-generic_5.3.18-050318.201912181133_amd64 linux-image-unsigned-5.3.18-050318-generic_5.3.18-050318.201912181133_amd64 linux-modules-5.3.18-050318-generic_5.3.18-050318.201912181133_amd64"
    ;;
"5.2")
    FOLDER="kernel.ubuntu.com/~kernel-ppa/mainline/v5.2.11"
    FILES="linux-headers-5.2.11-050211_5.2.11-050211.201908290731_all linux-headers-5.2.11-050211-generic_5.2.11-050211.201908290731_amd64 linux-image-unsigned-5.2.11-050211-generic_5.2.11-050211.201908290731_amd64 linux-modules-5.2.11-050211-generic_5.2.11-050211.201908290731_amd64"
    ;;
"5.1")
    FOLDER="kernel.ubuntu.com/~kernel-ppa/mainline/v5.1.21"
    FILES="linux-headers-5.1.21-050121_5.1.21-050121.201907280731_all linux-headers-5.1.21-050121-generic_5.1.21-050121.201907280731_amd64 linux-image-unsigned-5.1.21-050121-generic_5.1.21-050121.201907280731_amd64 linux-modules-5.1.21-050121-generic_5.1.21-050121.201907280731_amd64"
    ;;
"5.0") # ???
    FOLDER="kernel.ubuntu.com/~kernel-ppa/mainline/v5.0.21"
    FILES="linux-headers-5.0.21-050021_5.0.21-050021.201906040731_all linux-headers-5.0.21-050021-generic_5.0.21-050021.201906040731_amd64 linux-image-unsigned-5.0.21-050021-generic_5.0.21-050021.201906040731_amd64 linux-modules-5.0.21-050021-generic_5.0.21-050021.201906040731_amd64"
    ;;
*)
    exit 1
    ;;
esac

mkdir -p /tmp/kernel_$1
cd /tmp/kernel_$1

for FILE in ${FILES}
do
    wget https://${FOLDER}/${FILE}.deb
    RES="$?"
    echo "RES=${RES}"
    if [ ! "${RES}"=="0" ] ; then
        exit 1
    fi
done

echo "Install new kernel"
sudo dpkg -i *.deb

#rm -rf /tmp/kernel

echo "Done. Reboot required"
#reboot
