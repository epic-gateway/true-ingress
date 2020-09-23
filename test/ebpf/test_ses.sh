#!/bin/bash
# usage: $0 [-v|-V]

set -Eeo pipefail

# parse args
while getopts "vV" opt; do
    case "$opt" in
    v)  VERBOSE=1
        shift
        ;;
    V)  ARG="-v"
        VERBOSE=1
        shift
        ;;
    esac
done

RETURN=0

TESTS=" \
test_ses_2gw_01.sh \
test_ses_2gw_02.sh"

a=($TESTS)
for (( i=0; i<${#a[@]}; i++ ))
do
    echo "==========================================="
    echo -e "[$((i+1))/${#a[@]}]\t${a[i]}"

    if [ ! -f "${a[i]}" ] ; then
        echo -e "\e[31mDoes not exist\e[0m"
        continue
    fi

    if [ "${VERBOSE}" ]; then
        echo "==========================================="
        ./${a[i]} ${ARG}
    else
        #./${a[i]} | grep -E "PASS|FAIL"
        if [ "$(./${a[i]} | grep 'FAIL')" ] ; then
            echo -e "\e[31mFAILED\e[0m"
            RETURN=1
        else
            echo -e "\e[32mPASS\e[0m"
        fi
    fi
done

exit ${RETURN}
