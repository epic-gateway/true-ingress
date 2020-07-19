#!/bin/bash
# usage $0 [<gitlab-ssh-priate-key>]
#       <gitlab-ssh-priate-key> - ssh key for gitlab.com access (optional). If no ssh key provided, new keypair will be generated.

if [ "$1" ]; then   # use specific name
    if [ ! -f "$1" ]; then
        echo "KEY '$1' not found!"
        exit 1
    fi
    KEY=$1
else    # use default name
    KEY="id_ed25519"
fi

echo "============================="
echo "# Installing SSH key ${KEY} for gitlab.com"
echo "============================="

eval $(ssh-agent -s)

if [ ! -d ~/.ssh ]; then
    echo "### Creating ~/.ssh..."
    mkdir ~/.ssh
    chmod 700 ~/.ssh
else
    echo "### /.ssh already exists"
fi

# ssh key
CHECK=`ls ~/.ssh/${KEY}`
if [ ! "${CHECK}" ]; then
    CHECK=`ls ${KEY}`
    if [ "${CHECK}" ]; then
        echo "### Adding ${KEY} SSH key..."
        cp ${KEY} ~/.ssh/
        chmod 400 ~/.ssh/${KEY}

        # check
        ls -lt ~/.ssh/
    else
        echo "### Creating new ed25519 SSH keypair..."
        ssh-keygen -t ed25519 -C "acnodal@gitlab.com"
        #ssh-keygen -t rsa -b 2048 -C "acnodal@gitlab.com"

        # register public key
        echo "# Now copy your public key (${KEY}.pub) content to gitlab.com and then press <ENTER>"
        cat ~/.ssh/${KEY}.pub

        read
    fi

    ssh-add ${KEY}
else
    echo "### ${KEY} SSH key already exists"
fi

# test
echo "# test: ssh -T git@gitlab.com"
ssh -T git@gitlab.com
