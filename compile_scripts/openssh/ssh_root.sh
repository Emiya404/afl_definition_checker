#!/bin/bash
export LD_LIBRARY_PATH="/home/ubuntu/experiments/targets/openssl_for_ssh_install/lib"
rm -rf ~/.ssh
./sshd -d -e -p 10086 -r -f sshd_config & sleep 5
sshpass -p "ubuntu" ssh -oStrictHostKeyChecking=no ubuntu@127.0.0.1 -p 10086 "exit"