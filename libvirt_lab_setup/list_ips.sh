#!/bin/bash

for i in $(virsh list | grep -v Name | awk '{print $2}')
do
    VM_NAME=$i
    LAN_IP=$(ssh $IP "ip a | grep 10.0.0" | awk '{print $2}' | cut -d'/' -f1)
    IP=$(virsh domifaddr $i | grep ipv4 | awk '{print $4}' | cut -d'/' -f1)
    LAN_IP=$(ssh -o StrictHostKeyChecking=no $IP "ip a | grep 10.0.0" | awk '{print $2}' | cut -d'/' -f1)
    echo ""
    echo "Here are the IPs for $i"
    echo "Internal IP: $IP"
    echo "LAN IP: $LAN_IP"
    echo ""
done
