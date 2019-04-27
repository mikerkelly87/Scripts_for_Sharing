#/bin/bash

VM_NAME=ubuntu1
IP=$(virsh domifaddr $VM_NAME | grep ipv4 | awk '{print $4}' | cut -d'/' -f1)
LAN_IP=$(ssh $IP "ip a | grep 10.0.0" | awk '{print $2}' | cut -d'/' -f1)
echo ""
echo "The INTERNAL IP is $IP"
echo "The LAN IP is $LAN_IP"
echo ""

