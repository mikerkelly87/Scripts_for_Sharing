#!/bin/bash

VM_NAME=ubuntu1
DISK_NAME=$VM_NAME.qcow2

virsh destroy $VM_NAME
virsh undefine $VM_NAME

rm /var/lib/libvirt/images/$DISK_NAME

