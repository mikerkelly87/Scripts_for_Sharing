#!/bin/bash

# set variables
VM_NAME=ubuntu1
DISK_NAME=$VM_NAME.qcow2

# copy the base disk image
cp /var/lib/libvirt/images/ubuntu18.04-base.qcow2 /var/lib/libvirt/images/$DISK_NAME

# create vm
virt-install --name "$VM_NAME" --memory 2048 --vcpus 2 --import --disk "/var/lib/libvirt/images/$DISK_NAME" --network type=direct,source=enp60s0,source_mode=bridge,model=virtio --network default --noautoconsole

