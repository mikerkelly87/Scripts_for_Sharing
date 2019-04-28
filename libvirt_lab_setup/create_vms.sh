#!/bin/bash

# Function to set variables based on VM names provided
set_variables () {
    echo "Set variables for VM $1"
    VM_NAME=$1
    DISK_NAME=$VM_NAME.qcow2
}

# Function to copy the base image to be used for the VMs
copy_image () {
    echo "Copy disk image for $VM_NAME"
    #cp /var/lib/libvirt/images/ubuntu18.04-base.qcow2 /var/lib/libvirt/images/$DISK_NAME
    cp /var/lib/libvirt/images/ubuntu16.04-base.qcow2 /var/lib/libvirt/images/$DISK_NAME
}

# Function to create the VMs
create_vms () {
    echo "Create the VM $VM_NAME"
    #virt-install --name "$VM_NAME" --memory 2048 --vcpus 2 --import --disk "/var/lib/libvirt/images/$DISK_NAME" --network default --network type=direct,source=enp60s0,source_mode=bridge,model=virtio --os-variant=ubuntu18.04 --noautoconsole
    virt-install --name "$VM_NAME" --memory 2048 --vcpus 2 --import --disk "/var/lib/libvirt/images/$DISK_NAME" --network default --network type=direct,source=enp60s0,source_mode=bridge,model=virtio --os-variant=ubuntu16.04 --noautoconsole
}

# Make sure the user who runs this script provides VM names
if [ "$1" = "" ]; then
	echo "Please run the script with a list of VM names. EX:"
	echo "./create_vms vm1 vm2 vm3"
fi

# Loop through all the VM names that were provided
while [ "$1" != "" ]; do

    set_variables $1
    copy_image
    create_vms
    
    # Shift all the parameters down by one
    shift

done
