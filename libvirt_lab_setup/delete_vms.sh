#!/bin/bash

# Function to set variables based on VM names provided
set_variables () {
    echo "Set variables for VM $1"
    VM_NAME=$1
    DISK_NAME=$VM_NAME.qcow2
}


stop_vms () {
    echo "Stop the VM $VM_NAME"
    virsh destroy $VM_NAME
}

delete_vms () {
    echo "Delete the VM $VM_NAME"
    virsh undefine $VM_NAME
}

delete_disks () {
    echo "Delete the disk for VM $VM_NAME"
    rm -f /var/lib/libvirt/images/$VM_NAME.qcow2
}

# Make sure the user who runs this script provides VM names
if [ "$1" = "" ]; then
	echo "Warning this script is destructive"
	echo "Please run the script with a list of VM names. EX:"
	echo "./delete_vms vm1 vm2 vm3"
fi

# Loop through all the VM names that were provided
while [ "$1" != "" ]; do

    set_variables $1
    stop_vms
    delete_vms
    delete_disks
    
    # Shift all the parameters down by one
    shift

done
