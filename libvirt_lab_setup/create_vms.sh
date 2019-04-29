#!/bin/bash

# Function to set variables based on VM names provided
set_variables () {
    echo "Set variables for VM $1"
    VM_NAME=$1
    DISK_NAME=$VM_NAME.qcow2
}

prompt_user () {
    echo ""
    PS3='Please select your distro: '
    options=("Ubuntu 16.04" "CentOS 7")
    select opt in "${options[@]}"
    do
        case $opt in
            "Ubuntu 16.04")
                echo "you chose Ubuntu 16.04"
                BASE_DISK=ubuntu16.04-base.qcow2
		echo ""
                break
                ;;
            "CentOS 7")
                echo "you chose CentOS 7"
                BASE_DISK=base-centos7.qcow2
		echo ""
                break
                ;;
            *) echo "invalid option $REPLY";;
        esac
    done
}

# Function to copy the base image to be used for the VMs
copy_image () {
    echo "Copy disk image for $VM_NAME"
    cp /var/lib/libvirt/images/$BASE_DISK /var/lib/libvirt/images/$DISK_NAME
}

# Function to create the VMs
create_vms () {
    echo "Create the VM $VM_NAME"
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
    prompt_user
    copy_image
    create_vms
    
    # Shift all the parameters down by one
    shift

done
