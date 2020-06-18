#!/bin/bash

# link detection script

# Ask the user if they have already run switch_tool
echo ""
read -p "Have you already enabled LLDP with switch_tool.py for this server? (y/n)" choice1
case $choice1 in
  y|Y ) echo "";;
  n|N ) echo "Please enable LLDP with switch_tool.py before running this script" && exit 1;;
  * ) echo "Please answer 'y' for yes or 'n' for no" && exit 1;;
esac

# Ask the user if they would like to first make a backup of the interfaces file
read -p "Would you like to take a backup of /etc/network/interfaces first? (y/n)" choice2
case $choice2 in
  y|Y ) cp /etc/network/interfaces /etc/network/interfaces_$(date +"%Y_%m_%d_%I_%M_%p") && echo "Backup Created";;
  n|N ) echo "Continuing Script" && exit 1;;
  * ) echo "Please answer 'y' for yes or 'n' for no" && exit 1;;
esac


# Gather a list of all interfaces
ALL_PORTS=$(cat /proc/net/dev | awk '{print $1}' | grep : | cut -d: -f1 | grep -v lo)

# Add a manual line to /etc/network/interfaces for any interface not already in there
for i in $ALL_PORTS
do
  grep $i /etc/network/interfaces &> /dev/null
  if [ $? != 0 ]
  then
    echo "" >> /etc/network/interfaces
    echo "auto $i" >> /etc/network/interfaces
    echo "iface $i inet manual" >> /etc/network/interfaces
    ifup $i
  fi
done

# Check which interfaces have a physical link
for i in $ALL_PORTS
do
  echo "$i"
  ethtool $i | grep -i 'link detected'
  ip link set dev ${i} up
  LLDP_INFO=$(timeout 60s tcpdump -nnvi ${i} -s 1500 -c 1 'ether[12:2] == 0x88cc' 2>/dev/null | awk '/System Name TLV|Subtype Interface Name|PVID/')
  SWITCH=$(echo "${LLDP_INFO}" | awk '/System Name TLV/ {print $NF}' | sed 's@\..*@@g' | tr '[:lower:]' '[:upper:]')
  PORT=$(echo "${LLDP_INFO}" | awk '/Subtype Interface Name/ {print $NF}' | cut -c9-)
  VLAN=$(echo "${LLDP_INFO}" | awk '/PVID/ {print $NF}')
  if [[ -z ${VLAN} ]]
  then
    VLAN="Not found"
  fi
  echo -e "${SWITCH}[${PORT}]\t($RS_SERVER-${i})\tCurrent VLAN: ${VLAN}"
done
