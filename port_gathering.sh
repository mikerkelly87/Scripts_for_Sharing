#!/bin/bash

interfaces=$(ip a | grep ^[0-9] | awk '{print $2}' | cut -d: -f1 | grep -v lo)

echo ""
echo "Interface List:"
echo $interfaces
echo ""

for i in $interfaces
do
    echo $i && ethtool $i | grep 'Link detected'
    echo ""
    if [ $(ethtool $i | grep 'Link detected' | awk '{print $3}') = "yes" ]; then
      echo "There was a link Detected for $i"
      echo ""
      echo "Gathering port information for $i"
      echo ""
      tcpdump -Z root -nnvi $i -s 1500 -c 1 '(ether[12:2]=0x88cc or ether[20:2]=0x2000)'
    else
      echo "There was not a link Detected for $i"
      echo ""
      echo "Not gathering port information for $i"
    fi
done
