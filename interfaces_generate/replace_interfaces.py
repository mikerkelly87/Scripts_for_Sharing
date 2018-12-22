#!/usr/local/bin/python

import yaml
from shutil import copyfile
import fileinput

with open("addresses.yml", 'r') as ymlfile:
    addresses = yaml.load(ymlfile)

for i in addresses:
	print(i)
	print("br-mgmt")
	print(addresses[i]['br_mgmt_'])
	print("br-storage")
	print(addresses[i]['br_storage_'])
	print("br-storageprod")
	print(addresses[i]['br_storageprod_'])
	print("br-vlan")
	print(addresses[i]['br_vlan_'])
	print("br-vxlan")
	print(addresses[i]['br_vxlan_'])
	print("br-swift")
	print(addresses[i]['br_swift_'])
	print("")

for i in addresses:
	print("Copying File for "+i)
	copyfile("interfaces.txt", i+"interfaces.txt")

print("")

print("Replacing IP Addressess")

for i in addresses:
    for line in fileinput.FileInput(i+"interfaces.txt",inplace=1):
        line = line.replace("br_mgmt_",addresses[i]['br_mgmt_'])
        print line,
    else:
    	print
    for line in fileinput.FileInput(i+"interfaces.txt",inplace=1):
        line = line.replace("br_storage_",addresses[i]['br_storage_'])
        print line,
    else:
    	print
    for line in fileinput.FileInput(i+"interfaces.txt",inplace=1):
        line = line.replace("br_storageprod_",addresses[i]['br_storageprod_'])
        print line,
    else:
    	print
    for line in fileinput.FileInput(i+"interfaces.txt",inplace=1):
        line = line.replace("br_vlan_",addresses[i]['br_vlan_'])
        print line,
    else:
    	print
    for line in fileinput.FileInput(i+"interfaces.txt",inplace=1):
        line = line.replace("br_vxlan_",addresses[i]['br_vxlan_'])
        print line,
    else:
    	print
    for line in fileinput.FileInput(i+"interfaces.txt",inplace=1):
        line = line.replace("br_swift_",addresses[i]['br_swift_'])
        print line,
    else:
    	print