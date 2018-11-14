#!/usr/local/bin/python

import yaml
from shutil import copyfile
import fileinput

with open("addresses.yml", 'r') as ymlfile:
    addresses = yaml.load(ymlfile)

for i in addresses:
	print(i)
	print("br-host")
	print(addresses[i]['br_host'])
	print("br-mgmt")
	print(addresses[i]['br_mgmt'])
	print("br-storage")
	print(addresses[i]['br_storage'])
	print("br-vxlan")
	print(addresses[i]['br_vxlan'])
	print("")

for i in addresses:
	print("Copying File for "+i)
	copyfile("interfaces.txt", i+"interfaces.txt")

print("")

print("Replacing IP Addressess")

for i in addresses:
    for line in fileinput.FileInput(i+"interfaces.txt",inplace=1):
        line = line.replace("br_host",addresses[i]['br_host'])
        print line,
    else:
    	print
    for line in fileinput.FileInput(i+"interfaces.txt",inplace=1):
        line = line.replace("br_mgmt",addresses[i]['br_mgmt'])
        print line,
    else:
    	print
    for line in fileinput.FileInput(i+"interfaces.txt",inplace=1):
        line = line.replace("br_storage",addresses[i]['br_storage'])
        print line,
    else:
    	print
    for line in fileinput.FileInput(i+"interfaces.txt",inplace=1):
        line = line.replace("br_vxlan",addresses[i]['br_vxlan'])
        print line,
    else:
    	print
