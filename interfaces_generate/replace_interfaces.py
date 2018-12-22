#!/usr/local/bin/python

######################
# Author: Mike Kelly #
######################

import yaml
from shutil import copyfile
import fileinput

# create interfaces object
with open("interface-list.yml", 'r') as ymlfile:
    interfaces = yaml.load(ymlfile)

# create addresses object
with open("addresses.yml", 'r') as ymlfile:
    addresses = yaml.load(ymlfile)

print("")
print("List of Interfaces")

# print interfaces (for testing)
for i in interfaces:
	print(i)

print("")

# copy interfaces file template for each server provided in addresses.yml
for i in addresses:
	print("Copying File for "+i)
	copyfile("interfaces.txt", i+"interfaces.txt")

print("")

# print all the interfaces (for testing)
for i in addresses:
	print("")
	print(i)
	for n in interfaces:
            print(n,addresses[i][n])

print("")

print("Replaceing IP Addresses")

# Where the magic happens
for i in addresses:
	print("Setting IPs in file for",i)
	for n in interfaces:
            for line in fileinput.FileInput(i+"interfaces.txt",inplace=1):
                line = line.replace(n,addresses[i][n])
                print line,