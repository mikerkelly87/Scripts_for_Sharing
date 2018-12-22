#! /usr/local/bin/python3

#############################################################################
# Make sure you run 'pip3 install ipaddress' on the machine you run this on #
#############################################################################

# imort python ipaddress library
from ipaddress import *

# just a blank line to make things look cleaner
print()

# ask the user if they would like to supply the subnet mask or cidr
print("Type in 1 and press Enter if you would like to convert a CIDR to a subnet mask")
print("Ex: convert from /24 to 255.255.255.0")
print()
print("Type in 2 and press Enter if you would like to convert a subnet mask to a CIDR")
print("Ex: convert from 255.255.255.0 to /24")

# just a blank line to make things look cleaner
print()

# take the input from the user
choice = input()

# just a blank line to make things look cleaner
print()

# if the user chooses 1
if choice == '1':
    print('please type in the CIDR and press Enter Ex: /24')
    # take the user's CIDR input
    cidr = input()
    # have to convert it to a full address, 10.0.0.0/x in this case
    converted_cidr = IPv4Network("10.0.0.0" + cidr)
    print("")
    print("The subnet mask is:")
    # print the netmask of the provided cidr
    print(converted_cidr.netmask)
    print("")

# if the user chooses 2
elif choice == '2':
    print('please type in the subnet mask and press Enter Ex: 255.255.255.0')
    # take the user's netmask input
    netmask = input()
    # have to convert it to a full address, 10.0.0.0/x.x.x.x in this case
    converted_netmask = IPv4Network("10.0.0.0/" + netmask)
    print("")
    print("The CIDR is:")
    # print the cidr of the provided netmask
    print(converted_netmask.prefixlen)
    print("")

# the user didn't choose 1 or 2
else:
    print("you need to type in the number '1' or '2' and press Enter")
