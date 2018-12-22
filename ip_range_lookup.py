#! /usr/local/bin/python3

#############################################################################
# Make sure you run 'pip3 install ipaddress' on the machine you run this on #
#############################################################################

# imort python ipaddress library
from ipaddress import *

# just a blank line to make things look cleaner
print()

# ask the user to put in the IP address with CIDR
print("Please type in the IP address with CIDR and press Enter Ex: 192.168.1.7/27 :")

# take the input from the user
ip_input = input()

# convert the input into an IPv4 object the ipaddress library will understand
ipnet = IPv4Network(ip_input, strict=False)

# create a list of the ip addresses in the range given
ip_list = list(ipnet)

# print the subnet the address is in
print(' ')
print('The subnet for this IP is:')
print(ipnet)
print(' ')

# print the usable IP range in the subnet
# by default printing this list would print the first and last
# which would be the network ID and the broadcast address of the range
# so we are printing the second IP and the second to last IP in the range
print('The usable IP Addresses in this range are:')
print(ip_list[1],"-",ip_list[-2])
