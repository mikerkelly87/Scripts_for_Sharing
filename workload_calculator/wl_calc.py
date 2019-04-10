#!/usr/local/bin/python3

# Define build Variables
builds = ["1) RPC-R Greenfield Custom (Storage)", "2) RPC-R Greenfield", "3) RPC-O Greenfield Custom (Storage)", \
"4) RPC-O Greenfield", "5) New Ceph Cluster", "6) Swift Node Addition", "7) RPC-O Custom (ie: CAS Cobbler) Compute Addition", \
"8) RPC-O Compute Addition", "9) RPC-O Ceph Node Addition", "10) RPC-R Ceph Node Addition", "11) RPC-R Compute Addition"]

# Define weights for builds
weights = [17, 15, 12, 10, 8, 6, 5, 4, 3, 2, 1]

# Calculate the base weight of a build
def base_weight_calc(w):
	global base_weight
	base_weight = float(w) * .95

# Ask for the number of nodes in the build
def prompt_nodes():
	global total_weight
	global node_count
	global node_value
	print("Type in the number of nodes and hit Enter :")
	print("")
	node_count = float(input())
	node_value = node_count * .05
	total_weight = base_weight + node_value
	print("The total weight for this build is", total_weight)
	print("")

# Do Maths
def calculate():
	base_weight_calc(weight)
	print("The base weight is", base_weight)
	prompt_nodes()

# main function
def main():
	global weight
	print("")
	print("Please make a selection from below and press Enter (1-11) :")
	print("")
	
	for x in builds:
		print(x)
	
	print("")
	prompt = input()
	build_input = int(prompt)


	print("")
	print("You Selected", builds[build_input-1])
	weight = weights[build_input-1]
	calculate()

# Run the main function
main()