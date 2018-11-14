This tool will help you generate interface files for new nodes.
As every environment is a little different there is still some manual work required.

Steps:

1) Copy an interfaces file from an existing node to use as the template.
Place this file in the same directory as the replace_interfaces.py script and name it 'interfaces.txt'
When you clone this repo there is an existing interfaces.txt file, you will want to replace this with one from an existing node.

2) Replace the actual IP addresses in the interfaces.txt file with the name of the interface but with an underscore instead of a hypen.  
Ex:  
auto br-host  
iface br-host inet static  
address br_host  

3) Edit the addresses.yml file using the existing nodes as an example (but replace them with the info for the nodes you are adding. Be sure the interface names use the underscore naming scheme as described in step 2).

4) Run the replace_interfaces.py script. This will create a <node name>interfaces.txt file for every node you added to the addresses.yml file.
You can doublecheck to make sure your IP addresses were correctly added to these files with:  
$ grep -A1 address *interfaces.txt
