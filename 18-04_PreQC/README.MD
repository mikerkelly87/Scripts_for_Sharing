Tested on a VM  
Needs real world testing  
  
First Pass  
`mkdir /home/rack`  
`RS_SERVER_NAME=$(hostname)`  
`bash /home/rack/RPC_ADC-18-04.sh -fa "${RS_SERVER_NAME}" ; cat /home/rack/rs-automations/firstpass.log`  
  
`RS_SERVER_NAME=$(hostname)`  
`bash /home/rack/RPC_ADC-18-04.sh -sa "${RS_SERVER_NAME}"`
