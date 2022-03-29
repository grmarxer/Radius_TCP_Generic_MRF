#!/bin/bash
##########################################################################################
##                                                                                      ##
## Script to test BIG-IP Radius TCP Generic MRF                                         ##
##                                                                                      ##
## Created by Gregg Marxer (g.marxer@f5.com)                                            ##
## Date: 08262021 Revision 1                                                            ##
##                                                                                      ## 
##########################################################################################

# set AVP start value
sessionIDStartValue=1114320

#set AVP end value
sessionIDEndValue=1114326

# set to yes to run test without AVP 44 set
null=no

function echoCommandType44 {
   echo "User-Name=bob,User-Password=hello,Acct-Session-ID=$sessionID,Dialback-No=1234567,Dialback-Name=michael,Old-Password=old,Port-Message=listen,Framed-Filter-Id=xyz" | radclient -P tcp 172.16.5.25 auth default -x -r 1
}

function echoCommandTypeNull {
   echo "User-Name=bob,User-Password=hello,Dialback-No=1234567,Dialback-Name=michael,Old-Password=old,Port-Message=listen,Framed-Filter-Id=xyz" | radclient -P tcp 172.16.5.25 auth default -x -r 1
}


for ((sessionID=$sessionIDStartValue;sessionID<$sessionIDEndValue;sessionID++))
do
  if [[ $null == yes ]]
  then
    echoCommandTypeNull
    sleep 1
  else
    x=0
    sleep 2
    while [ $x -le 10 ]
    do
      echoCommandType44
      ((x=x+1))
      sleep 2
    done
  fi
done
