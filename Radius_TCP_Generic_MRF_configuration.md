## Steps to Configure Radius TCP Load Balancing using Generic MRF  

- BIG-IP version 15.1.3.1
- Persist on AVP Type 44 (Acct-Session-ID)
- Pass through if AVP Type 44 (Acct-Session-ID) is not present

### Steps


1. Create the following iRule `Radius_TCP_Generic_MRF_iRule` on BIG-IP using the GUI -- Local Traffic > iRules > Create  

    - Copy the contents of [this file](https://github.com/grmarxer/Radius_TCP_Generic_MRF/blob/main/iRules/Radius_TCP_Generic_MRF_iRule.tcl) to create the `Radius_TCP_Generic_MRF_iRule`.

2.  Create the Nodes and Pool for the Radius Servers  
    - Adjust the number of nodes according to your specific configuration, the IP addresses and port numbers

    ```
    tmsh create ltm node radius_server_1 address 172.16.10.10
    tmsh create ltm node radius_server_2 address 172.16.10.15
    tmsh create ltm pool radius_tcp_server_pool monitor gateway_icmp members add { radius_server_1:1812 radius_server_2:1812 }
    tmsh save sys config
    ```
3. Create the Generic MRF Configuration -- Generic MRF can only be configured in TMSH
    ```
    tmsh create ltm message-routing generic protocol radiusTcp no-response yes disable-parser yes
    tmsh create ltm message-routing generic transport-config toward-radiusServer-cluster01 profiles replace-all-with { radiusTcp f5-tcp-progressive } source-address-translation { type automap } rules { Radius_TCP_Generic_MRF_iRule }
    tmsh create ltm message-routing generic peer peer-radiusServer-cluster01 auto-initialization disabled connection-mode per-client pool radius_tcp_server_pool transport-config toward-radiusServer-cluster01
    tmsh create ltm message-routing generic route route-radiusServer-cluster01 peers { peer-radiusServer-cluster01 }
    tmsh create ltm message-routing generic router router-toward-radiusServer-cluster01 routes replace-all-with { route-radiusServer-cluster01 }
    tmsh save sys config
    ```  
4.  Create the LTM Virtual Server Listener for the Radius TCP Traffic
    - Adjust the Virtual Server IP address and port specific to your configuration

    ``` 
    tmsh create ltm virtual vs-radiusTCP-toward-radiusServer-cluster01 profiles replace-all-with { radiusTcp router-toward-radiusServer-cluster01 f5-tcp-progressive } destination 172.16.5.25:1812 rules { Radius_TCP_Generic_MRF_iRule }
    tmsh save sys config
    ```  