## Steps to Install, Configure, and Test FreeRadius Sever (TCP) on Centos 8  

<br/>  

- https://www.cyberithub.com/install-setup-freeradius-server-in-linux/  

<br/>  

### Installation and Configuration

1. Install FreeRadius on both your test client and server machines  
    ```
    yum install freeradius freeradius-utils freeradius-mysql freeradius-perl –y  
    ```  

2.  Start services  

    ```
    systemctl start radiusd
    systemctl enable radiusd
    systemctl status radiusd
    ```  

3.  On test server/s only -- Add each client network reaching out the radius system.  This will give this radius server the information it needs for each radius client attaching to it.  

    ```
    vi /etc/raddb/clients.conf
    ```  

    ```
    client labMgmtIpRange {
            ipaddr = 192.168.0.0/16
            proto = *
            secret = default
            require_message_authenticator = no
            limit {
                    max_connections = 16
                    lifetime = 0
                    idle_timeout = 30
            }
    }

    client labIpRange {
            ipaddr = 172.0.0.0/8
            proto = *
            secret = default
            require_message_authenticator = no
            limit {
                    max_connections = 16
                    lifetime = 0
                    idle_timeout = 30
            }
    }
    ```  

4.  On test server/s only -- To enable TCP on the radius server you must add the __proto__ line to both auth (port 1812) and acct (port 1813)  

    ```
    vi /etc/raddb/sites-enabled/default
    ```  

    ```
    listen {
            type = auth
            proto = tcp

    listen {
            ipaddr = *
            port = 0
            proto = tcp
            type = acct
    ```  
5. On each test server run this command to start FreeRadius in debug mode so you get the most verbose messaging.  Use crtl-c to exit debug mode  

    ```
    radiusd -X
    ``` 


<br/>  
<br/>  

### Testing  

1.  To test against the server run this command on the client, you can change the AVPs as you see fit.  In this example 172.16.5.25 is the VIP on the BIG-IP.

    ```
    echo "User-Name=bob,User-Password=hello,Acct-Session-ID=66,Dialback-No=1234,Dialback-Name=tony,Old-Password=old,Port-Message=listen,Framed-Filter-Id=xyz" | radclient -P tcp 172.16.5.25 auth default -x -r1
    ```  

2.  Expected result  

    ```
    [root@centos1 ~]# echo "User-Name=bob,User-Password=hello,Acct-Session-ID=66,Dialback-No=1234,Dialback-Name=tony,Old-Password=old,Port-Message=listen,Framed-Filter-Id=xyz" | radclient -P tcp 172.16.5.25 auth default -x -r1
    Sent Access-Request Id 135 from 172.16.5.10:52272 to 172.16.5.25:1812 length 77
            User-Name = "bob"
            User-Password = "hello"
            Acct-Session-Id = "66"
            Dialback-No = "1234"
            Dialback-Name = "tony"
            Old-Password = "old"
            Port-Message = "listen"
            Framed-Filter-Id = "xyz"
            Cleartext-Password = "hello"
    Received Access-Accept Id 135 from 172.16.5.25:1812 to 172.16.5.10:52272 length 32
            Reply-Message = "Hello, bob"
    ```  

