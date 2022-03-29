## Steps to Install and Configure FreeRadius Sever on Centos 8

- https://www.cyberithub.com/install-setup-freeradius-server-in-linux/

1. yum install freeradius freeradius-utils freeradius-mysql freeradius-perl –y  

2.  Start services  

    ```
    systemctl start radiusd
    systemctl enable radiusd
    systemctl status radiusd
    ```  

3.  Add each client network reaching out the radius system.  This will give this radius server the information it needs for each radius client attaching to it.  

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

4.  To enable TCP on the radius server you must add the __proto__ line to both auth (port 1812) and acct (port 1813)  

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

