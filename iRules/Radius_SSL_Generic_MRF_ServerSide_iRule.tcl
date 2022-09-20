#============================================================================================================================#
# Purpose  : Radius SSL/TCP Generic MRF iRule persisting on AVP Type 44 (Server-Side MRF Transport Config iRule)
# Author   : Gregg Marxer (g.marxer@f5.com), Vernon Wells (v.wells@f5.com)
# Date     : April 20, 2022
# Version  : 0.0.1
#
# Change Log:
#============================================================================================================================#


when RULE_INIT {
    #log local0. "HIT rule_init"
    # timeout for persistence entries in second
    # F5 Consulting verify what customer wants for the persistence timeout
    set static::radius_rule_persistence_entry_timeout 60
}

when SERVER_CONNECTED {
    #log local0. "HIT server_connected"
    set next_local_radius_identifier 1
    GENERICMESSAGE::peer name "[IP::server_addr]:[TCP::server_port]"
    
    set next_radius_pdu_length -1
    TCP::collect
}

when SERVER_DATA {
    #log local0. "HIT server_data"
    # PS add safety measure to prevent infintite loop
    while { [TCP::payload length] >= 20 } {
        if { $next_radius_pdu_length < 0 } {
            binary scan [TCP::payload] xxS next_radius_pdu_length
            set next_radius_pdu_length [expr { $next_radius_pdu_length & 0xffff }]
        }
     
        if { [TCP::payload length] < $next_radius_pdu_length } {
            TCP::collect
            return
        }
 
        GENERICMESSAGE::message create [TCP::payload $next_radius_pdu_length]
   
        TCP::release $next_radius_pdu_length
        set next_radius_pdu_length -1
    }
 
    TCP::collect
}

when MR_INGRESS {
    #log local0. "#### Starting MR_INGRESS SERVERSIDE ####"
    if { $client_return_flow ne "" } {
        MR::message nexthop $client_return_flow
        #log local0. "mr_ingress ss nexthop  [MR::message nexthop]"
        #log local0. "mr_ingress ss status  [MR::message status]"
        #log local0. "mr_ingress ss connection_instance  [MR::connection_instance]"
        #log local0. "mr_ingress ss transport  [MR::transport]"
        #log local0. "mr_ingress ss message attempted  [MR::message attempted]"
        #log local0. "mr_ingress ss route  [MR::message route]"
        #log local0. "mr_ingress ss remote_addr [IP::remote_addr]"
    } else {
        log local0.warn "Received RADIUS response from ([IP::remote_addr]:[TCP::remote_port]), but there is no response mapping.  Dropping."
        MR::message drop "Client return flow not defined"
        return
    }
}

when MR_EGRESS {
    #log local0. "#### Starting MR_EGRESS SERVERSIDE ####"
    #log local0. "Number of connection instance [MR::connection_instance]"
    #log local0. "mr_egress ss nexthop [MR::message nexthop]"
    #log local0. "mr_egress ss status [MR::message status]"
    #log local0. "mr_egress ss route [MR::message route]"
    #log local0. "mr_egress ss connection_instance [MR::connection_instance]"
    #log local0. "mr_egress ss transport [MR::transport]"
    #log local0. "mr_egress ss message attempted [MR::message attempted]"
    #log local0. "mr_egress ss remote_addr  [IP::remote_addr]"
    MR::restore client_return_flow egress_persistence_key
    if { $egress_persistence_key ne "" } {
      #log local0. "received persistence key in mr egress = $egress_persistence_key"
      table set $egress_persistence_key "[string range [MR::transport] [string first / [MR::transport]] end];[IP::remote_addr]%[ROUTE::domain]:[TCP::remote_port]" $static::radius_rule_persistence_entry_timeout indef
    }
}

when GENERICMESSAGE_EGRESS {
    #log local0. " HIT GENERICMESSAGE_EGRESS-serverside"
    TCP::respond [GENERICMESSAGE::message data]
}

when MR_FAILED {
    log local0. "**** Entering MR_FAILED SERVERSIDE ****"
    #log local0. "DEBUG: MR_FAILED"
    #log local0. "mr_failed ss nexthop  [MR::message nexthop]"
    #log local0. "mr_failed ss status  [MR::message status]"
    #log local0. "mr_failed ss connection_instance [MR::connection_instance]"
    #log local0. "mr_failed ss transport  [MR::transport]"
    #log local0. "mr_failed ss message attempted  [MR::message attempted]"
    #log local0. "mr_failed ss route  [MR::message route]"
    #log local0. "mr_failed ss remote_addr  [IP::remote_addr]"
    # in general, with mr-generic you need this event or unexpected things will happen when a route failure occurs
    if { [MR::message retry_count] < [MR::max_retries] } {
        log local0. "rc = ([MR::message retry_count]) : MR = ([MR::max_retries])"
        #MR::message nexthop none
        MR::retry
    } else {
        MR::message drop
    }
}