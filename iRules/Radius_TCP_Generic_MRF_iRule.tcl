#============================================================================================================================#
# Purpose  : Radius TCP Generic MRF iRule persisting on AVP Type 44
# Author   : Gregg Marxer (g.marxer@f5.com), Vernon Wells (v.wells@f5.com)
# Date     : March 25, 2022
# Version  : 0.0.1
#
# Change Log:
#============================================================================================================================#


when RULE_INIT {
    #log local0. "HIT rule_init"
    # timeout for persistence entries in second
    # F5 Consulting verify what customer wants for the persistence timeout
    set static::radius_rule_persistence_entry_timeout 20
}

when CLIENT_ACCEPTED {
    #log local0. "HIT client_accepted"
    # this is required to make mr-generic work as you expect
    GENERICMESSAGE::peer name "[IP::client_addr]:[TCP::client_port]"
    # This is necessary if multiple PDU's come accross as part of the TCP stream.  
    # Setting the value to -1 an impossilbe value will prevent the while loop from kicking off prematurely
    set next_radius_pdu_length -1
    TCP::collect
}

when SERVER_CONNECTED {
    #log local0. "HIT server_connected"
    set next_local_radius_identifier 1
    GENERICMESSAGE::peer name "[IP::server_addr]:[TCP::server_port]"
    
    set next_radius_pdu_length -1
    TCP::collect
}

when CLIENT_DATA {
    #log local0. "HIT client_data"
    # This "while loop" will ensure the we capture the entire radius message, even if it is across multiple TCP messages. 
    while { [TCP::payload length] >= 20 } {
        if { $next_radius_pdu_length < 0 } {
            binary scan [TCP::payload] xxS next_radius_pdu_length
            set next_radius_pdu_length [expr { $next_radius_pdu_length & 0xffff }]
            #log local0. "next_radius_pdu_length in client data = $next_radius_pdu_length"
        }
     
        if { [TCP::payload length] < $next_radius_pdu_length } {
            TCP::collect
            return
        }
        # Once the entire Radius message is collected it will be sent out as a Generic Message to Generic Message Ingress
        GENERICMESSAGE::message create [TCP::payload $next_radius_pdu_length]
        
        TCP::release $next_radius_pdu_length
        set next_radius_pdu_length -1
    }
 
    TCP::collect
}

when SERVER_DATA {
    #log local0. "HIT server_data"
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
 
when GENERICMESSAGE_INGRESS {
    #log local0. "HIT gerneric-message_ingress"
    if { [clientside] } {
        set acct_session_id_for_this_msg ""
        # The TCP header is 20 bytes and must be accounted for when parsing the Radius AVP's
        set starting_point_of_next_avp 20
        # This "while loop" performs a binary scan of the data identifying each AVP type, looking for AVP Type 44  -- Acct-Session-Id
        while { $starting_point_of_next_avp < [GENERICMESSAGE::message length] } {
            binary scan [GENERICMESSAGE::message data] x${starting_point_of_next_avp}cc avp_type avp_length
            set avp_length [expr { $avp_length & 0xff }]
            #log local0.  "generic message incress AVP Type = $avp_type"
            #log local0.  "generic message incress AVP length = $avp_length"
            if { $avp_type == 44 } {
                # This will set the length of AVP 44, minus the CODE and PACKET IDENTIFIER bytes
                set acct_session_id_data_length [expr { ($avp_length - 2) & 0xff }]
                #log local0. "acct_session_id_data_length = $acct_session_id_data_length"
                # This will collect the value of AVP TYPE 44 that will be used for persistence
                binary scan [GENERICMESSAGE::message data] x[expr { $starting_point_of_next_avp + 2 }]a${acct_session_id_data_length} acct_session_id_for_this_msg
                #log local0. "acct_session_id_for_this_msg - which is type 44 value = ($acct_session_id_for_this_msg)"
                return
            }
 
            incr starting_point_of_next_avp $avp_length
        }
    } 
}

when MR_INGRESS {
    #log local0. "HIT MR_ingress"
    if { [clientside] } {
        set client_return_flow [MR::message lasthop]
        set egress_persistence_key ""
        #log local0. " client_return_flow = [MR::message lasthop] "
        # This will determine if this AVP Type 44 value has been already been set as a persistence entry and route accordingly, or set the persistence entry
        if { $acct_session_id_for_this_msg ne "" } {
            #log local0. "IN MR ingress accounting session ID for this message = $acct_session_id_for_this_msg"
            if { [set existing_persist_dst_for_this_session_id [table lookup "asi-$acct_session_id_for_this_msg"]] ne "" } {
                #log local0. "HIT MR ingress set existing_persist_dst_for_this_session_id -- if"
                MR::message nexthop none
                #log local0. " value of first getfiled  = ([getfield $existing_persist_dst_for_this_session_id  {;} 1])"
				#log local0. " value of second getfield = ([getfield $existing_persist_dst_for_this_session_id {;} 2])"
                MR::message route config [getfield $existing_persist_dst_for_this_session_id  ";" 1] host [getfield $existing_persist_dst_for_this_session_id ";" 2]
            } else {
                 #log local0. "setting persistence key in mr ingress else"
                 set egress_persistence_key "asi-$acct_session_id_for_this_msg"
            }
        }
        #log local0. "value of the egress_persistence_key = $egress_persistence_key"
        MR::store client_return_flow egress_persistence_key
    } else {
        if { $client_return_flow ne "" } {
            MR::message nexthop $client_return_flow
        } else {
            log local0.warn "Received RADIUS response from ([IP::remote_addr]:[TCP::remote_port]), but there is no response mapping.  Dropping."
            MR::message drop "Client return flow not defined"
            return
        }
    }
}

when MR_EGRESS {
    #log local0. " HIT MR_egress"
    if { [serverside] } {
        MR::restore client_return_flow egress_persistence_key
        if { $egress_persistence_key ne "" } {
          #log local0. "received persistence key in mr egress = $egress_persistence_key"
          # Will this get thrown off using the / if the customer is using partitions?
          table set $egress_persistence_key "[string range [MR::transport] [string first / [MR::transport]] end];[IP::remote_addr]%[ROUTE::domain]:[TCP::remote_port]" $static::radius_rule_persistence_entry_timeout indef
        }
    }
}

when GENERICMESSAGE_EGRESS {
    #log local0. "HIT generic-message_egress"
    TCP::respond [GENERICMESSAGE::message data]
}

when MR_FAILED {
    #log local0. "HIT mr_failed"
    # in general, with mr-generic you need this event or unexpected things will happen when a route failure occurs
    if { [MR::message retry_count] < [MR::max_retries] } {
        #log local0. "rc = ([MR::message retry_count]) : MR = ([MR::max_retries])"
        MR::message nexthop none
        MR::retry
    } else {
        MR::message drop
    }
}