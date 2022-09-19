#============================================================================================================================#
# Purpose  : Radius SSL/TCP Generic MRF iRule persisting on AVP Type 44 (Client-Side VIP iRule)
# Author   : Gregg Marxer (g.marxer@f5.com), Vernon Wells (v.wells@f5.com)
# Date     : April 20, 2022
# Version  : 0.0.1
#
# Change Log:
#============================================================================================================================#

when CLIENT_ACCEPTED {
    #log local0. "HIT client-accepted"
    # this is required to make mr-generic work as you expect
    GENERICMESSAGE::peer name "[IP::client_addr]:[TCP::client_port]"
}

when CLIENTSSL_HANDSHAKE {
    #log local0. "HIT CLIENTSSL-HANDSHAKE"
    # if statement add to collect SSL session data to decrypt client side traffic in tcpdump
    if { [IP::addr [getfield [IP::client_addr] "%" 1] equals 100.100.100.100] } {
      log local0. "[TCP::client_port] :: RSA Session-ID:[SSL::sessionid] Master-Key:[SSL::sessionsecret]"
    }
    # This is necessary if multiple PDU's come accross as part of the TCP stream.  
    # Setting the value to -1 an impossilbe value will prevent the while loop from kicking off prematurely
    set next_radius_pdu_length -1
    SSL::collect
}

when CLIENTSSL_DATA {
    #log local0. "HIT CLIENTSSL-DATA"
    # This "while loop" will ensure the we capture the entire radius message, even if it is across multiple TCP messages. 
    # PS add safety measure to prevent infintite loop
    while { [SSL::payload length] >= 20 } {
        if { $next_radius_pdu_length < 0 } {
            binary scan [SSL::payload] xxS next_radius_pdu_length
            set next_radius_pdu_length [expr { $next_radius_pdu_length & 0xffff }]
            #log local0. "next_radius_pdu_length in client data = ($next_radius_pdu_length)"
        }
     
        if { [SSL::payload length] < $next_radius_pdu_length } {
            SSL::collect
            return
        }
        # Once the entire Radius message is collected it will be sent out as a Generic Message to Generic Message Ingress
        GENERICMESSAGE::message create [SSL::payload $next_radius_pdu_length]
        
        SSL::release $next_radius_pdu_length
        set next_radius_pdu_length -1
    }
 
    SSL::collect
}
 
when GENERICMESSAGE_INGRESS {
    #log local0. "#### Starting GENERICMESSAGE_INGRESS ####"
    set acct_session_id_for_this_msg ""
    # The TCP header is 20 bytes and must be accounted for when parsing the Radius AVP's
    set starting_point_of_next_avp 20
    # This "while loop" performs a binary scan of the data identifying each AVP type, looking for AVP Type 44  -- Acct-Session-Id
    # PS add safety measure to prevent infintite loop
    while { $starting_point_of_next_avp < [GENERICMESSAGE::message length] } {
        binary scan [GENERICMESSAGE::message data] x${starting_point_of_next_avp}cc avp_type avp_length
        set avp_length [expr { $avp_length & 0xff }]
        #log local0.  "generic message ingress AVP Type = $avp_type"
        #log local0.  "generic message ingress AVP length = $avp_length"
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

when MR_INGRESS {
    log local0. "####  Starting MR_INGRESS CLIENTSIDE ####"
    set client_return_flow [MR::message lasthop]
    set egress_persistence_key ""
    #log local0. " client_return_flow = [MR::message lasthop] "
    # This will determine if this AVP Type 44 value has been already been set as a persistence entry and route accordingly, or set the persistence entry
    if { $acct_session_id_for_this_msg ne "" } {
        #log local0. "IN MR ingress accounting session ID for this message = $acct_session_id_for_this_msg"
        if { [set existing_persist_dst_for_this_session_id [table lookup "asi-$acct_session_id_for_this_msg"]] ne "" } {
            log local0. "(existing_persist_dst_for_this_session_id) is = ($existing_persist_dst_for_this_session_id) and the AVP 44 Value = ($acct_session_id_for_this_msg)"
            MR::message nexthop none
            #log local0. " value of first getfiled  = ([getfield $existing_persist_dst_for_this_session_id  {;} 1])"
            #log local0. " value of second getfield = ([getfield $existing_persist_dst_for_this_session_id {;} 2])"
            MR::message route config [getfield $existing_persist_dst_for_this_session_id  ";" 1] connection-mode per-client host [getfield $existing_persist_dst_for_this_session_id ";" 2]
        } else {
            set egress_persistence_key "asi-$acct_session_id_for_this_msg"
            log local0. "(egress_persistence_key) has been set to = ($egress_persistence_key) and the AVP 44 Value = ($acct_session_id_for_this_msg)"
        }
    }
    MR::store client_return_flow egress_persistence_key
}

when GENERICMESSAGE_EGRESS {
    #log local0. "HIT generic-message_egress-clientside"
    SSL::respond [GENERICMESSAGE::message data]
}

when MR_FAILED {
    log local0. "**** Entering MR_FAILED CLIENTSIDE ****"
    log local0. "mr_failed cs nexthop  [MR::message nexthop]"
    log local0. "mr_failed cs status  [MR::message status]"
    log local0. "mr_failed cs connection_instance [MR::connection_instance]"
    log local0. "mr_failed cs transport  [MR::transport]"
    log local0. "mr_failed cs message attempted  [MR::message attempted]"
    log local0. "mr_failed cs route [MR::message route]"
    log local0. "mr_failed cs remote_addr  [IP::remote_addr]"
    # in general, with mr-generic you need this event or unexpected things will happen when a route failure occurs
    if { [MR::message retry_count] < [MR::max_retries] } {
        log local0. "rc = ([MR::message retry_count]) : MR = ([MR::max_retries])"
        #MR::message nexthop none
        MR::retry
    } else {
        MR::message drop
    }
}