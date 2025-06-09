#============================================================================================================================#
# Purpose  : Radius SSL/TCP Generic MRF iRule persisting on AVP Type 44 (Server-Side MRF Transport Config iRule)
# Author   : Gregg Marxer (g.marxer@f5.com), Vernon Wells (v.wells@f5.com)
# Revised  : June 9, 2025
# Date     : November 28, 2022
# Version  : 0.0.3
#
# Change Log: This iRule has been updated to correct for an issue where table lookups were being stepped on, resulting in
#             a different pool member being selected for known AVP 44 flows
#============================================================================================================================#


when CLIENT_ACCEPTED {
    GENERICMESSAGE::peer name "[IP::client_addr]:[TCP::client_port]"
}

when CLIENTSSL_HANDSHAKE {
    set next_radius_pdu_length -1
    SSL::collect
}

when CLIENTSSL_DATA {
    while { [SSL::payload length] >= 20 } {
        if { $next_radius_pdu_length < 0 } {
            binary scan [SSL::payload] xxS next_radius_pdu_length
            set next_radius_pdu_length [expr { $next_radius_pdu_length & 0xffff }]
        }

        if { [SSL::payload length] < $next_radius_pdu_length } {
            SSL::collect
            return
        }
        
        GENERICMESSAGE::message create [SSL::payload $next_radius_pdu_length]

        SSL::release $next_radius_pdu_length
        set next_radius_pdu_length -1
    }

    SSL::collect
}

when MR_INGRESS {
    set egress_persistence_key ""
    set starting_point_of_next_avp 20
    
    while { $starting_point_of_next_avp < [GENERICMESSAGE::message length] } {
        binary scan [GENERICMESSAGE::message data] x${starting_point_of_next_avp}cc avp_type avp_length
        set avp_length [expr { $avp_length & 0xff }]
        if { $avp_type == 44 } {
            set acct_session_id_data_length [expr { ($avp_length - 2) & 0xff }]
            binary scan [GENERICMESSAGE::message data] x[expr { $starting_point_of_next_avp + 2 }]a${acct_session_id_data_length} acct_session_id_for_this_msg

            if { $acct_session_id_for_this_msg ne "" } {
                if { [set existing_persist_dst_for_this_session_id [table lookup "asi-$acct_session_id_for_this_msg"]] ne "" } {
                    MR::message nexthop none
                    MR::message route config [getfield $existing_persist_dst_for_this_session_id  ";" 1] connection-mode per-client host [getfield $existing_persist_dst_for_this_session_id ";" 2]
                } else {
                    set egress_persistence_key "asi-$acct_session_id_for_this_msg"
                }
            }

            break
        }

        incr starting_point_of_next_avp $avp_length
    }

    
    MR::store egress_persistence_key
}

when GENERICMESSAGE_EGRESS {
    SSL::respond [GENERICMESSAGE::message data]
}

when MR_FAILED {
    if { [MR::message retry_count] < [MR::max_retries] } {
        log local0.warn "failed to route message; retrying"
        MR::retry
    } else {
        log local0.error "failed to route message after retries; dropping message"
        MR::message drop
    }
}
