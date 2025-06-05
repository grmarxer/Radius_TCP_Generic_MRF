#============================================================================================================================#
# Purpose  : Radius SSL/TCP Generic MRF iRule persisting on AVP Type 44 (Server-Side MRF Transport Config iRule)
# Author   : Gregg Marxer (g.marxer@f5.com), Vernon Wells (v.wells@f5.com)
# Revised  : June 4, 2025
# Date     : November 28, 2022
# Version  : 0.0.3
#
# Change Log: This iRule has been updated to correct for an issue where table lookups were being stepped on, resulting in
#             a different pool member being selected for known AVP 44 flows
#============================================================================================================================#



when RULE_INIT {
    set static::radius_rule_persistence_entry_timeout 60
}

when SERVER_CONNECTED {
    GENERICMESSAGE::peer name "[IP::server_addr]:[TCP::server_port]"
    set next_radius_pdu_length -1
    TCP::collect
}

when SERVER_DATA {
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

when MR_EGRESS {
    MR::restore egress_persistence_key
    if { $egress_persistence_key ne "" } {
      table set $egress_persistence_key "[string range [MR::transport] [string first / [MR::transport]] end];[IP::remote_addr]:[TCP::remote_port]" $static::radius_rule_persistence_entry_timeout indef
    }
}

when GENERICMESSAGE_EGRESS {
    TCP::respond [GENERICMESSAGE::message data]
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

