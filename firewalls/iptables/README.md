# OpenSPA firewall extension script - iptables
Rule add and rule remove extension scripts that use iptables as the firewall mechanism.

## Script Running Requirements
* iptables, version 1.4.21 or greater
* Python
* root permission to run `iptable` commands

## How it Works
Since iptables will be setup with a default drop policy on the INPUT chain along
with a jump to the custom `OPENSPA` chain only connections that will be explicitly
whitelisted will be allowed and the rules in the `OPENSPA` chain.
The rule add script will add to the `OPENSPA` chain only the requested host connections 
which should be triggered by the OpenSPA server. Once the OpenSPA servers built-in
firewall duration tracking mechanism triggers the revocation of the rule it will trigger
the rule remove script which will remove the connection from the `OPENSPA` iptables 
chain and deny network access to the host.

## Setup
Before adding the default drop policy on the input chain, it is recommended to add one 
or most hosts that have a whitelist rule to allow to connect without OpenSPA
(eg. administrators computer). Attach these rules directly to the INPUT 
chain. These IPs will not be under OpenSPA control and will permanently have 
network access on all protocols/ports (unless of course you modify the recommended 
rule specification). \
`iptables --append INPUT --source <SOURCE_IP> --jump ACCEPT`

Once you are confident you will not lose network access during the installation, follow
these steps:
1. Create new chain: `iptables --new-chain OPENSPA`
2. Attach the chain to INPUT chain: `iptables --append INPUT --jump OPENSPA`
3. Set the default drop policy on the INPUT chain: `iptables --policy INPUT DROP`

