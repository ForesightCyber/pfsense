# pfsense
PFSense tools


## Pfsense config anonymizer
Used to anonymize config before sending.

```
usage: pfsense-config-anonymizer.py [-h] [-d] [-v] [--xml-in XMLIN] [--xml-out XMLOUT] [--hide-nodes HSECTIONS]
                                    [--anonymize-ip-nodes ISECTIONS] [--anonymize-name-nodes NSECTIONS]
                                    [--anonymize-descr-nodes DSECTIONS] [--remove-nodes RSECTIONS]

optional arguments:
  -h, --help            show this help message and exit
  -d                    Debug messages (default: None)
  -v                    Verbose messages (default: None)
  --xml-in XMLIN        XML input (default: None)
  --xml-out XMLOUT      XML output (default: None)
  --hide-nodes HSECTIONS
                        Which sections to hide (Xpath) (default: ['.//bcrypt-hash', './/authorizedkeys',
                        './/cert/crt', './/cert/prv', './/gold_encryption_password', './/encryption_password',
                        './/gold_password', './/snmpd/rocommunity', './/pre-shared-key', './/aliases/*/url',
                        './/custom_options/tls', './/bcrypt-hash', './/sha512-hash', './/custom_options/tls',
                        './/cert/crt', './/cert/prv', './/ovpnserver/*/certca', './/openvpn-client/auth_pass',
                        './/ca/crt', './/ca/prv', './/quaggaospfdraw/*/ospfdrunning',
                        './/quaggaospfdraw/*/ospf6drunning', './/quaggaospfdraw/*/bgpdrunning',
                        './/quaggaospfdraw/*/zebrarunning', './/quaggaospfd/*/password', './/item/ssloffloadcert',
                        './/squidnac/*/allowed_subnets', './/squidnac/*/blacklist',
                        './/squid/*/custom_options_squid3', './/nut/*/upsd_users', './/pfblockerng/*/maxmind_key',
                        './/sid_mgmt_lists/*/content', './/suppress/*/suppresspassthru', './/rule/file_store_logdir',
                        './/zabbixagentlts/*/userparams', './/zabbixproxylts/*/tlspskfile',
                        './/zabbixproxylts/*/advancedparams', './/defaultsettings/advancedoptions',
                        './/item/advancedoptions', './/step9/authcertname', './/step6/authcertca',
                        './/unbound/custom_options', './/openvpn-client/tls', './/openvpn-server/tls', './/openvpn-
                        server/shared_key', './/syslogngadvanced/*/objectparameters', './/item/useproxypass',
                        './/item/publickey', './/item/privatekey', './/password'])
  --anonymize-ip-nodes ISECTIONS
                        Which sections to anonymize by IP (Xpath) (default: ['.//ipaddr', './/route/network',
                        './/failover_peerip', './/gateway', './/range/from', './/range/to', './/remoteid/address',
                        './/allowedips/row/address', './/endpoint'])
  --anonymize-name-nodes NSECTIONS
                        Which sections to anonymize by Name (Xpath) (default: ['.//username', './/name',
                        './/hostname', './/openvpn-csc/common_name', './/pfblockernglistsv4/config/*/url',
                        './/alias/address.//rule/*/username'])
  --anonymize-descr-nodes DSECTIONS
                        Which sections to anonymize by Descripton (Xpath) (default: ['.//descr', './/description',
                        './/separator/text', './/aliases/*/detail'])
  --remove-nodes RSECTIONS
                        Which sections to completely remove (Xpath) (default: [])
```

