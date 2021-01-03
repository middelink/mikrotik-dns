# mikrotik-dns

[![GoDoc](https://godoc.org/github.com/middelink/mikrotik-dns?status.svg)](https://godoc.org/github.com/middelink/mikrotik-dns)
[![License](https://img.shields.io/github/license/middelink/mikrotik-dns.svg)](https://github.com/middelink/mikrotik-dns/blob/master/LICENSE)
[![Build Status](https://travis-ci.org/middelink/mikrotik-dns.svg?branch=master)](https://travis-ci.org/middelink/mikrotik-dns)
[![Coverage Status](https://coveralls.io/repos/github/middelink/mikrotik-dns/badge.svg?branch=master)](https://coveralls.io/github/middelink/mikrotik-dns?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/middelink/mikrotik-dns)](https://goreportcard.com/report/github.com/middelink/mikrotik-dns)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fmiddelink%2Fmikrotik-dns.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fmiddelink%2Fmikrotik-dns?ref=badge_shield)

## TL;DR

* mikrotik-dns reads the given nameserver zone file(s) in RFC1034 format and
  updates the internal mikrotik's DNS and/or DHCP server with the discovered
  information.
* It handles all the resources records Mikrotik's DNS supports. (A, AAAA,
  CNAME, MX, NS, SRV and TXT)
* When there is a dhcp:<mac address> is added to A RRs, the tool is capable
  of maintaining the static leases of one or more dhcp servers on the Mikrotik.

> :warning: When used this tool will *remove all DNS and DHCP leases* which are not in the source zone(s)!

## Why did I write this?

Due to a ingrained need to maintain the DNSSEC keys for my domains myself, I
run a so-called blind nameserver (pushing changes via notifications to a set
of publicly known nameservers). However, due to a recent upgrade on the server
the nameserver runs, our house was temporarily deprived of a working DNS.
Unacceptable. That made me think how to sync the given nameserver records to
the Mikrotik, which would allow me in time of need to use that as a emergency
DNS. However while it functioned properly as a forwarding DNS, there were no
entries for my local zone...

While implementing this tool, I figured it would also be nice to have a single
source of truth for the static DHCP leases as well, having the tool a) figure
out to which dhcp server instance the lease would go to and b) populate the DNS
name as a comment.

## Command Line Flags

```
Usage: ./mikrotik-dns [OPTION]... ZONE...

When --use_dns is given, this tool copies compatible RRs from the given zones
into the Mikrotiks static DNS table. This can for example be used in emergency
modes where the local nameserver is down, but the organisation still requires
an internal DNS in the mean time. Unknown entries from the static DNS table
will be removed!

When --use_dhcp is given, all A records from the given zones which have a
comment matching 'dhcp:<mac address>' will update the Mikrotiks DHCP table.
Unknown entries from the DHCP table will be removed!

  -address api://user:pass@host
    	url like address of the MT to connect to api://user:pass@host. use `apis` for encrypted connections.
  -dry_run
    	run the program but do not make any changes on the Mikrotik
  -dnsfilter string
    	comma separated list of dns prefixes to filter
  -use_dhcp
    	maintain dhcp table based upon '; dhcp:<mac>' mac comments on the A records
  -use_dns
    	maintain static dns table from zone
  -verbose
    	be more verbose
  -version
    	output version information and exit
```

## Example usage

Given a example zone file containing:
```dns
example.com	SOA ns.example.com postmaster.example.com 2020092602 28800 7200 2419200 1200
		IN NS		virthost.polyware.nl.
		IN TXT		"v=spf1 a:smtp.example.com ?all"
		IN SPF		"v=spf1 a:smtp.example.com ?all"
		CAA		0 issue "letsencrypt.org"

localhost	IN A		127.0.0.1

@		IN A		192.168.10.10 ; dhcp:01:23:45:67:89:ab
		IN AAAA		2a02:ff:ff:ffff:ffff:ff:ffff:ffff
		IN MX		50 smtp

$GENERATE 128-254 dhcp${-127,3} A 192.168.10.$
```

Running the tool with `mikrotik-dns --use_dns --use_dhcp --dnsfilter="dhcp" --address apis://<user>:<passwd>@<mikrotik> /var/named/<zone>`
will add example.com's NS, TXT, A and AAAA records to the mikrotik's static DNS cache while removing anything else.
Then, if it can find a configured dhcp server for this range, it will add the leases, removing anthing else.

## Installation

I presume you have a working experiance with go.

### Building the binary

* Make sure you have `make`, `git` and `go` installed.
* Clone the source `git clone https://github.com/middelink/mikrotik-dns`.
* Execute `make` to create the mikrotik-fwban binary.
* Copy the binary to /usr/local/bin.

### Mikrotik changes

* Create a group (`apis`) on your mikrotik (system > users; groups) and
  give it at least the `read`, `write` and `api` policies.
* Create a user on your mikrotik (system > users; users) and have it
  belong to the group you just created.


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fmiddelink%2Fmikrotik-dns.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fmiddelink%2Fmikrotik-dns?ref=badge_large)