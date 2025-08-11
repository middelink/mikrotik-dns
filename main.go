package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	version = "dev"

	dnsFilter  = flag.String("dnsfilter", "", "comma separated list of dns prefixes to filter")
	address    = flag.String("address", "", "url like address of the MT to connect to `api://user:pass@host`. use apis for encrypted connections.")
	debug      = flag.Bool("debug", false, "run the program but do not make any changes on the Mikrotik")
	verbose    = flag.Bool("verbose", false, "be more verbose")
	useDNS     = flag.Bool("use_dns", false, "maintain static dns table from zone")
	useDHCP    = flag.Bool("use_dhcp", false, "maintain dhcp table based upon '; dhcp:<mac>' mac comments on the A records")
	hasVersion = flag.Bool("version", false, "output version information and exit")
)

func main() {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), `Usage: %s [OPTION]... ZONE...

When --use_dns is given, this tool copies compatible RRs from the given zones
into the Mikrotiks static DNS table. This can for example be used in emergency
modes where the local nameserver is down, but the organisation still requires
an internal DNS in the mean time. Unknown entries from the static DNS table
will be removed!

When --use_dhcp is given, all A records from the given zones which have a
comment matching 'dhcp:<mac address>' will update the Mikrotiks DHCP table.
Unknown entries from the DHCP table will be removed!

`, os.Args[0])

		flag.PrintDefaults()
	}
	flag.Parse()

	if *hasVersion {
		fmt.Printf("mikrotik-dns version %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
		return
	}

	if flag.NArg() < 1 {
		log.Fatalf("At least one zone file is required, none given")
	}

	dnsPrefixes := strings.Fields(strings.ReplaceAll(*dnsFilter, ",", " "))

	mtURL, err := url.Parse(*address)
	if err != nil {
		log.Fatalf("Unable to parse --address: %v", err)
	}
	if mtURL.Scheme != "api" && mtURL.Scheme != "apis" {
		log.Fatalf("Invalid scheme, expecting `api` or `apis`, not %v", mtURL.Scheme)
	}
	if mtURL.Opaque != "" || mtURL.Path != "" || mtURL.RawPath != "" || mtURL.RawQuery != "" || mtURL.Fragment != "" {
		log.Printf("Ignorning extra parts from url: %q", mtURL)
	}

	passwd, _ := mtURL.User.Password()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	mt, closer, err := NewMikrotik(ctx, "first", mtURL.Host, mtURL.User.Username(), passwd, mtURL.Scheme == "apis")
	defer cancel()
	if err != nil {
		log.Fatalf("Unable to connect to %s: %v", mtURL.Host, err)
	}
	defer func() {
		if err := closer(ctx); err != nil {
			log.Fatalf("Unable to close Mikrotik session: %v", err)
		}
	}()

	var existingRRs map[string]dns.RR
	if existingRRs, err = mt.FetchDNSlist(ctx); err != nil {
		log.Fatalf("Unable to fetch existing DNS entries: %v", err)
	}
	fmt.Printf("%d existing RRs found\n", len(existingRRs))

	mtRRs := map[uint16]struct{}{
		dns.TypeA:     {},
		dns.TypeAAAA:  {},
		dns.TypeCNAME: {},
		dns.TypeMX:    {},
		dns.TypeNS:    {},
		dns.TypeSRV:   {},
		dns.TypeTXT:   {},
	}

	var dhcpservers map[string][]*net.IPNet
	if *useDHCP {
		dhcpservers, err = mt.FetchDHCPNets(ctx)
		if err != nil {
			log.Fatalf("Unable to fetch existing DHCP servers: %v", err)
		}
	}

	zoneRRs := []dns.RR{}
	MACs := []DHCP{}
	for _, zonefile := range flag.Args() {
		origin := strings.TrimSuffix(filepath.Base(zonefile), ".db")

		stream, _ := os.Open(zonefile)
		scanner := dns.NewZoneParser(stream, origin, zonefile)

		for {
			rr, ok := scanner.Next()
			if !ok {
				if scanner.Err() != nil {
					fmt.Printf("error reading token: %v\n", scanner.Err())
				}
				break
			}

			cmtMap := mapComments(scanner.Comment())
			if _, ok := mtRRs[rr.Header().Rrtype]; ok {
				if _, ok := cmtMap["ignore"]; ok {
					continue
				}

				found := false
				for _, p := range dnsPrefixes {
					if strings.HasPrefix(rr.Header().Name, p) {
						found = true
						break
					}
				}
				if !found {
					if cmtMap["forward"] != "" {
						// Map a forward line to RR NULL so we can map it to MT dns.
						r := new(dns.NULL)
						r.Hdr = dns.RR_Header{Name: rr.Header().Name, Rrtype: dns.TypeNULL, Class: dns.ClassINET, Ttl: rr.Header().Ttl}
						r.Data = cmtMap["forward"]
						rr = r
					}

					for _, zoneRR := range zoneRRs {
						if dns.IsDuplicate(rr, zoneRR) && rr.Header().Ttl == zoneRR.Header().Ttl {
							log.Fatalf("Duplicate entry found (%v)\n", rr.Header().Name)
						}
					}
					zoneRRs = append(zoneRRs, rr)
				}
			}
			if *useDHCP {
				if rr.Header().Rrtype == dns.TypeA && cmtMap["dhcp"] != "" {
					hw, err := net.ParseMAC(cmtMap["dhcp"])
					if err != nil {
						fmt.Printf("parseMAC failed (%q): %v", cmtMap["dhcp"], err)
						continue
					}
					server := ""
				outside:
					for srv, nets := range dhcpservers {
						for _, net := range nets {
							if net.Contains(rr.(*dns.A).A) {
								server = srv
								break outside
							}
						}
					}
					if server != "" {
						suffix := ""
						if _, ok := cmtMap["static"]; ok {
							suffix = " (static)"
						}
						MACs = append(MACs, DHCP{Comment: rr.Header().Name + suffix, Server: server, IP: rr.(*dns.A).A, MAC: hw})
					} else if *verbose {
						fmt.Printf("[WARNING] Could not find a matching dhcp server for ip %v\n", rr.(*dns.A).A)
					}
				}
			}
		}
	}
	if *useDNS {
		sort.Slice(zoneRRs, func(i, j int) bool {
			if zoneRRs[i].Header().Rrtype < zoneRRs[j].Header().Rrtype {
				return true
			}
			if zoneRRs[i].Header().Rrtype == zoneRRs[j].Header().Rrtype && zoneRRs[i].Header().Name < zoneRRs[j].Header().Name {
				return true
			}
			return false
		})
		fmt.Printf("%v zone RR found\n", len(zoneRRs))

		// Prune the lists
		fmt.Println("Pruning lists for duplicates")
		for k, existingRR := range existingRRs {
			for i, r := range zoneRRs {
				if dns.IsDuplicate(existingRR, r) && r.Header().Ttl == existingRR.Header().Ttl {
					// Delete found element from both lists.
					zoneRRs = append(zoneRRs[:i], zoneRRs[i+1:]...)
					delete(existingRRs, k)
					break
				}
			}
		}

		fmt.Printf("%d existing RRs to be removed\n", len(existingRRs))
		for k, v := range existingRRs {
			fmt.Printf("%v: %v\n", k, v)
			if !*debug {
				if err := mt.DelDNS(ctx, k); err != nil {
					log.Printf("unable to remove DNS entry (%v, %v): %v", k, v, err)
				}
			}
		}
		fmt.Printf("%d missing RRs to be added\n", len(zoneRRs))
		for k, v := range zoneRRs {
			fmt.Printf("%v: %v\n", k, v)
			if !*debug {
				if err := mt.AddDNS(ctx, v, ""); err != nil {
					log.Printf("unable to add DNS entry (%v, %v): %v", k, v, err)
				}
			}
		}
	}

	if *useDHCP {
		existingDHCP, _ := mt.FetchDHCP(ctx)
		fmt.Printf("%d existing DHCP entries found\n", len(existingDHCP))
		fmt.Printf("%d zone DHCP entries found\n", len(MACs))

		fmt.Printf("Pruning duplicate DHCP entries\n")
		for k, dhcp := range existingDHCP {
			for i, d := range MACs {
				if dhcp.Comment == d.Comment && dhcp.Server == d.Server && dhcp.IP.String() == d.IP.String() && dhcp.MAC.String() == d.MAC.String() {
					// Delete found element from both lists.
					MACs = append(MACs[:i], MACs[i+1:]...)
					delete(existingDHCP, k)
					break
				}
			}
		}

		fmt.Printf("%d existing DHCP entries to be removed\n", len(existingDHCP))
		for k, v := range existingDHCP {
			fmt.Printf("  %v: %v\n", k, v)
			if !*debug {
				if err := mt.DelDHCP(ctx, k); err != nil {
					log.Printf("unable to remove DHCP entry (%v, %v): %v", k, v, err)
				}
			}
		}

		fmt.Printf("%d missing DHCP entries to be added\n", len(MACs))
		for k, v := range MACs {
			fmt.Printf("  %v: %v\n", k, v)
			if !*debug {
				if err := mt.AddDHCP(ctx, v); err != nil {
					log.Printf("unable to add DHCP entry (%v, %v): %v", k, v, err)
				}
			}
		}
	}
}

func mapComments(cmt string) map[string]string {
	m := make(map[string]string, 2)
	for _, c := range strings.Fields(strings.TrimPrefix(cmt, ";")) {
		if pos := strings.Index(c, ":"); pos < 0 {
			m[c] = ""
		} else {
			m[c[:pos]] = c[pos+1:]
		}
	}
	return m
}
