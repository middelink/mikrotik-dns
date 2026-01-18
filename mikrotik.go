package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"
	ros "github.com/go-routeros/routeros/v3"
	"github.com/miekg/dns"
)

var (
	// 28w4d23h59m56s
	regTimeout = regexp.MustCompile(`(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?`)
)

// Mikrotik contains the internal state of a Mikrotik object, configuration
// details but also the API connection to the Mikrotik. It acts as a cache
// between the rest of the program and the Mikrotik.
type Mikrotik struct {
	client   *ros.Client
	lock     sync.Mutex // prevent AddRR/DelRR racing
	needDots bool       // Version >= 7.17

	Name    string
	Version *semver.Version // E.g. 7.17

	Address string
	User    string
	Passwd  string
}

// DHCP contains a single dhcp entry.
type DHCP struct {
	Comment string // the comment for the dhcp entry.
	Server  string // one of the MTs dhcp servers.
	IP      net.IP
	MAC     net.HardwareAddr
}

func (d DHCP) String() string {
	return fmt.Sprintf("{%q %v %v %v}", d.Comment, d.Server, d.IP, d.MAC)
}

// NewMikrotik returns an initialized Mikrotik object, a closer and an error.
func NewMikrotik(ctx context.Context, name, address, user, passwd string, useTLS bool) (*Mikrotik, func(context.Context) error, error) {
	// Add port 8728/8729 if it was not included
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		// For anything else than missing port, bail.
		if !strings.Contains(err.Error(), "missing port in address") {
			return nil, nil, fmt.Errorf("%s: malformed address: %v", name, err)
		}
		if useTLS {
			address = net.JoinHostPort(address, "8729")
		} else {
			address = net.JoinHostPort(address, "8728")
		}
	}

	if *debug {
		log.Printf("NewMikrotik(name=%s, address=%s, user=%s, passwd=%s)\n", name, address, user, passwd)
	} else if *verbose {
		log.Printf("NewMikrotik(name=%s)\n", name)
	}

	mt := &Mikrotik{
		Name:    name,
		Address: address,
		User:    user,
		Passwd:  passwd,
	}
	dialctx, cancel := context.WithTimeout(ctx, time.Minute)
	if useTLS {
		mt.client, err = ros.DialTLSContext(dialctx, mt.Address, mt.User, mt.Passwd, nil)
	} else {
		mt.client, err = ros.DialContext(dialctx, mt.Address, mt.User, mt.Passwd)
	}
	cancel()
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			cerr := mt.client.Close()
			if cerr != nil {
				err = fmt.Errorf("error closing object: %w, original error: %w", cerr, err)
			}
		}
	}()

	if mt.Version, err = mt.fetchVersion(ctx); err != nil {
		return nil, nil, err
	}
	c, err := semver.NewConstraint(">= 7.17")
	if err != nil {
		return nil, nil, err
	}
	mt.needDots = c.Check(mt.Version)

	return mt, func(ctx context.Context) error { return mt.client.Close() }, nil
}

// fetchVersion returns the active running firmware version.
func (mt *Mikrotik) fetchVersion(ctx context.Context) (*semver.Version, error) {
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	reply, err := mt.client.RunContext(rctx, "/system/routerboard/print")
	cancel()
	if err != nil {
		return nil, fmt.Errorf("fetchVersion=%v", err)
	}
	for _, re := range reply.Re {
		if v, ok := re.Map["current-firmware"]; ok {
			return semver.NewVersion(v)
		}
	}
	return nil, fmt.Errorf("missing `current-firmware`")
}

// Convert the MT duration of weeks, days, hours, minute and seconds to a single seconds number.
func toDuration(ttl string) uint32 {
	res := regTimeout.FindStringSubmatch(ttl)
	var duration time.Duration
	if res[1] != "" {
		weeks, _ := strconv.Atoi(res[1])
		duration += time.Duration(weeks) * 7 * 24 * time.Hour
	}
	if res[2] != "" {
		days, _ := strconv.Atoi(res[2])
		duration += time.Duration(days) * 24 * time.Hour
	}
	if res[3] != "" {
		hours, _ := strconv.Atoi(res[3])
		duration += time.Duration(hours) * time.Hour
	}
	if res[4] != "" {
		minutes, _ := strconv.Atoi(res[4])
		duration += time.Duration(minutes) * time.Minute
	}
	if res[5] != "" {
		seconds, _ := strconv.Atoi(res[5])
		duration += time.Duration(seconds) * time.Second
	}
	return uint32(duration.Seconds())
}

// Convert a single seconds number into the MT days, hours, minutes and seconds duration.
func toSeconds(seconds uint32) string {
	dur := time.Duration(seconds) * time.Second
	str := ""
	if dur >= 24*time.Hour {
		days := int(dur / 24 / time.Hour)
		str = fmt.Sprintf("%dd ", days)
		dur -= time.Duration(days) * 24 * time.Hour
	}
	str += fmt.Sprintf("%02d:%02d:%02d", dur/time.Hour, dur/time.Minute%60, dur/time.Second%60)
	return str
}

func nameToRegexp(s string) string {
	if !strings.HasPrefix(s, "*.") {
		return s
	}

	// Detected wildcard RR. See https://en.wikipedia.org/wiki/Wildcard_DNS_record
	s = strings.TrimSuffix(s[1:], ".")
	return "^.*" + strings.ReplaceAll(s, ".", "\\.") + "$"
}

func regexpToName(s string) string {
	s = strings.TrimPrefix(s, "^")
	s = strings.ReplaceAll(s, ".*", "*")
	s = strings.TrimSuffix(s, "$")
	return strings.ReplaceAll(s, "\\.", ".")
}

func (mt *Mikrotik) fromFQDN(s string) string {
	if mt.needDots {
		return strings.TrimSuffix(s, ".")
	}
	return s
}

func (mt *Mikrotik) toFQDN(s string) string {
	if mt.needDots {
		return strings.TrimSuffix(s, ".") + "."
	}
	return s
}

// FetchDNSlist returns a map of resource records, indexed by the name.
// It handles regexps and ensures names are fqdn (ending with a dot).
func (mt *Mikrotik) FetchDNSlist(ctx context.Context) (map[string]dns.RR, error) {
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	reply, err := mt.client.RunContext(rctx, "/ip/dns/static/print", ".proplist=type")
	cancel()
	if err != nil {
		return nil, err
	}
	rrs := make(map[string]dns.RR, len(reply.Re))
	var rr dns.RR
	for _, re := range reply.Re {
		ttl := toDuration(re.Map["ttl"])
		name := mt.toFQDN(re.Map["name"])
		if v, ok := re.Map["regexp"]; ok {
			name = mt.toFQDN(regexpToName(v))
		}
		switch re.Map["type"] {
		case "": // mikrotik 6.47.3+ no longer return the type for "A" records. (Why? Is it the default?)
			fallthrough
		case "A":
			// dns entry: "!re @ [{`.id` `*1`} {`name` `router.polyware.nl`} {`type` `A`} {`address` `192.168.10.1`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
			// dns.A{Hdr:dns.RR_Header{Name:"router.polyware.nl", Rrtype:0x1, Class:0x1, Ttl:0x15180, Rdlength:0x0}, A:net.IP(nil)}
			r := new(dns.A)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			r.A = net.ParseIP(re.Map["address"])
			rr = r
		case "AAAA":
			// dns entry: "!re @ [{`.id` `*6`} {`name` `rp1.polyware.nl`} {`type` `AAAA`} {`address` `2a02:58:96:ab00:2dda:94ea:a768:a3e5`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
			// dns.AAAA{Hdr:dns.RR_Header{Name:"rp1.polyware.nl", Rrtype:0x1c, Class:0x1, Ttl:0x15180, Rdlength:0x0}, AAAA:net.IP(nil)}
			r := new(dns.AAAA)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			r.AAAA = net.ParseIP(re.Map["address"])
			rr = r
		case "CNAME":
			r := new(dns.CNAME)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl}
			r.Target = mt.toFQDN(re.Map["cname"])
			rr = r
		case "MX":
			// dns entry: "!re @ [{`.id` `*13`} {`name` `2`} {`type` `MX`} {`mx-preference` `50`} {`mx-exchange` `smtp.polyware.nl`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
			// dns.MX{Hdr:dns.RR_Header{Name:"2", Rrtype:0xf, Class:0x1, Ttl:0x15180, Rdlength:0x0}, Preference:0x0, Mx:""}
			r := new(dns.MX)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl}
			pref, _ := strconv.Atoi(re.Map["mx-preference"])
			r.Preference = uint16(pref)
			r.Mx = mt.toFQDN(re.Map["mx-exchange"])
			rr = r
		case "NS":
			// dns entry: "!re @ [{`.id` `*16`} {`name` `5`} {`type` `NS`} {`ns` `something`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
			// dns.NS{Hdr:dns.RR_Header{Name:"5", Rrtype:0x2, Class:0x1, Ttl:0x15180, Rdlength:0x0}, Ns:""}
			r := new(dns.NS)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl}
			r.Ns = mt.toFQDN(re.Map["ns"])
			rr = r
		case "SRV":
			// dns entry: "!re @ [{`.id` `*14`} {`name` `3`} {`type` `SRV`} {`srv-priority` `1`} {`srv-weight` `2`} {`srv-port` `1883`} {`srv-target` `rp1.polyware.nl`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
			// dns.SRV{Hdr:dns.RR_Header{Name:"3", Rrtype:0x21, Class:0x1, Ttl:0x15180, Rdlength:0x0}, Priority:0x0, Weight:0x0, Port:0x0, Target:""}
			prio, _ := strconv.Atoi(re.Map["srv-priority"])
			weight, _ := strconv.Atoi(re.Map["srv-weight"])
			port, _ := strconv.Atoi(re.Map["srv-port"])
			r := new(dns.SRV)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl}
			r.Priority = uint16(prio)
			r.Weight = uint16(weight)
			r.Port = uint16(port)
			r.Target = mt.toFQDN(re.Map["srv-target"])
			rr = r
		case "TXT":
			//dns entry: "!re @ [{`.id` `*15`} {`name` `4`} {`type` `TXT`} {`text` `spf thingy`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
			// dns.TXT{Hdr:dns.RR_Header{Name:"4", Rrtype:0x10, Class:0x1, Ttl:0x15180, Rdlength:0x0}, Txt:[]string(nil)}
			r := new(dns.TXT)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}
			r.Txt = []string{re.Map["text"]}
			rr = r
		case "(unknown)":
			r := new(dns.NULL)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeNULL, Class: dns.ClassINET, Ttl: ttl}
			rr = r
		case "FWD":
			//dns entry: "!re @ [{`.id` `*56F`} {`regexp` `^.*\.d\.polyware\.nl$`} {`type` `FWD`} {`forward-to` `192.168.40.44`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
			r := new(dns.NULL)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeNULL, Class: dns.ClassINET, Ttl: ttl}
			r.Data = re.Map["forward-to"]
			rr = r
		default:
			return nil, fmt.Errorf("unknown dns type: %v", re)
		}
		rrs[re.Map[".id"]] = rr
	}
	return rrs, nil
}

// FetchDHCP returns a map of all the static DHCP leases on the Mikrotik.
func (mt *Mikrotik) FetchDHCP(ctx context.Context) (map[string]DHCP, error) {

	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	reply, err := mt.client.RunContext(rctx, "/ip/dhcp-server/lease/print")
	cancel()
	if err != nil {
		return nil, err
	}
	macs := make(map[string]DHCP, len(reply.Re))
	// dhcp: map[.id:*7B address:192.168.10.2 address-lists: blocked:false comment:pve dhcp-option: disabled:false dynamic:false last-seen:3d10h3m53s mac-address:60:45:CB:A8:76:7D radius:false server:dhcp1 status:waiting]
	for _, re := range reply.Re {
		if re.Map["dynamic"] == "false" {
			ip := net.ParseIP(re.Map["address"])
			mac, _ := net.ParseMAC(re.Map["mac-address"])
			macs[re.Map[".id"]] = DHCP{Comment: re.Map["comment"], Server: re.Map["server"], IP: ip, MAC: mac}
		}
	}
	return macs, nil
}

// FetchDHCPNets returns a map of active dhcp server and the ip range they listen to.
func (mt *Mikrotik) FetchDHCPNets(ctx context.Context) (map[string][]*net.IPNet, error) {
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	reply, err := mt.client.RunContext(rctx, "/ip/address/print")
	cancel()
	if err != nil {
		return nil, err
	}
	intfs := make(map[string][]*net.IPNet, len(reply.Re))
	for _, re := range reply.Re {
		// map[.id:*1 actual-interface:bridge-local address:192.168.10.1/24 disabled:false dynamic:false interface:bridge-local invalid:false network:192.168.10.0]
		if re.Map["disabled"] == "false" && re.Map["dynamic"] == "false" {
			_, ipnet, err := net.ParseCIDR(re.Map["address"])
			if err != nil {
				return nil, err
			}
			name := re.Map["actual-interface"]
			intfs[name] = append(intfs[name], ipnet)
		}
	}

	rctx, cancel = context.WithTimeout(ctx, 5*time.Second)
	reply, err = mt.client.RunContext(rctx, "/ip/dhcp-server/print")
	cancel()
	if err != nil {
		return nil, err
	}
	dhcps := make(map[string][]*net.IPNet, len(reply.Re))
	for _, re := range reply.Re {
		// map[.id:*1 address-pool:default-dhcp authoritative:yes disabled:false dynamic:false interface:bridge-local invalid:false lease-script: lease-time:20m name:dhcp1 use-radius:no]
		if re.Map["disabled"] == "false" && re.Map["dynamic"] == "false" {
			name := re.Map["name"]
			intf := re.Map["interface"]
			if ips := intfs[intf]; ips != nil {
				dhcps[name] = ips
			} else {
				return nil, fmt.Errorf("dhcp server %q has an unknown, disabled or dynamic interface (%s)", name, intf)
			}
		}
	}

	return dhcps, nil
}

// AddDNS will add the given ip address to the Mikrotik, when duration is 0,
// the entry is seen as permanent and the white and blacklist are not checked
// for duplicates. Conflicts on those lists are checked when the configuration
// is read. It protects against double adding, as that will make the Mikrotik
// spit out an error which in the current implementation leads to a program
// restart. For all timeouts != 0, the index returned over the Mikrotik
// connection is stored, together with the IP itself, in the dynlist entry.
func (mt *Mikrotik) AddDNS(ctx context.Context, rr dns.RR, comment string) error {
	if *debug || *verbose {
		defer log.Printf("%s: AddDNS(%s) finished", mt.Name, rr)
	}
	// Protect against racing DelIP/AddIPs.
	mt.lock.Lock()
	defer mt.lock.Unlock()

	if *debug || *verbose {
		log.Printf("%s: AddDNS(%s) started", mt.Name, rr)
	}

	// Do the physical interaction with the MT.
	cmd := fmt.Sprintf("=name=%s", mt.fromFQDN(rr.Header().Name))
	if strings.HasPrefix(rr.Header().Name, "*.") {
		cmd = fmt.Sprintf("=regexp=%s", mt.fromFQDN(nameToRegexp(rr.Header().Name)))
	}
	args := []string{
		"/ip/dns/static/add",
		cmd,
		fmt.Sprintf("=ttl=%s", toSeconds(rr.Header().Ttl)),
	}
	switch rr.Header().Rrtype {
	case dns.TypeA:
		// dns entry: "!re @ [{`.id` `*1`} {`name` `router.polyware.nl`} {`type` `A`} {`address` `192.168.10.1`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
		args = append(args, "=type=A")
		args = append(args, fmt.Sprintf("=address=%s", rr.(*dns.A).A))
	case dns.TypeAAAA:
		// dns entry: "!re @ [{`.id` `*6`} {`name` `rp1.polyware.nl`} {`type` `AAAA`} {`address` `2a02:58:96:ab00:2dda:94ea:a768:a3e5`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
		args = append(args, "=type=AAAA")
		args = append(args, fmt.Sprintf("=address=%s", rr.(*dns.AAAA).AAAA))
	case dns.TypeCNAME:
		args = append(args, "=type=CNAME")
		args = append(args, fmt.Sprintf("=cname=%s", mt.fromFQDN(rr.(*dns.CNAME).Target)))
	case dns.TypeMX:
		// dns entry: "!re @ [{`.id` `*13`} {`name` `2`} {`type` `MX`} {`mx-preference` `50`} {`mx-exchange` `smtp.polyware.nl`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
		args = append(args, "=type=MX")
		args = append(args, fmt.Sprintf("=mx-preference=%d", rr.(*dns.MX).Preference))
		args = append(args, fmt.Sprintf("=mx-exchange=%s", mt.fromFQDN(rr.(*dns.MX).Mx)))
	case dns.TypeNS:
		// dns entry: "!re @ [{`.id` `*16`} {`name` `5`} {`type` `NS`} {`ns` `something`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
		args = append(args, "=type=NS")
		args = append(args, fmt.Sprintf("=ns=%s", mt.fromFQDN(rr.(*dns.NS).Ns)))
	case dns.TypeSRV:
		// dns entry: "!re @ [{`.id` `*14`} {`name` `3`} {`type` `SRV`} {`srv-priority` `1`} {`srv-weight` `2`} {`srv-port` `1883`} {`srv-target` `rp1.polyware.nl`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
		args = append(args, "=type=SRV")
		args = append(args, fmt.Sprintf("=srv-priority=%d", rr.(*dns.SRV).Priority))
		args = append(args, fmt.Sprintf("=srv-weight=%d", rr.(*dns.SRV).Weight))
		args = append(args, fmt.Sprintf("=srv-port=%d", rr.(*dns.SRV).Port))
		args = append(args, fmt.Sprintf("=srv-target=%s", mt.fromFQDN(rr.(*dns.SRV).Target)))
	case dns.TypeTXT:
		//dns entry: "!re @ [{`.id` `*15`} {`name` `4`} {`type` `TXT`} {`text` `spf thingy`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
		args = append(args, "=type=TXT")
		args = append(args, fmt.Sprintf("=text=%s", strings.Join(rr.(*dns.TXT).Txt, "\n")))
	case dns.TypeNULL:
		//dns entry: ;*.d.polyware.nl.	86400	IN	NULL	192.168.40.44
		args = append(args, "=type=FWD")
		args = append(args, fmt.Sprintf("=forward-to=%s", rr.(*dns.NULL).Data))
	default:
		return fmt.Errorf("unknown dns type: %v", rr)
	}
	if comment != "" {
		args = append(args, fmt.Sprintf("=comment=%s", comment))
	}
	if *debug {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	reply, err := mt.client.RunArgsContext(rctx, args)
	cancel()
	if err != nil {
		if strings.Contains(err.Error(), "already have") {
			return nil
		}
		return fmt.Errorf("adddns=%v", err)
	}
	if _, ok := reply.Done.Map["ret"]; !ok {
		return fmt.Errorf("missing `ret`")
	}
	return nil
}

// DelDNS removes an DNS entry from the Mikrotik.
func (mt *Mikrotik) DelDNS(ctx context.Context, entry string) error {
	// Protect against racing DelIP/AddIPs.
	mt.lock.Lock()
	defer mt.lock.Unlock()
	if *debug {
		return nil
	}

	selector := fmt.Sprintf("=.id=%s", entry)
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	_, err := mt.client.RunContext(rctx, "/ip/dns/static/remove", selector)
	cancel()

	return err
}

// AddDHCP adds a DHCP entry for the given argument.
func (mt *Mikrotik) AddDHCP(ctx context.Context, d DHCP) error {
	if *debug || *verbose {
		defer log.Printf("%s: AddDHCP(%s) finished", mt.Name, d)
	}
	// Protect against racing DelIP/AddIPs.
	mt.lock.Lock()
	defer mt.lock.Unlock()

	if *debug || *verbose {
		log.Printf("%s: AddDHCP(%s) started", mt.Name, d)
	}
	if *debug {
		return nil
	}

	// Do the physical interaction with the MT.
	args := []string{
		"/ip/dhcp-server/lease/add",
		fmt.Sprintf("=comment=%s", d.Comment),
		fmt.Sprintf("=address=%s", d.IP),
		fmt.Sprintf("=mac-address=%s", d.MAC),
		fmt.Sprintf("=server=%s", d.Server),
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	reply, err := mt.client.RunArgsContext(rctx, args)
	cancel()
	if err != nil {
		//if strings.Contains(err.Error(), "already have") {
		//	return nil
		//}
		return fmt.Errorf("adddhcp=%v", err)
	}
	if _, ok := reply.Done.Map["ret"]; !ok {
		return fmt.Errorf("missing `ret`")
	}
	return nil
}

// DelDHCP removes an DHCP entry from the Mikrotik.
func (mt *Mikrotik) DelDHCP(ctx context.Context, entry string) error {
	// Protect against racing DelIP/AddIPs.
	mt.lock.Lock()
	defer mt.lock.Unlock()
	if *debug {
		return nil
	}

	selector := fmt.Sprintf("=.id=%s", entry)
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	_, err := mt.client.RunContext(rctx, "/ip/dhcp-server/lease/remove", selector)
	cancel()

	return err
}
