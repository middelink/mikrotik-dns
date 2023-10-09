package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	ros "github.com/go-routeros/routeros"
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
	conn   net.Conn
	client *ros.Client
	lock   sync.Mutex // prevent AddRR/DelRR racing

	Name string

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

// Setup a deadline on the connection to the Mikrotik. It returns a cancel
// function, resetting the idle deadline on the connection.
func (mt *Mikrotik) startDeadline(duration time.Duration) func() {
	_ = mt.conn.SetDeadline(time.Now().Add(duration))
	return func() { _ = mt.conn.SetDeadline(time.Time{}) }
}

// NewMikrotik returns an initialized Mikrotik object.
func NewMikrotik(name, address, user, passwd string, useTLS bool) (*Mikrotik, error) {
	// Add port 8728/8729 if it was not included
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		// For anything else than missing port, bail.
		if !strings.Contains(err.Error(), "missing port in address") {
			return nil, fmt.Errorf("%s: malformed address: %v", name, err)
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
	// Open the connection, use our own code for this, as we need
	// access to it for setting deadlines.
	dialer := new(net.Dialer)
	dialer.Timeout = time.Minute
	if useTLS {
		mt.conn, err = tls.DialWithDialer(dialer, "tcp", mt.Address, nil)
	} else {
		mt.conn, err = dialer.Dial("tcp", mt.Address)
	}
	if err != nil {
		return nil, err
	}
	mt.client, err = ros.NewClient(mt.conn)
	if err != nil {
		mt.conn.Close()
		return nil, err
	}

	cancel := mt.startDeadline(5 * time.Second)
	err = mt.client.Login(mt.User, mt.Passwd)
	cancel()
	if err != nil {
		mt.client.Close()
		return nil, err
	}

	if _, err := mt.fetchDNSlist(); err != nil {
		mt.client.Close()
		return nil, err
	}

	return mt, nil
}

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

func (mt *Mikrotik) fetchDNSlist() (map[string]dns.RR, error) {

	cancel := mt.startDeadline(5 * time.Second)
	reply, err := mt.client.Run("/ip/dns/static/print", ".proplist=type")
	cancel()
	if err != nil {
		return nil, err
	}
	rrs := make(map[string]dns.RR, len(reply.Re))
	var rr dns.RR
	for _, re := range reply.Re {
		switch re.Map["type"] {
		case "": // mikrotik 6.47.3+ no longer return the type for "A" records. (Why? Is it the default?)
			fallthrough
		case "A":
			// dns entry: "!re @ [{`.id` `*1`} {`name` `router.polyware.nl`} {`type` `A`} {`address` `192.168.10.1`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
			// dns.A{Hdr:dns.RR_Header{Name:"router.polyware.nl", Rrtype:0x1, Class:0x1, Ttl:0x15180, Rdlength:0x0}, A:net.IP(nil)}
			r := new(dns.A)
			r.Hdr = dns.RR_Header{Name: re.Map["name"], Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: toDuration(re.Map["ttl"])}
			r.A = net.ParseIP(re.Map["address"])
			rr = r
		case "AAAA":
			// dns entry: "!re @ [{`.id` `*6`} {`name` `rp1.polyware.nl`} {`type` `AAAA`} {`address` `2a02:58:96:ab00:2dda:94ea:a768:a3e5`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
			// dns.AAAA{Hdr:dns.RR_Header{Name:"rp1.polyware.nl", Rrtype:0x1c, Class:0x1, Ttl:0x15180, Rdlength:0x0}, AAAA:net.IP(nil)}
			r := new(dns.AAAA)
			r.Hdr = dns.RR_Header{Name: re.Map["name"], Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: toDuration(re.Map["ttl"])}
			r.AAAA = net.ParseIP(re.Map["address"])
			rr = r
		case "CNAME":
			r := new(dns.CNAME)
			r.Hdr = dns.RR_Header{Name: re.Map["name"], Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: toDuration(re.Map["ttl"])}
			r.Target = re.Map["cname"]
			rr = r
		case "MX":
			// dns entry: "!re @ [{`.id` `*13`} {`name` `2`} {`type` `MX`} {`mx-preference` `50`} {`mx-exchange` `smtp.polyware.nl`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
			// dns.MX{Hdr:dns.RR_Header{Name:"2", Rrtype:0xf, Class:0x1, Ttl:0x15180, Rdlength:0x0}, Preference:0x0, Mx:""}
			r := new(dns.MX)
			r.Hdr = dns.RR_Header{Name: re.Map["name"], Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: toDuration(re.Map["ttl"])}
			pref, _ := strconv.Atoi(re.Map["mx-preference"])
			r.Preference = uint16(pref)
			r.Mx = re.Map["mx-exchange"]
			rr = r
		case "NS":
			// dns entry: "!re @ [{`.id` `*16`} {`name` `5`} {`type` `NS`} {`ns` `something`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
			// dns.NS{Hdr:dns.RR_Header{Name:"5", Rrtype:0x2, Class:0x1, Ttl:0x15180, Rdlength:0x0}, Ns:""}
			r := new(dns.NS)
			r.Hdr = dns.RR_Header{Name: re.Map["name"], Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: toDuration(re.Map["ttl"])}
			r.Ns = re.Map["ns"]
			rr = r
		case "SRV":
			// dns entry: "!re @ [{`.id` `*14`} {`name` `3`} {`type` `SRV`} {`srv-priority` `1`} {`srv-weight` `2`} {`srv-port` `1883`} {`srv-target` `rp1.polyware.nl`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
			// dns.SRV{Hdr:dns.RR_Header{Name:"3", Rrtype:0x21, Class:0x1, Ttl:0x15180, Rdlength:0x0}, Priority:0x0, Weight:0x0, Port:0x0, Target:""}
			prio, _ := strconv.Atoi(re.Map["srv-priority"])
			weight, _ := strconv.Atoi(re.Map["srv-weight"])
			port, _ := strconv.Atoi(re.Map["srv-port"])
			r := new(dns.SRV)
			r.Hdr = dns.RR_Header{Name: re.Map["name"], Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: toDuration(re.Map["ttl"])}
			r.Priority = uint16(prio)
			r.Weight = uint16(weight)
			r.Port = uint16(port)
			r.Target = re.Map["srv-target"]
			rr = r
		case "TXT":
			//dns entry: "!re @ [{`.id` `*15`} {`name` `4`} {`type` `TXT`} {`text` `spf thingy`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
			// dns.TXT{Hdr:dns.RR_Header{Name:"4", Rrtype:0x10, Class:0x1, Ttl:0x15180, Rdlength:0x0}, Txt:[]string(nil)}
			r := new(dns.TXT)
			r.Hdr = dns.RR_Header{Name: re.Map["name"], Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: toDuration(re.Map["ttl"])}
			r.Txt = []string{re.Map["text"]}
			rr = r
		case "(unknown)":
			r := new(dns.NULL)
			r.Hdr = dns.RR_Header{Name: re.Map["name"], Rrtype: dns.TypeNULL, Class: dns.ClassINET, Ttl: toDuration(re.Map["ttl"])}
			rr = r
		default:
			return nil, fmt.Errorf("unknown dns type: %v", re)
		}
		rrs[re.Map[".id"]] = rr
	}
	return rrs, nil
}

// fetchDHCP returns a map of all the static DHCP leases on the Mikrotik.
func (mt *Mikrotik) fetchDHCP() (map[string]DHCP, error) {

	cancel := mt.startDeadline(5 * time.Second)
	reply, err := mt.client.Run("/ip/dhcp-server/lease/print")
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

// fetchDHCPNets returns a map of active dhcp server and the ip range they listen to.
func (mt *Mikrotik) fetchDHCPNets() (map[string][]*net.IPNet, error) {

	cancel := mt.startDeadline(5 * time.Second)
	reply, err := mt.client.Run("/ip/address/print")
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
			if intfs[name] == nil {
				intfs[name] = []*net.IPNet{ipnet}
			} else {
				intfs[name] = append(intfs[name], ipnet)
			}
		}
	}

	cancel = mt.startDeadline(5 * time.Second)
	reply, err = mt.client.Run("/ip/dhcp-server/print")
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
func (mt *Mikrotik) AddDNS(rr dns.RR, comment string) error {
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
	args := []string{
		"/ip/dns/static/add",
		fmt.Sprintf("=name=%s", rr.Header().Name),
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
		args = append(args, fmt.Sprintf("=cname=%s", rr.(*dns.CNAME).Target))
	case dns.TypeMX:
		// dns entry: "!re @ [{`.id` `*13`} {`name` `2`} {`type` `MX`} {`mx-preference` `50`} {`mx-exchange` `smtp.polyware.nl`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
		args = append(args, "=type=MX")
		args = append(args, fmt.Sprintf("=mx-preference=%d", rr.(*dns.MX).Preference))
		args = append(args, fmt.Sprintf("=mx-exchange=%s", rr.(*dns.MX).Mx))
	case dns.TypeNS:
		// dns entry: "!re @ [{`.id` `*16`} {`name` `5`} {`type` `NS`} {`ns` `something`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
		args = append(args, "=type=NS")
		args = append(args, fmt.Sprintf("=ns=%s", rr.(*dns.NS).Ns))
	case dns.TypeSRV:
		// dns entry: "!re @ [{`.id` `*14`} {`name` `3`} {`type` `SRV`} {`srv-priority` `1`} {`srv-weight` `2`} {`srv-port` `1883`} {`srv-target` `rp1.polyware.nl`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
		args = append(args, "=type=SRV")
		args = append(args, fmt.Sprintf("=srv-priority=%d", rr.(*dns.SRV).Priority))
		args = append(args, fmt.Sprintf("=srv-weight=%d", rr.(*dns.SRV).Weight))
		args = append(args, fmt.Sprintf("=srv-port=%d", rr.(*dns.SRV).Port))
		args = append(args, fmt.Sprintf("=srv-target=%s", rr.(*dns.SRV).Target))
	case dns.TypeTXT:
		//dns entry: "!re @ [{`.id` `*15`} {`name` `4`} {`type` `TXT`} {`text` `spf thingy`} {`ttl` `1d`} {`dynamic` `false`} {`disabled` `false`}]"
		args = append(args, "=type=TXT")
		args = append(args, fmt.Sprintf("=text=%s", strings.Join(rr.(*dns.TXT).Txt, "\n")))
	default:
		return fmt.Errorf("unknown dns type: %v", rr)
	}
	if comment != "" {
		args = append(args, fmt.Sprintf("=comment=%s", comment))
	}
	if *debug {
		return nil
	}
	cancel := mt.startDeadline(5 * time.Second)
	reply, err := mt.client.RunArgs(args)
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
func (mt *Mikrotik) DelDNS(entry string) error {
	// Protect against racing DelIP/AddIPs.
	mt.lock.Lock()
	defer mt.lock.Unlock()
	if *debug {
		return nil
	}

	cancel := mt.startDeadline(5 * time.Second)
	selector := fmt.Sprintf("=.id=%s", entry)
	_, err := mt.client.Run("/ip/dns/static/remove", selector)
	cancel()

	return err
}

// AddDHCP adds a DHCP entry for the given argument.
func (mt *Mikrotik) AddDHCP(d DHCP) error {
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
	cancel := mt.startDeadline(5 * time.Second)
	reply, err := mt.client.RunArgs(args)
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
func (mt *Mikrotik) DelDHCP(entry string) error {
	// Protect against racing DelIP/AddIPs.
	mt.lock.Lock()
	defer mt.lock.Unlock()
	if *debug {
		return nil
	}

	cancel := mt.startDeadline(5 * time.Second)
	selector := fmt.Sprintf("=.id=%s", entry)
	_, err := mt.client.Run("/ip/dhcp-server/lease/remove", selector)
	cancel()

	return err
}

// Close closes the session with the mikrotik.
func (mt *Mikrotik) Close() {
	mt.client.Close()
}
