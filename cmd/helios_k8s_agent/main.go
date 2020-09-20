package main

import (
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

var calicoPattern = "cali"
var flannelPattern = "flannel"

func main() {
	l, _ := ListenNetlink()

	for {
		msgs, err := l.ReadMsgs()
		if err != nil {
			fmt.Println("Could not read netlink: %s", err)
		}

		for _, m := range msgs {
			if IsNewAddr(&m) {
				fmt.Println("New Addr")
				addr, family, ifindex, err := parseAddr(m.Data)
				if err != nil {
					fmt.Println("Failed to parse newlink message: %s", err)
					continue
				}
				onAddressAdded(addr, family, int64(ifindex))
			}

			if IsDelAddr(&m) {
				fmt.Println("Del Addr")
				addr, family, ifindex, err := parseAddr(m.Data)
				if err != nil {
					fmt.Println("Failed to parse newlink message: %s", err)
					continue
				}
				onAddressDeleted(addr, family, int64(ifindex))
			}

			if IsNewLink(&m) {
				fmt.Println("New Link")
				link, err := netlink.LinkDeserialize(nil, m.Data)
				if err != nil {
					fmt.Println("Netlink ADD event for %s(%d,%s) ", link.Attrs().Name, link.Attrs().Index, link.Type())
					continue
				}
				onLinkAdded(link)
			}

			if IsDelLink(&m) {
				fmt.Println("Del Link")
				link, err := netlink.LinkDeserialize(nil, m.Data)
				if err != nil {
					fmt.Println("Netlink DEL event for %s(%d) ", link.Attrs().Name, link.Attrs().Index)
					continue
				}
				onLinkDeleted(link)
			}
		}
	}
}

type NetlinkListener struct {
	fd int
	sa *syscall.SockaddrNetlink
}

func parseAddr(m []byte) (addr netlink.Addr, family, index int, err error) {
	msg := nl.DeserializeIfAddrmsg(m)

	family = -1
	index = -1

	attrs, err1 := nl.ParseRouteAttr(m[msg.Len():])
	if err1 != nil {
		err = err1
		return
	}

	family = int(msg.Family)
	index = int(msg.Index)

	var local, dst *net.IPNet
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case syscall.IFA_ADDRESS:
			dst = &net.IPNet{
				IP:   attr.Value,
				Mask: net.CIDRMask(int(msg.Prefixlen), 8*len(attr.Value)),
			}
			addr.Peer = dst
		case syscall.IFA_LOCAL:
			local = &net.IPNet{
				IP:   attr.Value,
				Mask: net.CIDRMask(int(msg.Prefixlen), 8*len(attr.Value)),
			}
			addr.IPNet = local
		}
	}

	// IFA_LOCAL should be there but if not, fall back to IFA_ADDRESS
	if local != nil {
		addr.IPNet = local
	} else {
		addr.IPNet = dst
	}
	addr.Scope = int(msg.Scope)

	return
}

func cniType(intfName string) (cniIntfType string, err error) {
	if strings.Contains(intfName, calicoPattern) {
		return calicoPattern, nil
	}

	if strings.Contains(intfName, flannelPattern) {
		return flannelPattern, nil
	}

	return nil, nil
}

func calicoLinkAdded(linkName string) error {
	k8sPodExtractWithIntfCMD = "kubectl get pods -n default -o wide --field-selector spec.nodeName=%s | awk 'NR != 1 { print $1}'"

	cmd = fmt.Sprintf(k8sPodExtractWithIntfCMD, linkName)
	// TODO 2. 현재 노드의 모든 POD 추출
	// kubectl get pods -n default -o wide --field-selector spec.nodeName=node6 | awk 'NR != 1 { print $1}'
	/*
		busybox1
	*/

	// TODO 3. 모든 POD 를 돌면서 해당 Interface 의 소유자 POD 찾음
	/* for pod in pods :
	cniguru pod $pod | awk 'NR == 3 { print }' | grep $intfName
	*/

	// TODO 4. POD 의 상세 정보 추출
	/*
		CONTAINER_ID  PID    NODE   INTF(C)  MAC_ADDRESS(C)     IP_ADDRESS(C)    INTF(N)          BRIDGE(N)
		aa9bcc46184b  25564  node6  eth0     8a:b4:c5:1c:20:9c  10.233.108.3/32  cali4405ed05989  -
	*/

	// TODO 5. Detach Container Interface & Allocation Helios VIF

	// TODO 6. Update Helios VIF DB
}

func flannelLinkAdded(linkName string) error {

}

func onLinkAdded(link netlink.Link) error {
	// has been deleted
	intfName := link.Attrs().Name

	if intfType, err := cniType(intfName); err != nil {
		// TODO 1. Determine Link Types (Calico, eBPF, etc)
		if intfType == calicoPattern {
			err = calicoLinkAdded(intfName)
		} else if intfType == flannelPattern {
			err = flannelLinkAdded(intfName)
		}
		return err
	}
}

func onLinkDeleted(link netlink.Link) {
	index := int64(link.Attrs().Index)
	name := link.Attrs().Name

	if _, err := nl.LinkByIndex(index); err != nil {
		// TODO 1. Determine Link Types (Calico, eBPF, etc)

		// TODO 2. Extract Interface Number (ex: 22: cali0d5af60a6c5@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> ==> number is 22)

		// TODO 3. Find Container ID which is connected with this Link

		// TODO 4. Extract Container Interface informations(MAC, IP, etc) using (#Container_ID, #Interface_Number, ex:nsenter -t #Container_ID -n ip addr | grep #Interface_Number)

		// TODO 5. Deallcation Helios VIF

		// TODO 6. Update Helios VIF DB

		return
	}
}

func onAddressAdded(addr netlink.Addr, family int, index int64) {
	return
}

func onAddressDeleted(addr netlink.Addr, family int, index int64) {
	return
}

func ListenNetlink() (*NetlinkListener, error) {
	groups := (1 << (syscall.RTNLGRP_LINK - 1)) |
		(1 << (syscall.RTNLGRP_IPV4_IFADDR - 1)) |
		(1 << (syscall.RTNLGRP_IPV6_IFADDR - 1))

	s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM,
		syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("socket: %s", err)
	}

	saddr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    uint32(0),
		Groups: uint32(groups),
	}

	err = syscall.Bind(s, saddr)
	if err != nil {
		return nil, fmt.Errorf("bind: %s", err)
	}

	return &NetlinkListener{fd: s, sa: saddr}, nil
}

func (l *NetlinkListener) ReadMsgs() ([]syscall.NetlinkMessage, error) {
	defer func() {
		recover()
	}()

	pkt := make([]byte, 2048)

	n, err := syscall.Read(l.fd, pkt)
	if err != nil {
		return nil, fmt.Errorf("read: %s", err)
	}

	msgs, err := syscall.ParseNetlinkMessage(pkt[:n])
	if err != nil {
		return nil, fmt.Errorf("parse: %s", err)
	}

	return msgs, nil
}

func IsNewAddr(msg *syscall.NetlinkMessage) bool {
	if msg.Header.Type == syscall.RTM_NEWADDR {
		return true
	}

	return false
}

func IsDelAddr(msg *syscall.NetlinkMessage) bool {
	if msg.Header.Type == syscall.RTM_DELADDR {
		return true
	}

	return false
}

func IsNewLink(msg *syscall.NetlinkMessage) bool {
	if msg.Header.Type == syscall.RTM_NEWLINK {
		return true
	}

	return false
}

func IsDelLink(msg *syscall.NetlinkMessage) bool {
	if msg.Header.Type == syscall.RTM_DELLINK {
		return true
	}

	return false
}

// rtm_scope is the distance to the destination:
//
// RT_SCOPE_UNIVERSE   global route
// RT_SCOPE_SITE       interior route in the
// local autonomous system
// RT_SCOPE_LINK       route on this link
// RT_SCOPE_HOST       route on the local host
// RT_SCOPE_NOWHERE    destination doesn't exist
//
// The values between RT_SCOPE_UNIVERSE and RT_SCOPE_SITE are
// available to the user.

func IsRelevant(msg *syscall.IfAddrmsg) bool {
	if msg.Scope == syscall.RT_SCOPE_UNIVERSE ||
		msg.Scope == syscall.RT_SCOPE_SITE {
		return true
	}

	return false
}
