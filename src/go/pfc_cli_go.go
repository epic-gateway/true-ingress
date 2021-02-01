package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	pfc "gitlab.com/acnodal/packet-forwarding-component/src/go/pfc"
)

var version string // initialized by gitlab CI via Makefile and ldflags
var commit string  // initialized by gitlab CI via Makefile and ldflags

func main() {
	if len(os.Args) < 2 {
		fmt.Println(os.Args[0], "version")
		fmt.Println(os.Args[0], "check")
		fmt.Println(os.Args[0], "add <interface> <group-id> <service-id> <pwd> <proto> <proxy-ip> <proxy-port> <service-ip> <service-port> <gue-ip> <gue-port>")
		fmt.Println(os.Args[0], "del <group-id> <service-id>")
		fmt.Println(os.Args[0], "list")
		fmt.Println(os.Args[0], "help")
		return
	}

	switch os.Args[1] {
	case "version":
		fmt.Println(version, commit)

	case "check":
		check, err := pfc.Check()
		if check {
			fmt.Printf("PFC ready: %s\n", err)
		} else {
			fmt.Println(err)
		}

	case "add":
		if len(os.Args) < 11 {
			fmt.Println(os.Args[0], " add <interface> <group-id> <service-id> <pwd> <proto> <proxy-ip> <proxy-port> <service-ip> <service-port> <gue-ip> <gue-port>")
			return
		}

		gid, _ := strconv.Atoi(os.Args[3])
		sid, _ := strconv.Atoi(os.Args[4])
		pip := net.ParseIP(os.Args[7])
		pport, _ := strconv.Atoi(os.Args[8])
		sip := net.ParseIP(os.Args[9])
		sport, _ := strconv.Atoi(os.Args[10])
		tip := net.ParseIP(os.Args[11])
		tport, _ := strconv.Atoi(os.Args[12])

		ip, port, err := pfc.ForwardingAdd(os.Args[2], gid, sid, os.Args[5], os.Args[6], pip, pport, sip, sport, tip, tport)
		if err != nil {
			log.Println(err)
		}
		fmt.Printf("EGW GUE endpoint: %s:%d\n", ip, port)

	case "del":
		if len(os.Args) < 4 {
			fmt.Println(os.Args[0], " del <group-id> <service-id>")
			return
		}

		gid, _ := strconv.Atoi(os.Args[2])
		sid, _ := strconv.Atoi(os.Args[3])

		err := pfc.ForwardingRemove(gid, sid)
		if err != nil {
			log.Println(err)
		}

	case "list":
		t, s, err := pfc.ForwardingGetAll()
		if err != nil {
			log.Println(err)
		}
		fmt.Println("Tunnels")
		for _, v := range t {
			fmt.Printf("  id %d from (%s:%d) to (%s:%d)\n", v.Id, v.LocalIp, v.LocalPort, v.RemoteIp, v.RemotePort)
		}
		fmt.Println("")
		fmt.Println("Services")
		for _, v := range s {
			fmt.Printf("  id (%d-%d) pwd '%s' Forwarding %s proxy %s:%d to %s:%d via tunnel %d\n", v.Gid, v.Sid, v.Pwd, v.Proto, v.ProxyIp, v.ProxyPort, v.BackendIp, v.BackendPort, v.Tid)
		}
		fmt.Println("")

		tt, err1 := pfc.ForwardingGetTunnel(0)
		if err1 {
			fmt.Println("Tunnels")
			fmt.Printf("  id %d from (%s:%d) to (%s:%d)\n", tt.Id, tt.LocalIp, tt.LocalPort, tt.RemoteIp, tt.RemotePort)
		}

		tt, err1 = pfc.ForwardingGetTunnel(65636)
		if !err1 {
			fmt.Println("Tunnels")
			fmt.Printf("  id %d from (%s:%d) to (%s:%d)\n", tt.Id, tt.LocalIp, tt.LocalPort, tt.RemoteIp, tt.RemotePort)
		}

		tt, err1 = pfc.ForwardingGetTunnel(65636)
		if !err1 {
			fmt.Println("Tunnels")
			fmt.Printf("  id %d from (%s:%d) to (%s:%d)\n", tt.Id, tt.LocalIp, tt.LocalPort, tt.RemoteIp, tt.RemotePort)
		}

	case "help":
		fmt.Println(os.Args[0], "version|add|del|list|help")
	default:
		fmt.Println("Unknown command '", os.Args[1], "'")
	}
}
