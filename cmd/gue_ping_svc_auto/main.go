package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func usage(name string) {
	fmt.Printf("Usage: %s <ping-delay>\n", name)
	fmt.Printf("    <ping-delay> - delay between GUE control packets (in seconds)\n")
	fmt.Printf("\nExample : %s 10\n", name)
}

const (
	// https://tools.ietf.org/html/draft-ietf-intarea-gue-01#section-3.1
	//
	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | 0 |C|   Hlen  |  Proto/ctype  |             Flags             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//       \     \---\    |                    /
	//        \         \   |     /-------------/
	//         \--------\\  |    /
	//                   || |   /
	GUEHeader uint32 = 0x2601a000
)

// sendPing sends an Acnodal EPIC GUE ping packet from localAddr to
// remoteAddr.
func sendPing(localAddr net.UDPAddr, remoteAddr net.UDPAddr, tunnelID uint32) error {
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, GUEHeader)
	binary.Write(b, binary.BigEndian, tunnelID)

	conn, err := net.DialUDP("udp", &localAddr, &remoteAddr)
	if err != nil {
		fmt.Println("DialUDP: ", err)
		return err
	}
	defer conn.Close()

	_, err = conn.Write(b.Bytes())
	if err != nil {
		fmt.Println("Write: ", err)
	}
	return err
}

func tunnelPing() {
	// get current tunnel list
	cmd := "/opt/acnodal/bin/cli_tunnel get all | grep '^TUN'"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		fmt.Println(out)
		fmt.Println(err)
		return
	}
	tnls := strings.Split(string(out), "\n")

	for _, tunnel := range tnls[:len(tnls)-1] {
		params := strings.Split(tunnel, "\t")

		if params[0] != "TUN" {
			continue
		}

		tid, _ := strconv.Atoi(strings.Trim(params[1], " "))
		ep := strings.Split(params[2], "->")
		src := strings.Split(strings.Trim(ep[0], " "), ":")
		dst := strings.Split(strings.Trim(ep[1], " "), ":")

		sPort, _ := strconv.Atoi(src[1])
		dPort, _ := strconv.Atoi(dst[1])

		serverAddr := net.UDPAddr{IP: net.ParseIP(dst[0]), Port: dPort}
		localAddr := net.UDPAddr{IP: net.ParseIP(src[0]), Port: sPort}

		fmt.Printf("  sending GUE ping %s -> %s (%d)\n", localAddr.String(), serverAddr.String(), tid)
		sendPing(localAddr, serverAddr, uint32(tid))
	}
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Args[0])
		return
	}

	tun_delay, _ := strconv.Atoi(os.Args[1])

	fmt.Println("Starting GUE ping daemon")

	for {
		tunnelPing()
		time.Sleep(time.Duration(tun_delay) * time.Second)
	}
}
