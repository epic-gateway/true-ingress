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
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+/
	// | 0 |C|   Hlen  |  Proto/ctype  |             Flags             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//       \     \---\
	//        \         \
	//         \--------\\
	//                   ||
	GUEHeader uint32 = 0x2601a000
)

var (
	tunnels = map[int]int{}
)

// sendPing sends an Acnodal EPIC GUE ping packet from localAddr to
// remoteAddr. The packet contains the groupID, serviceID, tunnelID,
// and pwd.
func sendPing(localAddr net.UDPAddr, remoteAddr net.UDPAddr, groupID uint16, serviceID uint16, pwd string, tunnelID uint32) error {
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, GUEHeader)
	binary.Write(b, binary.BigEndian, groupID)
	binary.Write(b, binary.BigEndian, serviceID)
	binary.Write(b, binary.BigEndian, []byte(pwd))
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

func tunnelPing(timeout int) {
	fmt.Println("Ping check")

	// set old tunnel list aside
	tmp := map[int]int{}
	for index, element := range tunnels {
		tmp[index] = element
	}
	tunnels = map[int]int{}

	// get current tunnel list
	cmd := "/opt/acnodal/bin/cli_service get all | grep '^VERIFY'"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		fmt.Println(out)
		fmt.Println(err)
		return
	}
	services := strings.Split(string(out), "\n")

	// read services for GUE HEADER info (group-id, service-id, key)"
	verify := map[int]string{}
	gids := map[int]uint16{}
	sids := map[int]uint16{}
	for _, service := range services[:len(services)-1] {
		params := strings.Split(service, " ")

		g, _ := strconv.ParseInt(strings.Split(strings.Split(params[1], "(")[1], ",")[0], 10, 16)
		s, _ := strconv.ParseInt(strings.Split(params[2], ")")[0], 10, 16)
		pwd := strings.Split(params[3], "'")[1]
		tid, _ := strconv.ParseInt(strings.Split(params[3], "\t")[2], 10, 32)
		verify[int(tid)] = pwd
		gids[int(tid)] = uint16(g)
		sids[int(tid)] = uint16(s)
	}

	if len(verify) == 0 {
		return
	}

	cmd = "/opt/acnodal/bin/cli_tunnel get all | grep '^TUN'"
	out, err = exec.Command("bash", "-c", cmd).Output()
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

		t, ok := tmp[tid]
		if ok && t < timeout {
			tunnels[tid] = tmp[tid] + 1
		} else {
			sPort, _ := strconv.Atoi(src[1])
			dPort, _ := strconv.Atoi(dst[1])

			serverAddr := net.UDPAddr{IP: net.ParseIP(dst[0]), Port: dPort}
			localAddr := net.UDPAddr{IP: net.ParseIP(src[0]), Port: sPort}

			fmt.Printf("  sending GUE ping %s -> %s (%d, '%s')\n", localAddr.String(), serverAddr.String(), tid, verify[tid])
			sendPing(localAddr, serverAddr, gids[tid], sids[tid], verify[tid], uint32(tid))

			tunnels[tid] = 1
		}
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
		tunnelPing(tun_delay)
		time.Sleep(1 * time.Second)
	}
}
