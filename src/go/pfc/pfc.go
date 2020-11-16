package pfc

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

func Check() (bool, string) {
	// see if we can run one of our executables
	bytes, err := exec.Command("/opt/acnodal/bin/pfc_cli_go", "version").Output()
	if err != nil {
		return false, "PFC not compiled"
	}

	return true, string(bytes)
}

type Tunnel struct {
	Id         int
	LocalIp    net.IP
	LocalPort  int
	RemoteIp   net.IP
	RemotePort int
}

type Service struct {
	Gid         int
	Sid         int
	Pwd         string
	Proto       string
	ProxyIp     net.IP
	ProxyPort   int
	BackendIp   net.IP
	BackendPort int
	Tid         int
}

func ForwardingAdd(nic string, group_id int, service_id int, passwd string, proto string, proxy_ip net.IP, proxy_port int, service_ip net.IP, service_port int, gue_remote_ip net.IP, gue_remote_port int) (net.IP, int, error) {
	cmd := fmt.Sprintf("pfc_add.sh %s %d %d %s %s %d %s %s %d %s %d\n", nic, group_id, service_id, passwd, gue_remote_ip, gue_remote_port, proto, proxy_ip, proxy_port, service_ip, service_port)
	_, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return net.IP{0}, 0, err
	}

	if gue_remote_port != 0 {
		return gue_remote_ip, gue_remote_port, nil
	}

	tunnel_id := group_id<<16 + service_id
	cmd = fmt.Sprintf("cli_tunnel get %d | grep %d | awk '{print $3}'\n", tunnel_id, tunnel_id)
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return net.IP{0}, 0, err
	}
	gue := strings.Split(strings.Split(string(out), "\n")[0], ":")
	gue_ip := gue[0]
	gue_port, _ := strconv.Atoi(gue[1])
	return net.ParseIP(gue_ip), gue_port, nil
}

func ForwardingRemove(group_id int, service_id int) error {
	cmd := fmt.Sprintf("pfc_delete.sh %d %d\n", group_id, service_id)
	_, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return err
	}

	return nil
}

func GetServiceKey(gid int, sid int) int {
	return ((gid & 0xFFFF) << 16) + (sid & 0xFFFF)
}

func ForwardingGetAll() (map[int]Tunnel, map[int]Service, error) {
	tunnels := map[int]Tunnel{}
	svcs := map[int]Service{}

	cmd := fmt.Sprintf("pfc_list.sh | grep -e 'TUN' -e 'VERIFY'\n")
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return tunnels, svcs, err
	}
	lines := strings.Split(string(out), "\n")

	for _, line := range lines[:len(lines)-1] {
		params := strings.Split(line, "\t")

		if params[0] != "TUN" {
			continue
		}

		tid, _ := strconv.Atoi(strings.Trim(params[1], " "))
		ep := strings.Split(params[2], "->")
		src := strings.Split(strings.Trim(ep[0], " "), ":")
		dst := strings.Split(strings.Trim(ep[1], " "), ":")
		p1, _ := strconv.Atoi(src[1])
		p2, _ := strconv.Atoi(dst[1])
		tunnels[tid] = Tunnel{tid, net.ParseIP(src[0]), p1, net.ParseIP(dst[0]), p2}
	}

	for _, line := range lines[:len(lines)-1] {
		params := strings.Split(line, " ")

		if params[0] != "VERIFY" {
			continue
		}

		pwd := strings.Split(params[4], "'")[1]
		p := strings.Split(line, "\t")
		ep1 := strings.Split(p[1], ", ")
		ep2 := strings.Split(p[2], ", ")
		gid, _ := strconv.Atoi(strings.Split(strings.Split(params[1], "(")[1], ",")[0])
		sid, _ := strconv.Atoi(strings.Split(params[2], ")")[0])
		p1, _ := strconv.Atoi(strings.Split(ep1[2], ")")[0])
		p2, _ := strconv.Atoi(strings.Split(ep2[2], ")")[0])
		tid, _ := strconv.Atoi(p[3])

		svcs[GetServiceKey(gid, sid)] = Service{gid, sid, pwd, strings.Split(ep1[0], "(")[1], net.ParseIP(ep1[1]), p1, net.ParseIP(ep2[1]), p2, tid}
	}

	return tunnels, svcs, nil
}

func ForwardingGetService(gid int, sid int) (Service, bool) {
	_, s, err := ForwardingGetAll()
	if err != nil {
		return Service{}, false
	}
	v, ok := s[GetServiceKey(gid, sid)]
	return v, ok
}

func ForwardingGetTunnel(tid int) (Tunnel, bool) {
	t, _, err := ForwardingGetAll()
	if err != nil {
		return Tunnel{}, false
	}
	v, ok := t[tid]
	return v, ok
}
