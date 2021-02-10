package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func usage(name string) {
	fmt.Printf("Usage: %s <sweep-delay> <sweep-count>\n", name)
	fmt.Printf("    <sweep-delay> - delay between session sweep checks (in seconds)\n")
	fmt.Printf("    <sweep-count> - number of inactive intervals for session expiration\n")
	fmt.Printf("\nExample : %s 10 60\n", name)
}

var (
	session_hash  = map[string]int{}
	session_ttl   = map[string]int{}
	sweep_counter int
)

func session_sweep(expire int) {
	fmt.Println("Sweep check")

	cmd := "/opt/acnodal/bin/cli_gc get all | grep 'ENCAP' | grep -v 'TABLE'"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		fmt.Println(out)
		fmt.Println(err)
		return
	}
	services := strings.Split(string(out), "\n")

	for _, service := range services[:len(services)-1] {
		params := strings.Split(service, " ")

		if params[0] != "ENCAP" {
			continue
		}

		foo := strings.Split(service, "->")
		key := foo[0]
		hash, _ := strconv.Atoi(strings.Split(foo[1], " ")[1])

		if hash == 0 { // static record
			continue
		}

		h, ok := session_hash[key]
		if ok && h == hash {
			if session_ttl[key] >= expire {
				to_del := strings.Split(strings.Split(strings.Split(key, "(")[1], ")")[0], ",")

				fmt.Printf("  delete %s%s%s\n", to_del[0], to_del[1], to_del[2])
				cmd := fmt.Sprintf("/opt/acnodal/bin/cli_gc del %s%s%s\n", to_del[0], to_del[1], to_del[2])
				_, err := exec.Command("bash", "-c", cmd).Output()
				if err != nil {
					fmt.Printf("ERR: [%s] cmd failed: %s\n", cmd, err)
				}

				delete(session_hash, key)
				delete(session_ttl, key)
			} else {
				session_ttl[key] += 1
			}
		} else {
			session_hash[key] = hash
			session_ttl[key] = 1
		}
	}
	//fmt.Printf(">>>  hash size %d, ttl size %d\n", len(session_hash), len(session_ttl))
}

func main() {
	fmt.Println(os.Args[1:])

	if len(os.Args) < 3 {
		usage(os.Args[0])
		return
	}

	sweep_delay, _ := strconv.Atoi(os.Args[1])
	sweep_count, _ := strconv.Atoi(os.Args[2])

	counter := sweep_delay

	for {
		// Session expiration
		if counter < sweep_delay {
			counter += 1
		} else {
			session_sweep(sweep_count)
			counter = 1
		}

		time.Sleep(1 * time.Second)
	}
}
