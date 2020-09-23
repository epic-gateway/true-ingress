package main
 
import (
    "fmt"
    "os"
    "time"
    "strconv"
    "net"
//    "bytes"
    "os/exec"
//    "log"
    "strings"
    "bytes"
    "encoding/binary"
)

func usage(name string) {
    fmt.Printf("Usage: %s <ping-delay> <sweep-delay> <sweep-count>\n", name)
    fmt.Printf("    <ping-delay> - delay between GUE control packets (in seconds)\n")
    fmt.Printf("    <sweep-delay> - delay between session sweep checks (in seconds)\n")
    fmt.Printf("    <sweep-count> - number of inactive intervals for session expiration\n")
    fmt.Printf("\nExample : %s 10 10 60\n", name)
}

var (
    tunnels      = map[int]int{}
    session_hash = map[string]int{}
    session_ttl  = map[string]int{}
    sweep_counter int
)

func send_ping(src_ip string, src_port string, dst_ip string, dst_port string, id int, pwd string) {
    //fmt.Printf("%s:%s -> %s:%s (%d '%s')\n", src_ip, src_port, dst_ip, dst_port, id, pwd)
    sport, _ := strconv.Atoi(src_port)
    dport, _ := strconv.Atoi(dst_port)

    ServerAddr := net.UDPAddr{IP: net.ParseIP(dst_ip), Port: dport}
    LocalAddr := net.UDPAddr{IP: net.ParseIP(src_ip), Port: sport}

    b := new(bytes.Buffer)
    binary.Write(b, binary.BigEndian, uint32(0x2101a000))
    binary.Write(b, binary.BigEndian, uint32(id))
    binary.Write(b, binary.BigEndian, []byte(pwd))
//    fmt.Println(b.Bytes())

//    fmt.Println("Open")
    conn, err := net.DialUDP("udp", &LocalAddr, &ServerAddr)
    if err  != nil {
        fmt.Println("DialUDP: " , err)
        return
    }
    
    defer conn.Close()

//    fmt.Println("Send")
    _ ,err = conn.Write(b.Bytes())
    if err != nil {
        fmt.Println("Write: " , err)
    }

//    fmt.Println("Done ")
}

func tunnel_ping(timeout int) {
    fmt.Println("ping check")

    var tmp = map[int]int{}
    for index, element := range tunnels{        
         tmp[index] = element
    }
    fmt.Println(tmp)
    tunnels = map[int]int{}
//    fmt.Println(tunnels)

//    fmt.Println("Services:")
    cmd := "/tmp/.acnodal/bin/cli_service get all | grep 'VERIFY' | grep -v 'TABLE'"
//    cmd := "../../src/cli_service get all | grep 'VERIFY' | grep -v 'TABLE'"
    out, err := exec.Command("bash", "-c", cmd).Output()
    if err != nil {
        fmt.Println("Error")
        //log.Fatal(err)
        return
    }
//    fmt.Printf("%s\n", out)
    var services = strings.Split(string(out), "\n")
//    fmt.Printf("%q\n", services[:len(services)-1])

    // read services for GUE HEADER info (group-id, service-id, key)"
    var verify = map[int]string{}
    for _, service := range services[:len(services)-1] {
//        fmt.Println(service)
//        continue
        var params = strings.Split(service, " ")
//        fmt.Printf("%q\n", params)

        if params[0] != "VERIFY" {
            continue
        }

        gid64, _ := strconv.ParseInt(strings.Split(params[8], "{")[1], 16, 32)
        gid := int(gid64)
//        fmt.Println(gid)
        pwd := strings.Split(params[4], "'")[1]
//        fmt.Println(pwd)
//        fmt.Printf("id [%d], password [%s]\n", gid, pwd)
        verify[gid]=pwd
    }
//    fmt.Println(verify)

    // read tunnels for outer header assembly
    if len(verify) == 0 {
        return
    }

//    fmt.Println("Tunnels:")
    cmd = "/tmp/.acnodal/bin/cli_tunnel get all | grep 'TUN' | grep -v 'TABLE'"
//    cmd = "../../src/cli_tunnel get all | grep 'TUN' | grep -v 'TABLE'"
    out, err = exec.Command("bash", "-c", cmd).Output()
    if err != nil {
        fmt.Println("Error")
        //log.Fatal(err1)
        return
    }
//    fmt.Printf("%s\n", out)
    var tnls = strings.Split(string(out), "\n")
//    fmt.Printf("%q\n", tnls[:len(tnls)-1])

    for _, tunnel := range tnls[:len(tnls)-1] {
//        fmt.Println(tunnel)
        var params = strings.Split(tunnel, "\t")
//        fmt.Printf("%q\n", params)

        if params[0] != "TUN" {
            continue
        }

        tid, _ := strconv.Atoi(strings.Trim(params[1], " "))
        //fmt.Printf("tunnel-id %d -> pwd '%s'\n", tid, verify[tid])

        ep := strings.Split(params[2], "->")
//        fmt.Printf("%q\n", ep)
        src := strings.Split(strings.Trim(ep[0], " "), ":")
//        fmt.Printf("%q\n", src)
        dst := strings.Split(strings.Trim(ep[1], " "), ":")
//        fmt.Printf("%q\n", dst)

        t, ok := tmp[tid]
        if ok && t < timeout {
            tunnels[tid] = tmp[tid] + 1
        } else {
            fmt.Printf("sending GUE ping %s:%s -> %s:%s -> %d -> %s\n", src[0], src[1], dst[0], dst[1], tid, verify[tid])
            send_ping(src[0], src[1], dst[0], dst[1], tid, verify[tid])

            tunnels[tid] = 1
        }
    }
    fmt.Println(tunnels)
}

func session_sweep(expire int) {
    fmt.Println("Sweep check")

    cmd := "/tmp/.acnodal/bin/cli_gc get all | grep 'ENCAP' | grep -v 'TABLE'"
    out, err := exec.Command("bash", "-c", cmd).Output()
    if err != nil {
        fmt.Println("Error")
        return
    }
    var services = strings.Split(string(out), "\n")
    
    for _, service := range services[:len(services)-1] {
        var params = strings.Split(service, " ")

        if params[0] != "ENCAP" {
            continue
        }

        key := strings.Split(service, "->")[0]
        hash, _ := strconv.Atoi(strings.Split(params[6], "\t")[2])

        if hash == 0 { // static record
            continue
        }

        h, ok := session_hash[key]
        if ok && h == hash {
            if session_ttl[key] >= expire {
                to_del := strings.Split(strings.Split(strings.Split(key, "(")[1], ")")[0], ",")

                delete(session_hash, key)
                delete(session_ttl, key)
                fmt.Printf("  delete %s%s%s\n", to_del[0], to_del[1], to_del[2])
                cmd := fmt.Sprintf("/tmp/.acnodal/bin/cli_gc del %s%s%s\n", to_del[0], to_del[1], to_del[2])
                exec.Command("bash", "-c", cmd).Output()
            } else {
                session_ttl[key] += 1
            }
        } else {
            session_hash[key] = hash
            session_ttl[key] = 1
        }
    }
}

func main() {
    fmt.Println(os.Args[1:])

    if (len(os.Args) < 4) {
        usage(os.Args[0])
        return
    }

    tun_delay, _   := strconv.Atoi(os.Args[1])
    sweep_delay, _ := strconv.Atoi(os.Args[2])
    sweep_count, _ := strconv.Atoi(os.Args[3])

    counter := sweep_delay

    fmt.Println("Starting PFC daemon")

    for {
        // GUE ping
        tunnel_ping(tun_delay)

        // Session expiration
        if counter < sweep_delay {
            counter += 1
        } else {
            session_sweep(sweep_count)
            counter = 1
        }

        time.Sleep(1 * time.Second)
    }

//    return 0
}
