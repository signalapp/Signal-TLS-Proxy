// License: WTFPL
// Credits to @studentmain
// Original Repository: https://github.com/studentmain/fuck-signal-tls-proxy/blob/rm/LICENSE

package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

func send(addr, server, sni string) int {
	c0, e := net.Dial("tcp", addr)
	if e != nil {
		log.Fatal(e)
	}

	c1 := tls.Client(c0, &tls.Config{
		ServerName:         server,
		InsecureSkipVerify: true,
	})

	c2 := tls.Client(c1, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	c2.SetDeadline(time.Now().Add(2 * time.Minute))
	s := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/7.68.0\r\n\r\n", sni)
	//b := make([]byte, 4096)
	l, _ := c2.Write([]byte(s))
	log.Println(l)
	if e != nil {
		return 0
	}
	log.Printf("%s->%s->%s\n", addr, server, sni)
	return l
}
func main() {
	if len(os.Args) != 3 {
		log.Fatalln("usage: main.exe server_name addr_port")
	}
	server := os.Args[1]
	addr := os.Args[2]
	l1 := send(addr, server, "updates.signal.org")
	l2 := send(addr, server, "telegram.org")
	if l1 != 0 && l2 == 0 {
		log.Fatalln("It is a Signal TLS Proxy")
	}
	log.Println("It is not a Signal TLS Proxy")
}
