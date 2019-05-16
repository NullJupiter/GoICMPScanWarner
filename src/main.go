package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/google/gopacket"

	"github.com/google/gopacket/pcap"
)

func main() {
	// listen for an icmpv4 scan and execute the custom command when signal is benn caught
	listenForScan(getFlags())
}

func getFlags() (string, string) {
	// ./go_scanning_warner -i "en0" -cmd "say 'Warning: You got scanned'"
	i := flag.String("i", "", "network interface to listen on")
	c := flag.String("cmd", "", "command being run after detecting icmp scan")
	flag.Parse()

	// check if all flags have been set
	// else print usage
	if *i == "" || *c == "" {
		flag.Usage()
		os.Exit(1)
	}

	return *i, *c
}

func listenForSig(doneChan chan bool) {

}

func listenForScan(networkInterface string, command string) {
	// open live sniffer
	handle, err := pcap.OpenLive(networkInterface, 65535, false, -1*time.Second)
	if err != nil {
		log.Fatalf("could not open live sniffer: %v", err)
	}
	defer handle.Close()

	// get local ip
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatalf("could not get interface adresses: %v", err)
	}
	var localIP string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				localIP = ipnet.IP.String()
			}
		}
	}

	// set filter to just listen to icmpv4
	if err = handle.SetBPFFilter(fmt.Sprintf("dst host %s and icmp", localIP)); err != nil {
		log.Fatalf("could not set bpf filter: %v", err)
	}

	// open log file
	logFile, err := os.OpenFile("logFile.log", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatalf("could not open/create log file: %v", err)
	}
	defer logFile.Close()

	// get a new packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// loop over all incoming packets
	for packet := range packetSource.Packets() {
		// extract ethernet layer
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}
		ethPacket := ethLayer.(*layers.Ethernet)

		// extract ipv4 layer
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ipv4Layer == nil {
			continue
		}
		ipv4Packet := ipv4Layer.(*layers.IPv4)

		// extract icmpv4 layer
		icmpv4Layer := packet.Layer(layers.LayerTypeICMPv4)
		if icmpv4Layer == nil {
			continue
		}
		icmpv4Packet := icmpv4Layer.(*layers.ICMPv4)

		// set log output to write to logFile
		log.SetOutput(logFile)

		// print data about attacker (MAC, IP, ICMP type code)
		log.Println(ethPacket.SrcMAC.String(), "->", ethPacket.DstMAC.String(), "\t",
			ipv4Packet.SrcIP.String(), "->", ipv4Packet.DstIP.String(), "\t",
			icmpv4Packet.TypeCode.String())

		// set log output back to standard out
		log.SetOutput(os.Stdout)

		// execute custom command
		commandSplit := strings.Split(command, " ")
		cmd := exec.Command(commandSplit[0], commandSplit[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err = cmd.Run(); err != nil {
			log.Fatalf("Warning: detected scan but could not run custom command!")
		}

		// break the loop and quit the program
		break
	}
}
