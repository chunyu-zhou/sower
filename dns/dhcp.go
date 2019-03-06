package dns

import (
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	broadcastMAC, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	ethLayer        = &layers.Ethernet{
		DstMAC:       broadcastMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer = &layers.IPv4{
		Version:  4,
		Protocol: layers.IPProtocolUDP,
		TTL:      64,
		DstIP:    net.ParseIP("255.255.255.255"),
	}
	udpLayer = &layers.UDP{
		SrcPort:  68,
		DstPort:  67,
		Length:   0,
		Checksum: 0,
	}
	dhcp4Layer = &layers.DHCPv4{
		Flags:        0x0000,
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		ClientIP:     net.ParseIP("0.0.0.0"),
	}
	dhcp4Opts = []layers.DHCPOption{{
		Type:   layers.DHCPOptMessageType,
		Length: 1,
		Data:   []byte{byte(layers.DHCPMsgTypeDiscover)},
	}}
	opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	setLayer = func(hardwareAddr net.HardwareAddr, srcIP net.IP) error {
		ethLayer.SrcMAC = hardwareAddr

		ipLayer.SrcIP = srcIP

		dhcp4Layer.Xid = uint32(rand.Int31())
		dhcp4Layer.ClientHWAddr = hardwareAddr
		dhcp4Layer.Options = append(dhcp4Opts, layers.DHCPOption{
			Type:   layers.DHCPOptRequestIP,
			Length: 4,
			Data:   srcIP,
		}, layers.DHCPOption{
			Type:   layers.DHCPOptClientID,
			Length: uint8(len(hardwareAddr)) + 1,
			Data:   append([]byte{0x01}, []byte(hardwareAddr)...),
		}, layers.DHCPOption{
			Type: layers.DHCPOptEnd,
		})

		return udpLayer.SetNetworkLayerForChecksum(ipLayer)
	}
)

// GetDefaultDNSServer get network dns setting via dhcp
// IPv4 only, non-parallel security
func GetDefaultDNSServer() string {
	for _, iface := range mustGetInterfaces() {
		// fill network data
		if err := setLayer(iface.HardwareAddr, iface.IP); err != nil {
			glog.Warningf("set layer on %s fail: %s", iface.Name, err)
			continue
		}

		// open device stream
		handle, err := pcap.OpenLive(iface.Name, 65536, true, time.Second)
		if err != nil {
			glog.Warningf("pcap open live on %s fail: %s", iface.Name, err)
			continue
		}
		defer handle.Close()

		if err := handle.SetBPFFilter("ether dst " + iface.HardwareAddr.String()); err != nil {
			glog.Warningf("set bpf on %s fail: %s", iface.Name, err)
			continue
		}

		// send discover message
		go func() {
			buff := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buff, opts, ethLayer, ipLayer, udpLayer, dhcp4Layer); err != nil {
				glog.Warningf("pcap serialize layers fail: %s", err)
			}
			if err := handle.WritePacketData(buff.Bytes()); err != nil {
				glog.Warningf("pcap write data fail: %s", err)
			}
		}()

		// receive dhcp message
		src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
		for {
			pack, err := src.NextPacket()
			if err != nil {
				if err != io.EOF {
					glog.Warningf("read pack from %s fail: %s", iface.Name, err)
				}
			}

			if layer := pack.Layer(layers.LayerTypeDHCPv4); layer != nil {
				dhcp4 := layer.(*layers.DHCPv4)
				for i := range dhcp4.Options {
					if dhcp4.Options[i].Type != layers.DHCPOptDNS {
						continue
					}

					if data := dhcp4.Options[i].Data; len(data) >= net.IPv4len {
						return net.IPv4(data[0], data[1], data[2], data[3]).String()
					}
				}
			}
		}
	}
	return ""
}

type netIface struct {
	*net.Interface
	net.Addr
	net.IP
}

func mustGetInterfaces() []*netIface {
	ifaces, err := net.Interfaces()
	if err != nil {
		glog.Fatalln(err)
	}

	v4Iface := make([]*netIface, 0, len(ifaces))
	for i := range ifaces {
		if len(ifaces[i].HardwareAddr) == 0 {
			continue
		}

		addrs, _ := ifaces[i].Addrs()
		for _, addr := range addrs {
			if ip := addr.(*net.IPNet).IP.To4(); ip != nil {
				v4Iface = append(v4Iface, &netIface{&ifaces[i], addr, ip})
				break
			}
		}
	}
	return v4Iface
}
