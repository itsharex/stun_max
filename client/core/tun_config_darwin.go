//go:build darwin

package core

import (
	"encoding/binary"
	"os/exec"

	"github.com/songgao/water"
)

// waterIface wraps water.Interface for macOS utun.
// macOS utun requires a 4-byte AF header before each IP packet.
type waterIface struct {
	dev *water.Interface
}

func (w *waterIface) Read(b []byte) (int, error) {
	// Read with 4-byte AF header, strip it
	buf := make([]byte, len(b)+4)
	n, err := w.dev.Read(buf)
	if err != nil {
		return 0, err
	}
	if n <= 4 {
		return 0, nil
	}
	copy(b, buf[4:n])
	return n - 4, nil
}

func (w *waterIface) Write(b []byte) (int, error) {
	// Prepend 4-byte AF header (AF_INET = 2 for IPv4)
	buf := make([]byte, 4+len(b))
	if len(b) > 0 && (b[0]>>4) == 6 {
		binary.BigEndian.PutUint32(buf[:4], 30) // AF_INET6
	} else {
		binary.BigEndian.PutUint32(buf[:4], 2) // AF_INET
	}
	copy(buf[4:], b)
	n, err := w.dev.Write(buf)
	if err != nil {
		return 0, err
	}
	if n <= 4 {
		return 0, nil
	}
	return n - 4, nil
}

func (w *waterIface) Close() error {
	return w.dev.Close()
}

func (w *waterIface) Name() string {
	return w.dev.Name()
}

func createPlatformTun() (tunIface, error) {
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return nil, err
	}
	return &waterIface{dev: iface}, nil
}

func configureTunInterface(ifName, localIP, peerIP string) error {
	if err := exec.Command("ifconfig", ifName, localIP, peerIP, "up").Run(); err != nil {
		return err
	}
	exec.Command("route", "add", "-host", peerIP, "-interface", ifName).Run()
	return nil
}

func removeTunInterface(ifName string) error {
	return nil
}

func addRoute(ifName, subnet, gateway string) error {
	return exec.Command("route", "add", "-net", subnet, gateway).Run()
}

func removeRoute(ifName, subnet string) error {
	exec.Command("route", "delete", "-net", subnet).Run()
	return nil
}

func enableIPForwarding() {
	exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1").Run()
}

func enableNAT(ifName string) {
	exec.Command("bash", "-c",
		`echo "nat on en0 from `+ifName+`:network to any -> (en0)" | pfctl -ef -`).Run()
}

func disableNAT(ifName string) {
	exec.Command("pfctl", "-d").Run()
}
