package itunes

import "net"
import "io"
import "log"
import "encoding/binary"
import "github.com/DHowett/go-plist"

type HeartbeatResponse struct {
	Command string
}

func StartHeartbeat(l *Lockdown) {
	h, err := l.StartService("com.apple.mobile.heartbeat")
	if err != nil {
		panic(err)
	}
	firstbeat := make(chan struct{})
	go heartbeat(l, h, firstbeat)
	firstbeat <- struct{}{}
	close(firstbeat)
}

func stop_heartbeat(l *Lockdown, heartbeat net.Conn) {
	log.Println("HEARTBEAT: STOP_HEARTBEAT")
	heartbeat.Close()
	l.StopSession()
}

func heartbeat(l *Lockdown, heartbeat net.Conn, f chan struct{}) {
	here := make([]byte, 4)
	var recv map[string]interface{}
	var bytes []byte
	var resp HeartbeatResponse
	defer stop_heartbeat(l, heartbeat)
	for {
		if l.IsGracefullyShuttingdown() {
			return
		}
		n, err := io.ReadFull(heartbeat, here)
		if err != nil || n != 4 {
			log.Println("HEARTBEAT: Read4 ", n, err)
			return
		}
		blen := binary.BigEndian.Uint32(here)
		if len(bytes) != int(blen) {
			bytes = make([]byte, blen)
		}
		n, err = io.ReadFull(heartbeat, bytes)
		if err != nil || n != int(blen) {
			log.Println("HEARTBEAT: FATAL Read", blen, n, err)
			return
		}
		recv = nil
		_, err = plist.Unmarshal(bytes, &recv)
		if err != nil {
			log.Println("HEARTBEAT: FATAL Unmarshal Query:", err)
			return
		}

		log.Println("HEARTBEAT ", recv)

		switch recv["Command"] {
		case "Marco":
			resp = HeartbeatResponse{"Polo"}
		case "SleepyTime":
			resp = HeartbeatResponse{"NightNight"}
		default:
			log.Println("HEARTBEAT UNKNOWN COMMAND: ", recv["Command"])
			return
		}

		pbytes, err := plist.Marshal(resp, 1)
		if err != nil {
			log.Println("FATAL: FATAL Marshal:", err)
			return
		}
		binary.BigEndian.PutUint32(here, uint32(len(pbytes)))

		n, err = heartbeat.Write(here)
		if err != nil || n != 4 {
			log.Println("HEARTBEAT: FATAL Write4", n, err)
			return
		}
		n, err = heartbeat.Write(pbytes)
		if err != nil || n != len(pbytes) {
			log.Println("HEARTBEAT: FATAL Write", len(pbytes), n, err)
			return
		}
		if recv["Command"] == "SleepyTime" {
			return
		}
		<-f
	}
}
