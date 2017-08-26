package itunes

import "log"
import "net"
import "crypto/tls"
import "fmt"
import "github.com/pkg/errors"
import "github.com/mehmooda/net_dump"
import "github.com/DHowett/go-plist"
import "sync"

var looper = loop_pcap.NewLooper(16 * 1024 * 1024) // 16MiB

type Lockdown struct {
	addr          net.IP
	pair          PairRecord
	cert          *tls.Certificate
	c             net.Conn
	session_id    string
	about_to_exit sync.Mutex
	exit          chan struct{}
}

func (l *Lockdown) IsGracefullyShuttingdown() bool {
	select {
	case <-l.exit:
		return true
	default:
		return false
	}
}

func (l *Lockdown) StartService(Service string) (net.Conn, error) {
	if l.IsGracefullyShuttingdown() {
		return nil, EGRACEFULSHUTDOWN
	}
	var res lockdownStartServiceResponse
	log.Println("StartService:", Service)
	s := lockdownStartServiceRequest{"2", "StartService", Service}
	err := sendPlist(l.c, s, &res)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to Send StartService Response")
	}
	log.Println("StartService: Connecting", Service, l.addr, res.Port, res.EnableServiceSSL)
	tcp, err := net.Dial("tcp", l.addr.String()+":"+fmt.Sprintf("%d", res.Port))
	if err != nil {
		return nil, errors.Wrap(err, "Unable to connect")
	}
	if res.EnableServiceSSL == true {
		c, err := tls_connect(tcp, l.GetCert())
		return loop_pcap.Wrap(c, looper), err
	}
	return loop_pcap.Wrap(tcp, looper), nil
}

func (l *Lockdown) GetValue(Key string, recv interface{}) error {
	if l.IsGracefullyShuttingdown() {
		return EGRACEFULSHUTDOWN
	}
	var res lockdownGetValueResponse
	s := lockdownGetValueRequest{"2", "GetValue", Key}
	err := sendPlist(l.c, s, &res)
	if err != nil {
		return errors.Wrap(err, "GetValue: Unable to Get Value")
	}
	bytes, err := plist.Marshal(res.Value, 1)
	if err != nil {
		return errors.Wrap(err, "GetValue: Unable to ReMarshal")
	}
	_, err = plist.Unmarshal(bytes, recv)
	if err != nil {
		return errors.Wrap(err, "GetValue: Unable to ReUnmarshal")
	}
	return nil
}

func (l *Lockdown) StopSession() {
	var res interface{}

	s := lockdownStopSessionRequest{"2", "StopSession", l.session_id}
	err := sendPlist(l.c, s, &res)
	if err != nil {
		log.Println(err)
	}
	log.Println(res)
	log.Println("LOCKDOWN: Disconnect")
	l.about_to_exit.Lock()
	if !l.IsGracefullyShuttingdown() {
		close(l.exit)
	}
	l.about_to_exit.Unlock()
	l.c.Close()
	looper.DumpToDisk()
}

func Connect(addr net.IP, pair PairRecord) (l *Lockdown, err error) {
	if len(addr) == 0 {
		log.Println("LOCKDOWN: Connect: ", ENOADDRESSGIVEN)
		return nil, ENOADDRESSGIVEN
	}

	log.Println("LOCKDOWN: Connect: ", addr.String())

	c, err := net.Dial("tcp", addr.String()+":62078")
	if err != nil {
		log.Println("LOCKDOWN: Connect: Dial: ", err)
		return nil, errors.Wrap(err, "Unable to Connect to Device")
	}
	l = &Lockdown{addr: addr, pair: pair}
	l.c = loop_pcap.Wrap(c, looper)

	// QUERY REQUEST
	err = func() error {
		var res lockdownQueryResponse
		s := lockdownQueryRequest{"2", "QueryType"}
		sendPlist(l.c, s, &res)
		if res.Request != "QueryType" || res.Type != "com.apple.mobile.lockdown" {
			log.Println("Unexpected QueryType: ", res)
			return EUNEXPECTEDRESPONSE
		}
		return nil
	}()

	if err != nil {
		l.c.Close()
		return nil, errors.Wrap(err, "Unexpected QueryType")
	}

	// STARTSESSION
	{
		var res lockdownStartSessionResponse
		s := lockdownStartSessionRequest{l.pair.HostID, "2", "StartSession", l.pair.SystemBUID}
		sendPlist(l.c, s, &res)
		l.session_id = res.SessionID
	}

	l.c.(*loop_pcap.NetWrapper).Conn, err = tls_connect(l.c.(*loop_pcap.NetWrapper).Conn, l.GetCert())
	if err != nil {
		l.c.Close()
		return nil, errors.Wrap(err, "Unable to StartSession")
	}

	log.Println("LOCKDOWN: Connected: SessionID: ", l.session_id)

	//HEARTBEAT
	l.exit = make(chan struct{})
	StartHeartbeat(l)

	return l, nil
}

func (l *Lockdown) GetCert() tls.Certificate {
	if l.cert == nil {
		cert, err := tls.X509KeyPair(l.pair.HostCertificate, l.pair.HostPrivateKey)
		if err != nil {
			log.Fatal("INVALID HOST CERTIFICATE", err)
		}
		l.cert = &cert
	}
	return *l.cert
}
