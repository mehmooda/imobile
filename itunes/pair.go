package itunes

import "os"
import "log"
import "github.com/DHowett/go-plist"
import "io/ioutil"
import "net"

type PairRecord struct {
	DeviceCertificate []byte
	EscrowBag         []byte
	HostCertificate   []byte
	HostID            string
	HostPrivateKey    []byte
	RootPrivateKey    []byte
	SystemBUID        string
	WiFiMACAddress    string
}

func LoadPairs() (ret map[string]PairRecord) {
	ret = make(map[string]PairRecord)
	//TODO: Determine file automatically
	files := []string{
		"Lockdown/02bf95695a8082259200385fca5a34ae00e80da7.plist",
		"Lockdown/9f79ffa8d50044b0457eb1ad970a6ab81982449b.plist",
	}
	for _, fn := range files {
		file, err := os.Open(fn)
		if err != nil {
			log.Fatal(err)
		}
		buf, err := ioutil.ReadAll(file)
		if err != nil {
			log.Fatal(err)
		}
		var v PairRecord
		_, err = plist.Unmarshal(buf, &v)
		if err != nil {
			log.Fatal(err)
		}
		hw, err := net.ParseMAC(v.WiFiMACAddress)
		if err != nil {
			log.Fatal(err)
		}
		IPbyte := []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, hw[0] ^ 0x02, hw[1], hw[2], 0xff, 0xfe, hw[3], hw[4], hw[5]}
		instanceName := hw.String() + "\\@" + net.IP(IPbyte).String()
		ret[instanceName] = v
		log.Println("Loaded Pair Record:", instanceName)
	}
	return
}
