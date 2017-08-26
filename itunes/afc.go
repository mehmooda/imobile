package itunes

import "net"
import "encoding/binary"
import "bytes"
import "log"
import "io"
import "errors"
import "strconv"
import "runtime/debug"

type AfcConn struct {
	net.Conn
	packetnum uint64
	exit      chan struct{}
}

func StartAFC(l *Lockdown) (*AfcConn, error) {
	c, err := l.StartService("com.apple.afc")
	if err != nil {
		return nil, err
	}
	return &AfcConn{Conn: c, exit: l.exit}, nil
}

type AFCPacket struct {
	packetnum uint64
	op        uint64
	vheader   []byte
	payload   []byte
}

func (afc *AfcConn) SendPacket(op uint64, vheader []byte, payload []byte) (*AFCPacket, error) {
	select {
	case <-afc.exit:
		log.Println("AFC SendPacket: Graceful Shutdown")
		debug.PrintStack()
		return nil, errors.New("Shutdown")
	default:
	}
	var fheader [40]byte
	binary.BigEndian.PutUint64(fheader[0:], 0x434641364c504141)
	binary.LittleEndian.PutUint64(fheader[8:], uint64(40+len(vheader)+len(payload)))
	binary.LittleEndian.PutUint64(fheader[16:], uint64(40+len(vheader)))
	binary.LittleEndian.PutUint64(fheader[24:], afc.packetnum)
	binary.LittleEndian.PutUint64(fheader[32:], op)

	n, err := afc.Write(fheader[:])
	if err != nil || n != 40 {
		log.Println("AFC: Write FHeader ", n, err)
	}
	n, err = afc.Write(vheader)
	if err != nil || n != len(vheader) {
		log.Println("AFC: Write VHeader ", n, err)
		panic("FATAL LOG")
	}
	n, err = afc.Write(payload)
	if err != nil || n != len(payload) {
		log.Println("AFC: Write Payload ", n, err)
		panic("FATAL LOG")
	}
	var rfheader [40]byte
	n, err = io.ReadFull(afc, rfheader[:])
	if err != nil || n != 40 {
		log.Println("AFC: Read FHeader ", n, err)
		select {
		case <-afc.exit:
			log.Println("AFC SendPacket: Graceful Shutdown after write")
		default:
			log.Println("AFC SendPacket: NON Graceful Shutdown")
			close(afc.exit)
			return nil, errors.New("Shutdown")
		}
	}
	if binary.BigEndian.Uint64(rfheader[0:]) != 0x434641364c504141 {
		log.Println("AFC: FHeader != CFA6LPAA")
		panic("FATAL LOG")
	}

	toread := binary.LittleEndian.Uint64(rfheader[8:]) - 40
	data := make([]byte, toread)
	n, err = io.ReadFull(afc, data)
	if err != nil || uint64(n) != toread {
		log.Println("AFC: Read ", toread, n, err)
		panic("FATAL LOG")
	}

	split := binary.LittleEndian.Uint64(rfheader[16:]) - 40
	res := &AFCPacket{
		packetnum: afc.packetnum,
		op:        binary.LittleEndian.Uint64(rfheader[32:]),
		vheader:   data[:split],
		payload:   data[split:],
	}
	afc.packetnum += 1

	switch res.op {
	case 0:
		log.Println("AFC: SendPacket: Unexpected Response", res)
		panic("FATAL LOG")
	case 1, 14: //STATUS
		if len(res.vheader) != 8 || len(res.payload) != 0 {
			log.Println("AFC: SendPacket: Unexpected Response", res)
			panic("FATAL LOG")
		}
	case 2: //Data
		if len(res.vheader) != 0 {
			log.Println("AFC: SendPacket: Unexpected Data Response", res)
			panic("FATAL LOG")
		}
	}
	return res, nil
}

func (afc *AfcConn) TEST() {
	afc.DumpFS("/")
}

type FileInfo struct {
	St_size      uint64
	St_blocks    uint64
	St_nlink     uint64
	St_ifmt      IFMT
	St_mtime     uint64
	St_birthtime uint64
}

type IFMT uint64

const (
	S_IFDIR IFMT = iota
	S_IFREG
)

func StringToIFMT(ifmt string) IFMT {
	switch ifmt {
	case "S_IFDIR":
		return S_IFDIR
	case "S_IFREG":
		return S_IFREG
	default:
		log.Println("Unknown IFMT:", ifmt)
		panic("FATAL LOG")
	}
	return 0
}

func (afc *AfcConn) GetFileInfo(file string) (FileInfo, error) {
	vheader := append([]byte(file), 0)
	res, err := afc.SendPacket(0x0A, vheader, nil)
	if err != nil {
		return FileInfo{}, err
	}
	v := NullTermToStrings(res.payload)
	if len(v) != 12 || v[0] != "st_size" || v[2] != "st_blocks" || v[4] != "st_nlink" || v[6] != "st_ifmt" || v[8] != "st_mtime" || v[10] != "st_birthtime" {
		log.Println("AFC GetFileInfo: Unexpected Payload", v)
		return FileInfo{}, errors.New("Unexpected Payload")
	}
	r1, err := strconv.ParseUint(v[1], 10, 64)
	if err != nil {
		log.Println("AFC ParseUint Error: ", res)
		return FileInfo{}, errors.New("ParseError")
	}
	r3, err := strconv.ParseUint(v[3], 10, 64)
	if err != nil {
		log.Println("AFC ParseUint Error: ", res)
		return FileInfo{}, errors.New("ParseError")
	}
	r5, err := strconv.ParseUint(v[5], 10, 64)
	if err != nil {
		log.Println("AFC ParseUint Error: ", res)
		return FileInfo{}, errors.New("ParseError")
	}
	r9, err := strconv.ParseUint(v[9], 10, 64)
	if err != nil {
		log.Println("AFC ParseUint Error: ", res)
		return FileInfo{}, errors.New("ParseError")
	}
	r11, err := strconv.ParseUint(v[11], 10, 64)
	if err != nil {
		log.Println("AFC ParseUint Error: ", res)
		return FileInfo{}, errors.New("ParseError")
	}
	return FileInfo{
		r1,
		r3,
		r5,
		StringToIFMT(v[7]),
		r9,
		r11,
	}, nil
}

func (afc *AfcConn) FileRefOpen(file string) (uint64, error) {
	vheader := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	vheader = append(vheader, []byte(file)...)
	vheader = append(vheader, 0)

	res, err := afc.SendPacket(13, vheader, nil)
	if err != nil {
		return 0, err
	}

	if res.op == 14 {
		return binary.LittleEndian.Uint64(res.vheader), nil
	}
	log.Println("AFC: Unexpected Response", res)
	panic("FATAL LOG")
	return 0, errors.New("AFC Unexpected Response")
}

func (afc *AfcConn) FileRefRead(handle uint64, length uint64) ([]byte, error) {
	vheader := make([]byte, 16)
	binary.LittleEndian.PutUint64(vheader[:], handle)
	binary.LittleEndian.PutUint64(vheader[8:], length)

	res, err := afc.SendPacket(15, vheader, nil)
	if err != nil {
		return nil, err
	}

	if res.op == 2 {
		return res.payload, nil
	}
	log.Println("AFC: Unexpected Response", res)
	panic("FATAL LOG")
	return nil, errors.New("AFC Unexpected Response")

}

func (afc *AfcConn) FileRefSeek(handle uint64, offset int64, whence int) error {
	vheader := make([]byte, 24)
	binary.LittleEndian.PutUint64(vheader[:], handle)
	binary.LittleEndian.PutUint64(vheader[8:], uint64(offset))
	binary.LittleEndian.PutUint64(vheader[8:], uint64(whence))

	res, err := afc.SendPacket(0x11, vheader, nil)
	if err != nil {
		return err
	}

	if res.op == 1 {
		status := binary.LittleEndian.Uint64(res.vheader)
		if status != 0 {
			panic(status)
		}
		return nil
	}
	log.Println("AFC: Unexpected Response", res)
	panic("FATAL LOG")
	return errors.New("AFC Unexpected Response")
}

func (afc *AfcConn) FileRefClose(handle uint64) error {
	vheader := make([]byte, 8)
	binary.LittleEndian.PutUint64(vheader[:], handle)
	res, err := afc.SendPacket(20, vheader, nil)
	if err != nil {
		return err
	}

	if res.op != 1 && binary.LittleEndian.Uint64(res.vheader) != 0 {
		log.Println("AFC: Unexpected Response", res)
		panic("FATAL LOG")
	}
	return nil
}

func (afc *AfcConn) GetDirectory(dir string) ([]string, error) {
	vheader := append([]byte(dir), 0)
	res, err := afc.SendPacket(3, vheader, nil)
	if err != nil {
		return nil, err
	}

	switch res.op {
	case 1:
		status := binary.LittleEndian.Uint64(res.vheader)
		if status == 4 { // NOT_DIRECTORY?
			return nil, errors.New("AFC Not directory")
		}
		log.Println("AFC: Unexpected Status Response", res)
		panic("FATAL LOG")
		return nil, errors.New("AFC Unexpected Response")
	case 2:
		if len(res.vheader) != 0 || len(res.payload) == 0 {
			log.Println("AFC: DumpFS Payload: ", res)
			panic("FATAL LOG")
			return nil, errors.New("Not sure")
		}
	}
	return NullTermToStrings(res.payload), nil
}

func (afc *AfcConn) DumpFS(dir string) bool {
	b, err := afc.GetDirectory(dir)
	if err != nil {
		panic(err)
	}
	for _, v := range b {
		switch v {
		case ".":
		case "..":
		default:
			fi, err := afc.GetFileInfo(dir + v)
			if err != nil {
				panic(err)
			}
			if fi.St_ifmt != S_IFDIR {
				log.Printf("%10d %10d %s\n", fi.St_size, fi.St_nlink, dir+v)
			} else {
				log.Printf("%10d %10d %s\n", fi.St_size, fi.St_nlink, dir+v+"/")
				afc.DumpFS(dir + v + "/")
			}
		}
	}
	return true
}

func NullTermToStrings(b []byte) (s []string) {
	for {
		i := bytes.IndexByte(b, 0)
		if i == -1 {
			break
		}
		s = append(s, string(b[0:i]))
		b = b[i+1:]
	}
	return
}
