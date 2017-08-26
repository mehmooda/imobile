package itunes

import "log"
import "time"
import "net"
import "io"
import "io/ioutil"

type afcpair struct {
	a *AfcConn
	l *Lockdown
}

type AfcRetryConn struct {
	inner   *AfcConn
	l       *Lockdown
	n       chan afcpair
	handles map[string]uint64
}

func NewRetryAfc(i net.IP, p PairRecord) (*AfcRetryConn, error) {
	l, err := Connect(i, p)
	if err != nil {
		log.Println("ERR: ", err)
		return nil, err
	}
	a, err := StartAFC(l)
	if err != nil {
		log.Println("ERR: ", err)
		l.StopSession()
		return nil, err
	}

	return &AfcRetryConn{
		inner:   a,
		l:       l,
		n:       make(chan afcpair),
		handles: make(map[string]uint64),
	}, nil
}

func (afc *AfcRetryConn) Give(i net.IP, p PairRecord) {
	if afc.inner == nil {
		l, err := Connect(i, p)
		if err != nil {
			log.Println("ERR: ", err)
			return
		}
		a, err := StartAFC(l)
		if err != nil {
			log.Println("ERR: ", err)
			l.StopSession()
			return
		}
		select {
		case afc.n <- afcpair{a, l}:
			return
		case <-time.After(5 * time.Second):
			log.Println("RETRYAFC: GIVE TIMEOUT")
		}
		a.Close()
		l.StopSession()
	}
}

func (afc *AfcRetryConn) retry_error(err error) bool {
	afc.inner.Close()
	afc.l.StopSession()
	if err.Error() != "Shutdown" {
		log.Println("RETRYAFC: ", err)
		return false
	}
	log.Println("RETRYAFC: WAITING FOR NEW CONNECTION")
	afc.l = nil
	afc.inner = nil
	afc.handles = make(map[string]uint64)
	ret := <-afc.n
	afc.inner = ret.a
	afc.l = ret.l
	log.Println("RETRYAFC: NEW CONNECTION")
	return true
}

type AfcFile struct {
	rafc  *AfcRetryConn
	file  string
	seek  int64
	last  int64
	lastT time.Time
}

// Reopen file and seeks to correct position
func (f *AfcFile) fixFile() error {
	for {
		new_f, err := f.rafc.OpenFile(f.file)
		if err != nil {
			return err
		}
		if f.seek != 0 {
			if _, err := new_f.Seek(f.seek, 0); err != nil {
				return err
			}
		}
		f = new_f
		return nil
	}
}

func (f *AfcFile) Read(p []byte) (n int, err error) {
	for {
		handle, ok := f.rafc.handles[f.file]
		if !ok {
			if err := f.fixFile(); err != nil {
				return 0, err
			}
			continue
		}
		read, err := f.rafc.inner.FileRefRead(handle, uint64(len(p)))
		if err == nil {
			f.seek += int64(len(read))
			copy(read, p)
			v := time.Now()
			if v.Sub(f.lastT) > time.Second {
				log.Println("READING : ", f.file, len(p), f.seek-f.last, v.Sub(f.lastT))
				f.lastT = v
				f.last = f.seek
			}
			if len(read) == 0 {
				return 0, io.EOF
			}
			return len(read), nil
		}
		if !f.rafc.retry_error(err) {
			return 0, err
		}
	}
}

func (f *AfcFile) Seek(offset int64, whence int) (int64, error) {
	for {
		handle, ok := f.rafc.handles[f.file]
		if !ok {
			if err := f.fixFile(); err != nil {
				return 0, err
			}
			continue
		}
		if whence < 0 || whence > 2 {
			panic("SEEK")
		}
		err := f.rafc.inner.FileRefSeek(handle, offset, whence)
		if err == nil {
			switch whence {
			case 0:
				f.seek = offset
			case 1:
				f.seek += offset
			case 2:
				fi, err := f.rafc.GetFileInfo(f.file)
				if err == nil {
					f.seek = int64(fi.St_size) + offset
				}
				if !f.rafc.retry_error(err) {
					return 0, err
				}
				continue
			}
			f.last = f.seek
			return f.seek, nil
		}
		if !f.rafc.retry_error(err) {
			return 0, err
		}
	}
}

func (f *AfcFile) Close() error {
	if handle, ok := f.rafc.handles[f.file]; ok {
		err := f.rafc.inner.FileRefClose(handle)
		if err != nil && err.Error() != "Shutdown" {
			return err
		}
	}
	return nil
}

func (afc *AfcRetryConn) OpenFile(file string) (*AfcFile, error) {
	for {
		handle, err := afc.inner.FileRefOpen(file)
		if err != nil {
			if !afc.retry_error(err) {
				return nil, err
			}
			continue
		}
		afc.handles[file] = handle
		return &AfcFile{afc,
			file,
			0,
			0,
			time.Now(),
		}, nil
	}
}

func (afc *AfcRetryConn) GetFile(file string) ([]byte, error) {
	f, err := afc.OpenFile(file)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(f)
}

func (afc *AfcRetryConn) GetFileHash(file string) error {
	vheader := []byte(nil)
	vheader = append(vheader, []byte(file)...)
	vheader = append(vheader, 0)
	vheader = append(vheader, 16, 0, 0, 0, 0, 0, 0, 0)
	vheader = append(vheader, 16, 0, 0, 0, 0, 0, 0, 0)
	res, err := afc.inner.SendPacket(0x1F, vheader, nil)
	if err != nil {
		return err
	}
	log.Println("FILE_HASH", res)
	return nil
}

func (afc *AfcRetryConn) GetFileInfo(file string) (FileInfo, error) {
	for {
		ret, err := afc.inner.GetFileInfo(file)
		if err == nil {
			return ret, err
		}
		if !afc.retry_error(err) {
			return ret, err
		}
	}
}

func (afc *AfcRetryConn) GetDirectory(dir string) ([]string, error) {
	for {
		ret, err := afc.inner.GetDirectory(dir)
		if err == nil {
			return ret, nil
		}
		if !afc.retry_error(err) {
			return nil, err
		}
	}
}
