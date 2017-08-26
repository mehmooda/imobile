package itunes

type iTunesError int

const (
	EGRACEFULSHUTDOWN iTunesError = iota
	ENOADDRESSGIVEN
	EUNEXPECTEDRESPONSE
)

type Error struct{}

func (e iTunesError) Error() string {
	switch e {
	case EGRACEFULSHUTDOWN:
		return "Device Requested Graceful Shutdown"
	case ENOADDRESSGIVEN:
		return "Connect called with empty IP address"
	case EUNEXPECTEDRESPONSE:
		return "Unexpected Response Recieved"
	}
	return "UNHANDLED"
}
