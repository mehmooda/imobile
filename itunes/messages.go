package itunes

type lockdownQueryRequest struct {
	ProtocolVersion string
	Request         string
}

type lockdownQueryResponse struct {
	Request string
	Type    string
}

type lockdownStartSessionRequest struct {
	HostID          string
	ProtocolVersion string
	Request         string
	SystemBUID      string
}

type lockdownStartSessionResponse struct {
	EnableSessionSSL bool
	Request          string
	SessionID        string
}

type lockdownStartServiceRequest struct {
	ProtocolVersion string
	Request         string
	Service         string
}

type lockdownStartServiceResponse struct {
	Service          string
	Port             int
	EnableServiceSSL bool
}

type lockdownStopSessionRequest struct {
	ProtocolVersion string
	Request         string
	SessionID       string
}

type lockdownGetValueRequest struct {
	ProtocolVersion string
	Request         string
	Key             string
}

type lockdownGetValueResponse struct {
	Request string
	Key     string
	Value   interface{}
}
