package identity

var reservedDSMNames = map[string]bool{
	"admin":          true,
	"administrator":  true,
	"administrators": true,
	"root":           true,
}

func IsReservedDSMUsername(value string) bool {
	return reservedDSMNames[Normalize(value)]
}

func IsReservedDSMGroupname(value string) bool {
	return reservedDSMNames[Normalize(value)]
}
