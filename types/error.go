package types

import "errors"

var ErrorClairServer = errors.New("clair server error")
var ErrorUnauthorized = errors.New("unauthorized")
var ErrorForbidden = errors.New("forbidden")
var ErrorUnknown = errors.New("unknown")

type ScanError struct {
	ErrMsg  string
	ErrType ScanErrorType
}

type ScanErrorType string

const (
	ClairServer  ScanErrorType = "errorClairServer"
	Forbidden    ScanErrorType = "errorForbidden"
	Unauthorized ScanErrorType = "errorUnauthorized"
	Unknown      ScanErrorType = "errorUnknown"
)

func ConvertError(err error) *ScanError {
	if errors.Is(err, ErrorUnauthorized) {
		return &ScanError{
			ErrMsg:  err.Error(),
			ErrType: Unauthorized,
		}
	} else if errors.Is(err, ErrorClairServer) {
		return &ScanError{
			ErrMsg:  err.Error(),
			ErrType: ClairServer,
		}
	} else if errors.Is(err, ErrorForbidden) {
		return &ScanError{
			ErrMsg:  err.Error(),
			ErrType: Forbidden,
		}
	} else {
		return &ScanError{
			ErrMsg:  err.Error(),
			ErrType: Unknown,
		}
	}
}
