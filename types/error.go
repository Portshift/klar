package types

import "errors"

var ErrorClairServer = errors.New("clair server error")
var ErrorUnauthorized = errors.New("unauthorized")

type ScanError struct {
	ErrMsg  string
	ErrType ScanErrorType
}

type ScanErrorType string

const (
	ClairServer  ScanErrorType = "errorClairServer"
	Unauthorized ScanErrorType = "errorUnauthorized"
	Unknown      ScanErrorType = "errorUnknown"
)

func ConvertError(err error) ScanError {
	if errors.Is(err, ErrorUnauthorized) {
		return ScanError{
			ErrMsg:  err.Error(),
			ErrType: Unauthorized,
		}
	} else if errors.Is(err, ErrorClairServer) {
		return ScanError{
			ErrMsg:  err.Error(),
			ErrType: ClairServer,
		}
	} else {
		return ScanError{
			ErrMsg:  err.Error(),
			ErrType: Unknown,
		}
	}
}

