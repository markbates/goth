package oura

// APIError describes an error from the Oura API
type APIError struct {
	Code        int
	Description string
}

// NewAPIError initializes an Oura APIError
func NewAPIError(code int, description string) APIError {
	return APIError{code, description}
}

func (e APIError) Error() string {
	return e.Description
}
