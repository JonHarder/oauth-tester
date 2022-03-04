package parameters

import "net/http"

type ParameterBag struct {
	Parameters map[string]string
}

func NewFromQuery(req *http.Request) *ParameterBag {
	params := &ParameterBag{
		Parameters: make(map[string]string),
	}
	for key, val := range req.URL.Query() {
		if len(val) > 0 {
			params.Parameters[key] = val[0]
		}
	}
	return params
}

func NewFromForm(req *http.Request) (*ParameterBag, error) {
	if err := req.ParseForm(); err != nil {
		return nil, err
	}
	params := &ParameterBag{
		Parameters: make(map[string]string),
	}
	for key, val := range req.Form {
		if len(val) > 0 {
			params.Parameters[key] = val[0]
		}
	}
	return params, nil
}
