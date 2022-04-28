package redact

import (
	"fmt"
	"net/url"
	"reflect"
)

const (
	redacted       = "*****"
	redactedString = "redacted"
)

var (
	process = map[string]func(value interface{}) (interface{}, bool){
		"omit":    processOmit,
		"protect": processProtect,
		"url":     processURL,
	}
)

func processOmit(value interface{}) (interface{}, bool) {
	return nil, false
}
func processProtect(_ interface{}) (interface{}, bool) {
	return redacted, true
}
func processURL(value interface{}) (interface{}, bool) {
	val := reflect.ValueOf(value)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() == reflect.String {
		u, err := url.ParseRequestURI(fmt.Sprintf("%v", val.Interface()))
		if err != nil {
			return value, false
		}
		if u.User != nil && u.User.Username() != "" {
			u.User = url.UserPassword(u.User.Username(), redactedString)
			return u.String(), true
		}
	}

	return value, true
}
