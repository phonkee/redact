package redact

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/fatih/structtag"
	"go.uber.org/zap"
)

// Field cleans all redacted data and returns something
func Field(name string, what interface{}) zap.Field {
	value := reflect.ValueOf(what)
	for value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return zap.Any(name, nil)
		}
		value = value.Elem()
	}

	if value.Kind() != reflect.Struct {
		return zap.Error(fmt.Errorf("%v not struct: %v", name, what))
	}

	if v, ok := redact(value); ok {
		return zap.Any(name, v)
	}

	return zap.Any(name, nil)
}

// redact redacts given value
func redact(value reflect.Value) (interface{}, bool) {
	for value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return nil, false
		}
		value = value.Elem()
	}

	switch value.Kind() {
	case reflect.Struct:
		data := make(map[string]interface{}, 0)

		// we are struct
		for i := 0; i < value.Type().NumField(); i++ {
			f := value.Type().Field(i)
			fv := value.Field(i).Interface()

			tags, err := structtag.Parse(string(f.Tag))
			if err != nil {
				continue
			}
			// check if we need to redact
			redactTag, err := tags.Get("redact")
			if err != nil {
				if strings.Contains(err.Error(), "tag does not exist") {
					if v, ok := redact(reflect.ValueOf(fv)); ok {
						data[f.Name] = v
					}
					continue
				}
			}

			if fn, ok := process[redactTag.Name]; ok {
				if val, ok := fn(fv); ok {
					data[f.Name] = val
				}
			} else {
				// warning
			}
		}
		return data, true
	case reflect.Array, reflect.Slice:
		result := make([]interface{}, 0, value.Len())
		for i := 0; i < value.Len(); i++ {
			if v, ok := redact(value.Index(i)); ok {
				result = append(result, v)
			}
		}

		return result, true
	case reflect.Map:
		result := make(map[interface{}]interface{})
		iter := value.MapRange()
		for iter.Next() {
			if v, ok := redact(iter.Value()); ok {
				result[iter.Key().Interface()] = v
			}
		}
		return result, true
	default:
		return value.Interface(), true
	}
}
