package redact

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrintf(t *testing.T) {
	t.Run("Test simple values", func(t *testing.T) {
		type Sub struct {
			Value          string
			OmitValue      string `redact:"omit"`
			ProtectedValue string `redact:"protect"`
			URLValue       string `redact:"url"`
			Subs           []Sub
		}
		type Data struct {
			Value          string
			OmitValue      string `redact:"omit"`
			ProtectedValue string `redact:"protect"`
			URLValue       string `redact:"url"`
			Sub            *Sub
			OmitSub        Sub `redact:"omit"`
		}

		data := Data{
			Value:          "hello",
			OmitValue:      "notshow",
			ProtectedValue: "some value",
			URLValue:       "http://username:secret@localhost/",
			Sub: &Sub{
				Value:          "hello",
				OmitValue:      "notshow",
				ProtectedValue: "some value",
				URLValue:       "http://username:secret@localhost/",
				Subs: []Sub{
					{
						Value:          "hello",
						OmitValue:      "notshow",
						ProtectedValue: "some value",
						URLValue:       "http://username:secret@localhost/",
					},
					{
						Value:          "hello",
						OmitValue:      "notshow",
						ProtectedValue: "some value",
						URLValue:       "http://username:secret@localhost/",
					},
				},
			},
			OmitSub: Sub{
				Value:          "hello",
				OmitValue:      "notshow",
				ProtectedValue: "some value",
				URLValue:       "http://username:secret@localhost/",
			},
		}

		result, ok := redact(reflect.ValueOf(data))
		assert.True(t, ok)
		assert.IsType(t, map[string]interface{}{}, result)

		resultString, _ := json.Marshal(result)
		resultExpect, _ := json.Marshal(map[string]interface{}{
			"Value":          "hello",
			"ProtectedValue": "*****",
			"Sub": map[string]interface{}{
				"Value":          "hello",
				"ProtectedValue": "*****",
				"Subs": []map[string]interface{}{
					{
						"Value":          "hello",
						"ProtectedValue": "*****",
						"Subs":           []interface{}{},
						"URLValue":       "http://username:redacted@localhost/",
					},
					{
						"Value":          "hello",
						"ProtectedValue": "*****",
						"Subs":           []interface{}{},
						"URLValue":       "http://username:redacted@localhost/",
					},
				},
				"URLValue": "http://username:redacted@localhost/",
			},
			"URLValue": "http://username:redacted@localhost/",
		})
		assert.JSONEq(t, string(resultExpect), string(resultString))
	})
}
