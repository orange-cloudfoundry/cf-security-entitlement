package cef

import (
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"reflect"
	"strings"
	"time"
)

const KeySignatureID = "signature_id"

type formatter struct {
	DeviceVendor     string
	Version          string
	DeviceProduct    string
	DeviceVersion    string
	DisableTimestamp bool
}

func NewCEFFormatter(deviceVendor, deviceProduct, deviceVersion string) *formatter {
	return &formatter{
		DeviceVendor:  deviceVendor,
		DeviceProduct: deviceProduct,
		DeviceVersion: deviceVersion,
		Version:       "0",
	}
}

func (f formatter) Format(entry *logrus.Entry) ([]byte, error) {
	sigId := entry.Message
	data := entry.Data
	if _, ok := entry.Data[KeySignatureID]; ok {
		sigId = fmt.Sprint(data[KeySignatureID])
		delete(data, KeySignatureID)
	}
	name := entry.Message
	if !f.DisableTimestamp {
		data["rt"] = time.Now().Unix()
	}
	fmtData, err := f.formatData(data)
	if err != nil {
		return []byte{}, err
	}
	cefMsg := fmt.Sprintf(
		"CEF:%s|%s|%s|%s|%s|%s|%d|%s\n",
		f.Version,
		f.DeviceVendor,
		f.DeviceProduct,
		f.DeviceVersion,
		sigId,
		name,
		f.level(entry),
		fmtData,
	)
	return []byte(cefMsg), nil
}

func (f formatter) formatData(fields logrus.Fields) (string, error) {
	keyVals := make([]string, 0)
	for k, v := range fields {
		vKind := reflect.TypeOf(v).Kind()
		vFormat := ""
		if vKind == reflect.Struct ||
			vKind == reflect.Slice ||
			vKind == reflect.Array ||
			vKind == reflect.Map {
			b, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			vFormat = string(b)
		} else {
			vFormat = fmt.Sprint(v)
		}
		keyVals = append(keyVals, fmt.Sprintf("%s=%s", k, vFormat))
	}
	return strings.Join(keyVals, " "), nil
}

func (f formatter) level(entry *logrus.Entry) int {
	switch entry.Level {
	case logrus.ErrorLevel:
		return 2
	case logrus.FatalLevel:
		return 10
	case logrus.PanicLevel:
		return 10
	case logrus.WarnLevel:
		return 1
	default:
		return 0
	}
}
