# logrus-cef-formatter [![Build Status](https://travis-ci.org/ArthurHlt/logrus-cef-formatter.svg?branch=master)](https://travis-ci.org/ArthurHlt/logrus-cef-formatter)

A logrus formatter to write log output as [common event format](https://kc.mcafee.com/resources/sites/MCAFEE/content/live/CORP_KNOWLEDGEBASE/78000/KB78712/en_US/CEF_White_Paper_20100722.pdf).

## Usage

```go
package main

import (
	"github.com/ArthurHlt/logrus-cef-formatter"
	"github.com/sirupsen/logrus"
	)

func main()  {
	logger := logrus.New()
	logger.Formatter = cef.NewCEFFormatter("device_vendor", "device_product", "device_version")
	
	logger.WithField("foo", "bar").Info("my message")
	// produce: CEF:0|device_vendor|device_product|device_version|my message|my message|0|rt=<unix timestamp> foo=bar
	
	// you can provide signature_id with field entry
	logger.WithField(cef.KeySignatureID, "my-sig").WithField("foo", "bar").Info("my message")
	// produce: CEF:0|device_vendor|device_product|device_version|my-sig|my message|0|rt=<unix timestamp> foo=bar
}
```