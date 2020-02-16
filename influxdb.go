package main

import (
	"crypto/tls"
	"crypto/x509"
	"expvar"
	"log"
	"os"
	"time"

	"github.com/influxdata/influxdb/client/v2"
)

const (
	influxTable    = "whoami"
	influxUsername = "frood"
	influxDatabase = "frood"
	influxAddr     = "https://influxdb:8086"
	influxRoot     = `-----BEGIN CERTIFICATE-----
MIIE1DCCAzygAwIBAgIRAL1uZZswS6fWex3VEuNfoKUwDQYJKoZIhvcNAQELBQAw
gYExHjAcBgNVBAoTFW1rY2VydCBkZXZlbG9wbWVudCBDQTErMCkGA1UECwwiZmls
aXBwb0BGaWxpcHBvcy1NYWNCb29rLVByby5sb2NhbDEyMDAGA1UEAwwpbWtjZXJ0
IGZpbGlwcG9ARmlsaXBwb3MtTWFjQm9vay1Qcm8ubG9jYWwwHhcNMTgwODI1MjIy
NzI5WhcNMjgwODI1MjIyNzI5WjCBgTEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3Bt
ZW50IENBMSswKQYDVQQLDCJmaWxpcHBvQEZpbGlwcG9zLU1hY0Jvb2stUHJvLmxv
Y2FsMTIwMAYDVQQDDClta2NlcnQgZmlsaXBwb0BGaWxpcHBvcy1NYWNCb29rLVBy
by5sb2NhbDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAMSzlxsjwhkZ
7l5Zqe7+UqdwA+tcbll2zc4n5k3qqnLXv5IaDlKSkJDp/XygYvw94Cg6YMZ4bTPF
nnPBH+YE+/+nXFWyLjlxfWHmpUVOV/W4aFaZQ8v8nScjgzwuN2fskigJBcrfD3eL
dXCAcMPTB0Sp/EJ8YIt+VgyMKuBBvBn9dg4sPxLnkC+T9JYSRHmZMSK/kkPhlJUh
Toj7CEBNR98J0YuozrxVL0qajlihSRcXv4zLBXPGBXbkodKlxDBRE+hyjMtWhqtL
WOZSH9lbuccRWohzomMpmwRxxwinxowUJ6SQrsJsUXsgRHMHN6cN7zEOkUflh4UY
JJvNAD9fErEHl1jiAIWEcx3sr085iko9PtY0Wg8CsnOyA8RR74iWxGi0HXJmSPD5
NWiFZJvzD/iz9mYTp1oLxMrKcwrxi57TmcDGJ50nwZFHwj1CCZr4nnNQhg3SH3Yh
P5BQGRQ5vDbtEh6t2HcdJnq3U8fEtJcZUP1LBwGVu6c1dYUMmLFi2QIDAQABo0Uw
QzAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU
H81fJLLgEa5AzctEzXCQrvnQ4uQwDQYJKoZIhvcNAQELBQADggGBAFMG0j1/tSdt
WnJBlv/tmfD4jJCHpUlD6mf5p19xy3ZfU8wDa59Cgi5ByvWRlrTgSkxRdILF7oxe
yuFceUbDXGWW+S2scJIExZVQLIHC33ki8wBe5N1C+O7/w6hPQsy7idVj9Z7xZQFb
JJQMLv1OaSK9p1L3eGCJ0rSrfqmEr/waL7Oelk9kAvRzx69A8KiGhskFsMjCW9Fc
cXhBSSRrdI5QI9gvsTh4R07r/yXeGW7qWdiMfrDh5i8FEeHUGz2f84LX1nap95e9
rYRgtMgDHO3bL1WiPjNBntUdLq3iLmTOa7zrXFUvZ0y5jd9HLhSexJ1TyXaoOr2M
Nb3Cf4ZiUTDe8hYdiNNdFcuLLBDXT6fZNvuolLIVPGsQXaNElSD6+xT8UY5/IyOg
pdNvDnPjkJ2ux+f9vqTiWFbuNRlqaTNphwjc/RigeIaKPB00DqohJR3vqf630XBL
3RHVEytTfupy/k9RJCbenkpITzTJgnW9WV3XkSTw/CCv2ikXmoTJlg==
-----END CERTIFICATE-----`
)

func startInfluxDB() {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(influxRoot))
	c, err := client.NewHTTPClient(client.HTTPConfig{
		Addr:      influxAddr,
		Username:  influxUsername,
		Password:  os.Getenv("INFLUXDB_PASSWORD"),
		Timeout:   10 * time.Second,
		TLSConfig: &tls.Config{RootCAs: pool},
	})
	if err != nil {
		log.Fatalln("InfluxDB error:", err)
	}

	go func() {
		for range time.Tick(10 * time.Second) {
			fields := make(map[string]interface{})
			var do func(string, expvar.KeyValue)
			do = func(prefix string, kv expvar.KeyValue) {
				switch v := kv.Value.(type) {
				case *expvar.Int:
					fields[prefix+kv.Key] = v.Value()
				case *expvar.Float:
					fields[prefix+kv.Key] = v.Value()
				case *expvar.String:
					fields[prefix+kv.Key] = v.Value()
				case *expvar.Map:
					v.Do(func(x expvar.KeyValue) { do(kv.Key+".", x) })
				default:
					fields[prefix+kv.Key] = v.String()
				}
			}
			expvar.Do(func(kv expvar.KeyValue) { do("", kv) })

			if len(fields) == 0 {
				continue
			}

			bp, _ := client.NewBatchPoints(client.BatchPointsConfig{
				Database:  influxDatabase,
				Precision: "s",
			})
			pt, err := client.NewPoint(influxTable, nil, fields, time.Now())
			if err != nil {
				log.Fatalln("InfluxDB error:", err)
			}
			bp.AddPoint(pt)
			if err := c.Write(bp); err != nil {
				log.Fatalln("InfluxDB write error:", err)
			}
		}
	}()
}
