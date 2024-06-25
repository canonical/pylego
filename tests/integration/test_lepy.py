from lepy import run_lego_command

# Run Pebble, a smaller version of Boulder from letsencrypt designed for CI/CD
# Set up Go
# Add ~/go/bin to your $PATH, or set GOBIN to a directory that is in your $PATH already, so that pebble will be in your $PATH for easy execution.
# One way to do this is to add export PATH=$PATH:$HOME/go/bin to your ~/.profile
# git clone https://github.com/letsencrypt/pebble/
# cd pebble
# go install ./cmd/pebble

# temporarily trust /test/certs/pebble.minica.pem
# Root CA certificate is also available at: https://0.0.0.0:15000/roots/0
# export SSL_CERT_FILE=/home/kayra/Documents/work/canonical/lepy/tests/integration/pebble/test/certs/pebble.minica.pem
# run pebble -config ./test/config/pebble-config.json -strict false

test_csr = b"""-----BEGIN CERTIFICATE REQUEST-----
MIICszCCAZsCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDC5KgrADpuOUPwSh0YLmpWF66VTcciIGC2HcGn
oJknL7pm5q9qhfWGIdvKKlIA6cBB32jPd0QcYDsx7+AvzEvBuO7mq7v2Q1sPU4Q+
L0s2pLJges6/cnDWvk/p5eBjDLOqHhUNzpMUga9SgIod8yymTZm3eqQvt1ABdwTg
FzBs5QdSm2Ny1fEbbcRE+Rv5rqXyJb2isXSujzSuS22VqslDIyqnY5WaLg+pjZyR
+0j13ecJsdh6/MJMUZWheimV2Yv7SFtxzFwbzBMO9YFS098sy4F896eBHLNe9cUC
+d1JDtLaewlMogjHBHAxmP54dhe6vvc78anElKKP4hm5N5nlAgMBAAGgWDBWBgkq
hkiG9w0BCQ4xSTBHMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcD
AQYIKwYBBQUHAwIwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQEL
BQADggEBACP1VKEGVYKoVLMDJS+EZ0CPwIYWsO4xBXgK6atHe8WIChVn/8I7eo60
cuMDiy4LR70G++xL1tpmYGRbx21r9d/shL2ehp9VdClX06qxlcGxiC/F8eThRuS5
zHcdNqSVyMoLJ0c7yWHJahN5u2bn1Lov34yOEqGGpWCGF/gT1nEvM+p/v30s89f2
Y/uPl4g3jpGqLCKTASWJDGnZLroLICOzYTVs5P3oj+VueSUwYhGK5tBnS2x5FHID
uMNMgwl0fxGMQZjrlXyCBhXBm1k6PmwcJGJF5LQ31c+5aTTMFU7SyZhlymctB8mS
y+ErBQsRpcQho6Ok+HTXQQUcx7WNcwI=
-----END CERTIFICATE REQUEST-----
"""

test_vars = {"NAMECHEAP_API_USER": "bigdawg", "NAMECHEAP_API_KEY": "smalldawg"}
run_lego_command("something@gmail.com", "127.0.0.1:14000", test_csr, "namecheap", test_vars)
