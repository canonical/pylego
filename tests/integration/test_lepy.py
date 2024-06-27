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

test_pk = b"""-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQInwobO/prFzQCAggA
MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECApDgrlQXzIuBIIEyGTVZT775XH2
aziIsM6yPPkLDRsMFWVdwfKwYs7RiyxkJed8WnR+NVpvFU9DKmLMj/qXht52mKrr
CjwtTKejrIu05IkYvsSQ1S9BdvuDXt8LXbjOV9WUBv8gAL+RbVgYD98NRHX9XJ5c
qLHaKITRcH4E4F1f4gpLHwmenQ5pIaG49V/8cnOFk+87SDrMmFUIDTvqjy5vyan4
uaBXBJEHx6J4/NPfuDNX8JrGaw5Dtppbhn5AwLc26MY6hbGwR0H4IadFmqkCGQYm
ASF+ZkcFu3xGoD44Nxh1jTi1WodDoTTThTfwCPUx+pYovPgS+dClRUEO+J80Ilhv
BAoEwoON2VzfoOx91+Y7MFcx5224oVWt2hoP09+CRy0BJUPNJ0ZQSv3ep3uiBxrd
5sOCrxiaZwKlL/eZJ2k4tNAoQk8U4Io712SZzmaR4ExxDjKoVYwROMgzIoBIa2Gt
2nIzTai27xWIktQ5fD/b55tTO8OLmYsvgU39w2mrDwuzrbVMxzgxzyo09jZm31Lu
bFMX7xVA4KzeSP5FaVT0D4N/p7L74acAEck6/E0nJZre0o8p4xDMeoRlebhwx8au
6JK2fdXlyIA/eU80NCWz4XbM2ezIBgKu6YROxtpm6u+GAPMDqwbMDDPjdx/29TKn
eAJ0pxwuU9b4xrpdUxmsX0l23xIamaXx3MowH3GJfojt9pQAXbawarOzyqQQdBF1
9LNt3aM3K1uqZsHNF7//tek20fDA3AwJZPtFnWlM05lV7jfsR0eGRcW/qNuWk+R1
r61FsjvqalW2wLdliCO6ktg2G8CO5RsOvhZ6cYL1r8uPtiR2/78JN6govzs0durb
Um4Q8tPh699F39LPU4v0Hkc1HFwiBuJpzRz0B5QaxJMv7vSTEe36R+xzx813a3oJ
amLFcxHkCazRfyqV5KlwRUrSBohZb9Ia8aAm01vG43Ihv8Hmy8ESBPggm8QxAO7O
4qYw/CqZVLGam/V780w16pgC/vV/OzpCRPRjywc/XF8NR8Ta8UKoK/v4bVrrCciL
Ovu+9WsrQXk1Hjg7UUcr3z7EWtcUwByYc08gDLlZd/bKdRW6cjRE6gV8HjW3oJr0
wg9wTfUA8N7+gDEnW0sCK0RoBFevqgK3PUR/ULMQTtE2pElE+GD1egU63sJUxvjx
lE7h9nt+lkL0Jri9/4KZIxtwE4Up2f0/oLBWK+6AblUVFsAy/1z9qv2mqx1zbYj3
rxWxXwE0Pueqgf0xbM7tKjE+z2l9I1t3+6AUV2Cvq2aRXdtIpapadEq/ZHFQPs1U
PnnSuRhgxeOVDd5x6H3amz7WDps2l8cqbaChbuiYc6ye1O4eK0pUFQrICkI6AzsN
IMANdU0b2Ynmx3EeVLImu/zn0H4BQsAXn07GLEJEKVhgXolyxAQ8O3xo+Rlns48Y
0kDVPYOj6mCjVXfrQyHQB6WFuelXdBKl0KKbAYp6THn1vbuJGx6yJOyDxhv577Hh
1TUu4/thvGA9j+VUFTukJ3Y7uX/+FSt39uUxP9jvzpfZ0kxNt7/qnfuVJDkE+2iu
8siG/bUH6KULT3/WRRra8NSrHEjdgBJSoS2ZFi6Qf2rqGwaJEj+GBn82/3SrZBrH
0bqeMBcOU+z/huqFOqPMlA==
-----END ENCRYPTED PRIVATE KEY-----
"""
test_csr = b"""-----BEGIN CERTIFICATE REQUEST-----
MIICnjCCAYYCAQAwWTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDESMBAGA1UEAwwJbG9j
YWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu9y7XNnVqijM
jgPjF0WwISXysaNs1mkk0S220zwkNLWTcnVgbhbkVK173Dpezaq25Y2hTtXLXXpZ
F10nbj8/GH4JkrYZQ3pz9+9Z7qQPwePVHZGKXGk22ZoULLJHL2x3V3TY/VZm6xKj
o8PqbD1rNNDao0j7AertnII9OQ86/fTPFpfBP4fK3657YFfJ1DlDdNPkmLwX7M4X
AumZ7DxiOJJPICVCMtOF6P5kyBp0CVuEJz+rSN9tXTWYV3ds/+ZU3ZzdLA3gzwIH
nKaUWRb1qwyobGQ/s93b8Lou4dXULeMRO1hhrNun+6mRjeNVw/7GiHecrFg1UmK4
1tB3eR1UuQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBABV6EghBJ8iP7ArEgkRc
JSmL22Oez6qUKDf7LjpFGIP0KBt7daMQ+X3VTG4a62tf4csm6J3l/UDpwqOCPis8
YyL4tF7xLQ3MIGZs1IPJpsL0lrvaYWwIMXUSEMpv/yyFgQZvDJqK+4V9hx6UK+sW
si5mEaTF697pYg+r9oZWasEg/gYKfJrVODEewGaYMwD/tAls416Efvd5X51fQw9g
joCOYgQSArvm+UIHXiN+yu2JKwhjg2UVpOuPXANPXObkfKqseWXlN8Y4U2t9yIPb
BFVA87d1D28/KzeSY/ngQxTs9otNmfR1DdSpwCFm8cCbJULHXxwt6uNC/1F9pbuc
40k=
-----END CERTIFICATE REQUEST-----
"""

test_vars = {"HTTPREQ_ENDPOINT": "http://my.server.com:9090"}
response = run_lego_command("something@gmail.com", "127.0.0.1:14000", test_csr, "httpreq", test_vars)
print(response)
