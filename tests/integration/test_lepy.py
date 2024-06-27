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

import os
filename = os.path.join(os.path.dirname(__file__), 'test_files/test.csr')
test_csr = open(filename).read().encode()
response = run_lego_command("something@gmail.com", "localhost:14000", test_csr, "httpreq", {})
print(response)