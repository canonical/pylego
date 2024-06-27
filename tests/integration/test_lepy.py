from lepy import run_lego_command
import os

# Run Pebble, a smaller version of Boulder from letsencrypt designed for CI/CD
# Set up Go
# Add ~/go/bin to your $PATH, or set GOBIN to a directory that is in your $PATH already, 
# so that pebble will be in your $PATH for easy execution.
# You already need Go in order to build this anyway
# One way to do this is to add export PATH=$PATH:$HOME/go/bin to your ~/.profile
# git clone https://github.com/letsencrypt/pebble/
# cd pebble
# go install ./cmd/pebble

# temporarily trust /test/certs/pebble.minica.pem
# Root CA certificate is also available at: https://0.0.0.0:15000/roots/0
# export SSL_CERT_FILE=/home/kayra/Documents/work/canonical/lepy/tests/integration/pebble/test/certs/pebble.minica.pem
# run pebble -config ./test/config/pebble-config.json -strict false

def test_given_request_certificate_when_request_sent_then_certificate_issued():
    filename = os.path.join(os.path.dirname(__file__), 'test_files/test.csr')
    test_csr = open(filename).read().encode()
    response = run_lego_command("something@nowhere.com", "localhost:14000", test_csr, "httpreq", {})
    
    assert response.error == None
    assert response.metadata.domain == 'localhost'