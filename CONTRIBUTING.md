# Requirements

Integration tests use [pebble](https://github.com/letsencrypt/pebble), a testing ACME server
created by LetsEncrypt. Go needs to be installed, and the PATH needs to include $GOBIN in order
to clone and install this dependency. The integration test imports pylego assuming pylego is installed
as a package, so installation is required for the integration test to execute properly.

To install the testing dependencies:

```
pip install '.[test]'
```
