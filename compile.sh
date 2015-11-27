set -x CGO_CFLAGS "-I/Users/remco/Projects/keytalk-proxy/includes/openssl-1.0.2d/include/"
set -x CGO_LDFLAGS "-L/Users/remco/Projects/keytalk-proxy/includes/openssl-1.0.2d/"
gb build

