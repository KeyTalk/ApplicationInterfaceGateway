Steps:

This is a `gb` project. Install at `getgb.io`

FOR ALL OPENSSL GENERATION STEPS, MAKE SURE YOU *TYPE IN* THE REQUIRED FIELDS. The suggested field is right next to it before the []. You can just copy-pasta this.

1. Generate a CA with `gen-ca.sh`.
2. Install the CA locally. In OSX, this is in Keychain Access -> Import.
3. Generate the server keypair with `gen-server-keypair.sh`
4. Generate the client keypair with `gen-client-cert.sh`
5. Turn the client keypair into a PEM with `generate-client-pem.sh`
6. Update `example-config.toml` to represent your settings. For our test data, that should work just fine.
7. `gb build`
8. Run with `./bin/keytalk --config <config-file>`
9. This is important. Request with something like `lvh.me` on the proper subdomain, eg `https://headfirst.lvh.me`


openssl s_client -connect 54.72.168.209:443 -showcerts -CAfile ./ca.crt -key ./client.pem -cert client.cert



Use etcd for token store?

https://github.com/coreos/go-etcd

Use keep-alive support:

http://stackoverflow.com/questions/17948827/reusing-http-connections-in-golang


// test ldap
http://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/


ssh ubuntu@52.49.166.207 -R 8389:127.0.0.1:8389

ldapsearch -W -h ldap.forumsys.com -D "uid=tesla,dc=example,dc=com" -b "dc=example,dc=com"


https://github.com/nmcclain/ldap/blob/master/examples/proxy.go
https://quarantaine.lvh.me:8445/
https://tconnect.lvh.me:8445/
