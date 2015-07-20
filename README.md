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
