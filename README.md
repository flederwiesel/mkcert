### mkcert-ca-complete.sh

Completely sets up your root/intermediate CA and issues one user certificate based on the values found in `mkcert-ca-complete.conf`.

```
     --ca-intermediate                      Create certificates from intermediate CA down to user.
     --ca-root                              Create all certificates including root.
     --genpkey=ca-root,ca-intermediate,user Create new private key before certificate creation. Sets --ca-root or --ca-intermediate accordingly.
  -h --help
  -p --prefix                               ... of ssldir (which defaults to ./etc/ssl).
  -v --verbose
```

#### Environment variables

ssldir=.

#### Exit Codes

-  1 Invalid parameter
-  2 File not found
-  3 No CA certificate found. Re-run with `--ca-root`/`--ca-intermediate` to create.
- 10 Creating private key failed
- 11 Creating CSR failed
- 12 Creating Certificate failed
- 13 Certificate verification failed
- 14 Creating CRL failed

### $HOME/mkcert-ca-complete.conf

```
[caRoot]
dir=/CA/root
name=ca-root
subject=/C=??/L=City/O=organisation/CN=ca-root-name
passwd=~/*'"'"'´`"?!$h|#*
distcrl=URI:https://www.example.com/CA/root.crl

[caIntermediate]
dir=/CA/intermediate
name=ca-intermediate
subject=/C=??/L=City/O=organisation/OU=unit/CN=ca-intermediate-name
passwd='''"""``$(*)
distcrl=URI:https://www.example.com/CA/intermediate.crl

[user]
dir=localhost
name=localhost
subject=/C=??/L=City/O=organisation/OU=unit/CN=localhost
passwd=********
```
