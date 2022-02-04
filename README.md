## mkcert-ca-complete.sh

Completely sets up your root/intermediate CA and issues one user certificate based on the values found in `mkcert-ca-complete.conf`.

```
     --ca-intermediate                      Create certificates from intermediate CA down to user.
     --ca-root                              Create all certificates including root.
     --genpkey=ca-root,ca-intermediate,user Create new private key before certificate creation. Sets --ca-root or --ca-intermediate accordingly.
  -h --help
  -p --prefix                               ... of ssldir (which defaults to ./etc/ssl).
  -v --verbose
```

#### Exit Codes

-  1 Configuration error
- 10 Creating private key failed
- 11 Creating CSR failed
- 12 Creating Certificate (self-signed or from CSR) failed
- 20 No root certificate found. Re-run with `--ca-root` to create.
- 21 No intermediate certificate found. Re-run with `--ca-intermediate` to create, or `--ca-root` to create the root certifiate as well.

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
dir=
name=user
subject=/C=??/L=City/O=organisation/OU=unit/CN=user
passwd=********
```

### mkcert

```
  -a --applicant=/CA/root|/CA/intermediate| Request originator. 'user', if empty.
  -B --no-backup                            Backup private keys and certificates
  -c --certname=                            Certificate to be created
  -f --force                                Overwrite private key as specified in --request-key
  -h --help
  -i --issuer=/CA/root|/CA/intermediate
  -k --keyname=                             Private key to be used for CSR/sign operation
  -K --request-key=                         Create private key
  -p --prefix=                              Sets ssl root path, overwites $ssldir
  -P --passwd=
  -r --request=                             CSR name
  -s --subj= --subject=
  -S --sign=                                CSR to be signed within --issuer
  -v --verbose
```

#### Environment variables

ssldir=.

#### Exit Codes
-  1 Invalid parameter
-  2 File exists
- 11 Creating private key (or removing passphrase from it) failed
- 12 Creating CSR failed
- 13 Creating Certificate (self-signed or from CSR) failed
- 14 Creating certificate chain failed
- 15 Creating CRL failed
