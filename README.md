### mkcert-ca-complete.sh

Completely sets up your root/intermediate CA and issues one user certificate
based on the values found in `mkcert-ca-complete.conf.json`.

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

### `mkcert-ca-complete.conf.json`

Configuration file containing an array of entity objects identified by "name".
Currently, only a set of known names is supported according to `mkcert-ca-complete.sh` options:

- `{ "name": "ca-root" }`
- `{ "name": "ca-intermediate" }`
- `{ "name": "user" }`

Each object must contain

- "subject" - certificate DN
- "altnames" - certificate subject alternative names, colon-separated
- "password"
- "dir" - location of the files to be created (below `--ssldir`)

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
