#!/bin/bash

this=$(readlink -f "${BASH_SOURCE[0]}")
scriptdir=$(dirname "$this")

intermediate=false
root=false
prefix=.

usage()
{
	cat <<EOF
$0
     --ca-intermediate
     --ca-root
  -c --config
     --genpkey=ca-root,ca-intermediate,user
  -h --help
  -p --prefix=/path/to:etc/ssl
     --ssldir
  -v --verbose
EOF

	exit 0
}

for arg
do
	if [ -n "$expect" ]; then
		eval "$expect=$arg"
		unset expect
	else
		case "$arg" in
		--ca-intermediate)
			intermediate=true
			;;
		--ca-root)
			root=true
			;;
		-c)
			expect=config
			;;
		--config)
			expect=config
			;;
		--config=*)
			config=${arg:9}
			;;
		--genpkey=*)
			genpkey=${arg:10}
			echo "$genpkey" | grep -Fq 'root' && root=true
			echo "$genpkey" | grep -Fq 'intermediate' && intermediate=true
			;;
		-h|--help)
			usage
			;;
		-p)
			expect=prefix
			;;
		--prefix=*)
			prefix="${arg:9}"
			;;
		--ssldir=*)
			ssldir="${arg:9}"
			;;
		--ssldir)
			expect=ssldir
			;;
		-v|--verbose)
			verbose="$arg"
			;;
		esac
	fi
done

if [ -z "$config" ]; then
	if [ -f "$HOME/mkcert-ca-complete.conf" ]; then
		config="$HOME/mkcert-ca-complete.conf"
	else
		config="$scriptdir/mkcert-ca-complete.conf"
	fi

	echo Using parameters from "$config"
fi

if settings=$(awk 'BEGIN { q = sprintf("%c", 0x27) }

			/\[.*\]/ {
				var = gensub(/[][]/, "", "g", $1)
			}

			/^[^#]+=/ {
				key = gensub(/=.*/, "", "g", $0)
				value = gensub(/^[^=]+=/, "", "g", $0)
				value = gensub(/\047/, "\047\"\047\"\047", "g", value)

				print "declare -A " var
				printf(var "[" key "]=\047" value "\047\n")
			}
			' "$config" 2>&1); then
	eval "$settings"
	unset settings
else
	echo -e "\033[37;1mUnable to read configuration:\033[m" >&2
	echo -e "  \033[31m${result:-'$config' not found}\033[m" >&2
	exit 1
fi

if [ -z "${user[subject]}" ]; then
	echo "Please specify subject." >&2
	exit 1
else
	if $intermediate; then
		if [ -z "${caIntermediate[subject]}" ]; then
			echo "No proper configuration found for intermediate CA." >&2
			exit 1
		fi
	fi

	if $root; then
		if [ -z "${caRoot[subject]}" ]; then
			echo "No proper configuration found for root CA." >&2
			exit 1
		fi
	fi
fi

if [[ $verbose ]]; then

	if [ -t 2 ]; then
		yellow=$'\033[33m'
		none=$'\033[m'
	fi

	openssl=$(command -v openssl 2>/dev/null) ||
	{
		echo -e "\033[37;1mopenssl not found.\033[m" >&2
		exit 2
	}

	exec 3<&2

	openssl() {
		local arg
		local args

		for arg
		do
			args+=("$(printf "%q" "$arg")")
		done

		echo -e "${yellow}$openssl ${args[@]}${none}" >&3

		"$openssl" "$@"
	}
fi

backup()
{
	for f
	do
		d=$(date -d @$(stat --format=%Z "$f") +%Y%m%d_%H%M%S)
		mv "$f" "$f~$d"
	done
}

ssldir="${ssldir:-${prefix}/etc/ssl}"
ssldir="${ssldir#./}"

### Populate folder structure

cd "$scriptdir"

mkdir -p "${ssldir}"

# Create config from template
#envsubst < "$scriptdir/openssl.cnf.template" > "$scriptdir/openssl.cnf"
sed "s:%{ssldir}:${ssldir}:g
s*%{distcrlRoot}*${caRoot[distcrl]}*g
s*%{distcrlIntm}*${caIntermediate[distcrl]}*g
${user[altnames]:+s/\[usr_cert\]/&\nsubjectAltName = @alt_names/g}
${user[altnames]:+\$ a \\\n[alt_names]\n${user[altnames]//:/\\n}}
" "${scriptdir}/openssl.cnf.template" > "${ssldir}/openssl.cnf"

for issuer in "${caRoot[dir]}" "${caIntermediate[dir]}"
do
	for dir in certs csr database newcerts private revoked
	do
		mkdir -p -m 0700 "${ssldir}/${issuer}/$dir"
	done

	touch "${ssldir}/${issuer}/database/index.txt"

	[ -f "${ssldir}/${issuer}/database/index.txt.attr" ] ||
	{
		echo 'unique_subject = no' > "${ssldir}/${issuer}/database/index.txt.attr"
		chmod 0600 "${ssldir}/${issuer}/database/index.txt.attr"
	}
	[ -f "${ssldir}/${issuer}/database/serial" ] ||
	{
		echo '1000' > "${ssldir}/${issuer}/database/serial"
		chmod 0600 "${ssldir}/${issuer}/database/serial"
	}
	[ -f "${ssldir}/${issuer}/revoked/crlnumber" ] ||
	{
		echo '1000' > "${ssldir}/${issuer}/revoked/crlnumber"
		chmod 0600 "${ssldir}/${issuer}/revoked/crlnumber"
	}
done

if $root; then

	intermediate=true

	### Create CA/root private key

	caRoot[pkey]="${ssldir}/${caRoot[dir]}/private/${caRoot[name]}.key"

	if [[ -f "${caRoot[pkey]}.enc" ]]; then
		if [[ $genpkey =~ root ]]; then
			backup "${caRoot[pkey]}" "${caRoot[pkey]}.enc"
			caRoot[genpkey]="${caRoot[pkey]}.enc"
		fi
	else
		caRoot[genpkey]="${caRoot[pkey]}.enc"
	fi

	if [[ ${caRoot[genpkey]} ]]; then
		if result=$(echo -n "${caRoot[passwd]}" |
				openssl genpkey \
					-algorithm RSA \
					-pkeyopt rsa_keygen_bits:8192 \
					-aes-256-cbc \
					-out "${caRoot[genpkey]}" \
					-pass stdin 2>&1); then
			chmod 0400 "${caRoot[genpkey]}"
		else
			echo -e "\033[37;1mCreating private key failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 10
		fi

		# Remove passphrase

		if result=$(echo -n "${caRoot[passwd]}" |
				openssl rsa \
					-out "${caRoot[pkey]}" \
					-in "${caRoot[genpkey]}" \
					-passin stdin 2>&1); then
			chmod 0400 "${caRoot[pkey]}"
		else
			echo -e "\033[37;1mRemoving passphrase from key failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 10
		fi
	fi

	### Create Self-signed CA/root certificate

	if result=$(echo -n "${caRoot[passwd]}" |
			openssl req \
				-new \
				-x509 -extensions v3_ca -sha512 -days 9125 \
				-config "${ssldir}/openssl.cnf" \
				-utf8 \
				-out "${ssldir}/${caRoot[dir]}/certs/${caRoot[name]}.crt" \
				-key "${caRoot[pkey]}" \
				-subj "${caRoot[subject]}" \
				-passin stdin 2>&1); then
		chmod 0600 "${ssldir}/${caRoot[dir]}/certs/${caRoot[name]}.crt"
	else
		echo -e "\033[37;1mCreating self-signed certificate for root CA failed:\033[m" >&2
		echo -e "  \033[31m$result\033[m" >&2
		exit 12
	fi
fi

if $intermediate; then

	### Create CA/intermediate private key

	if ! [ -f "${ssldir}/${caRoot[dir]}/certs/${caRoot[name]}.crt" ]; then
		echo -e "\033[37;1mChecking for CA certificate:\033[m"
		echo -e "  \033[31m${caRoot[name]} certificate not found.\033[m" >&2
		exit 3
	fi

	caIntermediate[pkey]="${ssldir}/${caIntermediate[dir]}/private/${caIntermediate[name]}.key"

	if [[ -f "${caIntermediate[pkey]}" ]]; then
		if [[ $genpkey =~ intermediate ]]; then
			backup "${caIntermediate[pkey]}" "${caIntermediate[pkey]}.enc"
			caIntermediate[genpkey]="${caIntermediate[pkey]}.enc"
		fi
	else
		caIntermediate[genpkey]="${caIntermediate[pkey]}.enc"
	fi

	if [[ ${caIntermediate[genpkey]} ]]; then
		if result=$(echo -n "${caIntermediate[passwd]}" |
				openssl genpkey \
					-algorithm RSA \
					-pkeyopt rsa_keygen_bits:8192 \
					-aes-256-cbc \
					-out "${caIntermediate[genpkey]}" \
					-pass stdin 2>&1); then
			chmod 0400 "${caIntermediate[genpkey]}"
		else
			echo -e "\033[37;1mCreating private key failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 10
		fi

		# Remove passphrase

		if result=$(echo -n "${caIntermediate[passwd]}" |
				openssl rsa \
					-out "${caIntermediate[pkey]}" \
					-in "${caIntermediate[genpkey]}" \
					-passin stdin 2>&1); then
			chmod 0400 "${caIntermediate[pkey]}"
		else
			echo -e "\033[37;1mRemoving passphrase from key failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 10
		fi
	fi

	### Create CSR for CA/intermediate to be signed by CA/root

	if ! result=$(echo -n "${caIntermediate[passwd]}" |
			openssl req \
				-new \
				-utf8 \
				-config ${ssldir}/openssl.cnf \
				-out "${ssldir}/${caRoot[dir]}/csr/${caIntermediate[name]}.csr" \
				-key "${caIntermediate[pkey]}" \
				-subj "${caIntermediate[subject]}" \
				-passin stdin 2>&1); then
		echo -e "\033[37;1mCreating CSR for intermediate CA failed:\033[m" >&2
		echo -e "  \033[31m$result\033[m" >&2
		exit 11
	fi

	### Create CA/intermediate certificate from CSR

	if result=$(echo -n "${caRoot[passwd]}" |
			openssl ca \
				-config "${ssldir}/openssl.cnf" \
				-name CA_root \
				-extensions v3_intermediate_ca \
				-notext \
				-batch \
				-passin stdin \
				-cert "${ssldir}/${caRoot[dir]}/certs/${caRoot[name]}.crt" \
				-keyfile "${caRoot[pkey]}" \
				-out "${ssldir}/${caIntermediate[dir]}/certs/${caIntermediate[name]}.crt" \
				-infiles "${ssldir}/${caRoot[dir]}/csr/${caIntermediate[name]}.csr" 2>&1); then
		chmod 0600 "${ssldir}/${caIntermediate[dir]}/certs/${caIntermediate[name]}.crt"
	else
		echo -e "\033[37;1mCreating Certificate from CSR failed:\033[m" >&2
		echo -e "  \033[31m$result\033[m" >&2
		exit 12
	fi

	# Check certificate against CA cert
	if ! result=$(openssl verify -partial_chain \
				-CAfile "${ssldir}/${caRoot[dir]}/certs/${caRoot[name]}.crt" \
				"${ssldir}/${caIntermediate[dir]}/certs/${caIntermediate[name]}.crt" 2>&1); then
		echo -e "\033[37;1mCreating certificate chain failed:\033[m" >&2
		echo -e "  \033[31m$result\033[m" >&2
		exit 13
	fi

	# Create revocation list
	if ! result=$(echo -n "${caRoot[passwd]}" |
			openssl ca \
				-gencrl \
				-config "${ssldir}/openssl.cnf" \
				-name CA_root \
				-cert "${ssldir}/${caRoot[dir]}/certs/${caRoot[name]}.crt" \
				-keyfile "${ssldir}/${caRoot[dir]}/private/${caRoot[name]}.key" \
				-out "${ssldir}/${caRoot[dir]}/revoked/${caRoot[name]}.crl" \
				-passin stdin 2>&1); then
		echo -e "\033[37;1mCreating CRL failed:\033[m" >&2
		echo -e "  \033[31m$result\033[m" >&2
		exit 14
	fi
fi

### Create user private key

if ! [ -f "${ssldir}/${caIntermediate[dir]}/certs/${caIntermediate[name]}.crt" ]; then
	echo -e "\033[37;1mChecking for CA certificate:\033[m"
	echo -e "  \033[31m${caIntermediate[name]} certificate not found.\033[m" >&2
	exit 3
fi

mkdir -p -m 0700 "${ssldir}/${user[dir]}/certs"
mkdir -p -m 0700 "${ssldir}/${user[dir]}/private"

user[pkey]="${ssldir}/${user[dir]}/private/${user[name]}.key"

if [[ -f "${user[pkey]}.enc" ]]; then
	if [[ $genpkey =~ user ]]; then
		backup "${user[pkey]}" "${user[pkey]}.enc"
		user[genpkey]="${user[pkey]}.enc"
	fi
else
	user[genpkey]="${user[pkey]}.enc"
fi

if [[ ${user[genpkey]} ]]; then
	if result=$(echo -n "${user[passwd]}" |
			openssl genpkey \
				-algorithm RSA \
				-pkeyopt rsa_keygen_bits:4096 \
				-aes-256-cbc \
				-out "${user[genpkey]}" \
				-pass stdin 2>&1); then
		chmod 0400 "${user[genpkey]}"
	else
		echo -e "\033[37;1mCreating private key failed:\033[m" >&2
		echo -e "  \033[31m$result\033[m" >&2
		exit 10
	fi

	# Remove passphrase

	if result=$(echo -n "${user[passwd]}" |
			openssl rsa \
				-out "${user[pkey]}" \
				-in "${user[genpkey]}" \
				-passin stdin 2>&1); then
		chmod 0400 "${user[pkey]}"
	else
		echo -e "\033[37;1mRemoving passphrase from key failed:\033[m" >&2
		echo -e "  \033[31m$result\033[m" >&2
		exit 10
	fi
fi

### Create CSR for user to be signed by CA/intermediate

if ! result=$(echo -n "${user[passwd]}" |
		openssl req \
			-new \
			-utf8 \
			-config ${ssldir}/openssl.cnf \
			-out "${ssldir}/${caIntermediate[dir]}/csr/${user[name]}.csr" \
			-key "${user[pkey]}" \
			-subj "${user[subject]}" \
			-passin stdin 2>&1); then
	echo -e "\033[37;1mCreating CSR for user failed:\033[m" >&2
	echo -e "  \033[31m$result\033[m" >&2
	exit 11
fi

### Create user certificate from CSR

if result=$(echo -n "${caIntermediate[passwd]}" |
		openssl ca \
			-config "${ssldir}/openssl.cnf" \
			-name CA_default \
			-extensions usr_cert \
			-notext \
			-batch \
			-passin stdin \
			-cert "${ssldir}/${caIntermediate[dir]}/certs/${caIntermediate[name]}.crt" \
			-keyfile "${caIntermediate[pkey]}" \
			-out "${ssldir}/${user[dir]}/certs/${user[name]}.crt" \
			-infiles "${ssldir}/${caIntermediate[dir]}/csr/${user[name]}.csr" 2>&1); then
	chmod 0600 "${ssldir}/${user[dir]}/certs/${user[name]}.crt"
else
	echo -e "\033[37;1mCreating Certificate from CSR failed:\033[m" >&2
	echo -e "  \033[31m$result\033[m" >&2
	exit 12
fi

# Check certificate against CA cert
if ! result=$(openssl verify -partial_chain \
			-CAfile "${ssldir}/${caIntermediate[dir]}/certs/${caIntermediate[name]}.crt" \
			"${ssldir}/${user[dir]}/certs/${user[name]}.crt" 2>&1); then
	echo -e "\033[37;1mCreating certificate chain failed:\033[m" >&2
	echo -e "  \033[31m$result\033[m" >&2
	exit 13
fi

# Create revocation list
if ! result=$(echo "${caIntermediate[passwd]}" |
		openssl ca \
			-gencrl \
			-config "${ssldir}/openssl.cnf" \
			-name CA_default \
			-cert "${ssldir}/${caIntermediate[dir]}/certs/${caIntermediate[name]}.crt" \
			-keyfile "${ssldir}/${caIntermediate[dir]}/private/${caIntermediate[name]}.key" \
			-out "${ssldir}/${caIntermediate[dir]}/revoked/${caIntermediate[name]}.crl" \
			-passin stdin 2>&1); then
	echo -e "\033[37;1mCreating CRL failed:\033[m" >&2
	echo -e "  \033[31m$result\033[m" >&2
	exit 14
fi

# Supply the chain of intermediate(s) with the certificate
cat "${ssldir}/${user[dir]}/certs/${user[name]}.crt" \
	"${ssldir}/${caIntermediate[dir]}/certs/${caIntermediate[name]}.crt" \
	> "${ssldir}/${user[dir]}/certs/${user[name]}-chain.crt"

chmod 0644 "${ssldir}/${user[dir]}/certs/${user[name]}-chain.crt"

### Create scripts for adding/removing certificates to/from store

if $root || $intermediate; then
	mkdir -p tmp

	:> tmp/certmgr-add.bat

	cat <<-EOF > tmp/certmgr-rm.bat
		:: This script is intended for debugging only!
		:: Do not use this script in a production environment, as it
		:: may leave your security (trust) settings misconfigured.
		:: You have been warned!
		chcp 65001
EOF

	if $root; then
		d="caRoot[dir]"
		n="caRoot[name]"
		s="caRoot[subject]"
		# Build DOS path to certificate
		path="%~dp0\\..\\${ssldir//\//\\}\\${!d//\//\\}\\certs\\${!n}.crt"

		# Order of arguments is important here - certmgr.exe is not that flexible...
		echo "%~dp0\\..\\bin\\certmgr.exe -add -c \"$path\" -s root" >> "$scriptdir/tmp/certmgr-add.bat"

		name=$(sed -r 's#.*/CN=(([^/]|\\/)+).*#\1#g' <<<"${!s}")

		cat <<EOF >> tmp/certmgr-rm.bat
:root
:: Enter cert # from the above list to delete-->
echo 1 | %~dp0\..\bin\certmgr.exe -del -c -n "$name" -s root
if errorlevel 0 goto root
EOF
	fi

	if $intermediate; then
		d="caIntermediate[dir]"
		n="caIntermediate[name]"
		s="caIntermediate[subject]"
		# Build DOS path to certificate
		path="%~dp0\\..\\${ssldir//\//\\}\\${!d//\//\\}\\certs\\${!n}.crt"

		# Order of arguments is important here - certmgr.exe is not that flexible...
		echo "%~dp0\\..\\bin\\certmgr.exe -add -c \"$path\" -s ca" >> "$scriptdir/tmp/certmgr-add.bat"

		name=$(sed -r 's#.*/CN=(([^/]|\\/)+).*#\1#g' <<<"${!s}")

		cat <<EOF >> tmp/certmgr-rm.bat
:intermediate
:: Enter cert # from the above list to delete-->
echo 1 | %~dp0\..\bin\certmgr.exe -del -c -n "$name" -s ca
if errorlevel 0 goto intermediate
EOF
	fi

	sed -i 's/$/\r/g' tmp/certmgr-add.bat
	sed -i 's/$/\r/g' tmp/certmgr-rm.bat
fi
