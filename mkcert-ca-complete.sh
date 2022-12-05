#!/bin/bash

this=$(realpath "${BASH_SOURCE[0]}")
scriptdir=$(dirname "$this")

prefix=.
separator=,
genpkey=()

inArray()
{
	local IFS="$separator"
	local __array="$1[*]"
	local __value=$2

	[[ "${IFS}${!__array}${IFS}" =~ "${IFS}${__value}${IFS}" ]]
}

usage()
{
	cat <<EOF
$0 [options] name [name [name ...]]

  name    Certificate name from JSON config.

          If CAs are being specified, certificates must be in order from
          root to user certificate(s).

  options

  -c --config=
     --genpkey=ca-root,ca-intermediate,name
         Force re-creation of private key for entities separated by --separator
  -h --help
  -p --prefix=/path/to:etc/ssl
     --separator=,
     --ssldir=
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
			readarray -t -d "${separator}" < <(echo -n "${arg:10}")
			genpkey+=("${MAPFILE[@]}")
			args+=("${MAPFILE[@]}") # Upon key creation, also create (new) cert
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
		--separator=*)
			separator="${arg:12}"
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
		*)
			inArray args "$arg" || args+=("$arg")
			;;
		esac
	fi
done

set -- "${args[@]}"

if [ -z "$config" ]; then
	if [ -f "$HOME/mkcert-ca-complete.conf.json" ]; then
		config="$HOME/mkcert-ca-complete.conf.json"
	else
		config="$scriptdir/mkcert-ca-complete.conf.json"
	fi

	echo Using parameters from "$config"
fi

if [[ $verbose ]]; then

	if [ -t 1 ]; then
		yellow=$'\033[33m'
		none=$'\033[m'
	fi

	openssl=$(command -v openssl 2>/dev/null) ||
	{
		echo -e "\033[37;1mopenssl not found.\033[m" >&2
		exit 2
	}

	exec 3<&1

	openssl()
	{
		# Don't trace within this function
		[[ $- == ${-//x/} ]] || set +x

		local arg
		local args

		for arg
		do
			args+=("$(printf "%q" "$arg")")
		done

		echo -e "${yellow}$openssl ${args[@]}${none}" >&3

		[[ $- == ${-//x/} ]] || set -x

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

fromJson()
{
	local name="$1"
	jq -er '.[] | select(.name=="'"$name"'") | to_entries[] |
		"[" + .key + "]=" + @sh "\(.value)"' "$config"
}

cd "$scriptdir"

mkdir -p "${ssldir}"

for name
do
	declare -A "user=($(fromJson "$name"))"

	if [ -z "${user[subject]}" ]; then
		echo "Please specify subject for '$name'." >&2
		exit 1
	fi

	if [ -z "${user[issuer]}" ]; then
		echo "Please specify issuer for '$name'." >&2
		exit 1
	fi

	declare -A "ca=($(fromJson "${user[issuer]}"))"

	if [ -z "${ca[subject]}" ]; then
		echo "Please specify subject for issuing CA '${ca[name]}'." >&2
		exit 1
	fi

	if [ -z "${ca[ca]}" ]; then
		echo "Please specify type for issuing CA '${ca[name]}'." >&2
		exit 1
	fi

	ca[pkey]="${ssldir}/${ca[dir]}/private/${ca[name]}.key"
	ca[cert]="${ssldir}/${ca[dir]}/certs/${ca[name]}.crt"
	ca[crl]="${ssldir}/${ca[dir]}/revoked/${ca[name]}.crl"

	user[pkey]="${ssldir}/${user[dir]}/private/${user[name]}.key"
	user[csr]="${ssldir}/${ca[dir]}/csr/${user[name]}.csr"
	user[cert]="${ssldir}/${user[dir]}/certs/${user[name]}.crt"

	# Create config from template
	sed "s:%{ssldir}:${ssldir}:g
		s:%{ca_dir}:${ca[dir]}:g
		s*%{distcrl}*${ca[distcrl]}*g
		${user[altnames]:+s/\[usr_cert\]/&\nsubjectAltName = @alt_names/g}
		${user[altnames]:+\$ a \\\n[alt_names]\n${user[altnames]//:/\\n}}
	" "${scriptdir}/openssl.cnf.template" > "${ssldir}/openssl.cnf"

	# Populate folder structure
	for dir in csr database newcerts revoked
	do
		mkdir -p -m 0700 "${ssldir}/${ca[dir]}/$dir"
	done

	touch "${ssldir}/${ca[dir]}/database/index.txt"

	[ -f "${ssldir}/${ca[dir]}/database/index.txt.attr" ] ||
	{
		echo 'unique_subject = no' > "${ssldir}/${ca[dir]}/database/index.txt.attr"
		chmod 0600 "${ssldir}/${ca[dir]}/database/index.txt.attr"
	}
	[ -f "${ssldir}/${ca[dir]}/database/serial" ] ||
	{
		echo '1000' > "${ssldir}/${ca[dir]}/database/serial"
		chmod 0600 "${ssldir}/${ca[dir]}/database/serial"
	}
	[ -f "${ssldir}/${ca[name]}/revoked/crlnumber" ] ||
	{
		echo '1000' > "${ssldir}/${ca[dir]}/revoked/crlnumber"
		chmod 0600 "${ssldir}/${ca[dir]}/revoked/crlnumber"
	}

	mkdir -p -m 0700 "${ssldir}/${user[dir]}/certs"
	mkdir -p -m 0700 "${ssldir}/${user[dir]}/private"

	# For intermediate CAs and user certificates we need an issuing CA cert
	if [[ ${user[ca]} != root ]]; then
		if ! [ -f "${ca[cert]}" ]; then
			echo -e "\033[37;1mChecking for CA certificate:\033[m"
			echo -e "  \033[31m${ca[name]} certificate not found.\033[m" >&2
			exit 3
		fi
	fi

	# Create private key, if not found or explicitly requested
	if [[ -f "${user[pkey]}" ]]; then
		if inArray genpkey "${user[name]}"; then
			backup "${user[pkey]}"
			pkey=
		else
			pkey="${user[pkey]}"
		fi
	else
		pkey=
	fi

	if [[ ${user[ca]} ]]; then
		bits=8192
	else
		bits=4096
	fi

	if [[ ! $pkey ]]; then
		if result=$(echo -n "${user[passwd]}" |
				openssl genpkey \
					-algorithm RSA \
					-pkeyopt rsa_keygen_bits:$bits \
					-aes-256-cbc \
					-out "${user[pkey]}" \
					-pass stdin 2>&1); then
			chmod 0400 "${user[pkey]}"
		else
			echo -e "\033[37;1mCreating private key failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 10
		fi
	fi

	if [[ root == ${user[ca]} ]]; then
		# Create Self-signed CA/root certificate
		if result=$(echo -n "${ca[passwd]}" |
				openssl req \
					-new \
					-x509 -extensions v3_ca -sha512 -days 9125 \
					-config "${ssldir}/openssl.cnf" \
					-utf8 \
					-out "${user[cert]}" \
					-key "${ca[pkey]}" \
					-subj "${user[subject]}" \
					-passin stdin 2>&1); then
			chmod 0600 "${ca[cert]}"
		else
			echo -e "\033[37;1mCreating self-signed certificate for '${user[name]}' failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 12
		fi
	else
		# Create CSR to be signed by CA
		if ! result=$(echo -n "${user[passwd]}" |
				openssl req \
					-new \
					-utf8 \
					-config ${ssldir}/openssl.cnf \
					-out "${user[csr]}" \
					-key "${user[pkey]}" \
					-subj "${user[subject]}" \
					-passin stdin 2>&1); then
			echo -e "\033[37;1mCreating CSR for '${user[name]}' failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 11
		fi

		# Create certificate from CSR
		if [[ root == ${ca[ca]} ]]; then
			section=CA_root
		else
			section=CA_default
		fi

		if [[ ${user[ca]} ]]; then
			extensions=v3_intermediate_ca
		else
			extensions=usr_cert
		fi

		if result=$(echo -n "${ca[passwd]}" |
				openssl ca \
					-config "${ssldir}/openssl.cnf" \
					-name "$section" \
					-extensions "$extensions" \
					-notext \
					-batch \
					-passin stdin \
					-cert "${ca[cert]}" \
					-keyfile "${ca[pkey]}" \
					-out "${user[cert]}" \
					-infiles "${user[csr]}" 2>&1); then
			chmod 0600 "${user[cert]}"
		else
			echo -e "\033[37;1mCreating Certificate from CSR failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 12
		fi

		# Check certificate against CA cert
		if ! result=$(openssl verify -partial_chain \
					-CAfile "${ca[cert]}" \
					"${user[cert]}" 2>&1); then
			echo -e "\033[37;1mCreating certificate chain failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 13
		fi

		# Create revocation list
		if ! result=$(echo -n "${ca[passwd]}" |
				openssl ca \
					-gencrl \
					-config "${ssldir}/openssl.cnf" \
					-name "$section" \
					-cert "${ca[cert]}" \
					-keyfile "${ca[pkey]}" \
					-out "${ca[crl]}" \
					-passin stdin 2>&1); then
			echo -e "\033[37;1mCreating CRL failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 14
		fi
	fi

	if [[ intermediate == ${ca[ca]} ]]; then
		chain=("${ca[cert]}" "${chain[@]}")
	fi

	if [[ ! ${user[ca]} ]]; then
		# Supply the chain of intermediate(s) with the certificate
		cat "${user[cert]}" "${chain[@]}" > "${user[cert]%.crt}-chain.crt"
		chmod 0644 "${user[cert]%.crt}-chain.crt"
	fi

	# Create scripts for adding/removing certificates to/from Windows trust store

	if [[ ${user[ca]} ]]; then
		mkdir -p tmp

		# Build DOS path to certificate
		path="${user[cert]}"
		path="%~dp0\\..\\${path//\//\\}"

		if [[ root == ${user[ca]} ]]; then
			store=root
		else
			store=ca
		fi

		sed 's/$/\r/g' <<-EOF > "tmp/certmgr-add-${user[name]}.bat"
			:: Order of arguments is important here - certmgr.exe is not that flexible...
			"%~dp0\\..\\bin\\certmgr.exe" -add -c "$path" -s $store
EOF

		sed 's/$/\r/g' <<-EOF > "tmp/certmgr-rm-${user[name]}.bat"
			:: This script is intended for debugging only!
			:: Do not use this script in a production environment, as it
			:: may leave your security (trust) settings misconfigured.
			:: You have been warned!
			chcp 65001
			:root
			:: Enter cert # from the above list to delete-->
			echo 1 | "%~dp0\..\bin\certmgr.exe" -del -c -n "$name" -s root
			if errorlevel 0 goto root
EOF
	fi
done
