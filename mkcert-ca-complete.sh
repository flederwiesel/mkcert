#!/bin/bash

this=$(realpath "${BASH_SOURCE[0]}")
scriptdir=$(dirname "$this")

intermediate=
root=
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
$0 name [name [name ...]]

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

if inArray genpkey ca-root ||
   inArray args    ca-root; then
	root=true
fi

if inArray genpkey ca-intermediate ||
   inArray args    ca-intermediate; then
	intermediate=true
fi

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

declare -A "caRoot=($(fromJson ca-root))"
declare -A "caIntermediate=($(fromJson ca-intermediate))"

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

	if [[ ca-root == ${user[name]} ]]; then

		### Create CA/root private key, if not found or explicitly requested

		if [[ -f "${user[pkey]}" ]]; then
			if inArray genpkey ca-root; then
				backup "${user[pkey]}"
				pkey=
			else
				pkey="${user[pkey]}"
			fi
		else
			pkey=
		fi

		if [[ ! $pkey ]]; then
			if result=$(echo -n "${user[passwd]}" |
					openssl genpkey \
						-algorithm RSA \
						-pkeyopt rsa_keygen_bits:8192 \
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

		### Create Self-signed CA/root certificate

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
			echo -e "\033[37;1mCreating self-signed certificate for root CA failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 12
		fi
	elif [[ ca-intermediate == ${user[name]} ]]; then

		if ! [ -f "${ca[cert]}" ]; then
			echo -e "\033[37;1mChecking for CA certificate:\033[m"
			echo -e "  \033[31m${ca[name]} certificate not found.\033[m" >&2
			exit 3
		fi

		### Create CA/intermediate private key, if not found or explicitly requested

		if [[ -f "${user[pkey]}" ]]; then
			if inArray genpkey ca-intermediate; then
				backup "${user[pkey]}"
				pkey=
			else
				pkey="${user[pkey]}"
			fi
		else
			pkey=
		fi

		if [[ ! $pkey ]]; then
			if result=$(echo -n "${user[passwd]}" |
					openssl genpkey \
						-algorithm RSA \
						-pkeyopt rsa_keygen_bits:8192 \
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

		### Create CSR for CA/intermediate to be signed by CA/root

		if ! result=$(echo -n "${user[passwd]}" |
				openssl req \
					-new \
					-utf8 \
					-config ${ssldir}/openssl.cnf \
					-out "${user[csr]}" \
					-key "${user[pkey]}" \
					-subj "${user[subject]}" \
					-passin stdin 2>&1); then
			echo -e "\033[37;1mCreating CSR for intermediate CA failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 11
		fi

		### Create CA/intermediate certificate from CSR

		if result=$(echo -n "${ca[passwd]}" |
				openssl ca \
					-config "${ssldir}/openssl.cnf" \
					-name CA_root \
					-extensions v3_intermediate_ca \
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
					-name CA_root \
					-cert "${ca[cert]}" \
					-keyfile "${ca[pkey]}" \
					-out "${ca[crl]}" \
					-passin stdin 2>&1); then
			echo -e "\033[37;1mCreating CRL failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 14
		fi
	else
		if ! [ -f "${ca[cert]}" ]; then
			echo -e "\033[37;1mChecking for CA certificate:\033[m"
			echo -e "  \033[31m${ca[name]} certificate not found.\033[m" >&2
			exit 3
		fi

		mkdir -p -m 0700 "${ssldir}/${user[dir]}/certs"
		mkdir -p -m 0700 "${ssldir}/${user[dir]}/private"

		### Create user private key, if not found or explicitly requested

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

		if [[ ! $pkey ]]; then
			if result=$(echo -n "${user[passwd]}" |
				openssl genpkey \
					-algorithm RSA \
					-pkeyopt rsa_keygen_bits:4096 \
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

		### Create CSR for user to be signed by CA/intermediate

		if ! result=$(echo -n "${user[passwd]}" |
				openssl req \
					-new \
					-utf8 \
					-config ${ssldir}/openssl.cnf \
					-out "${user[csr]}" \
					-key "${user[pkey]}" \
					-subj "${user[subject]}" \
					-passin stdin 2>&1); then
			echo -e "\033[37;1mCreating CSR for user failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 11
		fi

		### Create user certificate from CSR

		if result=$(echo -n "${ca[passwd]}" |
				openssl ca \
					-config "${ssldir}/openssl.cnf" \
					-name CA_default \
					-extensions usr_cert \
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
		if ! result=$(echo "${ca[passwd]}" |
				openssl ca \
					-gencrl \
					-config "${ssldir}/openssl.cnf" \
					-name CA_default \
					-cert "${ca[cert]}" \
					-keyfile "${ca[pkey]}" \
					-out "${ca[crl]}" \
					-passin stdin 2>&1); then
			echo -e "\033[37;1mCreating CRL failed:\033[m" >&2
			echo -e "  \033[31m$result\033[m" >&2
			exit 14
		fi

		# Supply the chain of intermediate(s) with the certificate
		cat "${user[cert]}" \
			"${ca[cert]}" \
			> "${user[cert]%.crt}-chain.crt"

		chmod 0644 "${user[cert]%.crt}-chain.crt"
	fi

	### Create scripts for adding/removing certificates to/from store

	if [[ $root || $intermediate ]]; then
		mkdir -p tmp

		if [[ $root ]]; then
			d="caRoot[dir]"
			n="caRoot[name]"
			s="caRoot[subject]"
			# Build DOS path to certificate
			path="%~dp0\\..\\${ssldir//\//\\}\\${!d//\//\\}\\certs\\${!n}.crt"
			name=$(sed -r 's#.*/CN=(([^/]|\\/)+).*#\1#g' <<<"${!s}")

			sed 's/$/\r/g' <<-EOF > "tmp/certmgr-add-${caRoot[name]}.bat"
				:: Order of arguments is important here - certmgr.exe is not that flexible...
				"%~dp0\\..\\bin\\certmgr.exe" -add -c "$path" -s root
EOF

			sed 's/$/\r/g' <<-EOF > "tmp/certmgr-rm-${caRoot[name]}.bat"
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
			root=
		fi

		if [[ $intermediate ]]; then
			d="caIntermediate[dir]"
			n="caIntermediate[name]"
			s="caIntermediate[subject]"
			# Build DOS path to certificate
			path="%~dp0\\..\\${ssldir//\//\\}\\${!d//\//\\}\\certs\\${!n}.crt"
			name=$(sed -r 's#.*/CN=(([^/]|\\/)+).*#\1#g' <<<"${!s}")

			sed 's/$/\r/g' <<-EOF > "tmp/certmgr-add-${caIntermediate[name]}.bat"
				:: Order of arguments is important here - certmgr.exe is not that flexible...
				"%~dp0\\..\\bin\\certmgr.exe" -add -c "$path" -s ca
EOF

			sed 's/$/\r/g' <<-EOF >> "tmp/certmgr-rm-${caIntermediate[name]}.bat"
				:: This script is intended for debugging only!
				:: Do not use this script in a production environment, as it
				:: may leave your security (trust) settings misconfigured.
				:: You have been warned!
				chcp 65001
				:intermediate
				:: Enter cert # from the above list to delete-->
				echo 1 | "%~dp0\..\bin\certmgr.exe" -del -c -n "$name" -s ca
				if errorlevel 0 goto intermediate
EOF
			intermediate=
		fi
	fi
done
