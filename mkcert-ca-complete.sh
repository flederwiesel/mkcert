#!/bin/bash

this=$(readlink -f "${BASH_SOURCE[0]}")
scriptdir=$(dirname "$this")

intermediate=false
root=false
debug=false
prefix=.

usage()
{
	cat <<EOF
$0
     --ca-intermediate
     --ca-root
  -c --config
  -d --debug
     --genpkey=ca-root,ca-intermediate,user
  -h --help
  -p --prefix
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
		--config=*)
			config=${arg:9}
			;;
		-d|--debug)
			export debug=true
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
	echo -e "  \033[31m$result\033[m" >&2
	exit 1
fi

if [ -z "user[subject]" ]; then
	echo "Line $LINENO" &>2
	exit 1
else
	if $intermediate; then
		if [ -z "caIntermediate[subject]" ]; then
			echo "Line $LINENO" &>2
			exit 1
		fi
	fi

	if $root; then
		if [ -z "caRoot[subject]" ]; then
			echo "Line $LINENO" &>2
			exit 1
		fi
	fi
fi

# Read a value from mkcert-ca-complete.conf
# `conf <section> <key>`
conf() {
	sed -n '/\['"$1"'\]/,/^$/{ /^'"$2"='/ { s/^$2=//g; p }}' "$config"
}

mkcert() {
	$debug && echo -e "\033[33mmkcert $@\033[m" >&2
	"$scriptdir/mkcert" "$@"
}

mkkey() {

	local d="$1[dir]"
	local n="$1[name]"

	if [ -f "${ssldir}${!d}/private/${!n}.key" ]; then
		if echo "$genpkey" | grep -Fq "$1"; then
			export force=--force
			return 0
		fi
	else
		return 0
	fi

	return 1 # Don't overwrite
}

caCertExists() {

	d="$1[dir]"
	n="$1[name]"

	if ! [ -f "${ssldir}${!d}/certs/${!n}.crt" ]; then
		echo -e "\033[37;1mChecking for CA certificate:\033[m"
		echo -e "  \033[31m${!d} certificate not found.\033[m" >&2
		return 1
	fi

	return 0
}

export ssldir="${prefix}/etc/ssl"

### Populate folder structure

cd "$scriptdir"

mkdir -p -m 0700 "${ssldir}/certs"
mkdir -p -m 0700 "${ssldir}/private"

# Create config from template
#envsubst < "$scriptdir/openssl.cnf.template" > "$scriptdir/openssl.cnf"
sed "s:%{prefix}:$prefix:g
s*%{distcrlRoot}*${caRoot[distcrl]}*g
s*%{distcrlIntm}*${caIntermediate[distcrl]}*g" "${prefix}/openssl.cnf.template" > "$scriptdir/etc/ssl/openssl.cnf"

for issuer in "${caRoot[dir]}" "${caIntermediate[dir]}"
do
	for dir in certs csr database newcerts private revoked
	do
		mkdir -p -m 0700 "${ssldir}${issuer}/$dir"
	done

	touch "${ssldir}${issuer}/database/index.txt"

	[ -f "${ssldir}${issuer}/database/index.txt.attr" ] ||
	{
		echo 'unique_subject = no' > "${ssldir}${issuer}/database/index.txt.attr"
		chmod 0600 "${ssldir}${issuer}/database/index.txt.attr"
	}
	[ -f "${ssldir}${issuer}/database/serial" ] ||
	{
		echo '1000' > "${ssldir}${issuer}/database/serial"
		chmod 0600 "${ssldir}${issuer}/database/serial"
	}
	[ -f "${ssldir}${issuer}/revoked/crlnumber" ] ||
	{
		echo '1000' > "${ssldir}${issuer}/revoked/crlnumber"
		chmod 0600 "${ssldir}${issuer}/revoked/crlnumber"
	}
done

if $root; then

	intermediate=true

	### Create CA/root private key

	if mkkey caRoot; then
		if result=$(mkcert $force \
					--prefix="$prefix" \
					--applicant="${caRoot[dir]}" \
					--request-key="${caRoot[name]}.key" \
					--passwd="${caRoot[passwd]}"); then
			# Reset, as we are going to ask each time a key should be created
			force=
		else
			echo "$result" >&2
			exit 10
		fi
	fi

	### Create Self-signed CA/root certificate

	if result=$(mkcert \
				--prefix="$prefix" \
				--issuer="${caRoot[dir]}" \
				--applicant="${caRoot[dir]}" \
				--request=- \
				--sign=- \
				--certname="${caRoot[name]}.crt" \
				--subject="${caRoot[subject]}" \
				--keyname="${caRoot[name]}.key" \
				--passwd="${caRoot[passwd]}"); then
		: # The if-branch serves only not do tamper with $?,
		: # which `if ! ...; then` would do...
	else
		exit 12
	fi
fi

if $intermediate; then

	### Create CA/intermediate private key

	if mkkey caIntermediate; then
		if result=$(mkcert $force \
					--prefix="$prefix" \
					--applicant=${caIntermediate[dir]} \
					--request-key="${caIntermediate[name]}.key" \
					--passwd="${caIntermediate[passwd]}"); then
			# Reset, as we are going to ask each time a key should be created
			force=
		else
			echo "$result" >&2
			exit 1
		fi
	fi

	if ! caCertExists caRoot; then
		exit 20
	fi

	### Create CSR for CA/intermediate to be signed by CA/root
	# TODO: Is --issuer necessary?

	if result=$(mkcert \
				--prefix="$prefix" \
				--issuer="${caRoot[dir]}" \
				--applicant="${caIntermediate[dir]}" \
				--request="${caIntermediate[name]}.csr" \
				--keyname="${caIntermediate[name]}.key" \
				--subject="${caIntermediate[subject]}" \
				--passwd="${caIntermediate[passwd]}"); then
		: # The if-branch serves only not do tamper with $?,
		: # which `if ! ...; then` would do...
	else
		exit 11
	fi

	### Create CA/intermediate certificate from CSR

	if result=$(mkcert \
				--prefix="$prefix" \
				--issuer="${caRoot[dir]}" \
				--applicant="${caIntermediate[dir]}" \
				--sign="${caIntermediate[name]}.csr" \
				--certname="${caRoot[name]}.crt" \
				--keyname="${caRoot[name]}.key" \
				--passwd="${caRoot[passwd]}"); then
		: # The if-branch serves only not do tamper with $?,
		: # which `if ! ...; then` would do...
	else
		exit 12
	fi
fi

### Create user private key

if mkkey user; then
	if result=$(mkcert $force \
				--prefix="$prefix" \
				--request-key="${user[name]}.key" \
				--passwd="${user[passwd]}"); then
		# Reset, as we are going to ask each time a key should be created
		force=
	else
		echo "$result" >&2
		exit 10
	fi
fi

if ! caCertExists caIntermediate; then
	exit 21
fi

### Create CSR for user to be signed by CA/intermediate
# TODO: Is --issuer necessary?

if result=$(mkcert \
			--prefix="$prefix" \
			--issuer="${caIntermediate[dir]}" \
			--request="${user[name]}.csr" \
			--keyname="${user[name]}.key" \
			--subject="${user[subject]}" \
			--passwd="${user[passwd]}"); then
	: # The if-branch serves only not do tamper with $?,
	: # which `if ! ...; then` would do...
else
	echo "$result" >&2
	exit 11
fi

### Create user certificate from CSR

if result=$(mkcert \
			--prefix="$prefix" \
			--issuer="${caIntermediate[dir]}" \
			--sign="${user[name]}.csr" \
			--certname="${caIntermediate[name]}.crt" \
			--keyname="${caIntermediate[name]}.key" \
			--passwd="${caIntermediate[passwd]}"); then
	: # The if-branch serves only not do tamper with $?,
	: # which `if ! ...; then` would do...
else
	echo "$result" >&2
	exit 12
fi

# If you don't have the intermediate(s) installed,
# supply the chain if them with the certificate
cat "${ssldir}${user[dir]}/certs/${user[name]}.crt" \
	"${ssldir}${caIntermediate[dir]}/certs/${caIntermediate[name]}.crt" \
	> "${ssldir}${user[dir]}/certs/${user[name]}-chain.crt"

### Create scripts for adding/removing certificates to/from store

if $root || $intermediate; then
	system=$(uname -s)

	case "${system^^}" in
	CYGWIN*) ;&
	MINGW*)

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
			cert=$(cygpath --absolute --windows "${ssldir}${!d}/certs/${!n}.crt")

			# Order is important here!
			echo "%~dp0\\..\\bin\\certmgr.exe -add -c \"$cert\" -s root" >> tmp/certmgr-add.bat

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
			cert=$(cygpath --absolute --windows "${ssldir}${!d}/certs/${!n}.crt")

			# Order is important here!
			echo "%~dp0\\..\\bin\\certmgr.exe -add -c \"$cert\" -s ca" >> tmp/certmgr-add.bat

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

		;;

	LINUX*)
		;;
	esac
fi
