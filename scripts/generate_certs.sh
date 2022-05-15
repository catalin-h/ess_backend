#/bin/sh

openssl_ver=$(openssl version -v)
if [[ $openssl_ver =~ ^(OpenSSL)[[:space:]](1\.[1-9]\.[1-9]) ]]; then
	echo "Found ${openssl_ver}"
else
	echo "Current OpenSSL is ${openssl_ver}. To use this script please install any 1.1.1* version"
fi

if [[ -z $1 ]]; then
	ns="default"
else
	ns=$1
fi

echo "Generate keys and certs with namespace: '${ns}'"

# Use either X25519, X448, ED25519 or ED448
ec_algo="ED448"

echo "Generate private CA key using eliptic curve signature algo: ${ec_algo}"

root_ca_key=${ns}-ca-key.pem

openssl genpkey -algorithm ${ec_algo} -out $root_ca_key

openssl_cfg=openssl.cnf
root_ca_crt=${ns}-root-ca.crt

# Don't prompt any fields while generating the rootCA certificate request by providing the config file
# Note: -x509 option outputs a self signed certificate instead of a certificate requesti
# see https://www.openssl.org/docs/man1.0.2/man1/req.html
echo "Creating self-signed root CA .."
openssl req -x509 -new -key $root_ca_key -sha512 -days 1024 \
	-out $root_ca_crt -config openssl.cnf
#openssl x509 -text -noout -in $root_ca_crt

echo "root CA files:"
ls -alh $root_ca_key $root_ca_crt

# Generate server key, and signed certificate
#
# see: https://gist.github.com/Soarez/9688998
# Note: x509_extensions specifies the configuration file section containing a list 
# of extensions to add to certificate generated when the -x509 switch is used.
# It can be overridden by the -extensions command line switch.
# -subj arg Replaces subject field of input request with specified
# data and outputs modified request. The arg must be formatted
# as /type0=value0/type1=value1/type2=..., characters may
# be escaped by \ (backslash), no spaces are skipped.

server_key=${ns}-server-key.pem
server_csr=${ns}-server-csr.pem
server_crt=${ns}-server-crt.pem

openssl genpkey -algorithm ${ec_algo} -out $server_key
openssl req -new -key $server_key -sha512 -out $server_csr -config openssl.cnf \
	-reqexts my_server_extensions -subj="/OU=${ns}" -verbose

#openssl req -in $server_csr  -noout -text

echo "Signing server certificate .."
# add extention to x509 command also as signing removes some extentions from csr
openssl x509 -req -days 365 -sha512 -in $server_csr -CA $root_ca_crt -CAkey $root_ca_key \
	  -CAcreateserial -out $server_crt -extfile openssl.cnf -extensions my_server_extensions

#openssl x509 -text -noout -in $server_crt

echo "Generated files:"
ls -alh $server_key $server_csr $server_crt

client_key=${ns}-client-key.pem
client_csr=${ns}-client-csr.pem
client_crt=${ns}-client-crt.pem

openssl genpkey -algorithm ${ec_algo} -out $client_key
openssl req -new -key $client_key -sha512 -out $client_csr -config openssl.cnf \
	-reqexts my_client_extensions -subj="/OU=${ns}/CN=client" -verbose

#openssl req -in $client_csr  -noout -text

echo "Signing client certificate .."

# add extention to x509 command also as signing removes some extentions from csr
openssl x509 -req -days 365 -sha512 -in $client_csr -CA $root_ca_crt -CAkey $root_ca_key \
	  -CAcreateserial -out $client_crt -extfile openssl.cnf -extensions my_client_extensions

#openssl x509 -text -noout -in $client_crt

echo "Generated files:"
ls -alh $client_key $client_csr $client_crt


