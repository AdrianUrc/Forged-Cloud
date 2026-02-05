#!/bin/bash
set -e

IPS=()
DNS_NAMES=()

usage() {
    echo "Usage: $0 [--ip IPv4] [--dns DNS]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip)
            IPS+=("$2")
            shift 2
            ;;
        --dns)
            DNS_NAMES+=("$2")
            shift 2
            ;;
        -*)
            usage
            ;;
        *)
            shift
            ;;
    esac
done

# ---------- ALT NAMES ----------
ALT_NAMES=""
dns_index=1
ip_index=1

# Defaults
ALT_NAMES+="DNS.${dns_index} = localhost"$'\n'
dns_index=$((dns_index + 1))

ALT_NAMES+="IP.${ip_index} = 127.0.0.1"$'\n'
ip_index=$((ip_index + 1))

# Custom DNS
for dns in "${DNS_NAMES[@]}"; do
    ALT_NAMES+="DNS.${dns_index} = ${dns}"$'\n'
    dns_index=$((dns_index + 1))
done

# Custom IPs
for ip in "${IPS[@]}"; do
    ALT_NAMES+="IP.${ip_index} = ${ip}"$'\n'
    ip_index=$((ip_index + 1))
done

# ---------- CA ----------
openssl genrsa -out ca.key 4096

openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/C=ZZ/ST=Anon/L=Anon/O=Anon/OU=Anon/CN=Anon-CA" \
  -out ca.pem

# ---------- SERVER ----------
openssl genrsa -out server.key 4096

openssl req -new -key server.key \
  -subj "/C=ZZ/ST=Anon/L=Anon/O=Anon/OU=Anon/CN=server" \
  -out server.csr

cat > server-ext.cnf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
$ALT_NAMES
EOF

openssl x509 -req \
  -in server.csr \
  -CA ca.pem \
  -CAkey ca.key \
  -CAcreateserial \
  -out server.crt \
  -days 1095 \
  -sha256 \
  -extfile server-ext.cnf

# ---------- CLIENT ----------
openssl genrsa -out client.key 4096

openssl req -new -key client.key \
  -subj "/C=ZZ/ST=Anon/L=Anon/O=Anon/OU=Anon/CN=client" \
  -out client.csr

cat > client-ext.cnf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl x509 -req \
  -in client.csr \
  -CA ca.pem \
  -CAkey ca.key \
  -CAcreateserial \
  -out client.crt \
  -days 1095 \
  -sha256 \
  -extfile client-ext.cnf

# ---------- VERIFY ----------
openssl verify -CAfile ca.pem server.crt
openssl verify -CAfile ca.pem client.crt

echo "✔ Certificates generated successfully"

mv server.crt server-cert.pem
mv server.key server-key.pem
mv client.crt client-cert.pem
mv client.key client-key.pem

mkdir certs

mv server-cert.pem certs
mv server-key.pem certs
mv server.csr certs
mv server-ext.cnf certs
mv client-cert.pem certs
mv client-key.pem certs
mv client.csr certs
mv client-ext.cnf certs
mv ca.pem certs
mv ca.key certs
mv ca.srl certs

cd ../

git clone https://github.com/AdrianUrc/Forged-Cloud-Client.git
mkdir Forged-Cloud-Client/certs

cp Forged-Cloud/certs/ca.pem Forged-Cloud-Client/certs/
cp Forged-Cloud/certs/client-cert.pem Forged-Cloud-Client/certs/
cp Forged-Cloud/certs/client-key.pem Forged-Cloud-Client/certs/
