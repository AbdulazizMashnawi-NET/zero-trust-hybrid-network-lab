#!/usr/bin/env bash
# Internal campus PKI - Team T01
# Builds: a campus root CA, and the exam service certificate the PEP presents.
# Run once, inside the lab image:   docker compose run --rm pki
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out
CA_SUBJ="/C=SA/O=University Lab/OU=coastal campus/CN=Coastal Campus Internal CA (T01)"

echo "[pki T01] creating campus root CA"
openssl genrsa -out out/ca.key 2048 2>/dev/null
openssl req -x509 -new -key out/ca.key -sha256 -days 1825 \
    -subj "$CA_SUBJ" -out out/ca.crt

echo "[pki T01] creating exam service key + CSR (CN=exam.engineering.t01.uni.lab)"
openssl genrsa -out out/exam.key 2048 2>/dev/null
openssl req -new -key out/exam.key -subj "/C=SA/O=University Lab/CN=exam.engineering.t01.uni.lab" \
    -out out/exam.csr

cat > out/exam.ext <<EXT
subjectAltName = DNS:exam.engineering.t01.uni.lab
extendedKeyUsage = serverAuth
EXT

cat > out/ca.cnf <<CNF
[ ca ]
default_ca = campus
[ campus ]
database      = out/index.txt
new_certs_dir = out
serial        = out/serial
default_md    = sha256
policy        = campus_policy
unique_subject = no
[ campus_policy ]
commonName = supplied
CNF
: > out/index.txt
echo 1000 > out/serial

# NOTE: exam cert validity window
openssl ca -batch -notext -config out/ca.cnf \
    -cert out/ca.crt -keyfile out/ca.key \
    -in out/exam.csr -out out/exam.crt \
    -extfile out/exam.ext -days 365 2>/dev/null

echo "[pki T01] done. Inspect with:"
echo "   openssl x509 -in out/exam.crt -noout -subject -dates -ext subjectAltName"
