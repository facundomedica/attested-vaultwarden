#!/usr/bin/env bash
# Generates the SYNTHETIC, NON-AMD test chain in this directory. These keys
# sign nothing real: the verifier only knows this "ARK" in `cfg(test)` builds.
# Shape mirrors AMD's: RSA-PSS/SHA-384 ARK -> ASK -> P-384 "VCEK" whose TCB and
# hwID extensions match ../sev/report_milan.hex (bl=3 tee=0 snp=8 ucode=115).
# Needs OpenSSL 3+. Output is not deterministic (fresh keys each run).
set -euo pipefail
cd "$(dirname "$0")"
CHIP=d49554ec717f4e5b0fe6b143bcf0405bd7ae304727edf46603f2a76aef6a3abc15d7af38db757039029f0efacfd08e244324884738c72b082e2f87a44d541eb6
PSS=(-sha384 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:48 -sigopt rsa_mgf1_md:sha384)
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
openssl genrsa -out "$t/ark.key" 2048
openssl genrsa -out "$t/ask.key" 2048
openssl ecparam -name secp384r1 -genkey -noout -out "$t/vcek.key"
cat > "$t/ca.cnf" <<EOF
[req]
distinguished_name = dn
[dn]
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign
EOF
cat > "$t/vcek.cnf" <<EOF
[vcek]
1.3.6.1.4.1.3704.1.3.1 = ASN1:INTEGER:3
1.3.6.1.4.1.3704.1.3.2 = ASN1:INTEGER:0
1.3.6.1.4.1.3704.1.3.3 = ASN1:INTEGER:8
1.3.6.1.4.1.3704.1.3.8 = ASN1:INTEGER:115
1.3.6.1.4.1.3704.1.4 = DER:$CHIP
EOF
openssl req -x509 -new -key "$t/ark.key" "${PSS[@]}" -days 36500 \
  -subj "/O=attested-vw TEST ONLY/CN=SYNTHETIC-NOT-AMD-ARK" -extensions v3_ca -config "$t/ca.cnf" -out ark.pem
openssl req -new -key "$t/ask.key" -subj "/O=attested-vw TEST ONLY/CN=SYNTHETIC-NOT-AMD-ASK" -out "$t/ask.csr"
openssl x509 -req -in "$t/ask.csr" -CA ark.pem -CAkey "$t/ark.key" -CAcreateserial "${PSS[@]}" -days 36500 \
  -extfile "$t/ca.cnf" -extensions v3_ca -out ask.pem
openssl req -new -key "$t/vcek.key" -subj "/O=attested-vw TEST ONLY/CN=SYNTHETIC-NOT-AMD-VCEK" -out "$t/vcek.csr"
openssl x509 -req -in "$t/vcek.csr" -CA ask.pem -CAkey "$t/ask.key" -CAcreateserial "${PSS[@]}" -days 36500 \
  -extfile "$t/vcek.cnf" -extensions vcek -outform der -out vcek.der
# Raw 48-byte P-384 private scalar as hex (TEST KEY, deliberately public).
openssl ec -in "$t/vcek.key" -noout -text 2>/dev/null \
  | awk '/priv:/{f=1;next}/pub:/{f=0}f' | tr -d ' :\n' | sed -E 's/^00(.{96})$/\1/' > vcek.key.hex
echo >> vcek.key.hex
rm -f ark.srl ask.srl
