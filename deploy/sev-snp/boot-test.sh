#!/usr/bin/env bash
# Boot an image built by build.sh in QEMU WITHOUT SEV-SNP (plain emulation,
# so it runs on any machine, slowly) and check the console output.
#
#   deploy/sev-snp/boot-test.sh <build output dir> [split|uki|tamper]
#
#   split   (default) -kernel vmlinuz -initrd initrd.img -append cmdline.txt
#   uki     the UKI through UEFI firmware (QEMU's bundled edk2, NOT Servury's
#           AmdSevX64 build, which refuses to boot without SEV)
#   tamper  split, with one digit of avw.compose_sha256 changed: the guest
#           must refuse to start anything and power off
#
# What this shows: the image boots, /init accepts the embedded document only
# when its hash is on the command line, the network comes up over DHCP, the
# three services start, and (image built with --selftest) Vaultwarden
# answers, the sidecar answers, and 443 is the only non-loopback listener.
# What it cannot show: anything about SEV-SNP. There is no /dev/sev-guest
# here, so the sidecar warns at start-up and answers 503; and no certificate,
# because Let's Encrypt cannot reach an emulated guest.
#
# Needs qemu-system-x86_64 (11.x used; `uki` needs a QEMU that loads EFI
# binaries with -kernel). QEMU=..., OVMF_CODE=... override the defaults.
set -euo pipefail
dir="$(cd "${1:?usage: boot-test.sh <build output dir> [split|uki|tamper]}" && pwd)"
mode="${2:-split}"
qemu="${QEMU:-qemu-system-x86_64}"
log="$dir/boot-test.$mode.log"
timeout_s="${BOOT_TEST_TIMEOUT:-600}"
cmdline="$(cat "$dir/cmdline.txt")"
selftest=0
case " $cmdline " in *" avw.selftest=1 "*) selftest=1;; esac

args=(-machine q35 -cpu max -smp 2 -m 3072 -display none -serial "file:$log" -no-reboot
      -netdev user,id=n0 -device virtio-net-pci,netdev=n0)
case "$mode" in
  split) args+=(-kernel "$dir/vmlinuz" -initrd "$dir/initrd.img" -append "$cmdline");;
  tamper)
    h="${cmdline##*avw.compose_sha256=}"; h="${h%% *}"
    if [ "${h:0:1}" = 0 ]; then bad="1${h:1}"; else bad="0${h:1}"; fi
    args+=(-kernel "$dir/vmlinuz" -initrd "$dir/initrd.img" -append "${cmdline/$h/$bad}");;
  uki)
    code="${OVMF_CODE:-$(dirname "$(dirname "$(command -v "$qemu")")")/share/qemu/edk2-x86_64-code.fd}"
    [ -f "$code" ] || { echo "no UEFI firmware at $code (set OVMF_CODE)" >&2; exit 1; }
    args+=(-drive "if=pflash,format=raw,readonly=on,file=$code" -kernel "$dir/attested-vw.efi");;
  *) echo "mode must be split, uki or tamper" >&2; exit 2;;
esac

: > "$log"
"$qemu" "${args[@]}" &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
t=0; started_at=""
while kill -0 "$pid" 2>/dev/null && [ "$t" -lt "$timeout_s" ]; do
  sleep 2; t=$((t + 2))
  if grep -q "avw-init: FATAL" "$log"; then sleep 6; break; fi
  if [ "$selftest" = 0 ] && grep -q "avw-init: started vaultwarden" "$log"; then
    # No self-test in this image: give the services a minute to fail.
    [ -n "$started_at" ] || started_at="$t"
    [ $((t - started_at)) -lt 60 ] || break
  fi
done
kill "$pid" 2>/dev/null || true
trap - EXIT

fails=0
want() { if grep -Eq -- "$1" "$log"; then echo "ok    $2"; else echo "FAIL  $2"; fails=1; fi; }
wantnot() { if grep -Eq -- "$1" "$log"; then echo "FAIL  $2"; fails=1; else echo "ok    $2"; fi; }
echo "console log: $log"
if [ "$mode" = tamper ]; then
  want "avw-init: FATAL: app-compose.json hashes to [0-9a-f]{64}, the command line says" "guest refuses a document whose hash is not on the command line"
  wantnot "avw-init: started vaultwarden" "nothing was started"
  wantnot "avw-init: network up" "the network was not configured"
else
  want "avw-init: app-compose.json sha256 [0-9a-f]{64} matches the kernel command line" "document hash checked against the command line"
  want "avw-init: network up on " "network up (DHCP)"
  want "avw-init: started vaultwarden, caddy and the attestation sidecar" "three services started"
  want "attest-sidecar: WARNING: NO SNP REPORT AVAILABLE" "sidecar says clearly that there is no SNP report"
  want "attest-sidecar: platform=sev-snp listening on 127.0.0.1:8081" "sidecar listening on loopback"
  wantnot "avw-init: FATAL" "no fatal error"
  if [ "$selftest" = 1 ]; then
    want "avw-selftest: vaultwarden /alive: \"?20[0-9]{2}-" "Vaultwarden answers /alive"
    want "avw-selftest: sidecar without nonce: .*400" "sidecar answers 400 without a nonce"
    want "avw-selftest: sidecar with nonce: .*503" "sidecar answers 503 with a nonce (no certificate, no SNP)"
    want "avw-selftest:   tcp .*:443 " "Caddy listens on 443"
    if grep -E "avw-selftest:   (tcp|udp) " "$log" | grep -Ev "127\.0\.0\.1:| :::443 | 0\.0\.0\.0:443 " | grep -q .; then
      echo "FAIL  a socket other than 443 listens on a non-loopback address"; fails=1
    else
      echo "ok    443 is the only non-loopback listening socket"
    fi
    want "avw-selftest: done" "self-test ran to the end"
  fi
fi
[ "$fails" = 0 ] && echo "boot test ($mode): PASS" || { echo "boot test ($mode): FAIL"; exit 1; }
