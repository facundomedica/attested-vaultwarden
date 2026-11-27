# Attested Vaultwarden guest image for SEV-SNP measured direct boot
# (QEMU `kernel-hashes=on`, AmdSevX64 OVMF), built for Servury Blackbox
# "bring your own image". docs/SNP_SERVURY.md.
#
# RESEARCH PROTOTYPE. Never booted on SEV-SNP hardware; boot-tested only in
# QEMU without SNP (deploy/sev-snp/boot-test.sh).
#
# Output (stage `out`, exported with `--output type=local`):
#   vmlinuz            Debian's kernel, extracted unmodified from the package
#   initrd.img         the whole operating system: one static busybox, the
#                      init script, three service binaries and their config
#   cmdline.txt        the kernel command line, with SHA-256(app-compose.json)
#   attested-vw.efi    a UKI: systemd-stub + the three files above
#   app-compose.json   the document the sidecar serves and the policy pins
#   build-info.json    input pins and output hashes
#   initrd.files.txt   SHA-256 of every file in the initrd
#
# There is no container runtime in the guest. Vaultwarden, Caddy and the
# sidecar run as three processes started by /init, as in deploy/gcp-cs: a
# runtime (containerd or podman, their storage drivers, a network stack for
# bridges, cgroup and namespace set-up) would be the largest component of
# the image and all of it would have to be read by whoever reviews the
# measurement. The binaries are copied out of the digest-pinned upstream
# images, unmodified.
#
# Build context: a `git archive` of the repository at one commit (build.sh).
#
# Determinism: base images by digest; Debian packages from one
# snapshot.debian.org timestamp, and the three that end up INSIDE the image
# (kernel, busybox, systemd-stub) additionally by SHA-256; the cpio archive
# is written by mkcpio.py with fixed owners, times and inode numbers.

# --- attestation sidecar (same recipe as attest-sidecar/Dockerfile) --------
# Only the workspace is copied, so that editing files under deploy/ does not
# rebuild it.
FROM docker.io/library/rust:1.97-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS sidecar
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=/src=/build --remap-path-prefix=/usr/local/cargo=/cargo -C strip=symbols"
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY common common
COPY attest-sidecar attest-sidecar
COPY verifier verifier
COPY web/wasm web/wasm
RUN cargo build --release --locked -p attest-sidecar

# --- Caddy 2.11.9: the upstream binary, unmodified (static Go binary) ------
FROM docker.io/library/caddy@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0 AS caddy

# --- Vaultwarden 1.37.5: binary, web vault, and the shared libraries the
# binary and the sidecar need (both are Debian bookworm glibc builds) -------
FROM docker.io/vaultwarden/server@sha256:4fe17f415f90087377d37c755e0ea3cf189dcc6794e49cdd2a9adbb4937d9e1f AS vaultwarden
COPY --from=sidecar /src/target/release/attest-sidecar /attest-sidecar
RUN set -eu; mkdir -p /closure/etc/ssl/certs /closure/usr/local/bin; \
    cp /vaultwarden /closure/vaultwarden; \
    cp -r /web-vault /closure/web-vault; \
    cp /attest-sidecar /closure/usr/local/bin/attest-sidecar; \
    cp /etc/ssl/certs/ca-certificates.crt /closure/etc/ssl/certs/ca-certificates.crt; \
    for b in /vaultwarden /attest-sidecar; do \
      ldd "$b" | awk '$2 == "=>" && $3 ~ /^\// {print $3} $1 ~ /^\// {print $1}'; \
    done | sort -u > /closure.libs; \
    test -s /closure.libs; \
    while read -r lib; do \
      real="$(readlink -f "$lib")"; \
      mkdir -p "/closure$(dirname "$lib")"; \
      cp "$real" "/closure$lib"; \
    done < /closure.libs

# --- assembly ---------------------------------------------------------------
FROM docker.io/library/debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0 AS assemble
ARG SOURCE_DATE_EPOCH
# The timestamp the base image itself was built from.
ARG DEBIAN_SNAPSHOT=20261123T000000Z
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} LC_ALL=C.UTF-8 TZ=UTC DEBIAN_FRONTEND=noninteractive
RUN set -eu; \
    sed -i -e "s|URIs: http://deb.debian.org/debian-security|URIs: http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}|" \
           -e "s|URIs: http://deb.debian.org/debian|URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}|" \
           /etc/apt/sources.list.d/debian.sources; \
    grep -q "snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}" /etc/apt/sources.list.d/debian.sources; \
    echo 'Acquire::Check-Valid-Until "false"; Acquire::Retries "5";' > /etc/apt/apt.conf.d/99snapshot; \
    apt-get update -qq; \
    apt-get install -y -qq --no-install-recommends \
      ca-certificates curl kmod xz-utils zstd python3 python3-yaml systemd-ukify; \
    rm -rf /var/lib/apt/lists/*

# The three packages whose bytes go into the measured image, by SHA-256.
# The kernel is the package Servury's own release 2026.11.3 uses (same hash
# as `kernel_package_sha256` in their RELEASE.json), so it is known to boot
# on their hosts with guest features 0x1.
ARG KERNEL_VERSION=6.12.115+deb13.1-amd64
ARG KERNEL_DEB=linux-image-6.12.115+deb13.1-amd64_6.12.115-2_amd64.deb
ARG KERNEL_DEB_URL=https://snapshot.debian.org/archive/debian-security/20261103T000000Z/pool/updates/main/l/linux-signed-amd64/linux-image-6.12.115+deb13.1-amd64_6.12.115-2_amd64.deb
ARG KERNEL_DEB_SHA256=6aa130b0864e58c7102b53ab9c2be4071fae62394f57c80bf4e1912f4c9b3b2a
ARG BUSYBOX_DEB_URL=https://snapshot.debian.org/archive/debian/20261123T000000Z/pool/main/b/busybox/busybox-static_1.37.0-6+b9_amd64.deb
ARG BUSYBOX_DEB_SHA256=598a3fd92bdafc34cd81196b2952ad36e910e47a4ecf162f8ce5e8e262598e53
ARG STUB_DEB_URL=https://snapshot.debian.org/archive/debian/20261123T000000Z/pool/main/s/systemd/systemd-boot-efi_257.13-1~deb13u1_amd64.deb
ARG STUB_DEB_SHA256=390ecdcef9bbb753f51bb6d8f696bdae2f1dbedde7239c49ccb2512f137a8933
WORKDIR /work
RUN set -eu; \
    fetch() { curl -fsSL --retry 5 --retry-delay 5 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    fetch kernel.deb "$KERNEL_DEB_URL" "$KERNEL_DEB_SHA256"; \
    fetch busybox.deb "$BUSYBOX_DEB_URL" "$BUSYBOX_DEB_SHA256"; \
    fetch stub.deb "$STUB_DEB_URL" "$STUB_DEB_SHA256"; \
    for p in kernel busybox stub; do mkdir "$p"; dpkg-deb -x "$p.deb" "$p"; done; \
    test -f "kernel/boot/vmlinuz-${KERNEL_VERSION}"; \
    test -x busybox/usr/bin/busybox || test -x busybox/bin/busybox; \
    test -f stub/usr/lib/systemd/boot/efi/linuxx64.efi.stub; \
    [ -e kernel/lib ] || ln -s usr/lib kernel/lib; \
    depmod -b /work/kernel "$KERNEL_VERSION"

COPY --from=vaultwarden /closure/ /work/rootfs/
COPY --from=caddy /usr/bin/caddy /work/rootfs/usr/local/bin/caddy
COPY deploy/sev-snp/init deploy/sev-snp/udhcpc.script deploy/sev-snp/manifest.template.yml \
     deploy/sev-snp/gen-config.py deploy/sev-snp/mkcpio.py deploy/sev-snp/modules.txt /work/in/

ARG DOMAIN
ARG ACME_HOST=acme-v02.api.letsencrypt.org
# `dhcp`, or the kernel's static form
# <ip>::<gateway>:<netmask>:<hostname>:<device>:off[:<dns0>[:<dns1>]]
ARG IP_CONFIG=dhcp
# true: service output goes to the serial console, which the host reads.
ARG PUBLIC_LOGS=false
# 1: after start-up, print a self-test to the console and power off. A
# different command line, hence a different measurement: never in a policy.
ARG SELFTEST=0
ARG SOURCE_COMMIT=unknown
RUN set -eu; \
    echo "${DOMAIN}" | grep -Eq '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' || { echo "build with --build-arg DOMAIN=<fqdn>" >&2; exit 1; }; \
    echo "${ACME_HOST}" | grep -Eq '^[a-z0-9.-]+$'; \
    echo "${IP_CONFIG}" | grep -Eq '^(dhcp|[0-9a-z.:-]+)$'; \
    case "${PUBLIC_LOGS}" in true|false) ;; *) exit 1;; esac; \
    case "${SELFTEST}" in 0|1) ;; *) exit 1;; esac; \
    r=/work/rootfs; \
    mkdir -p $r/bin $r/etc/attested-vw $r/proc $r/sys $r/dev $r/run $r/tmp $r/data \
             "$r/lib/modules"; \
    # busybox and the applets /init uses (and no others)
    bb="$(ls busybox/usr/bin/busybox busybox/bin/busybox 2>/dev/null | head -n1)"; \
    install -m 0755 "$bb" $r/bin/busybox; \
    for a in sh cat cut date env grep head ifconfig insmod ip ls mkdir mount netstat poweroff \
             route sha256sum sleep su sysctl tr udhcpc wget chown chmod; do \
      ln -s busybox "$r/bin/$a"; \
    done; \
    # kernel modules: the listed ones and their dependencies, decompressed,
    # in load order
    : > $r/etc/attested-vw/modules; \
    for m in $(grep -v '^#' in/modules.txt); do \
      modprobe -d /work/kernel -S "$KERNEL_VERSION" --show-depends "$m" > /work/deps; \
      while read -r kind path _; do \
        case "$kind" in \
          builtin) ;; \
          insmod) \
            name="$(basename "$path" .xz)"; \
            if [ ! -e "$r/lib/modules/$name" ]; then \
              xz -dc "$path" > "$r/lib/modules/$name"; \
              echo "$name" >> $r/etc/attested-vw/modules; \
            fi;; \
          *) echo "unexpected modprobe output: $kind $path" >&2; exit 1;; \
        esac; \
      done < /work/deps; \
    done; \
    test -s $r/etc/attested-vw/modules; \
    # accounts for the two unprivileged services
    printf 'root:x:0:0:root:/:/bin/sh\nvaultwarden:x:1000:1000::/data:/bin/sh\ncaddy:x:1001:1001::/run/caddy:/bin/sh\n' > $r/etc/passwd; \
    printf 'root:x:0:\nvaultwarden:x:1000:\ncaddy:x:1001:\n' > $r/etc/group; \
    printf 'hosts: files dns\n' > $r/etc/nsswitch.conf; \
    printf '127.0.0.1 localhost\n' > $r/etc/hosts; \
    ln -s /run/resolv.conf $r/etc/resolv.conf; \
    install -m 0755 in/init $r/init; \
    install -m 0755 in/udhcpc.script $r/etc/attested-vw/udhcpc.script; \
    # the document, and the service configuration generated from it
    python3 -I in/gen-config.py \
      --template in/manifest.template.yml --out $r/etc/attested-vw \
      --domain "$DOMAIN" --acme-host "$ACME_HOST" --public-logs "$PUBLIC_LOGS" \
      --source-commit "$SOURCE_COMMIT" --sidecar $r/usr/local/bin/attest-sidecar \
      --pin "kernel_package=${KERNEL_DEB}" --pin "kernel_package_sha256=${KERNEL_DEB_SHA256}" \
      --pin "busybox_static_package_sha256=${BUSYBOX_DEB_SHA256}" \
      --pin "systemd_stub_package_sha256=${STUB_DEB_SHA256}" \
      --pin "debian_snapshot=${DEBIAN_SNAPSHOT}"; \
    chmod -R go-w $r; \
    mkdir /out; \
    cp $r/etc/attested-vw/app-compose.json /out/app-compose.json; \
    compose_sha="$(sha256sum /out/app-compose.json | cut -d' ' -f1)"; \
    cmdline="console=ttyS0,115200 panic=-1 ip=${IP_CONFIG} avw.compose_sha256=${compose_sha}"; \
    [ "$SELFTEST" = 0 ] || cmdline="$cmdline avw.selftest=1"; \
    printf '%s' "$cmdline" > /out/cmdline.txt; \
    (cd $r && find . -mindepth 1 \( -type f -o -type l \) | sort | while read -r f; do \
       if [ -L "$f" ]; then echo "symlink -> $(readlink "$f")  $f"; else sha256sum "$f"; fi; done) > /out/initrd.files.txt; \
    python3 -I in/mkcpio.py $r "$SOURCE_DATE_EPOCH" > /work/initrd.cpio; \
    zstd -q -19 -T1 --no-check -o /out/initrd.img /work/initrd.cpio; \
    cp "kernel/boot/vmlinuz-${KERNEL_VERSION}" /out/vmlinuz; \
    printf 'NAME="Attested Vaultwarden (SEV-SNP)"\nID=attested-vw\nVERSION_ID=%s\n' "$SOURCE_COMMIT" > /work/os-release; \
    ukify build --linux /out/vmlinuz --initrd /out/initrd.img --cmdline "$cmdline" \
      --os-release @/work/os-release --uname "$KERNEL_VERSION" \
      --stub stub/usr/lib/systemd/boot/efi/linuxx64.efi.stub --output /out/attested-vw.efi; \
    python3 -I -c 'import hashlib,json,sys; \
f=lambda p: hashlib.sha256(open("/out/"+p,"rb").read()).hexdigest(); \
a=sys.argv; \
json.dump({"domain":a[1],"acme_host":a[2],"ip_config":a[3],"public_logs":a[4]=="true","selftest":a[5]=="1","source_commit":a[6],"source_date_epoch":int(a[7]),"kernel_version":a[8],"cmdline":open("/out/cmdline.txt").read(),"sha256":{p:f(p) for p in ["vmlinuz","initrd.img","attested-vw.efi","app-compose.json"]}},open("/out/build-info.json","w"),indent=2,sort_keys=True)' \
      "$DOMAIN" "$ACME_HOST" "$IP_CONFIG" "$PUBLIC_LOGS" "$SELFTEST" "$SOURCE_COMMIT" "$SOURCE_DATE_EPOCH" "$KERNEL_VERSION"; \
    echo >> /out/build-info.json

FROM scratch AS out
COPY --from=assemble /out/ /
