#!/usr/bin/env bash
# PRINTS the commands that would deploy Attested Vaultwarden on Google Cloud
# Confidential Space. It EXECUTES NOTHING: no gcloud, no docker, no network.
# Read the output, check every value, and run the commands yourself in a
# project you control.
#
#   deploy/gcp-cs/deploy.sh <domain> <sha256:image-digest> [dev]
#
# Environment (all optional; placeholders are printed otherwise):
#   PROJECT       Google Cloud project id            (default <PROJECT_ID>)
#   REGION        region                             (default europe-west4)
#   ZONE          zone with the machine type + TDX   (default europe-west4-a)
#   MACHINE_TYPE  Confidential VM machine type       (default c3-standard-4)
#   CC_TYPE       --confidential-compute-type        (default TDX)
#   REPO          Artifact Registry repository name  (default attested-vw)
#   NAME          VM / resource name prefix          (default attested-vw)
#
# `dev` as third argument adds Cloud Logging redirection of the container's
# stdout/stderr. It only has an effect if the image was built with
# LOG_REDIRECT=always (which changes the image digest). Never for real data.
set -euo pipefail
domain="${1:?usage: deploy.sh <domain> <sha256:digest> [dev]}"
digest="${2:?image digest as printed by build.sh (sha256:...)}"
mode="${3:-prod}"
[[ "$domain" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || { echo "bad domain" >&2; exit 1; }
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "digest must be sha256:<64 hex>" >&2; exit 1; }
case "$mode" in prod|dev) ;; *) echo "third argument must be 'dev' or absent" >&2; exit 1;; esac

P="${PROJECT:-<PROJECT_ID>}"
REGION="${REGION:-europe-west4}"
ZONE="${ZONE:-europe-west4-a}"
MT="${MACHINE_TYPE:-c3-standard-4}"
CC="${CC_TYPE:-TDX}"
REPO="${REPO:-attested-vw}"
NAME="${NAME:-attested-vw}"
SA="${NAME}-workload@${P}.iam.gserviceaccount.com"
IMAGE="${REGION}-docker.pkg.dev/${P}/${REPO}/attested-vw-gcp-cs"
case "$CC" in
  TDX) maint=TERMINATE ;;
  SEV) maint=MIGRATE ;;
  *) echo "CC_TYPE must be TDX or SEV (Confidential Space does not offer SEV-SNP)" >&2; exit 1 ;;
esac

metadata="tee-image-reference=${IMAGE}@${digest}~tee-restart-policy=Always"
logging_role=""
if [ "$mode" = dev ]; then
  metadata="${metadata}~tee-container-log-redirect=cloud_logging"
  logging_role="
gcloud projects add-iam-policy-binding ${P} \\
  --member=serviceAccount:${SA} --role=roles/logging.logWriter"
fi

cat <<EOF
# ---------------------------------------------------------------------------
# NOTHING BELOW HAS BEEN RUN. Review, then run by hand, in order.
# Research prototype: do not put real secrets in this deployment.
# ---------------------------------------------------------------------------

# 0. Make sure gcloud points at the project you intend (not a work project).
gcloud config list
gcloud config set project ${P}

# 1. APIs.
gcloud services enable compute.googleapis.com confidentialcomputing.googleapis.com \\
  artifactregistry.googleapis.com --project=${P}

# 2. Registry, and push the image built by deploy/gcp-cs/build.sh.
#    The pushed manifest digest must equal ${digest}.
gcloud artifacts repositories create ${REPO} --repository-format=docker \\
  --location=${REGION} --project=${P}
gcloud auth configure-docker ${REGION}-docker.pkg.dev
#    e.g. with skopeo (keeps the digest):
skopeo copy --preserve-digests oci-archive:deploy/gcp-cs/.generated/workload.oci.tar \\
  docker://${IMAGE}:${digest#sha256:}
gcloud artifacts docker images describe ${IMAGE}@${digest} --project=${P}

# 3. Service account the VM runs as. It can request attestation tokens and
#    pull the image, nothing else.
gcloud iam service-accounts create ${NAME}-workload --project=${P}
gcloud projects add-iam-policy-binding ${P} \\
  --member=serviceAccount:${SA} --role=roles/confidentialcomputing.workloadUser
gcloud artifacts repositories add-iam-policy-binding ${REPO} --location=${REGION} --project=${P} \\
  --member=serviceAccount:${SA} --role=roles/artifactregistry.reader${logging_role}

# 4. A static public IPv4 address, and a firewall rule for 443 only.
gcloud compute addresses create ${NAME}-ip --region=${REGION} --project=${P}
gcloud compute addresses describe ${NAME}-ip --region=${REGION} --project=${P} --format='value(address)'
gcloud compute firewall-rules create ${NAME}-allow-443 --project=${P} \\
  --network=default --direction=INGRESS --action=ALLOW --rules=tcp:443 \\
  --source-ranges=0.0.0.0/0 --target-tags=${NAME}

# 5. DNS (at your DNS provider, BEFORE creating the VM: Caddy asks for the
#    certificate as soon as it starts):
#      ${domain}.  300  IN  A    <address printed in step 4>
#      ${domain}.  300  IN  CAA  0 issue "letsencrypt.org; validationmethods=tls-alpn-01"

# 6. The Confidential Space VM (production image: no SSH, no shell).
gcloud compute instances create ${NAME} --project=${P} --zone=${ZONE} \\
  --machine-type=${MT} \\
  --confidential-compute-type=${CC} \\
  --maintenance-policy=${maint} \\
  --shielded-secure-boot \\
  --image-project=confidential-space-images \\
  --image-family=confidential-space \\
  --boot-disk-size=20GB \\
  --service-account=${SA} \\
  --scopes=cloud-platform \\
  --address=${NAME}-ip \\
  --tags=${NAME} \\
  --metadata="^~^${metadata}"

# 7. Write the release policy (see docs/GCP_CONFIDENTIAL_SPACE.md), then:
cargo run --release -p attested-vw-verify -- https://${domain} --policy policy/<release>.toml

# Teardown (deleting the VM destroys the vault: its data lives only in the
# VM; the address and firewall rule are separate resources):
#   gcloud compute instances delete ${NAME} --zone=${ZONE} --project=${P}
#   gcloud compute firewall-rules delete ${NAME}-allow-443 --project=${P}
#   gcloud compute addresses delete ${NAME}-ip --region=${REGION} --project=${P}
EOF
