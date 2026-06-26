#!/usr/bin/env bash
# setup-swtpm.sh — Start a software TPM (swtpm) and bridge it via socat
# Based on journal/tpm2.md section 11: Software TPM (swtpm) Setup

set -euo pipefail

VTPM_DIR="/tmp/tpm/vtpm"
SWTPM_SOCK="${VTPM_DIR}/swtpm-sock"
SWTPM_CTRL="${VTPM_DIR}/swtpm-ctrl"
VTPM_DEV="${VTPM_DIR}/vtpm-dev"

# ── helpers ────────────────────────────────────────────────────────────────────
log()  { echo "[INFO]  $*"; }
err()  { echo "[ERROR] $*" >&2; exit 1; }

check_deps() {
    for cmd in swtpm socat tpm2_getcap; do
        command -v "$cmd" &>/dev/null || err "'$cmd' not found. Install swtpm, socat, and tpm2-tools."
    done
}

cleanup() {
    log "Cleaning up background processes..."
    [[ -n "${SWTPM_PID:-}" ]] && kill "$SWTPM_PID" 2>/dev/null && log "Stopped swtpm (pid $SWTPM_PID)"
    [[ -n "${SOCAT_PID:-}" ]] && kill "$SOCAT_PID" 2>/dev/null && log "Stopped socat (pid $SOCAT_PID)"
    rm -rf "$VTPM_DIR"
}

provision_tpm_EK() {
	alg="rsa"
	ek_persistent_handle="0x81010001"
	
	certs_dir="./pki-demo/certs"
	ek_pub=${certs_dir}/ekpub.pem
	if [ ! -d ${certs_dir} ]; then
		printf "warning: dummy CA not available "
	fi
	mkdir -p ${certs_dir}

	echo "Creating EK ..."
	# Evict any existing object at the EK handle (ignore error if handle is empty)
	tpm2_evictcontrol -C o -c "${ek_persistent_handle}" "${ek_persistent_handle}" 2>/dev/null || true
	# Create the endorsement primary key and persist it
	tpm2_createek --ek-context=${ek_persistent_handle} --key-algorithm=${alg} --public=${ek_pub} --format=pem

	# Create dummy CA credentials in case they do not exist
	if ! test -r ${certs_dir}/dummy_CA_key.pem || ! test -r ${certs_dir}/dummy_CA_cert.pem; then
		printf "TPM CA cert not found, creating new one\n"
		#LD_LIBRARY_PATH=./pki-demo/lib:${LD_LIBRARY_PATH} \
		openssl req -x509 -new -newkey rsa:2048 -keyout ${certs_dir}/dummy_CA_key.pem -out ${certs_dir}/dummy_CA_cert.pem -nodes -subj "/CN=Dummy CA (for PoC use only!)/O=Dummy Org/C=DE" -addext "keyUsage = keyCertSign" -days 3650
	fi
	#LD_LIBRARY_PATH=/root/pki-demo/lib:${LD_LIBRARY_PATH} \
	openssl x509 -new -subj "/CN=Test EK (for PoC use only!)" -CAkey ${certs_dir}/dummy_CA_key.pem -CA ${certs_dir}/dummy_CA_cert.pem -days 365 -force_pubkey ${ek_pub} -CAcreateserial -out ${certs_dir}/cert.pem

}

create_IDevID() {
	alg="rsa"
	iddev_persistent_handle="0x81010003"
	IdevID_pubkey_file="./pki-demo/certs/idevid_pub.pem"

	echo "Creating IDevID ..."
	tpm2_createprimary \
	-C o \
	-G ecc256:ecdsa-sha256 \
	-a 'sign|fixedtpm|fixedparent|sensitivedataorigin|userwithauth' \
	-c ${VTPM_DIR}/idevid.ctx > /dev/null 2>&1
	
	tpm2_evictcontrol -C o -c ${VTPM_DIR}/idevid.ctx 0x81010003 > /dev/null 2>&1
	tpm2_readpublic -c "${iddev_persistent_handle}" -f pem -o "${IdevID_pubkey_file}" > /dev/null 2>&1 \
		|| { echo "Error: failed to extract public key" >&2; return 1; }
	
	tpm2_flushcontext -t > /dev/null 2>&1
}

# ── main ───────────────────────────────────────────────────────────────────────
check_deps

trap cleanup EXIT INT TERM

# Step 1: Create state directory
log "Creating TPM state directory: ${VTPM_DIR}"
mkdir -p "$VTPM_DIR"

# Step 2: Start swtpm in the background
log "Starting swtpm..."
swtpm socket \
    --tpmstate dir="$VTPM_DIR" \
    --ctrl type=unixio,path="$SWTPM_CTRL" \
    --tpm2 \
    --server type=unixio,path="$SWTPM_SOCK" \
    --log level=10 \
    --flags not-need-init,startup-clear &
SWTPM_PID=$!
log "swtpm started (pid ${SWTPM_PID})"

# Wait for the socket to appear
for i in $(seq 1 20); do
    [[ -S "$SWTPM_SOCK" ]] && break
    sleep 0.2
done
[[ -S "$SWTPM_SOCK" ]] || err "swtpm socket did not appear at ${SWTPM_SOCK}"

# Step 3: Bridge the Unix socket to a PTY device via socat
log "Starting socat bridge: ${SWTPM_SOCK} -> ${VTPM_DEV}"
socat pty,link="$VTPM_DEV",raw,echo=0 UNIX-CONNECT:"$SWTPM_SOCK" &
SOCAT_PID=$!
log "socat started (pid ${SOCAT_PID})"

# Wait for the PTY symlink to appear
for i in $(seq 1 20); do
    [[ -e "$VTPM_DEV" ]] && break
    sleep 0.2
done
[[ -e "$VTPM_DEV" ]] || err "socat PTY device did not appear at ${VTPM_DEV}"

# Step 4: Set the TCTI environment variable
export TPM2TOOLS_TCTI="device:${VTPM_DEV}"
log "TPM2TOOLS_TCTI set to: ${TPM2TOOLS_TCTI}"
export TPM2OPENSSL_TCTI="device:${VTPM_DEV}"
log "TPM2OPENSSL_TCTI set to: ${TPM2OPENSSL_TCTI}"

# Step 5: Verify the virtual TPM is responsive
log "Verifying swtpm with tpm2_getcap properties-fixed..."
tpm2_getcap properties-fixed

# Step 6: Provision the TPM EK and create a certificate
tpm2_clear
provision_tpm_EK

create_IDevID

log ""
log "Software TPM is running and ready."
log "  swtpm pid : ${SWTPM_PID}"
log "  socat pid : ${SOCAT_PID}"
log "  device    : ${VTPM_DEV}"
log "  TCTI      : ${TPM2TOOLS_TCTI}"
log ""
log "Press Ctrl+C to stop swtpm and socat."

# Keep running until the user interrupts
wait "$SWTPM_PID"
