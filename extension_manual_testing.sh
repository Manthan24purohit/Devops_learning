#!/bin/bash
set -e

echo "=============================================="
echo " Azure Arc Extension Local Validation Wizard "
echo "=============================================="

# ---------- INPUTS ----------
read -p "Enter Resource Group [ck8s-validation-rg]: " RESOURCE_GROUP
RESOURCE_GROUP=${RESOURCE_GROUP:-ck8s-validation-rg}

read -p "Enter Location [eastus]: " LOCATION
LOCATION=${LOCATION:-eastus}

read -p "Enter VM Name [ck8s-validation-vm]: " VM_NAME
VM_NAME=${VM_NAME:-ck8s-validation-vm}

read -p "Enter cluster name [k3s]: " CLUSTER_NAME
CLUSTER_NAME=${CLUSTER_NAME:-k3s}

read -p "Enter Subscription ID: " SUBSCRIPTION_ID
if [ -z "$SUBSCRIPTION_ID" ]; then
    echo "❌ Subscription ID is required"
    exit 1
fi

# Password is used for Azure Serial Console login (SSH keys don't work there).
# Requirements: 12-72 chars, with 3 of: lowercase, uppercase, digit, symbol.
read -s -p "Enter VM admin password (for Serial Console login): " ADMIN_PASSWORD
echo ""
if [ -z "$ADMIN_PASSWORD" ]; then
    echo "❌ Admin password is required for Serial Console login"
    exit 1
fi

read -p "Enter User Assigned Managed Identity Resource Group [arc-conformance]: " UAMI_RESOURCE_GROUP
UAMI_RESOURCE_GROUP=${UAMI_RESOURCE_GROUP:-arc-conformance}

read -p "Enter User Assigned Managed Identity Name [arcConformanceUAMI]: " UAMI_NAME
UAMI_NAME=${UAMI_NAME:-arcConformanceUAMI}

YAML_CONTENT=$(cat conformance.yaml | base64 -w0)

echo "🔹 Installing az cli..."
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

echo "Logging into Azure..."
az login
echo "🔹 Setting subscription..."
az account set --subscription $SUBSCRIPTION_ID

# ---------- CREATE RG ----------
echo "🔹 Creating Resource Group..."
az group create --name $RESOURCE_GROUP --location $LOCATION
# --------- Use Tags -----------
tags="AzSecPackAutoConfigReady=true"

# ---------- VERIFY / CREATE UAMI RESOURCE GROUP ----------
# Provision the managed identity (and its roles) early — BEFORE creating the
# network and VM — so any identity/role failure (e.g. Conditional Access
# AADSTS530084) surfaces immediately instead of after the VM is built.
# verify that UAMI resource group exists, if not create it
if ! az group show --name "$UAMI_RESOURCE_GROUP" >/dev/null 2>&1; then
    echo "Resource group '$UAMI_RESOURCE_GROUP' does not exist. Creating..."
    az group create --name "$UAMI_RESOURCE_GROUP" --location "$LOCATION"
else
    echo "Resource group '$UAMI_RESOURCE_GROUP' already exists."
fi

# ---------- VERIFY / CREATE UAMI ----------
# verify that UAMI exists, if not create it
if ! az identity show --name "$UAMI_NAME" --resource-group "$UAMI_RESOURCE_GROUP" >/dev/null 2>&1; then
    echo "User Assigned Managed Identity '$UAMI_NAME' does not exist. Creating..."
    az identity create --name "$UAMI_NAME" --resource-group "$UAMI_RESOURCE_GROUP" --location "$LOCATION"
    echo "Waiting for the new identity to propagate..."
    sleep 30
    UAMI_CREATED=true
else
    echo "User Assigned Managed Identity '$UAMI_NAME' already exists."
    UAMI_CREATED=false
fi

# ---------- VERIFY / ASSIGN UAMI ROLES ----------
# Only assign roles when THIS script created the UAMI. A pre-existing UAMI is
# assumed to be managed externally with roles already granted at the correct
# (and possibly resource-specific) scopes — e.g. 'Compute Gallery Image Reader'
# scoped to a compute gallery rather than the whole subscription. Re-assigning
# at subscription scope here would be both redundant and overly broad.
UAMI_PRINCIPAL_ID=$(az identity show --name "$UAMI_NAME" --resource-group "$UAMI_RESOURCE_GROUP" --query principalId -o tsv)
ROLE_SCOPE="/subscriptions/${SUBSCRIPTION_ID}"

REQUIRED_ROLES=(
    "Contributor"
    "Managed Identity Operator"
    "Storage Blob Data Contributor"
    "Compute Gallery Image Reader"
)

if [ "$UAMI_CREATED" = "true" ]; then
    for role in "${REQUIRED_ROLES[@]}"; do
        # Check existence by filtering ARM role assignments on principalId. We avoid
        # '--assignee', which would resolve the principal via Microsoft Graph and can
        # be blocked by Conditional Access token-protection policies (AADSTS530084).
        if az role assignment list --scope "$ROLE_SCOPE" \
             --query "[?principalId=='$UAMI_PRINCIPAL_ID' && roleDefinitionName=='$role'] | [0]" \
             -o tsv | grep -q .; then
            echo "Role '$role' already assigned to UAMI."
        else
            echo "Assigning role '$role' to UAMI..."
            az role assignment create --assignee-object-id "$UAMI_PRINCIPAL_ID" --assignee-principal-type ServicePrincipal --role "$role" --scope "$ROLE_SCOPE"
        fi
    done
else
    echo "Skipping role assignment: UAMI '$UAMI_NAME' already existed; assuming roles are managed externally at their correct scopes."
    echo "Required roles for reference: ${REQUIRED_ROLES[*]}"
fi

UAMI_ID=$(az identity show \
  -g $UAMI_RESOURCE_GROUP \
  -n $UAMI_NAME \
  --query id -o tsv)

UAMI_CLIENT_ID=$(az identity show \
  -g "$UAMI_RESOURCE_GROUP" \
  -n "$UAMI_NAME" \
  --query clientId \
  -o tsv)

echo "UAMI Client ID: $UAMI_CLIENT_ID"

# ---------- DETECT RUNNER PUBLIC IP (for SSH allow rule) ----------
# This script is intended to run locally (e.g. WSL). SSH access to the VM is
# restricted to the public IP of the machine running this script, instead of
# being opened to the whole internet.
echo "🔹 Detecting your public IP for SSH access..."
SSH_SOURCE=${SSH_SOURCE:-$(curl -s https://api.ipify.org)}
if [ -z "$SSH_SOURCE" ]; then
    echo "❌ Could not determine your public IP automatically."
    echo "   Re-run with SSH_SOURCE set to your '<ip>/32' (or CIDR), e.g.:"
    echo "   SSH_SOURCE=203.0.113.5/32 ./local-testing-main.sh"
    exit 1
fi
# Append /32 if a bare IP was provided
case "$SSH_SOURCE" in
    */*) ;;                      # already CIDR
    *)   SSH_SOURCE="${SSH_SOURCE}/32" ;;
esac
echo "SSH will be restricted to: $SSH_SOURCE"

# ---------- NETWORK NAMES ----------
VNET_NAME=${VNET_NAME:-k3s-vnet}
SUBNET_NAME=${SUBNET_NAME:-k3s-subnet}
NSG_NAME=${NSG_NAME:-k3s-nsg}

# ---------- CREATE NSG + RULES ----------
# Mirrors the NSG used in the conformance pipelines, but the SSH rule source is
# the runner's public IP (the pipeline uses the '1ESResourceManager' service tag,
# which only works for Microsoft build agents).
echo "🔹 Creating Network Security Group..."
az network nsg create \
  --resource-group $RESOURCE_GROUP \
  --name $NSG_NAME \
  --location $LOCATION

echo "🔹 Adding NSG rule: ssh (restricted to $SSH_SOURCE)..."
az network nsg rule create \
  --resource-group $RESOURCE_GROUP \
  --nsg-name $NSG_NAME \
  --name ssh \
  --priority 100 \
  --access Allow \
  --direction Inbound \
  --protocol Tcp \
  --source-address-prefixes "$SSH_SOURCE" \
  --source-port-ranges '*' \
  --destination-port-ranges 22 \
  --destination-address-prefixes '*'

echo "🔹 Adding NSG rule: kubeapi..."
az network nsg rule create \
  --resource-group $RESOURCE_GROUP \
  --nsg-name $NSG_NAME \
  --name kubeapi \
  --priority 121 \
  --access Allow \
  --direction Inbound \
  --protocol Tcp \
  --source-address-prefixes '*' \
  --source-port-ranges '*' \
  --destination-port-ranges 6443 16443 443 \
  --destination-address-prefixes '*'

echo "🔹 Adding NSG rule: AllowNginx..."
az network nsg rule create \
  --resource-group $RESOURCE_GROUP \
  --nsg-name $NSG_NAME \
  --name AllowNginx \
  --priority 122 \
  --access Allow \
  --direction Inbound \
  --protocol Tcp \
  --source-address-prefixes 172.16.0.0/16 10.0.0.0/16 \
  --source-port-ranges '*' \
  --destination-port-ranges 8765 \
  --destination-address-prefixes '*'

# ---------- CREATE VNET + SUBNET ----------
echo "🔹 Creating VNet and subnet..."
az network vnet create \
  --resource-group $RESOURCE_GROUP \
  --name $VNET_NAME \
  --location $LOCATION \
  --address-prefix 10.0.0.0/16 \
  --subnet-name $SUBNET_NAME \
  --subnet-prefix 10.0.0.0/24 \
  --nsg $NSG_NAME

# ---------- CREATE VM ----------
echo "🔹 Creating VM with Managed Identity..."
az vm create \
  --resource-group $RESOURCE_GROUP \
  --name $VM_NAME \
  --image Ubuntu2204 \
  --size Standard_D4s_v3 \
  --admin-username azureuser \
  --admin-password "$ADMIN_PASSWORD" \
  --authentication-type all \
  --tags $tags \
  --vnet-name $VNET_NAME \
  --subnet $SUBNET_NAME \
  --nsg "" \
  --generate-ssh-keys

# ---------- ENABLE BOOT DIAGNOSTICS (for Serial Console) ----------
echo "🔹 Enabling boot diagnostics (required for Serial Console)..."
az vm boot-diagnostics enable \
  --resource-group $RESOURCE_GROUP \
  --name $VM_NAME

# ---------- ENABLE BOOT DIAGNOSTICS (for Serial Console) ----------
echo "🔹 Enabling boot diagnostics (required for Serial Console)..."
az vm boot-diagnostics enable \
  -g $RESOURCE_GROUP \
  -n $VM_NAME

# ---------- BUILD PLUGIN ARGS (data-driven from manifest) ----------
# Plugin env vars are declared in an external manifest (plugin-env.list) instead
# of being hardcoded here. When a new test case needs a new variable, an author
# only adds a line to that manifest — this script picks it up automatically with
# no code changes required.
echo "🔹 Building plugin arguments from manifest..."
TENANT_ID=$(az account show --query tenantId -o tsv)
PLUGIN_PREFIX="azure-arc-flux"
PLUGIN_ENV_FILE="${PLUGIN_ENV_FILE:-$(dirname "$0")/plugin-env.list}"

if [ ! -f "$PLUGIN_ENV_FILE" ]; then
    echo "❌ Plugin env manifest not found: $PLUGIN_ENV_FILE"
    exit 1
fi

# ---------- AUTO-PROMPT FOR MISSING MANIFEST VARIABLES ----------
# Collect the value of every ${VAR} referenced in the manifest that isn't already
# set by this script (e.g. RESOURCE_GROUP, TENANT_ID, UAMI_CLIENT_ID). A brand new
# env var added to the manifest therefore needs NO script edits — its value is
# prompted for here automatically. Set the variable in the environment beforehand
# to skip its prompt (useful for non-interactive runs).
referenced_vars=$(grep -oE '\$\{[A-Za-z_][A-Za-z0-9_]*\}' "$PLUGIN_ENV_FILE" \
    | sed -e 's/^\${//' -e 's/}$//' | sort -u)
for var in $referenced_vars; do
    # Skip if the variable already has a value in the current shell.
    [ -n "${!var}" ] && continue
    read -p "Enter value for plugin env '${var}': " input
    export "$var=$input"
done

PLUGIN_ARGS=""
while IFS= read -r raw_line || [ -n "$raw_line" ]; do
    # Strip inline comments and trim surrounding whitespace.
    line="${raw_line%%#*}"
    line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [ -z "$line" ] && continue

    key="${line%%=*}"
    value_template="${line#*=}"

    # Expand ${VAR} references in the value against the current shell variables.
    # The manifest is repo-controlled/trusted, so eval-based expansion is safe.
    value=$(eval "printf '%s' \"$value_template\"")

    PLUGIN_ARGS="$PLUGIN_ARGS --plugin-env ${PLUGIN_PREFIX}.${key}=${value}"
done < "$PLUGIN_ENV_FILE"

# Trim the leading space introduced by the loop.
PLUGIN_ARGS="${PLUGIN_ARGS# }"

if [ -z "$PLUGIN_ARGS" ]; then
    echo "❌ No plugin env vars were resolved from $PLUGIN_ENV_FILE"
    exit 1
fi

PLUGIN_ARGS_B64=$(echo "$PLUGIN_ARGS" | base64 -w0)
echo "Plugin args: $PLUGIN_ARGS"

az vm identity assign \
  -g $RESOURCE_GROUP \
  -n $VM_NAME \
  --identities $UAMI_ID

# ---------- EXECUTE INSIDE VM ----------
# NOTE: SSH (port 22) is already allowed by the NSG 'ssh' rule, scoped to the
# runner's public IP ($SSH_SOURCE). We intentionally do NOT use
# 'az vm open-port' here, because that would open SSH to 0.0.0.0/0.

# ---------- GET PUBLIC IP ----------
echo "🔹 Fetching VM Public IP..."

while true; do
    PUBLIC_IP=$(az vm show -d \
      --resource-group "$RESOURCE_GROUP" \
      --name "$VM_NAME" \
      --query publicIps \
      -o tsv)

    [ -n "$PUBLIC_IP" ] && break

    echo "Waiting for Public IP..."
    sleep 10
done

PUBLIC_IP=$(az vm show -d \
  --resource-group $RESOURCE_GROUP \
  --name $VM_NAME \
  --query publicIps \
  -o tsv)

echo "VM Public IP: $PUBLIC_IP"

# ---------- WAIT FOR SSH ----------
echo "🔹 Waiting for SSH to become available..."

until ssh -o ConnectTimeout=5 \
          -o StrictHostKeyChecking=no \
          azureuser@$PUBLIC_IP \
          "echo SSH Ready" >/dev/null 2>&1
do
    echo "Waiting for SSH..."
    sleep 15
done

echo "SSH is available."

# ---------- CREATE REMOTE SCRIPT ----------
echo "🔹 Creating remote setup script..."

cat > /tmp/remote-validation.sh <<EOF
#!/bin/bash
set -ex

RESOURCE_GROUP='$RESOURCE_GROUP'
CLUSTER_NAME='$CLUSTER_NAME'
LOCATION='$LOCATION'
PLUGIN_ARGS_B64='$PLUGIN_ARGS_B64'
PLUGIN_ARGS=\$(echo "\$PLUGIN_ARGS_B64" | base64 -d)
YAML_CONTENT='$YAML_CONTENT'
SUBSCRIPTION_ID='$SUBSCRIPTION_ID'
UAMI_CLIENT_ID='$UAMI_CLIENT_ID'

echo "Using RESOURCE_GROUP: \$RESOURCE_GROUP"
echo "Using Cluster: \$CLUSTER_NAME"

curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

az login --identity --client-id "$UAMI_CLIENT_ID"
az account set --subscription "\$SUBSCRIPTION_ID"

cloud-init status --wait || true

while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
   || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 \
   || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
    echo "apt is busy, waiting..."
    sleep 10
done

apt update
apt install -y git docker.io curl

systemctl enable docker
systemctl start docker

curl -LO "https://dl.k8s.io/release/\$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
mv kubectl /usr/local/bin/

curl -LO https://github.com/vmware-tanzu/sonobuoy/releases/download/v0.57.3/sonobuoy_0.57.3_linux_amd64.tar.gz
tar -xvf sonobuoy_0.57.3_linux_amd64.tar.gz
chmod +x sonobuoy
mv sonobuoy /usr/local/bin/

sonobuoy version

curl -sfL https://get.k3s.io | sh -

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# Wait for the API server to start responding.
for i in {1..20}; do
    kubectl get nodes >/dev/null 2>&1 && break
    sleep 15
done

# Wait for the node to actually reach the Ready condition (the API answering
# does NOT mean the node/CNI is ready). Arc connect and the plugin both need a
# Ready node, otherwise pods stay Pending.
echo "Waiting for node to become Ready..."
kubectl wait --for=condition=Ready node --all --timeout=300s || {
    echo "⚠️  Node did not reach Ready within timeout. Current state:"
    kubectl get nodes -o wide || true
    kubectl describe nodes || true
    exit 1
}

# Wait for core kube-system pods (CoreDNS, etc.) to be Ready as well.
echo "Waiting for kube-system pods to become Ready..."
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=300s || {
    echo "⚠️  Some kube-system pods are not Ready yet. Current state:"
    kubectl get pods -A || true
}

kubectl get nodes
kubectl get pods -A

# ---- Connect the k3s cluster to Azure Arc (required for connectedClusters extension) ----
az extension add --name connectedk8s --yes || true
az provider register --namespace Microsoft.Kubernetes --wait || true
az provider register --namespace Microsoft.KubernetesConfiguration --wait || true
az provider register --namespace Microsoft.ExtendedLocation --wait || true

echo "Connecting k3s cluster '\$CLUSTER_NAME' to Azure Arc in RG '\$RESOURCE_GROUP'..."
az connectedk8s connect \
  --name "\$CLUSTER_NAME" \
  --resource-group "\$RESOURCE_GROUP" \
  --location "\$LOCATION"

# Wait until the cluster reports Connected before installing the extension
for i in {1..30}; do
    state=\$(az connectedk8s show --name "\$CLUSTER_NAME" --resource-group "\$RESOURCE_GROUP" --query connectivityStatus -o tsv 2>/dev/null || true)
    echo "Arc connectivity status: \$state"
    [ "\$state" = "Connected" ] && break
    sleep 10
done

echo "\$YAML_CONTENT" | base64 -d > conformance.yaml

export HOME=/root
mkdir -p \$HOME/.sonobuoy

echo "PLUGIN_ARGS=\$PLUGIN_ARGS"

sonobuoy run --skip-preflight --plugin conformance.yaml \$PLUGIN_ARGS

echo "Monitoring Sonobuoy..."

START_TIME=\$(date +%s)
TIMEOUT=7200
while true; do
    STATUS=\$(sonobuoy status 2>/dev/null || true)

    echo "\$STATUS"

    # Break only when the OVERALL run is done. The per-plugin line and the
    # "Sonobuoy plugins have completed. Preparing results for download." message
    # both contain "complete", but the aggregator tarball is NOT ready until the
    # overall "Sonobuoy has completed" message appears. Retrieving earlier yields
    # an empty result.
    echo "\$STATUS" | grep -q "Sonobuoy has completed" && break

    NOW=\$(date +%s)
    if [ \$((NOW - START_TIME)) -ge \$TIMEOUT ]; then
        echo "⚠️  Timed out waiting for Sonobuoy to complete."
        break
    fi

    sleep 30
done

kubectl get pods -A

# Retry retrieve: even after "completed", the tarball can take a moment to be
# written/flushed by the aggregator.
RESULT_FILE=""
for attempt in \$(seq 1 10); do
    RESULT_FILE=\$(sonobuoy retrieve 2>/dev/null || true)
    if [ -n "\$RESULT_FILE" ] && [ -f "\$RESULT_FILE" ]; then
        break
    fi
    echo "Results archive not ready yet (attempt \$attempt/10), waiting..."
    sleep 15
done

if [ -z "\$RESULT_FILE" ] || [ ! -f "\$RESULT_FILE" ]; then
    echo "⚠️  sonobuoy retrieve produced no results — the plugin likely errored."
    echo "===== plugin flux logs ====="
    kubectl -n sonobuoy logs job/sonobuoy-azure-arc-flux-job -c plugin --tail=300 2>/dev/null || true
    echo "===== sonobuoy worker logs ====="
    kubectl -n sonobuoy logs job/sonobuoy-azure-arc-flux-job -c sonobuoy-worker --tail=50 2>/dev/null || true
    echo "===== pod describe ====="
    kubectl -n sonobuoy describe pod -l sonobuoy-plugin=azure-arc-flux 2>/dev/null | tail -40 || true
    echo "===== flux extension status ====="
    az k8s-extension show --cluster-name "\$CLUSTER_NAME" --resource-group "\$RESOURCE_GROUP" \
      --cluster-type connectedClusters --name flux \
      --query "{state:provisioningState, statuses:statuses}" -o jsonc 2>/dev/null || true
    exit 1
fi

echo "Results Archive:"
echo "\$RESULT_FILE"

mkdir -p results

tar -xvf "\$RESULT_FILE" -C results

# Copy the results archive to a fixed, world-readable path so it can be
# downloaded back to the local machine via scp (the run executes as root).
cp "\$RESULT_FILE" /tmp/sonobuoy-results.tar.gz
chmod 644 /tmp/sonobuoy-results.tar.gz
echo "Results archive staged at /tmp/sonobuoy-results.tar.gz for download."

echo "Available Plugin Results:"
ls -R results/plugins
EOF

chmod +x /tmp/remote-validation.sh

# ---------- COPY SCRIPT ----------
echo "🔹 Copying script to VM..."

scp \
  -o StrictHostKeyChecking=no \
  /tmp/remote-validation.sh \
  azureuser@$PUBLIC_IP:/tmp/

# ---------- EXECUTE SCRIPT ----------
echo "🔹 Running validation on VM..."

ssh \
  -o StrictHostKeyChecking=no \
  azureuser@$PUBLIC_IP \
  "sudo bash /tmp/remote-validation.sh 2>&1 | sudo tee /tmp/remote-validation.log"

# ---------- DOWNLOAD RESULTS TO LOCAL ----------
echo "🔹 Downloading results archive from VM to local machine..."
mkdir -p ./results
LOCAL_RESULTS="./results/sonobuoy-results-$(date +%Y%m%d-%H%M%S).tar.gz"
if scp -o StrictHostKeyChecking=no \
     azureuser@$PUBLIC_IP:/tmp/sonobuoy-results.tar.gz \
     "$LOCAL_RESULTS"; then
    echo "✅ Results downloaded to: $LOCAL_RESULTS"
else
    echo "⚠️  Could not download results archive from VM (test may have errored)."
    echo "   You can retrieve it manually:"
    echo "   scp -o StrictHostKeyChecking=no azureuser@$PUBLIC_IP:/tmp/sonobuoy-results.tar.gz ."
fi

# ---------- POST-RUN INFO ----------
echo ""
echo "=============================================="
echo " Validation finished."
echo "=============================================="
echo "VM Public IP : $PUBLIC_IP"
echo ""
echo "NOTE: the SSH key was generated by THIS shell (WSL) at ~/.ssh/id_rsa."
echo "      You MUST ssh from this same WSL terminal/user, not from PowerShell,"
echo "      otherwise you will get 'Permission denied (publickey)'."
echo ""
echo "To SSH back into the VM (run inside WSL):"
echo "  ssh -i ~/.ssh/id_rsa -o StrictHostKeyChecking=no azureuser@$PUBLIC_IP"
echo ""
echo "If SSH complains about a changed host key, run first:"
echo "  ssh-keygen -R $PUBLIC_IP"
echo ""
echo "To view the full run log on the VM:"
echo "  ssh -i ~/.ssh/id_rsa -o StrictHostKeyChecking=no azureuser@$PUBLIC_IP 'sudo cat /tmp/remote-validation.log'"
echo ""
echo "Sonobuoy / kubectl commands (run inside the VM as root):"
echo "  sudo su -"
echo "  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml"
echo "  sonobuoy status"
echo "  kubectl get pods -A"
echo "=============================================="
