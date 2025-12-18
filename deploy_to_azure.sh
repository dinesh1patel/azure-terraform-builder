#!/usr/bin/env bash
set -euo pipefail

# ---------- Config ----------
SUBSCRIPTION_ID="c3669d3e-b5f2-410f-81b5-2d0f7db276e6"
LOCATION="uksouth"
RESOURCE_GROUP="DefaultResourceGroup-SUK"
VM_NAME="react-vm"
ADMIN_USER="azureuser"
SSH_KEY_PATH="$HOME/.ssh/id_rsa.pub"          # existing public key
REPO_URL="https://github.com/dinesh1patel/azure-terraform-builder.git"
APP_DIR="/var/www/azure-terraform-builder"
HTTP_PORT=80
# ----------------------------

#az account set --subscription "$SUBSCRIPTION_ID"

# Resource group
#az group create --name "$RESOURCE_GROUP" --location "$LOCATION"

# VM with cloud-init script that installs Node, clones repo, builds, and starts app via PM2
cat > cloud-init.yml <<'EOF'
#cloud-config
package_update: true
packages:
  - git
  - curl
  - build-essential

runcmd:
  - curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  - apt-get install -y nodejs
  - npm install -g pm2
  - rm -rf APP_DIR && mkdir -p APP_DIR
  - git clone REPO_URL APP_DIR
  - cd APP_DIR && npm install && npm run build
  - pm2 stop all || true
  - pm2 serve APP_DIR/dist 80 --name react-app --spa
  - pm2 startup systemd -u azureuser --hp /home/azureuser
  - pm2 save
EOF
# Replace placeholders (portable sed -i)
if sed --version >/dev/null 2>&1; then
  sed -i "s~APP_DIR~$APP_DIR~g; s~REPO_URL~$REPO_URL~g" cloud-init.yml
else
  sed -i '' "s~APP_DIR~$APP_DIR~g; s~REPO_URL~$REPO_URL~g" cloud-init.yml
fi

az vm create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --image Ubuntu2204 \
  --admin-username "$ADMIN_USER" \
  --ssh-key-values "$SSH_KEY_PATH" \
  --public-ip-sku Standard \
  --custom-data cloud-init.yml

# Open HTTP port
az vm open-port --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --port "$HTTP_PORT"

echo "Deployment complete. Fetch the public IP:"
az vm show -d -g "$RESOURCE_GROUP" -n "$VM_NAME" --query publicIps -o tsv
