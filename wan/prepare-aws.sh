#!/bin/sh
# Idempotent AWS staging for the WAN run: import the SSH key and create the
# security group in each region, and resolve the Ubuntu 24.04 arm64 AMI.
# Creates nothing billable. Run before wan/launch-instances.sh.
#
# Only SSH is opened, and only to this machine's public address. Set SSH_CIDR
# to override (an office range, say); opening it to the world is refused.
# Cross-node ports are never opened: the MPC parties and the member agents
# live inside the WireGuard mesh that run-wan.sh builds, and that mesh's
# single UDP port is scoped to the four node addresses.
set -eu
KEY=${KEY:-shachain-wan}
PUBKEY=${PUBKEY:-$HOME/.ssh/id_ed25519.pub}
SSM=/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id
REGIONS="us-east-1 us-west-2 eu-west-1 eu-central-1"

[ -f "$PUBKEY" ] || { echo "no public key at $PUBKEY"; exit 1; }
MATERIAL=$(base64 < "$PUBKEY" | tr -d '\n')

SSH_CIDR=${SSH_CIDR:-"$(curl -s https://checkip.amazonaws.com | tr -d '\n')/32"}
case "$SSH_CIDR" in
  0.0.0.0/0) echo "refusing to open SSH to the world; set SSH_CIDR to a real range"; exit 1 ;;
  */*) : ;;
  *) echo "SSH_CIDR must be a CIDR, got: $SSH_CIDR"; exit 1 ;;
esac
echo "SSH will be reachable from $SSH_CIDR only"

for R in $REGIONS; do
  aws ec2 import-key-pair --region "$R" --key-name "$KEY" \
    --public-key-material "$MATERIAL" >/dev/null 2>&1 || true

  SG=$(aws ec2 describe-security-groups --region "$R" \
        --filters Name=group-name,Values="$KEY" \
        --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo None)
  if [ "$SG" = None ] || [ -z "$SG" ]; then
    VPC=$(aws ec2 describe-vpcs --region "$R" \
          --filters Name=is-default,Values=true \
          --query 'Vpcs[0].VpcId' --output text)
    SG=$(aws ec2 create-security-group --region "$R" --group-name "$KEY" \
         --description "shachain WAN benchmark (temporary)" --vpc-id "$VPC" \
         --query GroupId --output text)
  fi

  aws ec2 authorize-security-group-ingress --region "$R" --group-id "$SG" \
    --protocol tcp --port 22 --cidr "$SSH_CIDR" >/dev/null 2>&1 || true
  # close the world open if an earlier run or an earlier version left one
  aws ec2 revoke-security-group-ingress --region "$R" --group-id "$SG" \
    --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true

  AMI=$(aws ssm get-parameter --region "$R" --name "$SSM" \
        --query Parameter.Value --output text)
  echo "$R $SG $AMI"
done
