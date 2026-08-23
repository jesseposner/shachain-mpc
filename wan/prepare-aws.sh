#!/bin/sh
# Idempotent AWS staging for the WAN run: import the SSH key and create the
# security group in each region, and resolve the Ubuntu 24.04 arm64 AMI.
# Creates nothing billable. Run before wan/launch-instances.sh.
#
# Cross-node ports are NOT opened here: they are scoped to the actual node
# IPs by run-wan.sh once the instances exist. Only SSH is opened at this
# stage.
set -eu
KEY=${KEY:-shachain-wan}
PUBKEY=${PUBKEY:-$HOME/.ssh/id_ed25519.pub}
SSM=/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id
REGIONS="us-east-1 us-west-2 eu-west-1 eu-central-1"

[ -f "$PUBKEY" ] || { echo "no public key at $PUBKEY"; exit 1; }
MATERIAL=$(base64 < "$PUBKEY" | tr -d '\n')

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
    --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true

  AMI=$(aws ssm get-parameter --region "$R" --name "$SSM" \
        --query Parameter.Value --output text)
  echo "$R $SG $AMI"
done
