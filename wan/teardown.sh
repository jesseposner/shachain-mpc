#!/bin/sh
# Terminate every WAN benchmark instance and remove the staging (security
# groups, key pairs) in all four regions. Safe to run more than once.
set -eu
KEY=${KEY:-shachain-wan}
REGIONS="us-east-1 us-west-2 eu-west-1 eu-central-1"
HERE=$(cd "$(dirname "$0")" && pwd)

for R in $REGIONS; do
  IDS=$(aws ec2 describe-instances --region "$R" \
        --filters "Name=tag:Name,Values=$KEY" \
                  "Name=instance-state-name,Values=pending,running,stopping,stopped" \
        --query 'Reservations[].Instances[].InstanceId' --output text)
  if [ -n "$IDS" ]; then
    echo "$R: terminating $IDS"
    aws ec2 terminate-instances --region "$R" --instance-ids $IDS >/dev/null
    aws ec2 wait instance-terminated --region "$R" --instance-ids $IDS
  fi
done

for R in $REGIONS; do
  SG=$(aws ec2 describe-security-groups --region "$R" \
       --filters Name=group-name,Values="$KEY" \
       --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo None)
  [ "$SG" = None ] || aws ec2 delete-security-group --region "$R" --group-id "$SG" >/dev/null 2>&1 || true
  aws ec2 delete-key-pair --region "$R" --key-name "$KEY" >/dev/null 2>&1 || true
  echo "$R: staging removed"
done

rm -f "$HERE/nodes.txt"
echo "teardown complete; verify with: aws ec2 describe-instances --region <r> --filters Name=tag:Name,Values=$KEY"
