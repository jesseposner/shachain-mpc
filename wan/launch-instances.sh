#!/bin/sh
# Launch the four WAN benchmark nodes. THIS COSTS MONEY (~$0.29/hr each,
# under $2 for a full run). Run wan/prepare-aws.sh first.
#
# member 0  us-east-1     also runs the coordinator and the LDK counterparty
# member 1  us-west-2
# member 2  eu-west-1     initial quorum is [0, 1, 2]
# member 3  eu-central-1  standby; quorum becomes [0, 1, 3] after the crash
#
# Resumable: a member that already has a live instance is left alone, so
# re-running after a partial failure launches only what is missing. A region
# the account has not used before answers RunInstances with
# PendingVerification while AWS validates it, which --dry-run does not
# predict; this retries such regions rather than giving up.
#
# Writes wan/nodes.txt (index region instance-id public-ip) for run-wan.sh.
# Tear everything down with wan/teardown.sh when finished.
set -eu
KEY=${KEY:-shachain-wan}
TYPE=${TYPE:-c7g.2xlarge}
DISK=${DISK:-40}
RETRIES=${RETRIES:-60}
SSM=/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id
HERE=$(cd "$(dirname "$0")" && pwd)
REGIONS="us-east-1 us-west-2 eu-west-1 eu-central-1"

existing() { # region member-index -> instance id or empty
  aws ec2 describe-instances --region "$1" \
    --filters "Name=tag:Name,Values=$KEY" "Name=tag:Member,Values=$2" \
              "Name=instance-state-name,Values=pending,running" \
    --query 'Reservations[].Instances[].InstanceId' --output text
}

i=0
for R in $REGIONS; do
  ID=$(existing "$R" "$i")
  if [ -n "$ID" ]; then
    echo "member $i already running in $R: $ID"
    i=$((i + 1)); continue
  fi

  SG=$(aws ec2 describe-security-groups --region "$R" \
       --filters Name=group-name,Values="$KEY" \
       --query 'SecurityGroups[0].GroupId' --output text)
  AMI=$(aws ssm get-parameter --region "$R" --name "$SSM" \
        --query Parameter.Value --output text)

  n=0
  while [ "$n" -lt "$RETRIES" ]; do
    OUT=$(aws ec2 run-instances --region "$R" --image-id "$AMI" \
          --instance-type "$TYPE" --key-name "$KEY" --security-group-ids "$SG" \
          --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=$DISK,VolumeType=gp3}" \
          --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$KEY},{Key=Member,Value=$i}]" \
          --query 'Instances[0].InstanceId' --output text 2>&1) || true
    case "$OUT" in
      i-*)
        echo "launched member $i in $R: $OUT"
        break ;;
      *PendingVerification*)
        n=$((n + 1))
        echo "member $i in $R: AWS is still validating this region, retry $n/$RETRIES"
        sleep 60 ;;
      *)
        echo "member $i in $R FAILED: $(echo "$OUT" | head -2)"
        echo "launched so far are recorded; re-run this script to resume"
        exit 1 ;;
    esac
  done
  [ "$n" -lt "$RETRIES" ] || { echo "member $i in $R still blocked; re-run later"; exit 1; }
  i=$((i + 1))
done

echo "waiting for instances to reach running state..."
: > "$HERE/nodes.txt"
i=0
for R in $REGIONS; do
  ID=$(existing "$R" "$i")
  aws ec2 wait instance-running --region "$R" --instance-ids "$ID"
  IP=$(aws ec2 describe-instances --region "$R" --instance-ids "$ID" \
       --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
  echo "$i $R $ID $IP" >> "$HERE/nodes.txt"
  echo "member $i  $R  $ID  $IP"
  i=$((i + 1))
done

echo
echo "nodes recorded in wan/nodes.txt. Next: sh wan/run-wan.sh"
