#!/bin/sh
# Launch the four WAN benchmark nodes. THIS COSTS MONEY (~$0.29/hr each,
# under $2 for a full run). Run wan/prepare-aws.sh first.
#
# member 0  us-east-1     also runs the coordinator and the LDK counterparty
# member 1  us-west-2
# member 2  eu-west-1     initial quorum is [0, 1, 2]
# member 3  eu-central-1  standby; quorum becomes [0, 1, 3] after the crash
#
# Writes wan/nodes.txt (index region instance-id public-ip) for run-wan.sh.
# Tear everything down with wan/teardown.sh when finished.
set -eu
KEY=${KEY:-shachain-wan}
TYPE=${TYPE:-c7g.2xlarge}
DISK=${DISK:-40}
SSM=/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id
HERE=$(cd "$(dirname "$0")" && pwd)
REGIONS="us-east-1 us-west-2 eu-west-1 eu-central-1"

: > "$HERE/nodes.txt"
i=0
for R in $REGIONS; do
  SG=$(aws ec2 describe-security-groups --region "$R" \
       --filters Name=group-name,Values="$KEY" \
       --query 'SecurityGroups[0].GroupId' --output text)
  AMI=$(aws ssm get-parameter --region "$R" --name "$SSM" \
        --query Parameter.Value --output text)
  ID=$(aws ec2 run-instances --region "$R" --image-id "$AMI" \
       --instance-type "$TYPE" --key-name "$KEY" --security-group-ids "$SG" \
       --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=$DISK,VolumeType=gp3}" \
       --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$KEY},{Key=Member,Value=$i}]" \
       --query 'Instances[0].InstanceId' --output text)
  echo "launched member $i in $R: $ID"
  echo "$i $R $ID" >> "$HERE/nodes.txt"
  i=$((i + 1))
done

echo "waiting for instances to reach running state..."
TMP=$(mktemp)
while read -r IDX R ID; do
  aws ec2 wait instance-running --region "$R" --instance-ids "$ID"
  IP=$(aws ec2 describe-instances --region "$R" --instance-ids "$ID" \
       --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
  echo "$IDX $R $ID $IP" >> "$TMP"
  echo "member $IDX  $R  $ID  $IP"
done < "$HERE/nodes.txt"
mv "$TMP" "$HERE/nodes.txt"

echo
echo "nodes recorded in wan/nodes.txt. Next: sh wan/run-wan.sh"
