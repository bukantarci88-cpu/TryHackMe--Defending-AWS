# AWS Security 5.4. The Shared Snapshot

### Task 1 - Introduction

An Elastic Block Store (EBS) snapshot can be shared with the entire world, and anyone running an automated AWS API scan across the catalog can discover and copy it. 

### Task 2 - Real-World Incident

An example of when the good guys raise awareness of misconfigurations that could lead to security incidents.

Bishop Fox is a US-based offensive security consultancy. In preparation for DEF CON 27, senior security analyst Ben Morris built an automated scanner to query the AWS Public Snapshot Catalog. The scanner required only a standard AWS account because the API call does not require special access.

**What Happened**

![Discovery of public snapshots](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781513194377.png)

1. **Public Snapshot Catalog Scanned**: Morris's tooling queried the AWS public EBS snapshot catalog across all available regions. The scan returned more than 100,000 publicly exposed snapshots.
2. **Snapshots Copied:** The research team replicated a representative sample of the exposed snapshots. No events were generated in the owners' CloudTrail logs because the snapshots are public.
3. **Data Browsing**: The copied snapshots were attached to EC2 instances as EBS volumes and mounted. Because the snapshots were unencrypted, the data was immediately readable in plaintext.
4. **High-value Data**: Among the data, the research team found AWS access keys, secret keys, SSH private keys, TLS/SSL certificates, and proprietary source code.
5. **Unawareness**: The affected organizations had no indication that their data had been accessed.
6. **Disclosure**: Morris presented the research publicly at DEF CON 27 in August 2019. The presentation prompted AWS to introduce additional account-level controls.

**Core Failures**

- **Public Snapshot**: The accounts had at some point misconfigured `createVolumePermission: Group=all` option that allowed for the snapshots to be publicly exposed. Once set, the permission persisted indefinitely.
- **No Encryption**: Because the snapshots were unencrypted, anyone who copied them received plaintext data immediately.
- **No Detection**: Snapshot copying generates no CloudTrail event in the source account. Organizations relying solely on their own logs cannot detect when a public snapshot has been copied.

**Answer the questions below**

> What `createVolumePermission` value makes a snapshot public?
> 

Group=all

### Task 3 - Identification

Based on the DEF CON 27 findings, you have been contracted by one of the affected companies to identify any public snapshots in their account, resolve the misconfiguration, and ensure it does not happen again.

**Set the Environment Variables**

```bash
$ export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ export AWS_REGION=${AWS_REGION:-$(aws configure get region)}

$ export SNAPSHOT_ID=$(aws ec2 describe-snapshots \
    --owner-ids self \
    --filters "Name=tag:Purpose,Values=room-54-lab" \
    --query "Snapshots[0].SnapshotId" \
    --output text)

$ echo "Account ID: $ACCOUNT_ID Region: $AWS_REGION Snapshot ID: $SNAPSHOT_ID"

Account ID: 377527781562 Region: us-east-1 Snapshot ID: snap-0c639965122efca91
```

**Find the Snapshot:** In a real-world situation, you will use the unfiltered command and evaluate all existing snapshots. This can be tedious at times, but you can use a script to automate the extraction of the required information.

```bash
$ aws ec2 describe-snapshots --owner-ids self --output table

--------------------------------------------------------------------------
|                            DescribeSnapshots                           |
+------------------------------------------------------------------------+
||                               Snapshots                              ||
|+--------------------------+-------------------------------------------+|
||  CompletionTime          |  2026-04-02T08:12:41.434000+00:00         ||
||  Description             |  Room 5.4 Lab - publicly shared snapshot  ||
||  Encrypted               |  False                                    ||
||  FullSnapshotSizeInBytes |  0                                        ||
||  OwnerId                 |  377527781562                             ||
||  Progress                |  100%                                     ||
||  SnapshotId              |  snap-0c639965122efca91                   ||
||  StartTime               |  2026-04-02T08:11:56.341000+00:00         ||
||  State                   |  completed                                ||
||  StorageTier             |  standard                                 ||
||  TransferType            |  standard                                 ||
||  VolumeId                |  vol-0edd29d1b807ecf11                    ||
||  VolumeSize              |  1                                        ||
|+--------------------------+-------------------------------------------+|
|||                                Tags                                |||
||+----------------------------+---------------------------------------+||
|||             Key            |                 Value                 |||
||+----------------------------+---------------------------------------+||
|||  Name                      |  room54-lab-snapshot                  |||
|||  DataClassification        |  Sensitive                            |||
|||  Purpose                   |  room-54-lab                          |||
|||  THMRoom                   |  5.4                                  |||
|||  Flag                      |  [REDACTED]                           |||
||+----------------------------+---------------------------------------+||
```

**FINDING**: The `Encrypted: False` entry means the snapshot is unencrypted.

Now, look at the sharing permissions.

```bash
$ aws ec2 describe-snapshot-attribute \
    --snapshot-id $SNAPSHOT_ID \
    --attribute createVolumePermission

{
    "SnapshotId": "snap-0c639965122efca91",
    "CreateVolumePermissions": [
        {
            "Group": "all"
        }
    ]
}
```

**FINDING:** The snapshot has `"Group": "all"` meaning it is publicly shared.

**Findings Summary**

The results are quite clear: there is a single public, unencrypted snapshot. As a note, nowadays, AWS natively prohibits sharing a snapshot globally if it is encrypted with a custom KMS key. In other words, encryption at rest breaks the attack path.

Great job, now it is time to address this issue. Let's see how you can do this.

**Answer the questions below**

> What is the flag for this task?
> 

THM{SNAPSHOTS_TRAVEL_FAST}

### Task 4 - Remediation

The damage is done, and the snapshot was exposed for some time. As a precaution, your next task would be to review the snapshot, check whether any sensitive data or secrets were exposed, report back, and press for the rotation of secrets, access keys, or passwords.

**Remove Public Sharing:** You can start by removing the public sharing permission.

```bash
$ aws ec2 modify-snapshot-attribute \
    --snapshot-id $SNAPSHOT_ID \
    --attribute createVolumePermission \
    --operation-type remove \
    --group-names all
```

Verify the snapshot is now private. The `CreateVolumePermissions` field should be empty.

```bash
$ aws ec2 describe-snapshot-attribute \
    --snapshot-id $SNAPSHOT_ID \
    --attribute createVolumePermission

{
    "SnapshotId": "snap-0c639965122efca91",
    "CreateVolumePermissions": []
}
```

If, for operational or business reasons, you need to share the snapshot, you can do so securely by specifying the target account. You do not need to run the following command, as you cannot test it in the lab.

```bash
$ aws ec2 modify-snapshot-attribute \
    --snapshot-id [REPLACE_WITH_SNAPSHOT_ID] \
    --attribute createVolumePermission \
    --operation-type add \
    --user-ids [REPLACE_WITH_TARGET_ACCOUNT_ID]
```

**Create Encrypted Copy:** The next step is to create an encrypted copy of the snapshot. First, identify the lab KMS key.

```bash
$ export KEY_ID=$(aws kms list-aliases \
    --query "Aliases[?AliasName=='alias/lab-ebs-key'].TargetKeyId" \
    --output text)

$ export KEY_ARN=$(aws kms describe-key \
    --key-id "$KEY_ID" \
    --query "KeyMetadata.Arn" \
    --output text)

$ echo "$KEY_ARN"

arn:aws:kms:us-east-1:377527781562:key/b8ed330e-109c-4a90-b33c-21eb35c8ac5d
```

Then, encrypt the snapshot.

Depending on the volume size, encryption can take some time. Wait for the encryption to complete and then verify.

```bash
$ ENCRYPTED_SNAP=$(aws ec2 copy-snapshot \
    --source-region "$AWS_REGION" \
    --source-snapshot-id $SNAPSHOT_ID \
    --region "$AWS_REGION" \
    --encrypted \
    --kms-key-id alias/lab-ebs-key \
    --description "Encrypted copy - Room 5.4 Lab" \
    --query SnapshotId \
    --output text)

$ echo "Encrypted snapshot: $ENCRYPTED_SNAP"

Encrypted snapshot: snap-02cc5424b0b4ec6a8
```

Then, describe the snapshot.

```bash
$ aws ec2 describe-snapshots --snapshot-ids $ENCRYPTED_SNAP \
    --query "Snapshots[0].{Encrypted:Encrypted,State:State}"

{
    "Encrypted": true,
    "State": "completed"
}
```

**Verify:** Now, run the helper Lambda function to retrieve the task flag.

```bash
$ aws lambda invoke \
    --function-name AWS504-VerifyRemediation \
    --cli-binary-format raw-in-base64-out \
    --payload '{}' /tmp/out.json \
    && python3 -m json.tool /tmp/out.json

[...]
{
    "public_check": "PASS - snapshot snap-0c639965122efca91 is private",
    "encryption_check": "PASS - 1 encrypted snapshot(s) found",
    "status": "PASS",
    "flag": "[REDACTED]"
}
```

The snapshot is not public anymore, and you created an encrypted copy that can be shared securely with specific accounts.

**Answer the questions below**

> What is the flag found after remediating the misconfiguration?
> 

THM{PRIVATE_AND_ENCRYPTED}

### Task 5 - Build It Securely

A modern pattern for snapshots is: encrypted-by-default, private-by-default, and account-specific sharing if needed. By following the steps in this task, you will establish a solid baseline for creating and securing snapshots.

**Create Dedicated Key:** First, create a dedicated KMS key for EBS encryption. This will also create an alias for the key and a rotation schedule.

```bash
$ AZ=$(aws ec2 describe-availability-zones \
    --query "AvailabilityZones[0].ZoneName" --output text)

$ echo $AZ

us-east-1a$ EBS_KEY_ID=$(aws kms create-key \
    --description "EBS encryption key - Module 5 Lab" \
    --key-usage ENCRYPT_DECRYPT \
    --query KeyMetadata.KeyId \
    --output text)

$ aws kms create-alias \
    --alias-name "alias/ebs-data-key" \
    --target-key-id $EBS_KEY_ID

$ aws kms enable-key-rotation --key-id $EBS_KEY_ID

$ echo "KMS Key ID: $EBS_KEY_ID"

KMS Key ID: 8c380edf-021f-413c-a8ca-6b1e1a098a27
```

**Create the Snapshot:** Next, create an encrypted EBS volume. The command will also add tags and save the EBS volume ID in an environment variable.

```bash
$ VOLUME_ID=$(aws ec2 create-volume \
    --size 1 \
    --availability-zone $AZ \
    --encrypted \
    --kms-key-id $EBS_KEY_ID \
    --tag-specifications "ResourceType=volume,Tags=[{Key=Name,Value=secure-data-volume},{Key=Environment,Value=lab}]" \
    --query VolumeId \
    --output text)

$ echo "Encrypted volume: $VOLUME_ID"

Encrypted volume: vol-0cb143022080b097f
```

Then, create a snapshot from the encrypted volume.

```bash
$ SECURE_SNAP=$(aws ec2 create-snapshot \
    --volume-id $VOLUME_ID \
    --description "Secure backup snapshot" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=Name,Value=secure-backup},{Key=Environment,Value=lab},{Key=DataClassification,Value=Confidential}]" \
    --query SnapshotId \
    --output text)

$ echo "Snapshot: $SECURE_SNAP"

Snapshot: snap-0c467f4d91dfcf043
```

Verify the snapshot is encrypted and private.

```bash
$ aws ec2 describe-snapshots --snapshot-ids $SECURE_SNAP \
    --query "Snapshots[0].{Encrypted:Encrypted,State:State,KmsKeyId:KmsKeyId}"

{
    "Encrypted": true,
    "State": "completed",
    "KmsKeyId": "arn:aws:kms:us-east-1:377527781562:key/36cd5bb0-6b7a-4255-a7be-436a2088b091"
}$ aws ec2 describe-snapshot-attribute \
    --snapshot-id $SECURE_SNAP \
    --attribute createVolumePermission

{
    "SnapshotId": "snap-0c467f4d91dfcf043",snap-0c467f4d91dfcf043
    "CreateVolumePermissions": []
}
```

You can ensure monitoring through an automated audit. In a production environment, you would use the AWS Config rule `ec2-ebs-snapshot-public-restorable-check` for continuous automated checking.

**Audit the Changes:** In the lab context, you can run the following script for a manual audit. The first command should not return anything, as you fixed the initial snapshot, and the second is secured.

```bash
# Public snapshots on the current account

$ aws ec2 describe-snapshots \
    --owner-ids self \
    --filters "Name=status,Values=completed" \
    --query "Snapshots[*].SnapshotId" \
    --output text | tr '\t' '\n' | while read snap_id; do
        perms=$(aws ec2 describe-snapshot-attribute \
          --snapshot-id $snap_id \
          --attribute createVolumePermission \
          --query "CreateVolumePermissions[?Group=='all']" \
          --output text)
        if [ -n "$perms" ]; then
          echo "PUBLIC: $snap_id"
        fi
      done# Show unencrypted snapshots

$ aws ec2 describe-snapshots \
    --owner-ids self \
    --filters "Name=encrypted,Values=false" \
    --query "Snapshots[*].{ID:SnapshotId,Description:Description}" \
    --output table

-----------------------------------------------------------------------
|                          DescribeSnapshots                          |
+------------------------------------------+--------------------------+
|                Description               |           ID             |
+------------------------------------------+--------------------------+
|  Room 5.4 Lab - publicly shared snapshot |  snap-0c639965122efca91  |
+------------------------------------------+--------------------------+
```

**Verify:** Lastly, you can run the helper Lambda function to validate the setup and retrieve the flag.

```bash
$ aws lambda invoke \
    --function-name AWS504-VerifySecureBuild \
    --cli-binary-format raw-in-base64-out \
    --payload '{}' /tmp/out.json \
    && python3 -m json.tool /tmp/out.json

[...]
{
    "secure_snapshot_check": "PASS - encrypted snapshot snap-0c467f4d91dfcf043 with Name=secure-backup found",
    "status": "PASS",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> What is the flag revealed by the helper Lambda function?
> 

THM{AUDIT_SNAPSHOTS_REGULARLY}

### Task 6 - Conclusion

In this room, we found a publicly exposed unencrypted snapshot and turned it into a private, encrypted one. You also have a baseline flow that you can share with the contracting company so they can adapt it to their needs. Great work!

**Key Takeaways**

- Never share snapshots with `"Group": "all"`: a public EBS snapshot is as dangerous as a public S3 bucket, but without even the URL barrier - it is in the public AWS catalog and can be copied silently.
- Encrypt all EBS volumes and snapshots: use a customer-managed KMS key to get an audit trail and key-level access control. Encrypted snapshots cannot be copied without access to the KMS key.
- Audit snapshot permissions regularly: use the AWS Config rule `ec2-ebs-snapshot-public-restorable-check` for continuous automated checking, or run the CLI audit script on a schedule.
- Treat any publicly shared snapshot as an active data exposure: unlike with an S3 bucket (where you can check access logs), there is no record in your account of who copied the snapshot after you shared it.
- Use account-level EBS encryption by default: this is a Well-Architected Framework best practice that ensures new volumes and snapshots start encrypted, reducing the chance of recreating the historical exposure path shown in this lab.
- Treat this lab exercise as the old failure mode, not the target design: the value of the room is understanding how public snapshot exfiltration happened and why modern encrypted private-by-default workflows are safer.
