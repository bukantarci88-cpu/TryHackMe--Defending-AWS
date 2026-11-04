# AWS Security 5.2. The Plain Bucket

### Task 1 - Introduction

Access controls decide who can request your data. Encryption at rest provides extra protection in case credentials are compromised, permissions drift, or storage is exposed. By default, AWS encrypts all S3 objects with SSE-S3, even if the bucket has no explicit bucket-level encryption. However, when dealing with compliance, you can use a customer-managed key, a separate decryption authorization, or a KMS-backed key usage audit.

### Task 2 - Real-World Incident

The 2022 LastPass breach is an example of how a single compromised set of cloud storage credentials can be enough to exfiltrate highly sensitive data at scale.

LastPass is one of the most widely used password managers in the world. The cloud infrastructure runs on AWS, with customer vault data and associated metadata stored in S3 buckets. Access to the decryption keys and cloud storage was restricted to a very small number of senior engineers.

**What Happened**

![Attack path through targeted credentials theft.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781513055624.png)

The exfiltration happened through a chain of attacks that built on each other:

- In August 2022, an attacker gained initial access to a development environment and exfiltrated source code and technical documentation.
- Using that information, the attacker identified one of the four engineers who had privileged access to the production environment.
- The attacker targeted that engineer and exploited a known vulnerability in a third-party media server application running on the engineer's personal device.
- That foothold was used to capture cloud credentials and access keys.
- With valid S3 credentials, the attacker accessed and downloaded encrypted customer password vault backups and metadata.

**Core Failures**

- **No second authorization layer**: The vault backup buckets relied on S3-managed encryption, with no customer-managed Key Management Service (KMS) key.
- **Extended blast radius**: A single compromised set of credentials provided full access to the data. A customer-managed KMS key with a separate policy would have reduced the risk.
- **Unencrypted sensitive metadata**: Vault structure metadata was stored without object-level encryption.
- **Privileged access to unmanaged device**: The personal device was outside of corporate endpoint controls, exposing high-privilege credentials.

**Answer the questions below**

> What security control would have reduced or could even have prevented the exfiltration?
> 

customer-managed KMS

### Task 3 - Identification

The differences between the three service types at a glance.

| **Type** | **SSE-S3** | **SSE-KMS** | **SSE-C** |
| --- | --- | --- | --- |
| **Key Managed By** | AWS (S3 managed) | AWS (KMS managed) | Customer (External) |
| **Default Option** | Yes (Automatic) | No (Must be enabled) | No |
| **Audit Trails** | No (Basic logs only) | Yes (via CloudTrail) | No |
| **Cost** | Free | KMS Key + Request Fees | Free |
| **Key Rotation** | Managed by S3 | Customer/AWS managed | Customer managed |
| **Access Control** | Standard IAM/Bucket policy | IAM/KMS key policy | Managed via Client Header |
| **Best For** | General use | Enhanced security and compliance | Legal/Legacy requirements |

**Find the Bucket**

![Lab bucket example](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774278462286.png)

```bash
$ aws s3api list-buckets --query "Buckets[?contains(Name, 'thm')].Name" --output text
thm-room52-bucket-071540691041
```

```bash
$ export BUCKET_NAME=$(aws s3api list-buckets \
--query "Buckets[?contains(Name, 'thm-room52-bucket')].Name" --output text)

$ echo $BUCKET_NAME

thm-room52-bucket-071540691041
```

**Check Encryption**

![Highlighted the default S3 encryption.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774278462579.png)

You can check the bucket-level encryption configuration by running this command.

```bash
$ aws s3api get-bucket-encryption --bucket "$BUCKET_NAME"

{
    "ServerSideEncryptionConfiguration": {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                },
                "BucketKeyEnabled": false
            }
        ]
    }
}
```

**FINDING:** The bucket has no explicit encryption configuration; it relies on the default SSE-S3 encryption.

**Check Objects:** You can inspect the stored objects to see their encryption configuration.

![Encryption type on one bucket object.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774278910943.png)

```bash
$ aws s3api list-objects-v2 --bucket "$BUCKET_NAME" --query "Contents[].Key" \
    --output table

-----------------------------
|       ListObjectsV2       |
+---------------------------+
|  flag.txt                 |
|  pii/customer-export.csv  |
|  sample-data.txt          |
+---------------------------+$ aws s3api head-object --bucket "$BUCKET_NAME" --key sample-data.txt \
    --query '{SSE:ServerSideEncryption,SSEKMSKeyId:SSEKMSKeyId}'

{
    "SSE": "AES256",
    "SSEKMSKeyId": null
}
```

**FINDING:** The objects in the bucket are protected only by S3-managed keys.  

**Retrieve the Flag:** Because SSE-S3 is transparent and you have S3 read permissions, S3 decryption is handled automatically.

```bash
$ aws s3 cp "s3://$BUCKET_NAME/flag.txt" -

[REDACTED]
```

**Findings Summary**

This was rather uneventful, but there are still some conclusions to be drawn:

- AWS defaults to SSE-S3 encryption for data at rest, even if the encryption is not set at the bucket level.
- SSE-S3 automatically decrypts the objects on retrieval if you have S3 read permission.
- There is no separate KMS authorization boundary yet.

**Answer the questions below**

> What is the flag for this task?
> 

THM{IS_MY_KMS_ON}

### Task 4 - Remediation

AWS Key Management Service (AWS KMS) is a fully managed AWS service that makes it easy to create, control, and manage cryptographic keys used to encrypt and digitally sign your data.

The lab has a KMS key in place that you will use to configure encryption on the bucket.

![Showing the lab customer managed key.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1774280241515.png)

**Find the Lab Key:** First, list all keys.

```bash
$ aws kms list-aliases --query "Aliases[?AliasName=='alias/lab-cmk'].{Alias:AliasName,KeyId:TargetKeyId}" --output table

-----------------------------------------------------------
|                       ListAliases                       |
+----------------+----------------------------------------+
|      Alias     |                 KeyId                  |
+----------------+----------------------------------------+
|  alias/lab-cmk |  e8dabddb-de92-45d0-98d5-43bd0abf95a1  |
+----------------+----------------------------------------+
```

Next, you will need to save the key ID and ARN.

**Note:** The `export` commands will save relevant information in environment variables for convenience.

```bash
$ export KEY_ID=$(aws kms list-aliases --query "Aliases[?AliasName=='alias/lab-cmk'].TargetKeyId" --output text)

$ echo $KEY_ID

e8dabddb-de92-45d0-98d5-43bd0abf95a1$ export KEY_ARN=$(aws kms describe-key --key-id "$KEY_ID" --query "KeyMetadata.Arn" \
    --output text)

$ echo $KEY_ARN

arn:aws:kms:us-east-1:071540691041:key/e8dabddb-de92-45d0-98d5-43bd0abf95a1
```

**Enable SSE-KMS:** This step will use the key you previously identified and update the lab bucket to use that key for encryption.

```bash
$ aws s3api put-bucket-encryption \
    --bucket "$BUCKET_NAME" \
    --server-side-encryption-configuration '{
      "Rules": [
        {
          "ApplyServerSideEncryptionByDefault": {
            "SSEAlgorithm": "aws:kms",
            "KMSMasterKeyID": "'$KEY_ARN'"
          },
          "BucketKeyEnabled": true
        }
      ]
    }'
```

**Note:** `BucketKeyEnabled: true` is an AWS best practice for cost control, reducing the number of direct KMS requests from S3.

**Verify The Bucket:** There is a very important point to understand: default bucket encryption applies to new writes; it does not retroactively re-encrypt existing objects.

You can see that the configuration is updated to use the lab key.

```bash
$ aws s3api get-bucket-encryption --bucket "$BUCKET_NAME"

{
    "ServerSideEncryptionConfiguration": {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "arn:aws:kms:us-east-1:071540691041:key/e8dabddb-de92-45d0-98d5-43bd0abf95a1"
                },
                "BucketKeyEnabled": true
            }
        ]
    }
}
```

But the existing object still shows `AES256`.

```bash
$ aws s3api head-object --bucket "$BUCKET_NAME" --key sample-data.txt \
    --query '{SSE:ServerSideEncryption,SSEKMSKeyId:SSEKMSKeyId}'

{
    "SSE": "AES256",
    "SSEKMSKeyId": null
}
```

To test this, you can upload a new object and check the output.

```bash
$ echo "May I have some KMS?" > ./kms-test.txt

$ aws s3 cp ./kms-test.txt "s3://$BUCKET_NAME/kms-test.txt"

upload: ./kms-test.txt to s3://thm-room52-bucket-071540691041/kms-test.txt$ aws s3api head-object --bucket "$BUCKET_NAME" --key kms-test.txt \
    --query '{SSE:ServerSideEncryption,SSEKMSKeyId:SSEKMSKeyId}'

{
    "SSE": "aws:kms",
    "SSEKMSKeyId": "arn:aws:kms:us-east-1:071540691041:key/e8dabddb-de92-45d0-98d5-43bd0abf95a1"
}
```

You can also test that S3 read permissions alone are no longer enough. The lab has a role set up with S3 read permissions but no KMS decryption permissions.

**Note:** The following commands are silent; you can echo the variables to confirm their values.

```bash
$ export ROLE_ARN=$(aws cloudformation list-exports --query "Exports[?Name=='room52-NoKMSReadRoleArn'].Value" --output text)

$ read AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN<<< "$(aws sts assume-role \
    --role-arn "$ROLE_ARN" \
    --role-session-name room52-no-kms-test \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text)"$ export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

If you correctly assumed the role using the previous set of commands and try to read the test object, you will get `AccessDenied`.

```bash
$ aws s3 cp "s3://$BUCKET_NAME/kms-test.txt" -

download failed: s3://thm-room52-bucket-071540691041/kms-test.txt to - An error occurred (AccessDenied)[...]
```

**Retrieve the Flag:** Now, make sure to unset the variables to regain the lab user permissions, then run the helper Lambda function to retrieve the flag.

```bash
$ unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

$ aws lambda invoke \
    --function-name AWS502-VerifyRemediation \
    --payload '{}' \
    output.json && python3 -m json.tool output.json

[...]
{"status": "PASS", "flag": "[REDACTED]"}
```

If everything was done correctly, you will see the flag in the output.

**Answer the questions below**

> When using SSE-KMS, what additional permission is required so you can decrypt the objects?
> 

kms:Decrypt

<img width="887" height="82" alt="image" src="https://github.com/user-attachments/assets/51c44267-32af-41d3-9bf0-fe9e528b1c85" />

> What is the flag found after remediating the misconfiguration?
> 

THM{I_CANT_READ_THIS}

### Task 5 - Build It Securely

Applying a secure configuration to the existing bucket! Here is how you would securely approach this from day one.

**Create a Secure Key:** First, save the account ID as you will need it later in the context of the exercise.

```bash
$ export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

Next, create the key. If you run the simple create-key command later, save the key ID.

```bash
$ export NEW_KEY_ID=$(aws kms create-key \
    --description "Room 5.2 secure data key" \
    --query 'KeyMetadata.KeyId' \
    --output text)
```

Then, save the key ARN as you will need it later.

```bash
$ export NEW_KEY_ARN=$(aws kms describe-key \
  --key-id "$NEW_KEY_ID" \
  --query 'KeyMetadata.Arn' \
  --output text)
```

Now, create a key alias.

```bash
$ aws kms create-alias \
    --alias-name alias/room52-secure-data-key \
    --target-key-id "$NEW_KEY_ID"
```

Enable key rotation.

```bash
$ aws kms enable-key-rotation --key-id "$NEW_KEY_ID"
```

You can review the information for a key by running the `describe-key` command.

```bash
$ aws kms describe-key --key-id $NEW_KEY_ID

{
    "KeyMetadata": {
        "AWSAccountId": "071540691041",
        "KeyId": "c7a3884d-5fd5-4f1b-a830-41220b42ed1a",
        "Arn": "arn:aws:kms:us-east-1:071540691041:key/c7a3884d-5fd5-4f1b-a830-41220b42ed1a",
        "CreationDate": "2026-03-23T16:57:18.255000+00:00",
        "Enabled": true,
        "Description": "Room 5.2 secure data key",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
        "Origin": "AWS_KMS",
        "KeyManager": "CUSTOMER",
        "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
        "KeySpec": "SYMMETRIC_DEFAULT",
        "EncryptionAlgorithms": [
            "SYMMETRIC_DEFAULT"
        ],
        "MultiRegion": false,
        "CurrentKeyMaterialId": "6f0a9338dd8c4a1f47ebad8b0b152f332f7cafd329d42e7dfaeccfd29a89204f"
    }
}
```

**Create a Secure Bucket:** Create a unique bucket name and store it in an environment variable. Then create the bucket.

```bash
$ export SECURE_BUCKET="room52-secure-${ACCOUNT_ID}-$(date +%s)"

$ aws s3api create-bucket --bucket "$SECURE_BUCKET" --region us-east-1

{
    "Location": "/room52-secure-071540691041-1774285544",
    "BucketArn": "arn:aws:s3:::room52-secure-071540691041-1774285544"
}
```

Next, enforce object ownership on the bucket.

```bash
$ aws s3api put-bucket-ownership-controls \
    --bucket "$SECURE_BUCKET" \
    --ownership-controls '{"Rules":[{"ObjectOwnership":"BucketOwnerEnforced"}]}'
```

Apply the encryption configuration to the bucket.

```bash
$ aws s3api put-bucket-encryption \
  --bucket "$SECURE_BUCKET" \
  --server-side-encryption-configuration '{
    "Rules": [
      {
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "aws:kms",
          "KMSMasterKeyID": "'$NEW_KEY_ARN'"
        },
        "BucketKeyEnabled": true
      }
    ]
  }'
```

**Enforce KMS:** Create a bucket policy that enforces KMS usage.

**Note:** Make sure you saved the bucket name and key ARN as environment variables. Otherwise, you will have to replace the variables in the policy file.

```bash
$ cat > ./room52-enforce-kms.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::$SECURE_BUCKET",
        "arn:aws:s3:::$SECURE_BUCKET/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "DenyMissingEncryptionHeader",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::$SECURE_BUCKET/*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "true"
        }
      }
    },
    {
      "Sid": "DenyWrongEncryptionAlgorithm",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::$SECURE_BUCKET/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    },
    {
      "Sid": "DenyWrongKMSKey",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::$SECURE_BUCKET/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "$NEW_KEY_ARN"
        }
      }
    }
  ]
}
EOF
```

Now, attach the policy to the bucket.

```bash
$ aws s3api put-bucket-policy \
  --bucket "$SECURE_BUCKET" \
  --policy file://room52-enforce-kms.json
```

**Verify:** The policy enforces callers to send `SSE-KMS` headers explicitly. You can test this by running the following command.

```bash
$ echo "You shall not pass." > ./denied.txt

$ aws s3api put-object \
    --bucket "$SECURE_BUCKET" \
    --key denied.txt \
    --body ./denied.txt

aws: [ERROR]: An error occurred (AccessDenied) [...]
```

The request is denied. However, if you explicitly provide the key ARN, the upload will succeed.

```bash
$ echo "Speak friend and enter." > ./allowed.txt

$ aws s3api put-object \
    --bucket "$SECURE_BUCKET" \
    --key allowed.txt \
    --body ./allowed.txt \
    --server-side-encryption aws:kms \
    --ssekms-key-id "$NEW_KEY_ARN"

{
    "ETag": "\"dddb0c97eddd3932ff15fab64cf35354\"",
    "ChecksumCRC64NVME": "l/XDur1KuJg=",
    "ChecksumType": "FULL_OBJECT",
    "ServerSideEncryption": "aws:kms",
    "SSEKMSKeyId": "arn:aws:kms:us-east-1:071540691041:key/c7a3884d-5fd5-4f1b-a830-41220b42ed1a",
    "BucketKeyEnabled": true
}
```

You can also check the object encryption.

```bash
$ aws s3api head-object --bucket "$SECURE_BUCKET" --key allowed.txt \
    --query '{SSE:ServerSideEncryption,SSEKMSKeyId:SSEKMSKeyId}'

{
    "SSE": "aws:kms",
    "SSEKMSKeyId": "arn:aws:kms:us-east-1:071540691041:key/c7a3884d-5fd5-4f1b-a830-41220b42ed1a"
}
```

Lastly, you can run the helper Lambda function to validate the setup and retrieve the flag.

```bash
$ aws lambda invoke \
    --function-name AWS502-VerifySecureBuild \
    --payload '{}' \
    output.json && python3 -m json.tool output.json

[...]
{
    "secure_bucket": "room52-secure-071540691041-1774285544",
    "status": "PASS",
    "flag": "[REDACTED]"
}
```

You are now a true key master.

**Answer the questions below**

> What type of policy explicitly denies the put-object command if you do not provide the key?
> 

resource-based

the policy is attached directly to the AWS resource itself rather than to an IAM user or role.

> What is the flag revealed by the helper Lambda function?
> 

THM{LOCKED_STOCKED_AND_DONE}

### Task 6 - Conclusion

Learned why SSE-KMS still matters even when S3 encrypts by default and are also able to build a secure bucket.

**Key Takeaways**

- AWS applies SSE-S3 encryption by default on all objects.
- Automatic SSE-S3 is a baseline but can be extended with customer-managed keys.
- SSE-KMS provides an additional security control, requiring both S3 and KMS key permissions.
- Default bucket encryption is not retroactive.
- A layered security pattern can be applied to sensitive buckets by combining:
    - S3 Block Public Access.
    - `BucketOwnerEnforced` ownership controls.
    - Default SSE-KMS.
    - Bucket policy.
    - KMS key rotation and monitoring.
