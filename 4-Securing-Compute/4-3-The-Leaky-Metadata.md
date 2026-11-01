# AWS Security 4.3. The Leaky Metadata

### Task 1 - Introduction

The EC2 Instance Metadata Service is one of the most useful and most dangerous convenience features in AWS. It provides local access to metadata and temporary IAM credentials for any workload running on an instance. When `HttpTokens` is set to `optional`, any process that can send a plain HTTP `GET` to `169.254.169.254` can retrieve those credentials, including requests forwarded by a misconfigured proxy or a vulnerable application running on the same host.

That is how a server-side request forgery becomes IAM credential theft. IMDSv2 raises the bar by requiring a PUT-based token exchange before any credential retrieval. That one design change breaks the most common SSRF-to-metadata attack path entirely.

### Task 2 - Real-World Incident

Shopify is one of the largest e-commerce platforms in the world, hosting millions of merchant storefronts on AWS-backed infrastructure. Like many large platforms, Shopify provided features that involved server-side URL fetching - accepting external URLs as inputs and issuing HTTP requests on behalf of users or applications. These features ran on EC2 instances with attached IAM roles that granted access to Shopify's AWS environment.

In 2019, a security researcher participating in Shopify's HackerOne bug bounty program identified a server-side request forgery (SSRF) vulnerability in one of these URL-fetching features. The instance was running with `HttpTokens=optional`.

**What Happened**

![The image shows a new Shopify feature that is vulnerable to SSRF and can extract credentials from the EC2 metadata.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781512735741.png)

1. **SSRF discovery**: The researcher identified a Shopify feature that accepted a URL as input and issued an HTTP `GET` request to it from a backend server running on an EC2 instance with an attached IAM role.
2. **Internal address targeting**: By supplying `http://169.254.169.254/latest/meta-data/iam/security-credentials/` as the input URL, the researcher directed the server-side request to the EC2 instance metadata endpoint.
3. **Unauthenticated role disclosure**: Because the instance was running with `HttpTokens=optional`, the metadata endpoint returned the name of the attached IAM role in response to a plain HTTP `GET`.
4. **Full credential extraction**: A follow-up request to the role-specific path returned a complete set of temporary IAM credentials: `AccessKeyId`, `SecretAccessKey`, and `SessionToken`.
5. **Demonstrated blast radius**: With those credentials, an attacker could have authenticated to AWS from outside the instance and accessed any service permitted by the attached role. The researcher documented the full retrieval path and reported it before accessing any data.
6. **Remediation**: Shopify fixed the SSRF vulnerability and transitioned affected instances to require IMDSv2, which requires an additional `PUT` request for the initial token request. The report was publicly disclosed through HackerOne after remediation was confirmed.

**Core Failures**

- **IMDSv1 still allowed**: `HttpTokens=optional` meant any process on the instance - including requests forwarded by the application - could retrieve credentials with a plain HTTP `GET` and no token.
- **No SSRF input validation**: URL inputs were not validated to block requests to link-local address space (`169.254.0.0/16`).
- **No network-layer controls**: There was no host-level or network control blocking the application tier from reaching `169.254.169.254`.
- **SSRF amplified by IMDS exposure**: Without IMDSv2, a single SSRF bug became a direct path to IAM credential theft - no privilege escalation, no lateral movement required.

**Answer the questions below**

> What HTTP method does IMDSv2 require for the initial token request that IMDSv1 skips entirely?
> 

PUT

> What link-local IP address does the EC2 Instance Metadata Service listen on?
> 

169.254.169.254

### Task 3 - Identification

In this task, you will take on the role of a security analyst and investigate an instance that allows IMDSv1 access, then follow the credential retrieval path to see exactly what an attacker would obtain.

**Info:** To start the AWS environment, click the `Cloud Details` button at the top of the room, then click `Generate Environment`. When the environment is ready, use the Credentials tab to navigate to the AWS Console and log in. Start by saving the account ID and lab instance ID to environment variables.

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Purpose,Values=room-43-lab" "Name=instance-state-name,Values=running" \
    --query "Reservations[0].Instances[0].InstanceId" \
    --output text)

$ echo "Account ID: $ACCOUNT_ID | Instance ID: $INSTANCE_ID"

Account ID: 203918859777 | Instance ID: i-0cb9c49e546a674bd
```

**Inspect the Metadata Options:** Check the configuration on the instance.

```bash
$ aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].MetadataOptions" \
  --output json

{
    "State": "applied",
    "HttpTokens": "optional",
    "HttpPutResponseHopLimit": 2,
    "HttpEndpoint": "enabled",
    "HttpProtocolIpv6": "disabled",
    "InstanceMetadataTags": "disabled"
}
```

**FINDING:** `HttpTokens` is set to `optional`, allowing IMDSv1.

**Verify the Instance:** Connect to the instance and verify that credentials can be retrieved through an unauthenticated request.

```bash
$ aws ssm start-session --target "$INSTANCE_ID"

Starting session with SessionId: 203918859777-bruyynuluynf59svjr8z63ylcy

sh-5.2$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

Room43ManagedInstanceRole

sh-5.2$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/Room43ManagedInstanceRole
{
  "Code" : "Success",
  "LastUpdated" : "2026-05-08T09:39:21Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAS66UC3YARKHWSXYX",
  "SecretAccessKey" : "j8Ac[...]",
  "Token" : "IQoJ[...]",
  "Expiration" : "2026-05-08T16:14:29Z"
}
```

**FINDING:** The metadata endpoint returned a full set of temporary IAM credentials.

**Retrieve the Flag:** Make sure you close the session before continuing by typing `exit` in the terminal. An EC2 tag hides the flag. Run the following command to retrieve it.

```bash
$ aws ec2 describe-tags \
    --filters "Name=resource-id,Values=$INSTANCE_ID" \
    --query "Tags[?Key=='Flag'].Value" \
    --output text

[REDACTED]
```

**Findings Summary**

The findings are quite clear:

- The lab instance has `HttpTokens=optional`, meaning IMDSv1 is active.
- The unauthenticated GET path to `169.254.169.254` returns temporary IAM credentials for the attached role without requiring any session token.
- Any SSRF vulnerability in an application running on this instance can silently retrieve those credentials in two HTTP requests.

**Answer the questions below**

> What value of `HttpTokens` in the metadata options indicates that IMDSv1 is still allowed?
> 

optional

> What is the flag for this task?
> 

THM{OPEN_CHANNEL_FOUND}

### Task 4 - Remediation

Now that you have confirmed the IMDSv1 path is open, it is time to close it. You will enforce IMDSv2 on the existing instance and verify that the old unauthenticated flow no longer works.

In this task, you will:

- Enforce IMDSv2 with `modify-instance-metadata-options`.
- Verify the metadata options now show `HttpTokens: required`.
- Confirm the old IMDSv1 GET flow fails.
- Confirm the IMDSv2 token-based flow succeeds.

First, make sure you have the right information in the environment variables.

```bash
$ INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Purpose,Values=room-43-lab" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].InstanceId" \
  --output text)
$ echo $INSTANCE_ID

i-0cb9c49e546a674bd
```

The IMDSv2 change is transparent, and the EC2 instance does not need to be rebooted for changes to take effect.

```bash
$ aws ec2 modify-instance-metadata-options \
    --instance-id "$INSTANCE_ID" \
    --http-tokens required \
    --http-endpoint enabled

{
    "InstanceId": "i-0cb9c49e546a674bd",
    "InstanceMetadataOptions": {
        "State": "pending",
        "HttpTokens": "required",
        "HttpPutResponseHopLimit": 2,
        "HttpEndpoint": "enabled",
        "HttpProtocolIpv6": "disabled",
        "InstanceMetadataTags": "disabled"
    }
}
```

The `HttpTokens` is now set to `required`, and the instance will reject any metadata request that does not include a valid session token.

**Verify the Fix:** You can try requesting the metadata again with an unauthenticated `GET`, but it will fail. Using the token-based IMDSv2 flow will succeed.

```bash
$ aws ssm start-session --target "$INSTANCE_ID"

Starting session with SessionId: 203918859777-786f5c8egf2ab6sukktip74xzy

sh-5.2$ curl -I http://169.254.169.254/latest/meta-data/iam/security-credentials/Room43ManagedInstanceRole

HTTP/1.1 [REDACTED]
Content-Length: 0
Date: Fri, 08 May 2026 10:02:17 GMT
Server: EC2ws
Connection: close
Content-Type: text/plain

sh-5.2$ TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

sh-5.2$ curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/iam/security-credentials/Room43ManagedInstanceRole
{
  "Code" : "Success",
  "LastUpdated" : "2026-05-08T09:38:41Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAS66UC3YA5JNDS6SZ",
  "SecretAccessKey" : "I7vn[...]",
  "Token" : "IQoJ[...]",
  "Expiration" : "2026-05-08T16:14:29Z"
}
```

Now type `exit` to quit the SSM session and run the helper function to retrieve the flag.

```bash
$ aws lambda invoke \
  --function-name AWS403-VerifyRemediation \
  --payload '{}' \
  /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "status": "PASS",
    "imds_check": "PASS - lab instance requires IMDSv2",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> What is the HTTP code returned now by the plain `curl` request?
> 

401

> What flag is returned after enforcing IMDSv2 on the lab instance?
> 

THM{CHANNEL_SECURED}

### Task 5 - Build It Securely

Enforcing IMDSv2 on a running instance is one step. The stronger control is to ensure that no future instance can ever be launched with `HttpTokens=optional`. That starts with getting the metadata options right at launch time.

The lab has a working VPC and subnet you will use to deploy an instance in a secure way. Start by retrieving the required IDs and saving them in local variables.

```bash
$ INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Purpose,Values=room-43-lab" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].InstanceId" \
  --output text)

$ SUBNET_ID=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --query "Reservations[0].Instances[0].SubnetId" \
    --output text)

$ VPC_ID=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --query "Reservations[0].Instances[0].VpcId" \
    --output text)

$ echo "VPC ID: $VPC_ID | Subnet ID: $SUBNET_ID | Instance ID: $INSTANCE_ID"

VPC ID: vpc-06789e35d4e184b65 | Subnet ID: subnet-03e97bcd079a55ffc | Instance ID: i-0cb9c49e546a674bd
```

**Create Security Group:** You will create a security group with no inbound rules. In a real infrastructure, you would scope the rules to match the instance role and requirements.

```bash
$ SECURE_SG=$(aws ec2 create-security-group \
  --group-name room43-secure-$(date +%s) \
  --description "Room 4.3 IMDSv2 secure instance SG" \
  --vpc-id "$VPC_ID" \
  --query GroupId \
  --output text)

$ echo $SECURE_SG

sg-09b73909d667bda17
```

**Launch the Instance:** Launch a secure instance with IMDSv2 already configured.

```bash
$ AMI_ID=$(aws ec2 describe-images \
    --owners amazon \
    --filters "Name=name,Values=al2023-ami-*-x86_64" \
    --query "sort_by(Images,&CreationDate)[-1].ImageId" \
    --output text)

$ aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type t3.micro \
    --subnet-id "$SUBNET_ID" \
    --security-group-ids "$SECURE_SG" \
    --iam-instance-profile Name=Room43ManagedInstanceProfile \
    --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
    --no-associate-public-ip-address \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=imdsv2-secure-instance},{Key=Purpose,Value=room-43-secure-build}]'

{
    "ReservationId": "r-083f284c7a4fe1073",
    "OwnerId": "203918859777",
    "Groups": [],
    "Instances": [
        {
            "Architecture": "x86_64",
            "BlockDeviceMappings": [],
            "ClientToken": "b1f6e376-0071-4944-8154-747529388ec6",
            "EbsOptimized": false,
            "EnaSupport": true,
[...]
```

**Verify:** Run the verification function to validate the setup and retrieve the flag.

```bash
$ aws lambda invoke \
  --function-name AWS403-VerifySecureBuild \
  --payload '{}' \
  /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "status": "PASS",
    "secure_instance_check": "PASS - imdsv2-secure-instance found with HttpTokens required",
    "flag": "[REDACTED]"
}
```

You deployed a secure EC2 instance that negates the IMDSv1 attack path.

**Answer the questions below**

> What flag is returned after launching a secure instance with IMDSv2 required from the start?
> 

THM{NO_REDIRECT_POSSIBLE}

### Task 6 - Conclusion

In this room, you found the misconfiguration, blocked the redirect path, and built a new instance that requires a token for every metadata request.

**Key Takeaways**

- Never leave `HttpTokens=optional` on instances; require IMDSv2 on every instance at launch and enforce it via launch templates and SCPs.
- Understand that IMDSv2 is not just a hardening option; it is the specific control that breaks the SSRF-to-credential-theft attack chain.
- Even though the change applies immediately, always verify metadata options with `describe-instances` after enforcing IMDSv2.
- Treat SSRF as inevitable in complex applications and design IMDS access so that a GET-only forwarder cannot retrieve credentials.
- Combine IMDSv2 enforcement with least-privilege instance roles. In this way, even if credentials are exposed, you limit the blast radius.
