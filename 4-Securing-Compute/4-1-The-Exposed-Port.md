# AWS Security 4.1. The Exposed Port

### Task 1 - Introduction

An engineer spins up an EC2 instance during a late-night deployment. Port 22 goes in as a temporary convenience - just until the setup is done. The instance gets its workload, the team moves on, and the rule is never revisited. Three days later, a GuardDuty alert fires: `UnauthorizedAccess:EC2/SSHBruteForce`. The port has been answering automated scanners since the moment the instance came online.

Modern AWS environments require no inbound management ports. AWS Systems Manager Session Manager provides authenticated, audited shell access over the AWS control plane - no inbound rules, no key pairs, no brute-force surface. The port was never needed. This room shows you how to find it, close it, and build correctly from the start.

### Task 2 - Real-World Incident

In 2020, a threat group known as TeamTNT ran a sustained, automated campaign against cloud environments hosted on AWS and other major providers. TeamTNT's goal was straightforward: find instances with management ports exposed to the internet, gain access, and deploy cryptocurrency miners and credential-harvesting tools. Their tooling required no manual targeting - scanners ran continuously, finding exposed hosts faster than most security teams could respond.

The targets were not high-profile organizations chosen for their data. They were ordinary cloud workloads - development servers, build agents, and small production services - that shared one thing in common: port 22 was reachable from any address on the internet.

**What Happened**

![Attack chain from port scanning, to brute-force, initial access, credentials harvesting, and persistance and mining.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781512548192.png)

1. **Port scanning**: Automated tools swept AWS and other cloud IP ranges continuously, probing for open TCP/22 and TCP/3389 and logging every responsive address.
2. **Credential brute-force**: Each discovered instance was subjected to login attempts using lists of common usernames and default or weak passwords.
3. **Initial access**: On a successful login, the attacker gained a shell on the instance under the credentials of the compromised account.
4. **Credential harvest**: TeamTNT tooling scanned the instance for AWS access keys stored in environment variables, configuration files, and common paths such as `~/.aws/credentials`.
5. **Lateral movement**: Harvested AWS credentials were used to pivot into the broader account - reaching S3 buckets, other EC2 instances, and any service the stolen key could access.
6. **Persistence and mining**: A cryptocurrency miner was deployed on the compromised instance, and a backdoor was installed for re-entry.

**Core Failures**

- **Exposed management port**: TCP/22 open to `0.0.0.0/0` made every instance a publicly addressable target from the moment it came online.
- **No access path enforcement**: AWS Systems Manager was not configured as the standard access method, leaving SSH as the only option and giving the open port a permanent justification.
- **Credentials stored on the instance**: AWS access keys in plaintext on the host gave the attacker an immediate path to the wider account after initial compromise.
- **No detective controls**: Without GuardDuty or alerting on SSH activity, organizations had no visibility into the attack until compute costs spiked or instances degraded.

**Answer the questions below**

> What network port did TeamTNT's scanners target to gain initial access to cloud instances?
> 

22

|What type of program did TeamTNT install to ensure re-entry and persistence?

backdoor

### Task 3 - Identification

You will take on the role of a security analyst and audit an EC2 instance to determine whether its management port is exposed to the internet and whether a safer access path is already in place.

Start by saving the environment variables you'll need later.

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ INSTANCE_ID=$(aws ec2 describe-instances \
      --filters "Name=tag:Purpose,Values=room-41-lab" \
                "Name=instance-state-name,Values=running" \
      --query "Reservations[0].Instances[0].InstanceId" \
      --output text)

$ echo "Account ID: $ACCOUNT_ID | Instance ID: $INSTANCE_ID"

Account ID: 740047840772 | Instance ID: i-03b2ac6305f4a87a9
```

**Look at the Security Group:** Find the attached security group for the instance and review its inbound rules.

```bash
$ SG_ID=$(aws ec2 describe-instances \
      --instance-ids "$INSTANCE_ID" \
      --query "Reservations[0].Instances[0].SecurityGroups[0].GroupId" \
      --output text)

$ echo $SG_ID

sg-0e26cf330a4c30a7d$ aws ec2 describe-security-groups \
      --group-ids "$SG_ID" \
      --query "SecurityGroups[0].IpPermissions" \
      --output json

[
    {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "UserIdGroupPairs": [],
        "IpRanges": [
            {
                "CidrIp": "0.0.0.0/0"
            }
        ],
        "Ipv6Ranges": [],
        "PrefixListIds": []
    }
]
```

**FINDING:** The security group attached to the instance allows SSH (Port `22`) connections from anywhere (CIDR `0.0.0.0/0`).

**Check Session Manager:** Verify if AWS Session Manager is available for this instance.

```bash
$ aws ssm describe-instance-information \
      --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
      --query "InstanceInformationList[0].{Ping:PingStatus,Platform:PlatformName,Agent:AgentVersion}" \
      --output table

------------------------------------------
|       DescribeInstanceInformation      |
+-------------+---------+----------------+
|    Agent    |  Ping   |   Platform     |
+-------------+---------+----------------+
|  3.3.4108.0 |  Online |  Amazon Linux  |
+-------------+---------+----------------+
```

**FINDING:** The instance is already registered with the AWS Systems Manager Session Manager service, and it is `Online`.

**Retrieve the Flag:** An EC2 tag hides the flag. Run the following command to retrieve it.

```bash
$ aws ec2 describe-tags \
      --filters "Name=resource-id,Values=$INSTANCE_ID" \
      --query "Tags[?Key=='Flag'].Value" \
      --output text

[REDACTED]
```

**Findings Summary**

- The lab instance has TCP/22 open to `0.0.0.0/0` through its attached security group, so any host on the internet can attempt an SSH login at any time.
- AWS Systems Manager is already online on this instance, providing an authenticated, auditable access path over the AWS control plane without any inbound port.
- The public SSH rule is entirely redundant. The blast radius of this misconfiguration extends to every credential that could be brute-forced or found stored on the instance after initial access.

**Answer the questions below**

> What CIDR range is the TCP/22 rule open to, confirming it is exposed to the entire internet?
> 

0.0.0.0/0

> What is the flag for this task?
> 

THM{NO_IDC_RECEIVED}

### Task 4 - Remediation

The path to fix this is straightforward. You already confirmed that Session Manager is running, which means a safer access path is ready right now. Here is what you will do:

- Revoke the public inbound SSH rule from the lab security group.
- Confirm the inbound rules are now clear.
- Connect to the instance through Session Manager to prove access is retained.
- Run the verifier Lambda to retrieve the flag.

First, let's make sure we have the needed IDs in the environment variables.

```bash
$ INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Purpose,Values=room-41-lab" \
  "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].InstanceId" \
  --output text)

$ SG_ID=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].SecurityGroups[0].GroupId" \
  --output text)
```

**Revoke SSH Access:** Remove the security group Inbound rule that allows SSH access.

```bash
$ aws ec2 revoke-security-group-ingress \
      --group-id "$SG_ID" \
      --ip-permissions '[{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'

{
    "Return": true,
    "RevokedSecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-0dc75616559f8d3b0",
            "GroupId": "sg-06b139d58716dbe9c",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "CidrIpv4": "0.0.0.0/0"
        }
    ]
}
```

**Confirm the Change:** Review the security group rules to validate that the SSH rule has been removed.

```bash
$ aws ec2 describe-security-groups \
  --group-ids "$SG_ID" \
  --query "SecurityGroups[0].IpPermissions" \
  --output json

[ ]
```

An empty output means there are no (more) rules.

**Connect via Session Manager:** Connect to the instance via SSM to verify management access still works.

```bash
$ aws ssm start-session --target "$INSTANCE_ID"

Starting session with SessionId: 980637429072-x9sjne6v8flf9oqkcf7e4ehtbu

sh-5.2$ whoami

ssm-user
```

Now type `exit` to quit the SSM session and run the helper function to retrieve the flag.

```bash
$ aws lambda invoke \
      --function-name AWS401-VerifyRemediation \
      --payload '{}' \
      /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "status": "PASS",
    "security_group_check": "PASS - no public SSH or RDP rule found on the lab instance",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> What flag is returned by the verifier function after removing the public management rule?
> 

THM{IRIS_CLOSED}

### Task 5 - Build It Securely

So how would you build this securely from the start?

Before launching any instance, you can run through these questions:

1. What access path do you use for administration? Session Manager - no inbound port needed.
2. What inbound rules does the security group require? None for management. Outbound to AWS  endpoints is sufficient.
3. What IAM role does the instance need? One that includes `AmazonSSMManagedInstanceCore` so the SSM agent can register.
4. What should happen to the SSH key pair? It is not needed. Leave it out entirely.

The lab provides a pre-configured instance profile (`Room41ManagedInstanceProfile`) that already includes the required SSM policy.

You will create a new security group with no inbound rules and launch an instance that is manageable from day one, with no public ports.

Ensure you have the right IDs in the environment variables.

```bash
$ INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Purpose,Values=room-41-lab" \
  "Name=instance-state-name,Values=running" \
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

$ echo "Subnet ID: $SUBNET_ID | VPC ID: $VPC_ID"

Subnet ID: subnet-04bed18e662f450e9 | VPC ID: vpc-07944678ca7254e33
```

**Create a Simple Security Group:** Create a security group with no inbound rules, as you will need to attach it to the instance.

```bash
$ SECURE_SG=$(aws ec2 create-security-group \
      --group-name "room41-no-inbound-sg" \
      --description "Room 4.1 secure management SG - no inbound rules" \
      --vpc-id "$VPC_ID" \
      --query GroupId \
      --output text)
$ echo $SECURE_SG

sg-025d24445f2284824
```

**Launch a Managed Instance:** You will now launch an EC2 instance without a key pair and attach the SG you created.

```bash
$ AMI_ID=$(aws ec2 describe-images \
  --owners amazon \
  --filters "Name=name,Values=al2023-ami-*-x86_64" \
  --query "sort_by(Images,&CreationDate)[-1].ImageId" \
  --output text)
$ echo $AMI_ID

ami-027a2644c5c1d0aff$ aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type t3.micro \
    --subnet-id "$SUBNET_ID" \
    --security-group-ids "$SECURE_SG" \
    --iam-instance-profile Name="Room41ManagedInstanceProfile" \
    --no-associate-public-ip-address \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=secure-ssm-instance},{Key=Purpose,Value=room-41-secure-build}]'

{
    "ReservationId": "r-0fc1b869999de7fe5",
    "OwnerId": "555488996595",
    "Groups": [],
    "Instances": [
        {
            "Architecture": "x86_64",
            "BlockDeviceMappings": [],
            "ClientToken": "f0db7363-b908-4b9b-8388-e43b751dd06c",
            "EbsOptimized": false,
            "EnaSupport": true,
            "Hypervisor": "xen",
            "IamInstanceProfile": {
                "Arn": "arn:aws:iam::555488996595:instance-profile/Room41ManagedInstanceProfile",
                "Id": "AIPAYCVNZNTZ2NG3ONFAF"
            },
[...]
```

The `--key-name` parameter is intentionally left out. This instance has no SSH key pair associated with it, so it cannot be accessed via SSH from the start.

**Verify:** Run the verification function to validate the setup and retrieve the flag.

```bash
$ aws lambda invoke \
  --function-name AWS401-VerifySecureBuild \
  --payload '{}' \
  /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "status": "PASS",
    "secure_instance_check": "PASS - secure-ssm-instance found with no public SSH or RDP exposure",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> What flag is returned by the verifier after building the secure no-inbound instance?
> 

THM{BUGS_ON_A_WINDSHIELD}

### Task 6 - Conclusion

In this room, you have taken an EC2 instance from one of the most common cloud exposure patterns to a modern, port-free access model and built a second one the right way from the start.

**Key Takeaways**

- **Never treat an open management port as temporary**: once it is open, automated scanners will find it within minutes and test it continuously until it is closed.
- **Use Session Manager as the default EC2 access path**: it requires no inbound ports, no key pair, and automatically logs every session to CloudTrail.
- **Set no inbound management rules as the baseline**: the right number of inbound SSH or RDP rules for most EC2 instances is zero.
- **Audit security groups regularly for `0.0.0.0/0` on ports 22 and 3389**: these two rules are the highest-signal finding in any EC2 security review.
- **Add detective controls alongside preventive ones**: GuardDuty's `UnauthorizedAccess:EC2/SSHBruteForce` finding tells you the port is being probed, but by then, it should already be closed.
