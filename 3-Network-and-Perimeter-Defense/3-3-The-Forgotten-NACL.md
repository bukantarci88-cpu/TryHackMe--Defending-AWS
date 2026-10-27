# AWS Security 3.3. The Forgotten NACL

### Task 1 - Introduction

The deployment goes smoothly. Security groups are set on every instance - ports scoped, source IPs locked down. Everything looks right. What nobody checked were the network ACLs, and now the subnet boundary is wide open.

Network Access Control Lists (NACLs) operate at the subnet level - a layer above security groups. They are stateless, meaning both inbound and outbound traffic must be explicitly allowed, including return traffic on ephemeral ports. They evaluate rules in numbered order, and the first match wins. Unlike security groups, NACLs can explicitly deny traffic, making them a powerful coarse-grained perimeter around an entire subnet.

AWS creates a default NACL for every VPC that allows all traffic in all directions. Most teams never replace it. The result is that the subnet boundary provides zero additional filtering - if a security group rule is misconfigured, the traffic passes straight through without a second checkpoint.

In this room, you will investigate a VPC where both subnets use the default NACL, understand the associated risks, remediate them with custom NACLs, and build proper subnet-level network controls from scratch.

**Learning Objectives**

- Understand how NACLs differ from security groups: stateless vs stateful, subnet-level vs instance-level, rule ordering, and explicit deny capability
- Identify when a subnet is using the default "allow all" NACL instead of a custom, scoped one
- Explain why the default NACL provides no meaningful defense-in-depth alongside security groups
- Create custom NACLs with scoped inbound and outbound rules, including correct ephemeral port handling
- Design a layered network security model that uses NACLs as the subnet perimeter and security groups as the instance firewall.
- Verify NACL configurations using the AWS CLI.

### Task 2 - Real-World Incident

Let us understand how this misconfiguration played a role in one real-world incident.

**The Context**

In February 2023, the Sysdig Threat Research Team uncovered a sophisticated cloud attack they named SCARLETEEL. The target was an organization running workloads in a self-managed Kubernetes cluster on AWS. The cluster handled sensitive engineering workloads, including proprietary source code and data stored in Amazon S3 buckets. Both the Kubernetes cluster and the underlying EC2 nodes operated in subnets with the default AWS NACL; no subnet-level network filtering was in place beyond the security groups attached to individual instances.

**What Happened**

![Attack chain showing the publicly exposed Kubernetes application to IMDSv1 credentials leak to S3 exfiltration.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1782374302977.png)

1. **Container compromise** - Attackers exploited a public-facing application running in a Kubernetes pod. They deployed an XMRig cryptominer inside the pod - believed to be a decoy while the real objective played out in the background.
2. **IMDS credential theft** - From inside the compromised container, the attackers accessed the EC2 Instance Metadata Service (IMDSv1). Because the Kubernetes node did not restrict metadata endpoint access for pods, the pods retrieved the IAM role credentials of the underlying EC2 instance.
3. **AWS enumeration** - Using the stolen IAM credentials, the attackers called AWS APIs to enumerate EC2 instances, Lambda functions, S3 buckets, and other resources across the account.
4. **Cross-account lateral movement** - Inside the enumerated S3 buckets, the attackers found Terraform state files containing plaintext IAM credentials for a second AWS account. They used those credentials to pivot into the second account.
5. **Data theft and evasion** - The attackers accessed and exfiltrated proprietary source code and sensitive data. They then turned off CloudTrail logging in both accounts to cover their tracks. 

**Core Failures**

- **Default NACLs left in place** - Both subnets used the default "allow all" NACL. A NACL blocking outbound traffic to `169.254.169.254` or restricting cross-subnet lateral movement would have significantly limited the attack's reach.
- **IMDSv1 accessible from container workloads** - The metadata service was reachable from inside Kubernetes pods without hop-limit enforcement. IMDSv2 with a hop count of 1 would have blocked this access vector entirely.
- **Credentials stored in Terraform state** - Plaintext IAM credentials in S3-backed Terraform state provided a secondary exposure vector that enabled cross-account compromise.
- **No outbound traffic restrictions** - Nothing blocked the compromised workload from reaching external command-and-control infrastructure or exfiltrating data to the internet.

**Answer the questions below**

> What service on the EC2 instance did the attackers use to steal IAM credentials?
> 

IMDS

> What type of files are stored in S3 that contain credentials for a second AWS account?
> 

Terraform state files

### Task 3 - Identification

In this task, you will take on the role of a security analyst reviewing the network configuration of a two-tier VPC. The environment has a public subnet with a web server and a private subnet with a backend application. Security groups are already in place. Your job is to determine whether the NACLs are providing any additional defense.

**Info:** To start the AWS environment, click the `Cloud Details` button at the top of the room, then click `Generate Environment`. When the environment is ready, use the Credentials tab to navigate to the AWS Console and log in.

Make sure you first connect to the lab environment, either via `CloudShell` or by configuring the AWS CLI. Save the VPC and instance IDs to environment variables.

```bash
$ VPC_ID=$(aws ec2 describe-vpcs \
  --filters "Name=tag:Name,Values=room33-vpc" \
  --query "Vpcs[0].VpcId" --output text)

$ INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=room33-web-server" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].InstanceId" --output text)

$ echo "VPC: $VPC_ID | Web Server: $INSTANCE_ID"

VPC: vpc-07ed7cbdafcea302b | Web Server: i-0c3e7a28a0a9348c8
```

List the subnets in the VPC.

```bash
$ aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --query "Subnets[*].{Name:Tags[?Key=='Name']|[0].Value,CIDR:CidrBlock,SubnetId:SubnetId}" \
    --output table

----------------------------------------------------------------------
|                           DescribeSubnets                          |
+-------------+-------------------------+----------------------------+
|    CIDR     |          Name           |         SubnetId           |
+-------------+-------------------------+----------------------------+
|  10.0.1.0/24|  room33-public-subnet   |  subnet-065aa68ea7dd5a383  |
|  10.0.2.0/24|  room33-private-subnet  |  subnet-08f3bba41cfec1e9b  |
+-------------+-------------------------+----------------------------+
```

**FINDING:** The VPC has two subnets, as expected: a public subnet for the web server and a private subnet for the backend application.

Inspect the NACLs associated with the subnets.

```bash
$ aws ec2 describe-network-acls \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --query "NetworkAcls[*].{ID:NetworkAclId,IsDefault:IsDefault,Subnets:length(Associations), \
  InboundRules:Entries[?Egress].{Rule:RuleNumber,Action:RuleAction,CIDR:CidrBlock}, \
  OutboundRules:Entries[?Egress].{Rule:RuleNumber,Action:RuleAction,CIDR:CidrBlock}}" \
  --output json
[
    {
        "ID": "acl-0dacdb6731544adf4",
        "IsDefault": true,
        "Subnets": [REDACTED],
        "InboundRules": [
            {
                "Rule": 100,
                "Action": "allow",
                "CIDR": "0.0.0.0/0"
            },
            {
                "Rule": [REDACTED],
                "Action": "deny",
                "CIDR": "0.0.0.0/0"
            }
        ],
[...]
```

**FINDING:** There is a single NACL in the VPC with IsDefault: true, which is associated with both subnets. Rule 100 allows all traffic from `0.0.0.0/0` in both directions. The implicit deny rule can never be reached because rule 100 matches every packet first. Both subnets have no effective subnet-level filtering.

Check the security groups for comparison.

```bash
$ aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --query "SecurityGroups[*].{Name:GroupName,Ingress:IpPermissions[*].{Port:FromPort,Source:IpRanges[0].CidrIp}}" \
    --output json
[
    {
        "Name": "room33-backend-sg",
        "Ingress": [
            {
                "Port": 8080,
                "Source": null
            }
        ]
    },
[...]
```

**FINDING:** The security groups are correctly scoped - the web server allows only HTTP, and the backend allows only port 8080 from the web server security group.

Connect to the web server via SSM Session Manager and retrieve the flag.

```bash
$ aws ssm start-session --target $INSTANCE_ID

Starting session with SessionId: 910083608150-fgovavdzyuzj94j8b37qrnpro4

sh-5.2$ cat /opt/flags/identification-flag.txt

[REDACTED]
```

**Findings Summary**

Here is what you found:

- Both subnets - `room33-public-subnet` and `room33-private-subnet` - are associated with the single default NACL.
- The default NACL has one rule (100) that allows all traffic from `0.0.0.0/0` in both inbound and outbound directions. The implicit deny rule is never reached.
- Security groups on the instances are correctly scoped, but they operate at the instance level only. A misconfigured security group rule or an attacker moving laterally within the VPC would face zero resistance at the subnet boundary.
- The blast radius of any security group misconfiguration is the entire subnet - there is no second layer to catch it.

**Answer the questions below**

> What is the rule number in the default NACL that denies all inbound and outbound traffic?
> 

 32767

> How many subnets in the lab VPC are associated with the default NACL?
> 

 2

> What is the flag retrieved from the web server?
> 

THM{WHAT_NACL}

### Task 4 - Remediation

Now that you have identified the problem, here is the structured approach to fixing it:

1. Create a custom NACL for the public subnet with scoped inbound and outbound rules.
2. Associate the new public NACL with the public subnet.
3. Create a custom NACL for the private subnet that restricts access to VPC-internal traffic only.
4. Associate the new private NACL with the private subnet.
5. Verify that the web server remains reachable, and that both subnets now use custom NACLs.

**Note:** If you are starting a new `CloudShell` session, rerun the environment variable setup from Task 3 before proceeding.

**Create a Custom NACL for the Public Subnet**

The public subnet runs the web server. It needs to accept inbound HTTP from the internet and communicate with the private subnet on port 8080. Make sure you exit the SSM session with `exit` or open a new CloudShell tab and re-run the environmental variable setup from Task 3.

```bash
$ PUBLIC_NACL_ID=$(aws ec2 create-network-acl \
  --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=network-acl,Tags=[{Key=Name,Value=room33-public-nacl}]' \
  --query "NetworkAcl.NetworkAclId" --output text)

$ echo "Public NACL: $PUBLIC_NACL_ID"

Public NACL: acl-0cf64140b44bb5a9e
```

Add inbound rules for HTTP, HTTPS, and ephemeral return ports.

```bash
$ aws ec2 create-network-acl-entry --network-acl-id $PUBLIC_NACL_ID \
    --rule-number 100 --protocol tcp --port-range From=80,To=80 \
    --cidr-block 0.0.0.0/0 --rule-action allow --ingress

$ aws ec2 create-network-acl-entry --network-acl-id $PUBLIC_NACL_ID \
    --rule-number 110 --protocol tcp --port-range From=443,To=443 \
    --cidr-block 0.0.0.0/0 --rule-action allow --ingress

$ aws ec2 create-network-acl-entry --network-acl-id $PUBLIC_NACL_ID \
    --rule-number 200 --protocol tcp --port-range From=1024,To=65535 \
    --cidr-block 0.0.0.0/0 --rule-action allow --ingress
```

Add outbound rules for HTTP, HTTPS for external calls, port 8080 to the private subnet, and ephemeral response ports.

```bash
$ aws ec2 create-network-acl-entry --network-acl-id $PUBLIC_NACL_ID \
  --rule-number 100 --protocol tcp --port-range From=80,To=80 \
  --cidr-block 0.0.0.0/0 --rule-action allow --egress

$ aws ec2 create-network-acl-entry --network-acl-id $PUBLIC_NACL_ID \
  --rule-number 110 --protocol tcp --port-range From=443,To=443 \
  --cidr-block 0.0.0.0/0 --rule-action allow --egress

$ aws ec2 create-network-acl-entry --network-acl-id $PUBLIC_NACL_ID \
  --rule-number 120 --protocol tcp --port-range From=8080,To=8080 \
  --cidr-block 10.0.2.0/24 --rule-action allow --egress

$ aws ec2 create-network-acl-entry --network-acl-id $PUBLIC_NACL_ID \
  --rule-number 200 --protocol tcp --port-range From=1024,To=65535 \
  --cidr-block 0.0.0.0/0 --rule-action allow --egress
```

**Associate the Public NACL**

Replace the default NACL association on the public subnet.

```bash
$ PUB_SUBNET_ID=$(aws ec2 describe-subnets \
    --filters "Name=tag:Name,Values=room33-public-subnet" "Name=vpc-id,Values=$VPC_ID" \
    --query "Subnets[0].SubnetId" --output text)

$ PUB_ASSOC_ID=$(aws ec2 describe-network-acls \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=default,Values=true" \
    --query "NetworkAcls[0].Associations[?SubnetId=='$PUB_SUBNET_ID'].NetworkAclAssociationId" \
    --output text)

$ aws ec2 replace-network-acl-association \
    --association-id $PUB_ASSOC_ID \
    --network-acl-id $PUBLIC_NACL_ID

{
    "NewAssociationId": "aclassoc-02a4f76d338f89883"
}
```

**Create a Custom NACL for the Private Subnet**

The private subnet runs the backend application. It should accept traffic only from the public subnet on port 8080; never directly from the internet.

```bash
$ PRIVATE_NACL_ID=$(aws ec2 create-network-acl \
  --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=network-acl,Tags=[{Key=Name,Value=room33-private-nacl}]' \
  --query "NetworkAcl.NetworkAclId" --output text)

$ echo "Private NACL: $PRIVATE_NACL_ID"

Private NACL: acl-039653b8f377387a9
```

Add inbound rules for port 8080 from the public subnet only, and ephemeral return traffic from within the VPC.

```bash
$ aws ec2 create-network-acl-entry --network-acl-id $PRIVATE_NACL_ID \
    --rule-number 100 --protocol tcp --port-range From=8080,To=8080 \
    --cidr-block 10.0.1.0/24 --rule-action allow --ingress

$ aws ec2 create-network-acl-entry --network-acl-id $PRIVATE_NACL_ID \
    --rule-number 200 --protocol tcp --port-range From=1024,To=65535 \
    --cidr-block 10.0.0.0/16 --rule-action allow --ingress
```

Add outbound rules for ephemeral response traffic to the public subnet, and HTTPS within the VPC for internal calls.

```bash
$ aws ec2 create-network-acl-entry --network-acl-id $PRIVATE_NACL_ID \
  --rule-number 100 --protocol tcp --port-range From=1024,To=65535 \
  --cidr-block 10.0.1.0/24 --rule-action allow --egress

$ aws ec2 create-network-acl-entry --network-acl-id $PRIVATE_NACL_ID \
  --rule-number 110 --protocol tcp --port-range From=443,To=443 \
  --cidr-block 10.0.0.0/16 --rule-action allow --egress
```

**Associate the Private NACL**

Replace the default NACL associated with the private subnet.

```bash
$ PRIV_SUBNET_ID=$(aws ec2 describe-subnets \
    --filters "Name=tag:Name,Values=room33-private-subnet" "Name=vpc-id,Values=$VPC_ID" \
    --query "Subnets[0].SubnetId" --output text)

$ PRIV_ASSOC_ID=$(aws ec2 describe-network-acls \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=default,Values=true" \
    --query "NetworkAcls[0].Associations[?SubnetId=='$PRIV_SUBNET_ID'].NetworkAclAssociationId" \
    --output text)

$ aws ec2 replace-network-acl-association \
    --association-id $PRIV_ASSOC_ID \
    --network-acl-id $PRIVATE_NACL_ID

{
    "NewAssociationId": "aclassoc-09288832b6b2a0d0d"
}
```

**Verify**

Confirm the web server is still reachable on HTTP:

```bash
$ WEB_IP=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=room33-web-server" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].PublicIpAddress" --output text)

$ curl -s --connect-timeout 5 http://$WEB_IP | head -3
<html>
<head><title>Room 3.3 - NACL Lab</title></head>
<body>
```

Verify that both subnets now use custom NACLs, and that the default NACL has no associations.

```bash
$ aws ec2 describe-network-acls \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --query "NetworkAcls[*].{Name:Tags[?Key=='Name']|[0].Value,IsDefault:IsDefault,Subnets:length(Associations)}" \
    --output table

-------------------------------------------------
|              DescribeNetworkAcls              |
+------------+-----------------------+----------+
|  IsDefault |         Name          | Subnets  |
+------------+-----------------------+----------+
|  False     |  room33-public-nacl   |  1       |
|  False     |  room33-private-nacl  |  1       |
|  True      |  None                 |  0       |
+------------+-----------------------+----------+
```

**NOTE:** The default NACL now has `0` subnet associations. Each subnet has its own dedicated custom NACL.

Run the verifier Lambda to confirm both NACLs are in place and retrieve the flag.

**NOTE:** The Lambda function is a custom function used to check the completion of the task exercise.

```bash
$ aws lambda invoke \
    --function-name AWS303-VerifyRemediation \
    --payload '{}' \
    --cli-binary-format raw-in-base64-out \
    /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "status": "PASS",
    "room33_public_subnet_nacl": "PASS - room33-public-subnet is using a custom NACL",
    "room33_private_subnet_nacl": "PASS - room33-private-subnet is using a custom NACL",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> Which NACL property explains why rules must explicitly allow the ephemeral port range for return traffic?
> 

 Stateless

> What is the flag found by running the helper function?
> 

THM{NO_MORE_REPEATS}

### Task 5 - Build It Securely

Great job. Now, let us see how to build NACL defenses correctly from the start. Before creating any NACL rules, answer these questions:

1. What resources need unrestricted internet access? Only internet-facing resources belong in the public subnet. Everything else should be in the private subnet with no direct internet route.
2. What application traffic flows exist between subnets? Map each flow before writing rules. In this architecture: web server → backend on TCP 8080. Every defined flow requires two rules - the request direction and the return direction (ephemeral ports 1024–65535).
3. What outbound internet access do private resources need? If private instances must access external APIs, route them through a NAT Gateway, not directly through an Internet Gateway. Restrict private subnet outbound NACLs to VPC-internal CIDRs unless a NAT Gateway is present.
4. What should each subnet be completely blocked from doing? The private subnet must never accept inbound traffic from `0.0.0.0/0`. The public subnet should deny traffic on any port not required by the application.

**Create the VPC and Internet Gateway**

Create a new VPC and ensure DNS support is enabled and add an internet gateway for the public subnet.

```bash
$ SECURE_VPC=$(aws ec2 create-vpc \
--cidr-block 10.1.0.0/16 \
--tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=room33-secure-vpc}]" \
--query "Vpc.VpcId" --output text)

$ aws ec2 modify-vpc-attribute --vpc-id $SECURE_VPC --enable-dns-support "{\"Value\":true}"

$ aws ec2 modify-vpc-attribute --vpc-id $SECURE_VPC --enable-dns-hostnames "{\"Value\":true}"

$ SECURE_IGW=$(aws ec2 create-internet-gateway \
  --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=room33-secure-igw}]" \
  --query "InternetGateway.InternetGatewayId" --output text)

$ aws ec2 attach-internet-gateway \
  --internet-gateway-id $SECURE_IGW --vpc-id $SECURE_VPC

$ echo "Secure VPC: $SECURE_VPC | IGW: $SECURE_IGW"

Secure VPC: vpc-09d1468c12aeb617f | IGW: igw-0fcc23cc2d19b936e
```

**Create the Subnets**

Create the public and private subnets.

```bash
$ AZ=$(aws ec2 describe-availability-zones \
  --query "AvailabilityZones[0].ZoneName" --output text)

$ SECURE_PUBLIC=$(aws ec2 create-subnet \
  --vpc-id $SECURE_VPC --cidr-block 10.1.1.0/24 --availability-zone $AZ \
  --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=room33-secure-public}]" \
  --query "Subnet.SubnetId" --output text)

$ SECURE_PRIVATE=$(aws ec2 create-subnet \
  --vpc-id $SECURE_VPC --cidr-block 10.1.2.0/24 --availability-zone $AZ \
  --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=room33-secure-private}]" \
  --query "Subnet.SubnetId" --output text)

$ echo "Public: $SECURE_PUBLIC | Private: $SECURE_PRIVATE"

Public: subnet-057c63a2131589a9a | Private: subnet-02138b34aaf05297d
```

**Create Route Tables**

Associate the public subnet with an IGW route and the private subnet with a local-only route table.

```bash
$ PUB_RT=$(aws ec2 create-route-table \
--vpc-id $SECURE_VPC \
--tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=room33-secure-public-rt}]" \
--query "RouteTable.RouteTableId" --output text)

$ aws ec2 create-route --route-table-id $PUB_RT \
--destination-cidr-block 0.0.0.0/0 --gateway-id $SECURE_IGW

{
    "Return": true
}

$ aws ec2 associate-route-table --route-table-id $PUB_RT --subnet-id $SECURE_PUBLIC

{
    "AssociationId": "rtbassoc-0261d460183fcbdc8",
    "AssociationState": {
        "State": "associated"
    }
}$ PRIV_RT=$(aws ec2 create-route-table \
--vpc-id $SECURE_VPC \
--tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=room33-secure-private-rt}]" \
--query "RouteTable.RouteTableId" --output text)

$ aws ec2 associate-route-table --route-table-id $PRIV_RT --subnet-id $SECURE_PRIVATE

{
    "AssociationId": "rtbassoc-05a3d248dd627e6ad",
    "AssociationState": {
        "State": "associated"
    }
}$ echo "Public RT: $PUB_RT | Private RT: $PRIV_RT"

Public RT: rtb-0aca3cf8de639c036 | Private RT: rtb-00f7395686aa024cb
```

**Create the Public Subnet NACL**

Create the NACL first.

```bash
$ PUB_NACL=$(aws ec2 create-network-acl \
  --vpc-id $SECURE_VPC \
  --tag-specifications "ResourceType=network-acl,Tags=[{Key=Name,Value=room33-secure-public-nacl}]" \
  --query "NetworkAcl.NetworkAclId" --output text)

$ echo "Public NACL: $PUB_NACL"

Public NACL: acl-057a0a15560b7562e
```

Add the inbound rules for HTTP, HTTPS, and ephemeral return traffic:

```bash
$ aws ec2 create-network-acl-entry --network-acl-id $PUB_NACL \
  --rule-number 100 --protocol tcp --port-range From=80,To=80 \
  --cidr-block 0.0.0.0/0 --rule-action allow --ingress

$ aws ec2 create-network-acl-entry --network-acl-id $PUB_NACL \
  --rule-number 110 --protocol tcp --port-range From=443,To=443 \
  --cidr-block 0.0.0.0/0 --rule-action allow --ingress

$ aws ec2 create-network-acl-entry --network-acl-id $PUB_NACL \
  --rule-number 200 --protocol tcp --port-range From=1024,To=65535 \
  --cidr-block 0.0.0.0/0 --rule-action allow --ingress
```

Now add the outbound rules for HTTP/HTTPS, application traffic to the private subnet, and ephemeral response ports.

```bash
$ aws ec2 create-network-acl-entry --network-acl-id $PUB_NACL \
  --rule-number 100 --protocol tcp --port-range From=80,To=80 \
  --cidr-block 0.0.0.0/0 --rule-action allow --egress

$ aws ec2 create-network-acl-entry --network-acl-id $PUB_NACL \
  --rule-number 110 --protocol tcp --port-range From=443,To=443 \
  --cidr-block 0.0.0.0/0 --rule-action allow --egress

$ aws ec2 create-network-acl-entry --network-acl-id $PUB_NACL \
  --rule-number 120 --protocol tcp --port-range From=8080,To=8080 \
  --cidr-block 10.1.2.0/24 --rule-action allow --egress

$ aws ec2 create-network-acl-entry --network-acl-id $PUB_NACL \
  --rule-number 200 --protocol tcp --port-range From=1024,To=65535 \
  --cidr-block 0.0.0.0/0 --rule-action allow --egress
```

Associate with the public subnet:

```bash
$ PUB_ASSOC=$(aws ec2 describe-network-acls \
  --filters "Name=vpc-id,Values=$SECURE_VPC" "Name=default,Values=true" \
  --query "NetworkAcls[0].Associations[?SubnetId=='$SECURE_PUBLIC'].NetworkAclAssociationId" \
  --output text)

$ aws ec2 replace-network-acl-association \
  --association-id $PUB_ASSOC --network-acl-id $PUB_NACL

{
    "NewAssociationId": "aclassoc-0e63fea8069ba196d"
}
```

**Create the Private Subnet NACL**

Create the NACL first.

```bash
$ PRIV_NACL=$(aws ec2 create-network-acl \
  --vpc-id $SECURE_VPC \
  --tag-specifications "ResourceType=network-acl,Tags=[{Key=Name,Value=room33-secure-private-nacl}]" \
  --query "NetworkAcl.NetworkAclId" --output text)

$ echo "Private NACL: $PRIV_NACL"

Private NACL: acl-0ca33cdb8a4df488b
```

Add the inbound rules for port 8080 from the public subnet only, ephemeral return traffic from within the VPC.

```bash
$ aws ec2 create-network-acl-entry --network-acl-id $PRIV_NACL \
--rule-number 100 --protocol tcp --port-range From=8080,To=8080 \
--cidr-block 10.1.1.0/24 --rule-action allow --ingress

$ aws ec2 create-network-acl-entry --network-acl-id $PRIV_NACL \
--rule-number 200 --protocol tcp --port-range From=1024,To=65535 \
--cidr-block 10.1.0.0/16 --rule-action allow --ingress
```

Then the outbound rules for ephemeral response traffic to the public subnet, HTTPS within the VPC.

```bash
$ aws ec2 create-network-acl-entry --network-acl-id $PRIV_NACL \
  --rule-number 100 --protocol tcp --port-range From=1024,To=65535 \
  --cidr-block 10.1.1.0/24 --rule-action allow --egress

$ aws ec2 create-network-acl-entry --network-acl-id $PRIV_NACL \
  --rule-number 110 --protocol tcp --port-range From=443,To=443 \
  --cidr-block 10.1.0.0/16 --rule-action allow --egress
```

Associate with the private subnet:

```bash
$ PRIV_ASSOC=$(aws ec2 describe-network-acls \
--filters "Name=vpc-id,Values=$SECURE_VPC" "Name=default,Values=true" \
--query "NetworkAcls[0].Associations[?SubnetId=='$SECURE_PRIVATE'].NetworkAclAssociationId" \
--output text)

$ aws ec2 replace-network-acl-association \
--association-id $PRIV_ASSOC --network-acl-id $PRIV_NACL

{
    "NewAssociationId": "aclassoc-07b4ce2dd65056dda"
}
```

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** The private NACL has no `0.0.0.0/0` inbound rule. The implicit `*` rule denies any traffic arriving from outside the VPC CIDR. This is intentional; the private subnet must never be directly reachable from the internet.

**Verify**

Compare both NACL configurations to confirm they are correctly scoped:

```bash
$ echo "=== Public NACL Inbound ===" && \
  aws ec2 describe-network-acls --network-acl-ids $PUB_NACL \
    --query 'NetworkAcls[0].Entries[?!Egress].{Rule:RuleNumber,Action:RuleAction,CIDR:CidrBlock,From:PortRange.From,To:PortRange.To}' \
    --output table

=== Public NACL Inbound ===
---------------------------------------------------
|               DescribeNetworkAcls               |
+--------+-------------+-------+--------+---------+
| Action |    CIDR     | From  | Rule   |   To    |
+--------+-------------+-------+--------+---------+
|  allow |  0.0.0.0/0  |  80   |  100   |  80     |
|  allow |  0.0.0.0/0  |  443  |  110   |  443    |
|  allow |  0.0.0.0/0  |  1024 |  200   |  65535  |
|  deny  |  0.0.0.0/0  |  None |  32767 |  None   |
+--------+-------------+-------+--------+---------+

$ echo "=== Private NACL Inbound ===" && \
  aws ec2 describe-network-acls --network-acl-ids $PRIV_NACL \
    --query 'NetworkAcls[0].Entries[?!Egress].{Rule:RuleNumber,Action:RuleAction,CIDR:CidrBlock,From:PortRange.From,To:PortRange.To}' \
    --output table

=== Private NACL Inbound ===
-----------------------------------------------------
|                DescribeNetworkAcls                |
+--------+---------------+-------+--------+---------+
| Action |     CIDR      | From  | Rule   |   To    |
+--------+---------------+-------+--------+---------+
|  allow |  10.1.1.0/24  |  8080 |  100   |  8080   |
|  allow |  10.1.0.0/16  |  1024 |  200   |  65535  |
|  deny  |  0.0.0.0/0    |  None |  32767 |  None   |
+--------+---------------+-------+--------+---------+
```

Run the verifier to retrieve the flag:

```bash
$ aws lambda invoke \
    --function-name AWS303-VerifySecureBuild \
    --payload '{}' \
    --cli-binary-format raw-in-base64-out \
    /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "status": "PASS",
    "room33_secure_public_nacl_check": "PASS - room33-secure-public-nacl exists with 7 custom rule(s) and 1 subnet association(s)",
    "room33_secure_private_nacl_check": "PASS - room33-secure-private-nacl exists with 4 custom rule(s) and 1 subnet association(s)",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> What is the ephemeral port range that must be allowed in NACL rules for return traffic on Linux?
> 

1024-65535

> What is the flag from the secure build verifier?
> 

THM{TODAY_IS_DIFFERENT}

### Task 6 - Conclusion

Congratulations. You identified a VPC running without effective subnet-level network controls, remediated it with scoped custom NACLs, and built a properly layered network security design from scratch.

**Key Takeaways**

- Never use the default NACL in any environment that handles real data. It allows all traffic in all directions and provides no defense. Replace it with a custom NACL on every subnet.
- Design NACLs and security groups as two independent layers. Each should enforce your security intent on its own - if either fails, the other still provides meaningful protection.
- Always account for ephemeral ports in NACL rules. NACLs are stateless: every allowed flow requires both the request-direction rule and a return-direction rule for ports 1024–65535. Forgetting either direction causes connections to silently fail.
- Number rules with gaps (100, 110, 120). The first match wins, so the order of rules matters. Gaps let you insert rules later without renumbering.
- Restrict private subnet NACLs to VPC-internal CIDRs only. Private subnets must never have an inbound allow rule for `0.0.0.0/0`. If the source is not within the VPC, deny it at the subnet boundary.
- Use explicit deny rules for known bad traffic. Unlike security groups, NACLs support explicit deny - use them to block specific CIDRs, restrict lateral movement between subnets, and enforce perimeter rules that security groups cannot express.
