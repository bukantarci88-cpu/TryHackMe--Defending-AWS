# TryHackMe -- AWS Networking

> **Platform:** TryHackMe\
> **Room:** AWS Networking\
> **Category:** Cloud Security \| AWS \| Networking\
> **Services & Tools:** Amazon VPC, Subnets, Route Tables, Internet
> Gateway, NAT Gateway, Security Groups, Network ACLs, AWS CLI,
> CloudShell

------------------------------------------------------------------------

## Overview

This write-up covers core AWS networking components and how network
traffic flows through a Virtual Private Cloud (VPC). The practical
exercises focus on identifying VPC resources, examining routes and
access controls, and understanding how a public web server communicates
with other resources.

The lab uses the AWS region `us-east-1`.

## Task 1 -- Introduction

The room introduces AWS network resources and the way traffic flows
between them.

## Task 2 -- Virtual Private Cloud (VPC)

A **Virtual Private Cloud (VPC)** is an isolated network within AWS. It
provides control over IP address ranges, network segmentation, and
traffic flow.

### Key concepts

-   A VPC exists in a single AWS Region.
-   Each Region contains multiple Availability Zones (AZs), which are
    physically separate data centers connected by low-latency links.
-   A VPC uses a CIDR block, such as `10.0.0.0/16`, which can be divided
    into smaller subnet ranges.
-   Each AWS account has a default VPC in each Region.

### Security best practices

-   Segment networks to reduce the blast radius of a compromise.
-   Use a planned VPC and network topology for production environments
    rather than relying on the default VPC.
-   Place subnets across multiple Availability Zones where appropriate
    to support availability, fault tolerance, and scalability.
-   Control access to VPC resources with well-defined IAM roles and
    permissions.
-   Enable **VPC Flow Logs** to record metadata about IP traffic for
    monitoring and analysis.

### Practical commands

Use the AWS Console, CloudShell, or the AWS CLI to inspect VPCs:

``` bash
aws ec2 describe-vpcs
```

The command returns VPC details, including CIDR blocks and associated
metadata.

### Lab findings

  Question             Answer
  -------------------- -----------------
  VPC name             `lab-vpc`
  Lab VPC CIDR block   `172.16.0.0/16`

## Task 3 -- Subnets and Routing

A subnet is a defined IP address range inside a VPC. Route tables
determine where traffic from a subnet is directed.

### Public and private subnets

-   **Public subnet:** Has a route to an Internet Gateway. Resources
    generally also need a public IP address and suitable security rules
    to communicate directly with the internet.
-   **Private subnet:** Has no direct route to an Internet Gateway. It
    can use a NAT Gateway for outbound internet access, while remaining
    unavailable for direct inbound connections from the internet.

### Route tables

A route table contains destination-and-target rules. Each subnet is
associated with a route table, either explicitly or through the VPC's
main route table.

Example public-subnet routes:

  -----------------------------------------------------------------------
  Destination             Target                  Purpose
  ----------------------- ----------------------- -----------------------
  `10.0.0.0/16`           `local`                 Routes traffic within
                                                  the VPC

  `0.0.0.0/0`             Internet Gateway        Routes other IPv4
                          (`igw-...`)             traffic toward the
                                                  internet
  -----------------------------------------------------------------------

The `0.0.0.0/0` route is a default route for IPv4 traffic not matched by
a more specific route.

### Gateways

-   **Internet Gateway (IGW):** Enables internet connectivity for a VPC
    when routing, public addressing, and access rules are configured
    appropriately.
-   **NAT Gateway:** Allows resources in private subnets to initiate
    outbound connections, such as downloading updates, without allowing
    unsolicited inbound internet connections through the NAT Gateway.

### Inspect subnets

First, save the ID of the non-default lab VPC in a shell variable:

``` bash
LAB_VPC=$(aws ec2 describe-vpcs \
  --filters "Name=isDefault,Values=false" \
  --query "Vpcs[0].VpcId" \
  --output text)
```

Then list the subnets associated with that VPC:

``` bash
aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$LAB_VPC" \
  --query "Subnets[*].{ID:SubnetId,CIDR:CidrBlock,AZ:AvailabilityZone,Name:Tags[?Key=='Name']|[0].Value}" \
  --output table
```

### Inspect route tables

``` bash
aws ec2 describe-route-tables \
  --filters "Name=vpc-id,Values=$LAB_VPC" \
  --query "RouteTables[*].{ID:RouteTableId,Name:Tags[?Key=='Name']|[0].Value,Routes:Routes[*].{Dest:DestinationCidrBlock,Target:GatewayId||NatGatewayId}}" \
  --output json
```

These commands can help automate the collection of subnet and routing
information.

### Lab findings

  Question                Answer
  ----------------------- -----------------
  Public subnet CIDR      `172.16.1.0/24`
  Route table ID prefix   `rtb`

## Task 4 -- Security Groups and Network ACLs

AWS provides two key network access-control layers: **Security Groups**
and **Network Access Control Lists (NACLs)**.

### Security Groups vs. NACLs

  -----------------------------------------------------------------------
  Capability              Security Group          Network ACL (NACL)
  ----------------------- ----------------------- -----------------------
  Applied at              Network interface /     Subnet level
                          instance level          

  Connection tracking     Stateful                Stateless

  Rule actions            Allow rules only        Allow and deny rules

  Rule evaluation         All applicable rules    Rules are evaluated in
                          are evaluated together  ascending rule-number
                                                  order

  -----------------------------------------------------------------------

**Stateful** means response traffic for an allowed connection is
automatically permitted. **Stateless** means inbound and outbound
traffic are evaluated independently, so NACL rules must account for both
directions.

### Security best practices

-   Use Security Groups to control traffic to individual resources or
    groups of resources.
-   Use NACLs as an additional subnet-level control.
-   Apply the **Principle of Least Privilege**: allow only the required
    sources, destinations, protocols, and ports.
-   Use layered controls, with Security Groups providing resource-level
    restrictions and NACLs acting as additional guardrails.

### List Security Groups

``` bash
aws ec2 describe-security-groups \
  --filters "Name=vpc-id,Values=$LAB_VPC" \
  --query "SecurityGroups[*].{ID:GroupId,Name:GroupName,Description:Description}" \
  --output table
```

### List Network ACLs

``` bash
aws ec2 describe-network-acls \
  --filters "Name=vpc-id,Values=$LAB_VPC" \
  --query "NetworkAcls[*].{ID:NetworkAclId,Default:IsDefault,Entries:Entries[*].{Rule:RuleNumber,Action:RuleAction,CIDR:CidrBlock,Protocol:Protocol}}" \
  --output json
```

### Lab findings

  Question                                              Answer
  ----------------------------------------------------- ----------------
  Which network access control is stateful?             Security Group
  Inbound ports open in `lab-web-sg`, ascending order   `22, 80, 443`

## Task 5 -- AWS Network Flow

Understanding the packet path helps identify where access may be
permitted or blocked.

### Internet to the public web server

The lab describes the following inbound path:

1.  The request arrives at the **Internet Gateway (IGW)**.
2.  The IGW forwards the traffic into the VPC.
3.  The VPC router checks the route table associated with the
    destination subnet.
4.  The subnet's **Network ACL** evaluates the inbound rules.
5.  The web server's **Security Group** evaluates the inbound traffic.
6.  If allowed, traffic reaches the instance through its **Elastic
    Network Interface (ENI)**.
7.  The response returns through the instance's Security Group; the
    stateless NACL separately evaluates outbound rules.

A simplified path is:

``` text
Internet
   |
Internet Gateway
   |
VPC routing
   |
Subnet Route Table
   |
Inbound Network ACL
   |
Web Server Security Group
   |
Elastic Network Interface
   |
EC2 Web Server
```

### Network security recommendations

-   Understand the complete traffic path before changing network
    controls.
-   Use network segmentation to reduce the blast radius and improve
    containment during an incident.
-   Avoid broad source ranges such as `0.0.0.0/0` unless public access
    is genuinely required.
-   Avoid opening large port ranges when specific ports are sufficient.
-   Remember that Security Groups do not filter certain AWS-related
    traffic and services, including Amazon DNS, DHCP, EC2 instance
    metadata, ECS metadata, Windows license activation, and Amazon NTP.

### Identify the lab web server

``` bash
aws ec2 describe-instances \
  --filters "Name=vpc-id,Values=$LAB_VPC" "Name=instance-state-name,Values=running" \
  --query "Reservations[*].Instances[*].{ID:InstanceId,PublicIP:PublicIpAddress,PrivateIP:PrivateIpAddress,Name:Tags[?Key=='Name']|[0].Value}" \
  --output table
```

The lab output identifies an instance named `lab-web-server`. The
instance's public IP can vary between lab deployments.

To retrieve the HTTP response from the lab server, use the public IP
returned by your own command:

``` bash
curl -s http://<PUBLIC_IP>
```

Replace `<PUBLIC_IP>` with the actual public IP address from your lab.
Do not assume an IP shown in an example will remain valid.

### Lab flags

  Exercise                 Flag
  ------------------------ ---------------------------
  Network flow mini-game   `THM{AWS_NETWORKING_101}`
  Web server               `THM{TANGLED_WEBS}`

  <img width="634" height="451" alt="image" src="https://github.com/user-attachments/assets/f6a0e4df-1d74-4778-baa4-2668eff8ce85" />
  <img width="485" height="334" alt="image" src="https://github.com/user-attachments/assets/67124396-6821-4f7f-a7df-01eb20f4201f" />



## Task 6 -- Conclusion

This room demonstrates how AWS networking components work together and
how they can be reviewed from a security perspective.

### Key takeaways

-   A VPC provides an isolated network boundary within AWS.
-   CIDR blocks define address ranges, which can be divided into
    subnets.
-   Public-subnet internet connectivity typically uses an Internet
    Gateway and appropriate routing and access rules.
-   Private subnets can use a NAT Gateway for outbound connections
    without exposing resources to direct inbound internet connections.
-   Route tables determine where network traffic is directed.
-   Security Groups are stateful and apply at the
    network-interface/resource level.
-   NACLs are stateless and apply at the subnet level.
-   A typical inbound path to a public EC2 web server is: **IGW → VPC
    routing → route table → NACL → Security Group → ENI/instance**.
-   VPC Flow Logs can support network monitoring, investigation, and
    traffic analysis.
-   Least-privilege rules and network segmentation help reduce exposure
    and limit the impact of a compromise.

------------------------------------------------------------------------

## Skills Demonstrated

-   AWS VPC and subnet inspection
-   Route table and gateway analysis
-   Security Group and Network ACL comparison
-   AWS CLI querying and filtering with `--query`
-   Understanding inbound traffic flow to an EC2 web server
-   Applying network segmentation and least-privilege principles
