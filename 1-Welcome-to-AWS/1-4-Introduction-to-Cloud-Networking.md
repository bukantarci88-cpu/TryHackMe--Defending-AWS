# AWS Security 1-4-Introduction to Cloud Networking

### Task 1 - Introduction

In this room, you will explore the different AWS network resources and how traffic flows between them.

### Task 2 - Virtual Private Cloud Service

A Virtual Private Cloud allows you to define your very own little corner in the cloud. You can think of it as a small data center where you define IP address ranges, network segmentation, and control traffic flow.

A virtual private cloud (VPC) is an isolated, private cloud inside of a public cloud environment. VPCs are granted to users of cloud providers so that their resources aren't accessible by other users in the same public cloud.

VPC key points:

- A VPC lives in a single region - a representative geographical location.
- Each region consists of multiple Availability Zones, which are physically separated data centers connected with low-latency links.
- When creating a VPC, you define the CIDR block, for example, `10.0.0.0/16`, that you can further split into subnets.
- Every AWS account comes with a default VPC in each region.

**Security Best Practices**

- Well-segmented networks reduce blast radius in case of a compromise.
- While the default VPC is good for short tests, when implementing a production setup, it is best to define your own VPC and network topology.
- VPCs are core building blocks of network isolation, so planning a good network layout goes a long way.
- Use different Availability Zones when defining your subnets; this ensures high availability, fault tolerance, and scalability.
- Tightly manage VPC resource access through well-defined roles and permissions through the IAM service.
- Use VPC Flow Logs, the service that records metadata about IP traffic, as a first line of network monitoring and analysis.

**Practical Exercise**

1. Log in to the AWS Console with the provided credentials.

**Note:** Be sure to check and switch to the `us-east-1` region.

1. Navigate to the VPC service.

![Navigate to the VPC service](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772604068172.png)

1. The VPC dashboard will give you a summary of network resources.

![Identify the details of the VPC](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772604073308.png)

1. Alternatively, you can use CloudShell or AWS CLI to get a feel of the commands used.

```bash
$ aws ec2 describe-vpcs

{
    "Vpcs": [
        {
            "OwnerId": "146655971864",
            "InstanceTenancy": "default",
            "CidrBlockAssociationSet": [
                {
                    "AssociationId": "vpc-cidr-assoc-0c671245996463616",
                    "CidrBlock": "[REDACTED]",
                    "CidrBlockState": {
                        "State": "associated"
                    }
                }
            ],
[...]
```

**Answer the questions below**

> What is the name of the VPC?
> 

lab-vpc

> What is the CIDR block of the lab VPC?
> 

172.16.0.0/16

### Task 3 - Subnet and Routing

Within a VPC, you divide the defined CIDR into usable IP ranges called subnets and shape traffic flow between them using routes.

**Subnets**

Within a subnet, you define the IP range that can be used by resources.

Typically, you will see two main subnet types:

- **Public subnets** - they have a route to an Internet Gateway, so resources with public IPs can reach the internet directly.
- **Private subnets** - there is no direct internet route, so resources are isolated from the internet.

**Routing**

A route table is a set of rules, called routes, that determine where network traffic is directed. Each subnet must be associated with a route table.

One noticeable aspect is the main route table. This is the route table that automatically comes with your VPC. It controls the routing for all subnets that are not explicitly associated with any other route table.

A typical public subnet route table looks like this:

| **Destination** | **Target** |
| --- | --- |
| 10.0.0.0/16 | local |
| 0.0.0.0/0 | igw-0abc123 |

In simple terms, whatever goes to the `10.0.0.0/16` subnet stays within the VPC, while the `0.0.0.0/0` route redirects traffic outside the VPC, in this case to the internet.

Private subnets usually have the "catch-all" destination set to a NAT Gateway so they can reach the internet (e.g., for updates, patching, etc.), but they will not be reachable from the internet.

**Gateways**

Gateways are network nodes that connect different networks and act as translators between different protocols, data formats, or architectures.

In AWS, most commonly, you will see:

- **Internet Gateway** - enables bidirectional Internet access for public subnets.
- **NAT Gateway** - enables outbound-only Internet access for private subnets.

**Practical Exercise**

1. First, you can view the lab setup subnets in the Subnets dashboard.

**Note:** When multiple VPCs have associated subnets, this dashboard provides an overview of all subnets across those VPCs.

![Find the details of the subnets](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772604575848.png)

1. You can see the routes for your VPC in the Routes dashboard.

![Explore the VPC route tables](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772604575767.png)

1. Lastly, you can further explore different VPC elements by using the left-side shortcuts.

![VPC important subservices](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772604575749.png)

As a good exercise, you can also explore the components from CloudShell or AWS CLI using AWS commands.

1. You will have to be aware of the VPC ID. In this example, the ID is saved in a local variable.

**Note:** There will be commands, like the one below, that have no output.

```bash
$ LAB_VPC=$(aws ec2 describe-vpcs \
            --filters "Name=isDefault,Values=false" \
            --query "Vpcs[0].VpcId" --output text)
```

1. Next, you can list the subnets for the VPC.

```bash
$ aws ec2 describe-subnets \
            --filters "Name=vpc-id,Values=$LAB_VPC" \
            --query "Subnets[*].{ID:SubnetId,CIDR:CidrBlock,AZ:AvailabilityZone,Name:Tags[?Key=='Name']|[0].Value}" \
            --output table

-----------------------------------------------------------------------------------
|                                 DescribeSubnets                                 |
+------------+----------------+----------------------------+----------------------+
|     AZ     |     CIDR       |            ID              |        Name          |
+------------+----------------+----------------------------+----------------------+
|  us-east-1a|  [REDACTED]    |  subnet-04f506d8031f4d6e7  |  lab-public-subnet   |
|  us-east-1a|  [REDACTED]    |  subnet-008254d25456c7b43  |  lab-private-subnet  |
+------------+----------------+----------------------------+----------------------+
```

1. Or you can list the VPC routes.

```bash
$ aws ec2 describe-route-tables \
            --filters "Name=vpc-id,Values=$LAB_VPC" \
            --query "RouteTables[*].{ID:RouteTableId,Name:Tags[?Key=='Name']|[0].Value,Routes:Routes[*].{Dest:DestinationCidrBlock,Target:GatewayId||NatGatewayId}}" \
            --output json

[
    {
        "ID": "[REDACTED]",
        "Name": "lab-public-rt",
        "Routes": [
            {
                "Dest": "[REDACTED]",
                "Target": "local"
            },
            {
                "Dest": "0.0.0.0/0",
                "Target": "igw-02d11d6658c2dfcd0"
            }
        ]
    },

[...]
```

You can use the CLI commands for programmatic access and extract just the needed information. This can be used in automation scripts.

**Answer the questions below**

> What is the CIDR of the public subnet?
> 

172.16.1.0/24

> What is the usual prefix for route IDs?
> 

rtb

### Task 4 - Security Groups and Network ACLs

AWS provides two layers of network-level access control with similar goals but that work differently: Security Groups and Network Access Control Lists.

**SG Versus NACL**

Security Groups act as a virtual, stateful firewall at the instance level, attached to Elastic Network Interfaces (ENIs).

Network Access Control Lists act as broader, stateless firewalls at the subnet level to control inbound/outbound traffic.

You have to be aware of the distinction between stateful and stateless. Stateful means the state of the connection is retained, meaning an SG would only need inbound rules. Stateless, by contrast, does not retain connection state, so NACLs need both inbound and outbound rules.

Here is a helpful table to view the key capabilities and differences at a glance.

| **Capability** | **Security Group** | **Network Access Control List** |
| --- | --- | --- |
| **Level** | Instance (ENI) | Subnet |
| **Stateful** | Yes | No |
| **Rule types** | Allow only | Allow and Deny |
| **Evaluation** | All rules together | Numbered order |
| **Default Inbound** | Deny all | Allow all |

**Security Best Practices**

- Use Security Groups to control access to individual resources or groups of resources.
- Use NACLs as a broader safety net at the subnet level.
- In line with the Principle of Least Privilege, understand the traffic your VPC or subnet will have and open only the appropriate ports.
- Use layered security by implementing tighter constraints with Security Groups and use NACLs as additional guardrails.

**Practical Exercise**

Security Groups and NACLs can be explored in the web interface with ease.

1. From the left side, select Security groups and you can drill down into the details by selecting one Security Group.

![Details about the security groups](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772604796007.png)

1. Similarly, you can see the defined NACLs.

![Showing details about the Network Access Control Lists](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1772605299333.png)

1. From CLI, you can run the following command to list a VPC's Security Groups.

**Note:** Either replace the `$LAB_VPC` placeholder or use the command from the previous task to save the VPC ID.

```bash
$ aws ec2 describe-security-groups \
            --filters "Name=vpc-id,Values=$LAB_VPC" \
            --query "SecurityGroups[*].{ID:GroupId,Name:GroupName,Description:Description}" \
            --output table

------------------------------------------------------------------------------
|                          DescribeSecurityGroups                            |
+-------------------------------------+------------------------+-------------+
|           Description               |          ID            |    Name     |
+-------------------------------------+------------------------+-------------+
|  default VPC security group         |  sg-033f66042b736b1d4  |  default    |
|  Allow access to the lab web server |  sg-08d6604eefc9dd6d9  |  lab-web-sg |
+-------------------------------------+------------------------+-------------+
```

1. NACLs can be shown in a similar manner.

```bash
$ aws ec2 describe-network-acls \
            --filters "Name=vpc-id,Values=$LAB_VPC" \
            --query "NetworkAcls[*].{ID:NetworkAclId,Default:IsDefault,Entries:Entries[*].{Rule:RuleNumber,Action:RuleAction,CIDR:CidrBlock,Protocol:Protocol}}" \
            --output json

[
    {
        "ID": "acl-0977594a5268e386d",
        "Default": false,
        "Entries": [
            {
                "Rule": 100,
                "Action": "allow",
                "CIDR": "0.0.0.0/0",
                "Protocol": "-1"
            },
            {
                "Rule": 32767,
                "Action": "deny",
                "CIDR": "0.0.0.0/0",
                "Protocol": "-1"
            },
            {
                "Rule": 100,
                "Action": "allow",
                "CIDR": "0.0.0.0/0",
                "Protocol": "6"
[...]
```

**Answer the questions below**

> What type of network access control is stateful?
> 

Security Group

> What inbound ports are opened by the lab-web-sg Security Group (listed in ascending order)?
> 

22,80,443

### Task 5 - AWS Network Flow

Now that you have a good understanding of the different components, let us put everything together and follow the journey of a network request. Below is a common network topology.

![AWS Network Flow Diagram](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1770978108517.png)

Let us follow a packet that arrives from the Internet and tries to reach the web server (green trace):

1. The request arrives at the Internet Gateway (IGW).
2. The IGW forwards it to the VPC router.
3. The VPC router checks the route table associated with the target subnet.
4. The request is then forwarded to the target subnet Network Access Control List (NACL), where inbound rules are evaluated.
5. Then the request reaches the Security Group (SG) of the web server instance.
6. If the SG allows it, the request reaches the Elastic Network Interface (ENI) of the instance.
7. The response from the instance travels back to the SG (stateful), but the NACL evaluates the outbound rules (stateless).

See if you can figure out the flow when the web server reaches the backend application server (blue trace).

**Security Best Practices**

- Understanding how traffic flows within a VPC is essential in implementing tight security controls.
- Network is essential for reducing the blast radius and improving containment in the event of a security incident.
    
    segmentation
    
- Keep in mind that Security Groups do not filter the following services: Amazon DNS, Amazon DHCP, Amazon EC2 instance metadata, Amazon ECS metadata, License activation for Windows instances, or Amazon NTP service.
- Avoid using catch-all IP ranges, like `0.0.0.0/0`.
- Avoid opening port ranges unless you really need them. Use port-specific entries for tighter security.

**Practical Exercise**

Let us better understand how everything fits together. Open the `View Site`, and you will have two exercises:

- In the first exercise, you will have to place the elements in their correct place and order.
- In the second exercise, you will have to configure each element in accordance with the principle of least privilege so that the web server is accessible from the Internet and the private instance is managed only from the public subnet.

Moving back to the AWS environment, the lab deployment includes a small web server. Can you find it?

**Note:** Either replace the `$LAB_VPC` placeholder or use the command from the previous task to save the VPC ID.

1. Identify the EC2 instance.

```bash
$ aws ec2 describe-instances \
            --filters "Name=vpc-id,Values=$LAB_VPC" "Name=instance-state-name,Values=running" \
            --query "Reservations[*].Instances[*].{ID:InstanceId,PublicIP:PublicIpAddress,PrivateIP:PrivateIpAddress,Name:Tags[?Key=='Name']|[0].Value}" \
            --output table

----------------------------------------------------------------------------
|                             DescribeInstances                            |
+----------------------+-----------------+---------------+-----------------+
|          ID          |      Name       |   PrivateIP   |    PublicIP     |
+----------------------+-----------------+---------------+-----------------+
|  i-03443b8bad51619d5 |  lab-web-server |  172.16.1.223 |  54.227.90.236  |
+----------------------+-----------------+---------------+-----------------+
```

1. From the command output, you can note the public IP associated with the instance and use curl to extract the flag.

**Note:** The public IP will vary by lab deployment, and the web page is served over HTTP.

```bash
$ curl -s <http://54.227.90.236>
<html>
<body>
<h1>Cloud Networking Lab</h1>
<p>Flag: [REDACTED]</p>
</body>
</html>
```

**Answer the questions below**

> What is the mini-game flag?
> 

THM{AWS_NETWORKING_101}

> What is the web server flag?
> 

THM{TANGLED_WEBS}SSssssssS

### Task 6 - Conclusion

Well done! You now have a good understanding of the networking building blocks in AWS and how to view them from a security perspective.

**Key Takeaways**

- VPCs are isolated networks in the cloud.
- Good network segmentation limits blast radius.
- Public subnets access the internet through IGW routes; private subnets use NAT gateways for outbound-only access.
- Security Groups are stateful and operate at the instance level, while NACLs are stateless and are attached to subnets.
- Typical network flow in a VPC : IGW -> route table -> NACL -> SG -> instance.
