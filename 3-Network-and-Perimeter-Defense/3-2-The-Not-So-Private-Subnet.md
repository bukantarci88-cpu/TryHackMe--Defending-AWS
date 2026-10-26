# AWS Security 3.2. The Not So Private Subnet

### Task 1 - Introduction

A team deploys a new backend API server. They place it in a subnet named `backend-private` and assume it is isolated from the internet. Months later, a security scan reveals the instance has a public IP and a direct route to the Internet Gateway. The name on the subnet said "private." The route table said otherwise.

In AWS, a subnet is not private because of its name or tag. It is private because its route table has no route to an Internet Gateway. This is one of the most commonly misunderstood networking concepts in AWS, and it has played a role in multiple real-world breaches.

### Task 2 - Real-World Incident

Tesla is a globally recognized technology company running AWS as a core part of its cloud infrastructure. By 2018, Tesla operated Kubernetes clusters on AWS to support internal engineering workloads handling sensitive operations, such as vehicle telemetry, engineering test data, and mapping information stored in Amazon S3 buckets. Like many organizations, Tesla ran internal management dashboards intended only for engineering teams, not for public access.

**What Happened**

![Attack chain for exposed management that led to credentials discovery and cryptojacking deployments.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1781260522153.png)

1. **Exposed management console** - Tesla's Kubernetes administrative dashboard was reachable from the public internet with no authentication.
2. **Credential discovery** - Inside the unprotected dashboard, attackers found a Kubernetes pod containing AWS access credentials, providing access to Tesla's broader AWS environment, including S3.
3. **Cryptojacking deployment** - The attackers deployed cryptocurrency mining software within Tesla's Kubernetes pods using Tesla's own cloud compute. They concealed the activity behind CloudFlare and kept CPU usage deliberately low to avoid resource utilization alerts.
4. **Data exposure** - The same AWS credentials gave access to an S3 bucket containing sensitive vehicle telemetry and engineering test data.
5. **Discovery** - The breach was not detected internally. RedLock security researchers discovered it during routine scanning of the public internet for exposed cloud resources.

**Core Failures**

- **Internal resources exposed to the internet** - The Kubernetes dashboard was a management interface that should have been accessible only from internal networks. A properly isolated private subnet with no IGW route would have made it undiscoverable by external scanners.
- **No authentication on the management console** - Even if network-accessible, the dashboard required no password, token, or certificate. Network isolation is the first line of defense; authentication is the second.
- **Credentials stored in accessible pods** - AWS access keys were available inside Kubernetes pods exposed by the unprotected dashboard. With no network barrier, those credentials were one step away.
- **No monitoring for anomalous activity** - The cryptomining ran undetected because Tesla had no alerting on unusual CPU patterns, unexpected outbound connections, or anomalous S3 access.

**Answer the questions below**

> What internal management tool was exposed to the public internet in the Tesla breach?
> 

Kubernetes dashboard

> What is the network principle that was not applied and was a core failure that enabled the breach?
> 

Network segmentation

### Task 3 - Identification

In this task, you will take on the role of a security analyst reviewing the network configuration of an AWS environment. The architecture is supposed to have a public-facing web server in one subnet and an internal API server in a separate, private subnet. Your job is to verify whether that segmentation is actually in place.

The first step is to save the required IDs in environment variables.

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ VPC_ID=$(aws ec2 describe-vpcs \
  --filters "Name=tag:Name,Values=room32-vpc" \
  --query "Vpcs[0].VpcId" --output text)

$ BACKEND_SUBNET=$(aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Name,Values=room32-backend-private" \
  --query "Subnets[0].SubnetId" --output text)

$ echo "VPC: $VPC_ID | Backend Subnet: $BACKEND_SUBNET"

VPC: vpc-0e79cd7760c0a7bed | Backend Subnet: subnet-03ebe773651ec0e85
```

List the subnets in the VPC and check their settings.

```bash
$ aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --query "Subnets[*].{Name:Tags[?Key=='Name']|[0].Value,CIDR:CidrBlock,PublicIP:MapPublicIpOnLaunch,SubnetId:SubnetId}" \
  --output table

-----------------------------------------------------------------------------------
|                                 DescribeSubnets                                 |
+-------------+--------------------------+-----------+----------------------------+
|    CIDR     |          Name            | PublicIP  |         SubnetId           |
+-------------+--------------------------+-----------+----------------------------+
|  10.0.1.0/24|  room32-web-public       |  True     |  subnet-0ec3ba186583b70f8  |
|  10.0.2.0/24|  room32-backend-private  |  True     |  subnet-03ebe773651ec0e85  |
+-------------+--------------------------+-----------+----------------------------+
```

**FINDING:** Both subnets have `MapPublicIpOnLaunch` (here renamed as `PublicIP`) set to `True`. A truly private subnet should never auto-assign public IP addresses to instances launched in it.

Check the route table associated with the backend subnet and look for an Internet Gateway route.

```bash
$ aws ec2 describe-route-tables \
  --filters "Name=association.subnet-id,Values=$BACKEND_SUBNET" \
  --query "RouteTables[].{Name:Tags[?Key=='Name']|[0].Value,Routes:Routes[].{Dest:DestinationCidrBlock,Target:GatewayId}}" \
  --output json

[
    {
        "Name": "[REDACTED]",
        "Routes": [
            {
                "Dest": "10.0.0.0/16",
                "Target": "local"
            },
            {
                "Dest": "0.0.0.0/0",
                "Target": "igw-03f67867770827c60"
            }
        ]
    }
]
```

**FINDING:** The backend subnet is associated with a shared route table that contains a `0.0.0.0/0 → igw-03f67867770827c60` route. This is the misconfiguration: both subnets share the same route table, giving the "private" subnet a direct route to the Internet Gateway.

Confirm the internal API instance has a public IP address.

```bash
$ aws ec2 describe-instances \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=instance-state-name,Values=running" \
  --query "Reservations[].Instances[].{Name:Tags[?Key=='Name']|[0].Value,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress,SubnetId:SubnetId}" \
  --output table

------------------------------------------------------------------------------------
|                                 DescribeInstances                                |
+----------------------+------------+-----------------+----------------------------+
|         Name         | PrivateIP  |    PublicIP     |         SubnetId           |
+----------------------+------------+-----------------+----------------------------+
|  room32-internal-api |  10.0.2.10 |  44.197.132.201 |  subnet-03ebe773651ec0e85  |
|  room32-web-server   |  10.0.1.17 |  100.53.40.190  |  subnet-0ec3ba186583b70f8  |
+----------------------+------------+-----------------+----------------------------+
```

**FINDING:** The `room32-internal-api` instance has a public IP. A backend API server should have no public IP address.

Confirm the exposure by attempting to reach the internal API from the internet.

```bash
$ INTERNAL_API_IP=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=room32-internal-api" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].PublicIpAddress" --output text)

$ curl -s --connect-timeout 5 http://$INTERNAL_API_IP:8080

{
  "service": "internal-api",
  "endpoints": [
    "/health",
    "/data"
  ],
  "flag": "[REDACTED]",
  "subnet": "room32-backend-private (10.0.2.0/24)",
  "warning": "This API is meant for internal VPC traffic only."
}
```

**FINDING:** The internal API responded from the internet. This confirms that the instance is directly internet-reachable - a critical misconfiguration.

**Findings Summary**

Here is what you found:

- The backend subnet `room32-backend-private` is associated with the same route table as the public subnet. That route table has a `0.0.0.0/0 → igw-xxx` route, making both subnets functionally public.
- `MapPublicIpOnLaunch` is enabled on the backend subnet, so any instance launched in it automatically receives a public IP.
- The `room32-internal-api` instance has a public IP and responds to HTTP requests from the internet.

The root cause is simple: a dedicated private route table was never created. Both subnets inherited the same shared route table with an Internet Gateway route, and the "private" label was never enforced in the routing configuration.

**Answer the questions below**

> What is the name of the route table associated with the backend subnet?
> 

room32-shared-rt

> What destination CIDR in the route table points to the Internet Gateway?
> 

0.0.0.0/0

> What is the flag revealed by probing the public IP of the backend instance?
> 

THM{UNFORESEEN_CONSEQUENCES}



### Task 4 - Remediation

Now that you have identified the problem, here is the structured approach to fixing it:

1. Create a dedicated private route table with no Internet Gateway route.
2. Associate the new route table with the backend subnet.
3. Disable public IP auto-assignment on the backend subnet.
4. Verify the internal API is no longer internet-reachable.
5. Verify internal VPC connectivity is preserved.

**Create a Private Route Table**

Create a new route table with only the local VPC route, no Internet Gateway.

```bash
$ PRIVATE_RT=$(aws ec2 create-route-table \
  --vpc-id $VPC_ID \
  --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=room32-private-rt}]" \
  --query "RouteTable.RouteTableId" --output text)

$ echo "Private route table: $PRIVATE_RT"

Private route table: rtb-032015616a834019b
```

Verify the new route table has only the local route.

```bash
$ aws ec2 describe-route-tables \
  --route-table-ids $PRIVATE_RT \
  --query "RouteTables[0].Routes[*].{Dest:DestinationCidrBlock,Target:GatewayId}" \
  --output table

---------------------------
|   DescribeRouteTables   |
+--------------+----------+
|     Dest     | Target   |
+--------------+----------+
|  10.0.0.0/16 |  local   |
+--------------+----------+
```

The new route table has only the VPC-local route. No Internet Gateway. This is the correct configuration for a private subnet.

**Associate the Private Route Table**

Replace the existing route table association on the backend subnet.

```bash
$ ASSOC_ID=$(aws ec2 describe-route-tables \
  --filters "Name=association.subnet-id,Values=$BACKEND_SUBNET" \
  --query "RouteTables[0].Associations[?SubnetId=='$BACKEND_SUBNET'].RouteTableAssociationId" \
  --output text)

$ aws ec2 replace-route-table-association \
  --association-id $ASSOC_ID \
  --route-table-id $PRIVATE_RT

{
    "NewAssociationId": "rtbassoc-0b49e871b5d716ada",
    "AssociationState": {
        "State": "associated"
    }
}
```

Verify the backend subnet is now associated with the private route table.

```bash
$ aws ec2 describe-route-tables \
  --filters "Name=association.subnet-id,Values=$BACKEND_SUBNET" \
  --query "RouteTables[].{Name:Tags[?Key=='Name']|[0].Value,Routes:Routes[].{Dest:DestinationCidrBlock,Target:GatewayId}}" \
  --output json

[
    {
        "Name": "room32-private-rt",
        "Routes": [
            {
                "Dest": "10.0.0.0/16",
                "Target": "local"
            }
        ]
    }
]
```

**Disable Public IP Auto-Assignment**

Modify the private subnet settings to disable public IP auto-assignment.

```bash
$ aws ec2 modify-subnet-attribute \
  --subnet-id $BACKEND_SUBNET \
  --no-map-public-ip-on-launch

$ aws ec2 describe-subnets \
  --subnet-ids $BACKEND_SUBNET \
  --query "Subnets[0].{Name:Tags[?Key=='Name']|[0].Value,MapPublicIpOnLaunch:MapPublicIpOnLaunch}" \
  --output table

---------------------------------------------------
|                 DescribeSubnets                 |
+----------------------+--------------------------+
|  MapPublicIpOnLaunch |          Name            |
+----------------------+--------------------------+
|  False               |  room32-backend-private  |
+----------------------+--------------------------+
```

**Note:** Disabling `MapPublicIpOnLaunch` only affects future launches. The existing instance retains its current public IP. However, with the IGW route removed from the route table, Internet traffic can no longer reach it - the routing path no longer exists.

**Verify**

Test that the internal API is no longer reachable from the internet.

```bash
$ curl -s --connect-timeout 5 http://$INTERNAL_API_IP:8080
```

The command will have no output or display a connection timeout. Either way, the instance is no longer reachable on the internet.

Now verify that internal VPC connectivity is preserved. Connect to the web server via SSM and reach the API via its private IP.

```bash
$ WEB_INSTANCE=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=room32-web-server" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].InstanceId" --output text)

$ aws ssm start-session --target $WEB_INSTANCE

Starting session with SessionId: 093229127661-clzrzvv7bpxp7gyknxtevssnha

sh-5.2$ curl -s http://10.0.2.10:8080

{
  "service": "internal-api",
  "endpoints": [
    "/health",
    "/data"
  ],
  "flag": "[REDACTED]",
  "subnet": "room32-backend-private (10.0.2.0/24)",
  "warning": "This API is meant for internal VPC traffic only."
}
```

Internal traffic still works. The local route remains in both route tables. Type `exit` to leave the SSM session.

Make sure you exit the SSM session or open another CloudShell tab and run the verifier to confirm the remediation and retrieve the flag.

```bash
$ aws lambda invoke \
  --function-name AWS302-VerifyRemediation \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "status": "PASS",
    "map_public_ip_check": "PASS - MapPublicIpOnLaunch is disabled",
    "route_table_check": "PASS - room32-backend-private has no route to an Internet Gateway",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> What is the aws ec2 subcommand that replaces a route table association on a subnet?
> 

replace-route-table-association

> What is the flag from the remediation verifier?
> 

THM{BLACK_MESA_SECURED}

### Task 5 - Build It Securely

Let us see how to build this correctly from the start. Before creating any networking resource, answer these questions:

1. **What resources need internet access?** Only internet-facing resources (load balancers, NAT Gateways, bastion hosts) belong in public subnets.
2. **What resources should be internal only?** Application servers, databases, internal APIs, and management interfaces should be in private subnets with no internet connectivity.
3. **What outbound access do private resources need?** If they need to reach external services, route through a NAT Gateway - not an Internet Gateway.
4. **How many Availability Zones do you need?** For production, create paired subnets in at least two AZs.

**Create the VPC**

Create a VPC and ensure that DNS hostname and resolution are enabled in the new VPC.

```bash
$ SECURE_VPC=$(aws ec2 create-vpc \
  --cidr-block 10.1.0.0/16 \
  --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=room32-secure-vpc}]" \
  --query "Vpc.VpcId" --output text)

$ aws ec2 modify-vpc-attribute --vpc-id $SECURE_VPC --enable-dns-support "{\"Value\":true}"

$ aws ec2 modify-vpc-attribute --vpc-id $SECURE_VPC --enable-dns-hostnames "{\"Value\":true}"

$ echo "Secure VPC: $SECURE_VPC"

Secure VPC: vpc-03a10c178377a6052
```

**Create and Attach the Internet Gateway**

Create an Internet Gateway resource and attach it to the newly created VPC. This will ensure public subnets can reach the Internet.

```bash
$ SECURE_IGW=$(aws ec2 create-internet-gateway \
  --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=room32-secure-igw}]" \
  --query "InternetGateway.InternetGatewayId" --output text)

$ aws ec2 attach-internet-gateway \
  --internet-gateway-id $SECURE_IGW \
  --vpc-id $SECURE_VPC

$ echo "IGW: $SECURE_IGW"

IGW: igw-05629b79d4453a843
```

**Create the Public Subnet and Route Table**

The public subnet will hold resources that should reach and be reachable from the internet.

```bash
$ AZ=$(aws ec2 describe-availability-zones \
  --query "AvailabilityZones[0].ZoneName" --output text)

$ SECURE_PUBLIC=$(aws ec2 create-subnet \
  --vpc-id $SECURE_VPC \
  --cidr-block 10.1.1.0/24 \
  --availability-zone $AZ \
  --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=room32-secure-public}]" \
  --query "Subnet.SubnetId" --output text)

$ aws ec2 modify-subnet-attribute \
  --subnet-id $SECURE_PUBLIC \
  --map-public-ip-on-launch

$ echo "Public subnet: $SECURE_PUBLIC"

Public subnet: subnet-037acdd12aef1ecec
```

**Note:** `MapPublicIpOnLaunch` is intentionally enabled here - and only here. Internet-facing resources in the public subnet need public IP addresses.

```bash
$ SECURE_PUBLIC_RT=$(aws ec2 create-route-table \
  --vpc-id $SECURE_VPC \
  --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=room32-secure-public-rt}]" \
  --query "RouteTable.RouteTableId" --output text)

$ aws ec2 create-route \
  --route-table-id $SECURE_PUBLIC_RT \
  --destination-cidr-block 0.0.0.0/0 \
  --gateway-id $SECURE_IGW

{
    "Return": true
}$ aws ec2 associate-route-table \
  --route-table-id $SECURE_PUBLIC_RT \
  --subnet-id $SECURE_PUBLIC

{
    "AssociationId": "rtbassoc-09edfb07d7ae99f14",
    "AssociationState": {
        "State": "associated"
    }
}$ echo "Public RT: $SECURE_PUBLIC_RT"

Public RT: rtb-0b8f7dc08a7268cc2
```

**Create the Private Subnet and Route Table**

Resources in this subnet will be private and accessible only to other internal resources.

```bash
$ SECURE_PRIVATE=$(aws ec2 create-subnet \
  --vpc-id $SECURE_VPC \
  --cidr-block 10.1.2.0/24 \
  --availability-zone $AZ \
  --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=room32-secure-private}]" \
  --query "Subnet.SubnetId" --output text)

$ aws ec2 modify-subnet-attribute \
  --subnet-id $SECURE_PRIVATE \
  --no-map-public-ip-on-launch

$ echo "Private subnet: $SECURE_PRIVATE"

Private subnet: subnet-01b6168f660737510
```

Now, create the private route table and associate it with the private subnet.

```bash
$ SECURE_PRIVATE_RT=$(aws ec2 create-route-table \
  --vpc-id $SECURE_VPC \
  --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=room32-secure-private-rt}]" \
  --query "RouteTable.RouteTableId" --output text)

$ aws ec2 associate-route-table \
  --route-table-id $SECURE_PRIVATE_RT \
  --subnet-id $SECURE_PRIVATE

{
    "AssociationId": "rtbassoc-030282c4cdebbcade",
    "AssociationState": {
        "State": "associated"
    }
}$ echo "Private RT: $SECURE_PRIVATE_RT"

Private RT: rtb-074a1b970afe2bd84
```

**Note:** No `0.0.0.0/0` route is added to this route table. The only route is the automatic local route - VPC-internal traffic only. This is the key difference between public and private route tables.

**Verify**

Compare both route tables to confirm the correct configuration.

```bash
$ echo "=== Public RT ===" && \
  aws ec2 describe-route-tables \
  --route-table-ids $SECURE_PUBLIC_RT \
  --query "RouteTables[0].Routes[*].{Dest:DestinationCidrBlock,Target:GatewayId}" \
  --output table

=== Public RT ===
------------------------------------------
|           DescribeRouteTables          |
+--------------+-------------------------+
|     Dest     |         Target          |
+--------------+-------------------------+
|  10.1.0.0/16 |  local                  |
|  0.0.0.0/0   |  igw-05629b79d4453a843  |
+--------------+-------------------------+$ echo "=== Private RT ===" && \
  aws ec2 describe-route-tables \
  --route-table-ids $SECURE_PRIVATE_RT \
  --query "RouteTables[0].Routes[*].{Dest:DestinationCidrBlock,Target:GatewayId}" \
  --output table

=== Private RT ===
---------------------------
|   DescribeRouteTables   |
+--------------+----------+
|     Dest     | Target   |
+--------------+----------+
|  10.1.0.0/16 |  local   |
+--------------+----------+
```

Run the verifier to retrieve the flag.

```bash
$ aws lambda invoke \
  --function-name AWS302-VerifySecureBuild \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "status": "PASS",
    "map_public_ip_check": "PASS - MapPublicIpOnLaunch is disabled",
    "route_table_check": "PASS - room32-secure-private has no route to an Internet Gateway",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> How many route tables should a properly segmented VPC with one public and one private tier have at a minimum?
> 

2

> What subnet attribute that automatically allocates public IPs should always be disabled on private subnets?
> 

MapPublicIpOnLaunch

> What is the flag from the secure build verifier?
> 

THM{RIGHT_PLACE_RIGHT_ROUTE}

### Task 6 - Conclusion

You traced a subnet misconfiguration from its root cause through to remediation and rebuilt the correct design from scratch.

**Key Takeaways**

- Subnet names do not determine exposure; route tables do. If the route table has a route to an Internet Gateway, the subnet is public.
- Never share a route table between public and private subnets. Each tier needs its own, with only the routes it requires.
- Disable `MapPublicIpOnLaunch` on every private subnet to prevent accidental public IP assignment on future instances.
- Do not rely on security groups as your only network defense. Security groups are host-level controls; route tables are network-level controls. Both layers matter.
- Use a NAT Gateway for outbound-only Internet access from private subnets. Never route backend resources through an Internet Gateway.
- Audit route table associations regularly. A single shared route table can silently expose an entire backend tier.
