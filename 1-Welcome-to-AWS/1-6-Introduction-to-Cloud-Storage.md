# AWS Security 1.6. Introduction to Cloud Storage

### Task 1 - Introduction

Every application generates, processes, or stores data. In AWS, how you store that data affects its availability, durability, cost, and most importantly, security.

In this room, you will explore the most common storage services found in AWS and understand how to use them securely.

**Learning Objectives**

- Understand main AWS storage types and when to use them
- Work with S3 buckets
- Understand EBS volumes and snapshots
- Explore EFS as a shared file system

### Task 2 - Storage Models

Before diving into individual services, it is a good idea to understand the three storage models AWS uses. Each model addresses a different use case, and most of the real-world architectures combine all three.

- **Object Storage** - Every piece of data is a self-contained object, a file, and the associated metadata, stored in a flat structure called a bucket. This is ideal for files written once and read many times (WORM).
- **Block Storage** - This is like your traditional hard drive. It can be formatted, attached to an EC2 instance, is persistent across stop/start cycles, and can be detached and reattached to other EC2 Instances in the same Availability Zone. EBS is a good choice for frequently changing data that needs low-latency access.
- **File Storage** - This type of model provides a shared file system accessible by multiple instances simultaneously over a network. EFS is an AWS fully managed service that scales automatically. It is designed for when multiple EC2 instances require concurrent read/write access to the same files.

**Models Comparison**

| **Feature** | **S3 (Object)** | **EBS (Block)** | **EFS (File)** |
| --- | --- | --- | --- |
| **Access** | HTTP API (CLI/SDK/Console) | Attached to one EC2 | NFS mount |
| **Structure** | Flat | File System (ext4, xfs) | File System (NFS v4) |
| **Persistence** | Independent of Compute | Persist across stop/start cycles | Independent of Compute |
| **AZ Scope** | Regional (cross-AZ) | Single AZ | Regional (cross-AZ) |
| **Use Cases** | Backups, Logs, Static Sites | OS Drives, Databases, Application Data | Shared Files, CMS, ML Data |
| **Security** | Bucket Policies, ACLs, Block Public Access | Encryption, Snapshot Permissions | Encryption, SG, Mount Targets |

**Security Best Practices**

- An exposed S3 bucket is one of the most common misconfigurations, so make sure to restrict or block public access.
- Data at rest should always be encrypted, so make sure you encrypt your volumes and snapshots.
- Apply the Principle of Least Privilege and secure access to EFS by restricting Security Group permissions, mount targets, and NFS mount point permissions.

**Practical Exercise**

Choosing the appropriate storage model can be stressful, but you can start by practicing with this mini-game.

Open the `View Site`, and you will have one simple task: "Put each storage Use Case in the right basket".

Once completed, your efforts will be rewarded with a flag.

**Answer the questions below**

> From a security point of view, how is data at rest usually protected?
> 

Encryption

> What is the flag from the mini-game?
> 

THM{ONE_BITE_AT_A_TIME}

### Task 3 - Simple Storage Service

Ever heard of the term "leaky bucket"? In this task, you will better understand the term and how to prevent this common security misconfiguration.

Even if AWS strongly fights to keep your buckets private and public access is blocked by default, there are cases where people, willingly or not, make them public.

**Core Concepts**

AWS S3 uses buckets, which are containers for storing objects. Here are a couple of key ideas:

- Bucket names are globally unique, are created, and live in a specific AWS Region. Amazon also introduced [Account Regional namespaces](https://aws.amazon.com/blogs/aws/introducing-account-regional-namespaces-for-amazon-s3-general-purpose-buckets/), but this is outside the scope of this room.
- Objects stored in buckets stay in that Region unless you explicitly replicate them (cross-region replication).
- Objects are any files stored in S3 (images, log files, backups), and they can be up to 5 TB in size.
- Buckets have an inherent flat structure; the "folder" illusion is given by the key prefix (e.g., logs/2026/january/access.log).

**Access Controls**

S3 access is controlled through a few mechanisms. The most common ones you will see:

- **Bucket Policies** - JSON policies attached to buckets that define who can access what.
- **Block Public Access** - Account-level and bucket-level setting that overwrites any policy or ACL that would make the bucket public.
- **Access Control Lists (ACLs)** - Legacy mechanism for granting access.

**Security Best Practices**

- Always enable Block Public Access (either at the account or bucket level).
- Use bucket policies over ACLs.
- Enable default encryption ( SSE-S3 or SSE-KMS ).
- Enable versioning for critical data to protect against accidental deletion or "bad" updates.
- Scope IAM permissions to specific buckets and key prefixes; avoid granting `s3:*` on .

**Practical Exercise**

Let us explore the lab environment. A bucket has been provisioned in the lab environment with some objects to be discovered.

**Info:** To start the AWS environment, click the `Cloud Details` button at the top of the room, then click `Generate Environment`. When the environment is ready, use the Credentials tab to navigate to the AWS Console and log in.

**Accessing S3 Objects**

1. Navigate to the S3 service.

![Navigate to the S3 service](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771925800412.png)

1. Identify the lab bucket and look at the details.

![Identify the lab bucket and look at the details.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771925800752.png)

**Note:** To become more comfortable with the CLI, commands will be used more frequently in place of UI steps.

1. Open `CloudShell` (or configure and use AWS CLI in the Attack Box) and list all buckets in the account.

```bash
           $ aws s3 ls

2026-02-23 08:56:04 storage-lab-957207444373
```

1. Note down the bucket name, replace it in the command, and list the contents of the lab bucket.

```bash
           $ aws s3 ls s3://storage-lab-957207444373

                           PRE data/
                           PRE logs/
```

1. List the objects inside `logs/`.

```bash
           $ aws s3 ls s3://storage-lab-957207444373/logs/

2026-02-23 08:56:35         25 access-log.txt
```

1. Look at the content of `access-log`.

```bash
           $ aws s3 cp s3://storage-lab-957207444373/logs/access-log.txt -

[REDACTED]
```

**Note:** You can replace the `-` with `.` at the end of the command to download the file.

**Create/Update S3 Objects**

1. Create and upload a file to `data/`.

```bash
           $ echo "No leaky bucket on my watch." > ./my-file.txt

$ aws s3 cp ./my-file.txt s3://storage-lab-957207444373/data/

upload: ./my-file.txt to s3://storage-lab-957207444373/data/my-file.txt
```

1. Verify that the upload was successful.

```bash
           $ aws s3 ls s3://storage-lab-957207444373/data/

2026-02-24 09:44:23         29 my-file.txt
2026-02-23 08:56:35         43 readme.txt
```

1. Lastly, let us do some security work. Check the Public Access of the bucket

```bash
           $ aws s3api get-public-access-block --bucket storage-lab-957207444373

{
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }
}
```

We can see the bucket is not publicly exposed, which is good. Excellent work.

**Answer the questions below**

> What access control method should you use in favor of ACLs?
> 

bucket policy

> What is the flag found in access-log.txt?
> 

THM{NO_PUBLIC_S3}

### Task 4 - Elastic Block Store

Elastic Block Store (EBS) provides persistent storage for EC2 instances. Let us have a closer look.

**Core Concepts**

**Volumes**

An EBS volume is a durable block storage device you attach to an EC2. Once attached, you treat it just like a local disk (format, mount).

A few points that you need to take into account when dealing with EBS:

- **AZ-locked** - A volume exists in a single Availability Zone and can only be attached to instances in that same AZ.
- **Persistent** - Data survives instance stop/start. By contrast, EC2 ephemeral storage (also known as instance store) data is lost when an instance is stopped, hibernated, or terminated.
- **Types** - Here are a couple of EBS types you can choose from: gp3 (general-purpose SSD), io2 (high IOPS SSD), st1 (throughput HDD), sc1 (cold HDD).

**Snapshots**

A snapshot is a point-in-time backup of an EBS volume. They are stored in S3 (AWS-managed) and have the following characteristics:

- **Incremental** - only changed blocks since the last snapshot are stored.
- **Regional** - From a snapshot, you can restore an EBS in any AZ within the same Region.
- **Shareable** - Snapshots can be shared with other AWS accounts or made public (!).

**Security Best Practices**

- Always encrypt EBS volumes by enabling default encryption at the account level.
- Do not share snapshots publicly unless they contain no sensitive data.
- Regularly review snapshots' permissions.
- Tag volumes and snapshots for ownership and lifecycle management.
- Delete unused volumes and snapshots to reduce cost and attack surface.

**Practical Exercise**

The lab environment has an EC2 instance with an additional EBS volume attached.

1. Navigate to the EC2 service and identify the lab instance.

![Navigate to the EC2 service and identify the lab instance.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771927016144.png)

1. Navigate to the Volumes dashboard and identify the volume's details.

![Identify EC2 volume details.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771927965244.png)

1. Using `CloudShell` (or configure AWS CLI on the Attack Box), list all volumes in the account.

```bash
           $ aws ec2 describe-volumes --query "Volumes[*].{ID:VolumeId,Size:Size,Type:VolumeType,State:State,AZ:AvailabilityZone,Encrypted:Encrypted}" --output table

--------------------------------------------------------------------------------
|                                DescribeVolumes                               |
+------------+------------+-------------------------+-------+---------+--------+
|     AZ     | Encrypted  |           ID            | Size  |  State  | Type   |
+------------+------------+-------------------------+-------+---------+--------+
|  us-east-1a|  True      |  vol-0a8a487375a26191a  |  5    |  in-use |  gp3   |
|  us-east-1a|  False     |  vol-07f3244f72e77a381  |  8    |  in-use |  gp3   |
+------------+------------+-------------------------+-------+---------+--------+
```

1. Look at a specific volume. You will have to replace the volume ID with the appropriate one.

**Note:** Usually, the encrypted volume is the EBS we will be looking at.

```bash
           $ aws ec2 describe-volumes --volume-ids vol-0a8a487375a26191a --query "Volumes[0].Attachments[0].{InstanceId:InstanceId,Device:Device,State:State}" --output table

--------------------------------------------------
|                 DescribeVolumes                |
+------------+-----------------------+-----------+
|   Device   |      InstanceId       |   State   |
+------------+-----------------------+-----------+
|  /dev/xvdf |  i-0be7427c7e76bf743  |  attached |
+------------+-----------------------+-----------+
```

1. Check if the account contains any snapshots.

```bash
           $ aws ec2 describe-snapshots --owner-ids self --query "Snapshots[*].{ID:SnapshotId,VolumeId:VolumeId,Size:VolumeSize,State:State,Encrypted:Encrypted}" --output table

---------------------------------------------------------------------------------------
|                                  DescribeSnapshots                                  |
+-----------+--------------------------+-------+------------+-------------------------+
| Encrypted |           ID             | Size  |   State    |        VolumeId         |
+-----------+--------------------------+-------+------------+-------------------------+
|  True     |  snap-05ab036f4ff386d11  |  5    |  completed |  vol-0a8a487375a26191a  |
+-----------+--------------------------+-------+------------+-------------------------+
```

1. Connect to the EC2 instance and identify the mounted Volume.

**Note:** You will connect from either `CloudShell` or AWS CLI using SSM and replace the instance ID in the command. You can skip this step if you connected via the Console.

```bash
           $ aws ssm start-session --target [REPLACE_WITH_INSTANCEID]

Starting session with SessionId: 957207444373-jf2sobjzy5x94gvfsoo7suffbi

sh-5.2$ lsblk

NAME      MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
xvda      202:0    0    8G  0 disk
├─xvda1   202:1    0    8G  0 part /
├─xvda127 259:0    0    1M  0 part
└─xvda128 259:1    0   10M  0 part /boot/efi
xvdf      202:80   0    5G  0 disk /mnt/data
zram0     253:0    0  458M  0 disk [SWAP]
```

1. Look for the `flag.txt` on the mounted volume.

```bash
           sh-5.2$ ls /mnt/data

flag.txt

sh-5.2$ cat /mnt/data/flag.txt

[REDACTED]
```

Great job. You have successfully navigated through this task.

**Answer the questions below**

> What is one of the limitations of EBS?
> 

az-locked

> What is the flag found on the mounted Volume?
> 

THM{EBS_SPEAKS_VOLUMES}

### Task 5 - Elastic File System

What is EFS? It is a storage type that fills the gap between S3 and EBS, providing a shared file system accessible by multiple EC2 instances simultaneously.

**Core Concepts**

**File System**

EFS is a fully managed Network File System (NFS) resource that you create, mount, and have read/write access to files as if they were local. It automatically scales with usage, with no provisioning required.

**Mount Target**

To access an EFS from an EC2 instance, you create a mount target in the AZ where the instance is located.

A mount target is an Elastic Network Interface (ENI) placed in a subnet with a Security Group attached.

**Storage Classes**

EFS supports storage classes for cost optimization:

- **Standard** - frequently accessed files.
- **Infrequent Access (IA)** - lower cost for infrequently accessed files.
- **Archive** - lowest cost for rarely accessed data.

**Security Best Practices**

- Enable encryption at rest when you create the file system, since it cannot be enabled afterward.
- Use Security Groups on mount targets to restrict which instances can connect.
- Implement IAM authorization for NFS clients.
- Use access points, application-specific entry points, to enforce user identity and root directory for applications.
- Monitor access with CloudWatch and VPC Flow Logs on mount target ENIs.

**Practical Lab**

In this hands-on exercise, you will explore a preconfigured EFS file system.

1. Navigate to the EFS service.

![Navigate to the EFS service.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771929521643.png)

1. Identify the lab file system and review its details.

![Identify the lab EFS](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1771929521745.png)

1. Using `CloudShell` (or configure AWS CLI on the Attack Box), list the EFS file systems.

**Note:** Make sure you `exit` the SSM session if still connected. In `CloudShell`, you can open another tab by clicking the plus sign next to the current session's tab.

```bash
           $ aws efs describe-file-systems --query "FileSystems[*].{ID:FileSystemId,Name:Name,Size:SizeInBytes.Value,Encrypted:Encrypted,State:LifeCycleState}" --output table

-------------------------------------------------------------------------------
|                             DescribeFileSystems                             |
+-----------+------------------------+------------------+-------+-------------+
| Encrypted |          ID            |      Name        | Size  |    State    |
+-----------+------------------------+------------------+-------+-------------+
|  True     |  fs-0717ac46064cb24dd  |  storage-lab-efs |  6144 |  available  |
+-----------+------------------------+------------------+-------+-------------+
```

1. Identify the mount targets.

**Note:** Replace the file system ID with the one identified above.

```bash
           $ aws efs describe-mount-targets --file-system-id fs-0717ac46064cb24dd --query "MountTargets[*].{ID:MountTargetId,SubnetId:SubnetId,AZ:AvailabilityZoneName,IP:IpAddress}" --output table

------------------------------------------------------------------------------------
|                               DescribeMountTargets                               |
+------------+--------------------------+-------------+----------------------------+
|     AZ     |           ID             |     IP      |         SubnetId           |
+------------+--------------------------+-------------+----------------------------+
|  us-east-1a|  fsmt-0c7b4cc8843561b7c  |  10.0.1.109 |  subnet-0ffdba8f5bbd864a0  |
+------------+--------------------------+-------------+----------------------------+
```

1. Now, connect to the EC2 instance (or use the session from the previous task) and explore the mounted EFS, under `/mnt/shared`. The first command will show that the EFS is mounted.

```bash
           sh-5.2$ df -h

[...]/dev/nvme1n1      5.0G   68M  4.9G   2% /mnt/data
/dev/nvme0n1p128   10M  1.3M  8.7M  13% /boot/efi
127.0.0.1:/       8.0E     0  8.0E   0% /mnt/shared

sh-5.2$ ls /mnt/shared

flag.txt

sh-5.2$ cat /mnt/shared/flag.txt

[REDACTED]
```

Job done.

**Answer the questions below**

> What security control can you apply to a mount point to ensure only the intended resources can access the storage?
> 

Security Group

> What is the flag found on the EFS mount?
> 

THM{SHARING_IS_CARING}

```jsx
~ $ aws ec2 describe-instances --query "Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,Name:Tags[?Key=='Name']|[0].Value}" --output table
```

### Task 6 - Conclusion

Excellent. You have explored three fundamental storage services in AWS and saw what security considerations they introduce.

**Key Takeaways**

- S3 is an object storage accessed through API; bucket policies, Block Public Access, and encryption are your primary security controls.
- EBS is a single-instance block storage that you can protect through encryption and snapshot permissions.
- EFS is a multi-instance shared file system that can be controlled through Security Groups and encryption at rest to protect your data.
- And lastly, a "leaky bucket" is a misconfigured S3 bucket that publicly exposes sensitive data.
