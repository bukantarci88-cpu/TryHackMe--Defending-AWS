# ☁️ AWS Security

A hands-on cybersecurity portfolio focused on **Amazon Web Services (AWS) security**, covering Identity and Access Management (IAM), cloud networking, compute security, storage protection, and native AWS security tools.

This repository documents practical cloud security exercises, common misconfigurations, attack scenarios, and remediation techniques to develop skills in identifying and securing vulnerable AWS environments.

## 🎯 Learning Objectives

- 🔐 **Identity & Access Management:** Identify excessive permissions, exposed credentials, and insecure IAM roles.
- 🌐 **Network Security:** Assess security groups, network ACLs, subnet exposure, and perimeter controls.
- 🖥️ **Compute Security:** Recognize exposed services, unpatched instances, metadata risks, and container misconfigurations.
- 🗄️ **Storage & Data Protection:** Secure S3 buckets, enforce encryption, review access controls, and protect snapshots.
- 🛡️ **AWS Security Tooling:** Understand AWS-native security services for monitoring, detection, and protection.
- ⚖️ **Cloud Security Fundamentals:** Apply the AWS Shared Responsibility Model and foundational cloud security principles.

## 📚 Learning Path

### 1. ☁️ Welcome to AWS

Build a strong foundation in AWS architecture, core services, cloud networking, identity, storage, and security tooling.

- `1-Welcome-to-AWS`
  - `1-1-First-Steps-Into-AWS`
  - `1-2-Shared-Responsibility-Model`
  - `1-3-Introduction-to-IAM`
  - `1-4-Introduction-to-Cloud-Networking`
  - `1-5-Introduction-to-Cloud-Computing`
  - `1-6-Introduction-to-Cloud-Storage`
  - `1-7-Introduction-to-AWS-Security-Tools`

**Key Focus:** AWS fundamentals, cloud architecture, IAM basics, networking, storage, and native security tools.

### 2. 🔐 Identity and Access Management

Identity is a critical security boundary in the cloud. Explore how excessive permissions, exposed credentials, and poorly configured roles can compromise AWS environments.

- `2-Identity-and-Access-Management`
  - `2-1-The-Over-Privileged-User`
  - `2-2-The-Forgotten-Access-Key`
  - `2-3-The-Overpowered-Role`
  - `2-4-The-Silence-of-the-IAMs`

**Key Focus:** IAM policies, least privilege, credential security, role trust relationships, privilege escalation risks, and access monitoring.

### 3. 🌐 Network and Perimeter Defense

Identify network misconfigurations that expose AWS resources to unauthorized access and external threats.

- `3-Network-and-Perimeter-Defense`
  - `3-1-The-Wide-Open-Security-Group`
  - `3-2-The-Not-So-Private-Subnet`
  - `3-3-The-Forgotten-NACL`
  - `3-4-The-Invisible-Network`

**Key Focus:** VPCs, subnet routing, security groups, network ACLs, network exposure, traffic filtering, and visibility.

### 4. 🖥️ Securing Compute

Understand common security weaknesses affecting EC2 instances, instance metadata, and containerized workloads.

- `4-Securing-Compute`
  - `4-1-The-Exposed-Port`
  - `4-2-The-Unpatched-Instance`
  - `4-3-The-Leaky-Metadata`
  - `4-4-The-Oversharing-Container`

**Key Focus:** EC2 hardening, exposed services, patch management, instance metadata protection, and container security.

### 5. 🗄️ Storage and Data Security

Protect sensitive information by identifying insecure storage configurations, missing encryption, and excessive data access.

- `5-Storage-and-Data-Security`
  - `5-1-The-Leaky-Bucket`
  - `5-2-The-Plain-Bucket`
  - `5-3-The-Blind-Bucket`
  - `5-4-The-Shared-Snapshot`

**Key Focus:** Amazon S3 permissions, encryption at rest, bucket policies, logging, monitoring, and snapshot access controls.

## 🛠️ Key Technologies and Security Concepts

- **Cloud Platform:** Amazon Web Services (AWS)
- **Identity & Access:** IAM users, groups, roles, policies, least privilege
- **Networking:** VPC, subnets, routing, security groups, network ACLs
- **Compute:** EC2, instance metadata, patch management, container security
- **Storage:** Amazon S3, encryption, bucket policies, snapshots
- **Security & Monitoring:** AWS CloudTrail, AWS Config, Amazon GuardDuty, AWS Security Hub
- **Security Principles:** Shared Responsibility Model, defense in depth, attack surface reduction, secure configuration

## 🧪 Practical Skills

- 🔎 Identify common AWS security misconfigurations and excessive permissions.
- 🔑 Assess IAM policies, role trust relationships, and credential exposure.
- 🌐 Evaluate network exposure and access-control weaknesses.
- 🛡️ Recognize cloud workload vulnerabilities and apply appropriate mitigations.
- 🔒 Assess data access, encryption, and storage-sharing configurations.
- 📊 Understand cloud logging, monitoring, and threat detection capabilities.
- ✅ Recommend security improvements aligned with least privilege and defense in depth.

## 📈 Portfolio Goals

This repository demonstrates a practical approach to **AWS cloud security, misconfiguration assessment, and defensive security engineering**. It supports the development of skills relevant to Cloud Security Analyst, Cloud Security Engineer, SOC Analyst, and Security Engineer roles.

## ⚠️ Disclaimer

All security exercises should be conducted only in authorized environments, dedicated training labs, or AWS accounts for which you have explicit permission. Do not test third-party infrastructure without authorization.

## 👨‍💻 Author

**Burak Kantarci**

Cybersecurity professional focused on security operations, threat detection, and cloud security.

**GitHub:** `bukantarci88-cpu`
