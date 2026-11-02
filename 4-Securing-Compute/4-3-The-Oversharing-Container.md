# AWS Security 4.3. The Oversharing Container

### Task 1 - Introduction

Containers do not automatically enforce least privilege. If an ECS task has no dedicated `taskRoleArn`, the workload can fall back to the EC2 instance's credentials. Those credentials belong to the platform, and they can carry far more permissions than any container should inherit.

The clean ECS identity model has three distinct roles:

- The container instance role for the EC2 host.
- The task execution role for ECS infrastructure actions.
- The task role for the application workload itself.

### Task 2 - Real-World Incident

TeamTNT is a threat group known for targeting cloud and container environments, primarily for cryptocurrency mining and credential theft. In February 2021, Palo Alto Unit 42 documented a TeamTNT campaign they named Hildegard. This was the group's first known attack specifically targeting Kubernetes clusters at scale.

Hildegard targeted environments where Kubernetes API servers or kubelets were exposed without authentication. In many of these clusters, Kubernetes pods ran on EC2 worker nodes without IAM Roles for Service Accounts (IRSA) configured - the Kubernetes equivalent of ECS's `taskRoleArn`. Without dedicated pod-level identities, every pod on a node quietly inherited the IAM role assigned to the EC2 host, which carried the broad permissions needed to manage cluster infrastructure rather than the narrow permissions any individual workload should have.

**What Happened**

![The attack path TeamTNT followed, from discovery of insecure Kubernetes clusters to IMDS metadata and credentials retrieval, credentials harvesting and malicious actions.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1782374552443.png)

1. **Initial access**: TeamTNT scanned for exposed Kubernetes API servers and kubelets reachable without authentication, finding clusters where the management plane had no access controls in place.
2. **Container deployment**: Once inside the cluster, the attackers used the cluster's own scheduling infrastructure to deploy malicious containers across available nodes.
3. **Credential harvesting**: From within a deployed container, the attackers queried `169.254.169.254`, the EC2 instance metadata endpoint, to retrieve the IAM credentials for the EC2 node's instance role. Every pod on that node shared the same credentials.
4. **AWS enumeration**: Using the harvested credentials from outside the cluster, TeamTNT enumerated S3 buckets, IAM policies, and other AWS services accessible to the overprivileged instance role.
5. **Cryptomining and persistence**: Hildegard deployed the xmrig cryptominer within compromised containers and installed a reverse shell for re-entry. The malware disguised itself as a known Linux process to evade detection.
6. **Lateral movement**: Stolen cloud credentials were used to access AWS APIs and reach account resources beyond the original cluster, following the same path any identity with that role's permissions could take.

**Core Failures**

- **No workload identity isolation**: Kubernetes pods inherited the EC2 node's IAM role - the same architectural failure as an ECS task without `taskRoleArn`. Application containers had access to platform credentials they should not have had.
- **Exposed management plane**: The Kubernetes API server or kubelet was reachable without authentication, providing the initial foothold that made everything else possible.
- **Overprivileged node role**: The EC2 instance role carried far more permissions than any individual pod application required, maximizing the blast radius of any container compromise.
- **No runtime detection**: Unusual metadata queries, outbound mining connections, and new process execution inside containers went undetected until discovered by external researchers.

**Answer the questions below**

> What ECS task definition field, when absent, causes a container to fall back to the EC2 instance role?
> 

taskRoleArn

### Task 3 - Identification

In this task, you will take on the role of a security analyst and inspect a running ECS service.

Start by setting up the environment so you can reuse the variable values.

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ CLUSTER_NAME=room44-ecs-cluster

$ SERVICE_NAME=room44-app-svc

$ aws ecs describe-services \
    --cluster "$CLUSTER_NAME" \
    --services "$SERVICE_NAME" \
    --query "services[0].{Service:serviceName,TaskDefinition:taskDefinition,Desired:desiredCount,Running:runningCount}" \
    --output table

-------------------------------------------------------------------------------------------------------------
|                                             DescribeServices                                              |
+---------+----------+-----------------+--------------------------------------------------------------------+
| Desired | Running  |     Service     |                          TaskDefinition                            |
+---------+----------+-----------------+--------------------------------------------------------------------+
|  0      |  0       |  room44-app-svc |  arn:aws:ecs:us-east-1:664418977660:task-definition/room44-app:1   |
+---------+----------+-----------------+--------------------------------------------------------------------+
```

Make sure you also grab the task ARN.

```bash
$ TASK_DEF_ARN=$(aws ecs describe-services \
  --cluster "$CLUSTER_NAME" \
  --services "$SERVICE_NAME" \
  --query "services[0].taskDefinition" \
  --output text)
$ echo $TASK_DEF_ARN

arn:aws:ecs:us-east-1:664418977660:task-definition/room44-app:1
```

**FINDING:** The revision number `:1` shows this is the original, unmodified definition.

**Inspect the Task:** Check whether the task definition has a `taskRoleArn` assigned.

```bash
$ aws ecs describe-task-definition \
    --task-definition "$TASK_DEF_ARN" \
    --query "taskDefinition.{Family:family,TaskRole:taskRoleArn,ExecutionRole:executionRoleArn,NetworkMode:networkMode}" \
    --output json

{
    "Family": "room44-app",
    "TaskRole": null,
    "ExecutionRole": "arn:aws:iam::664418977660:role/room44-lab-execution-role",
    "NetworkMode": "bridge"
}
```

**FINDING:** `taskRoleArn` value, here renamed as `TaskRole` in the output, is `null`. Any container running from this definition can fall back to the EC2 instance role of the host.

**Container Definition Variables:** The flag is stored as an environment variable in the container definition.

```bash
$ aws ecs describe-task-definition \
    --task-definition "$TASK_DEF_ARN" \
    --query "taskDefinition.containerDefinitions[0].environment[?name=='FLAG'].value" \
    --output text

[REDACTED]
```

**FINDING:** Sensitive information stored in container definition environment variables is visible to anyone with the `ecs:DescribeTaskDefinition` permission.

**Findings Summary**

Here are the clues you found:

- The task definition is the original, unmodified version.
- The lab ECS service runs with a task definition that has `taskRoleArn` set to `null`. Any container running from this definition can fall back to the EC2 instance role.
- The execution role exists for ECS infrastructure actions, but no application-level identity has been defined.
- Sensitive information is stored in the container definition environmental variables.

**Answer the questions below**

> If the task definition field is `null`, whose role will the container inherit?
> 

host

> What is the sensitive information value (flag) you retrieved from the container definition?
> 

THM{BORROWED_IDENTITY}

### Task 4 - Remediation

To fix the misconfiguration, you will create a scoped application role, register a corrected task definition revision, and update the service to use it.

Make sure you have the required information set up in the environment variables.

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ CLUSTER_NAME=room44-ecs-cluster

$ SERVICE_NAME=room44-app-svc

$ TASK_DEF_ARN=$(aws ecs describe-services \
  --cluster "$CLUSTER_NAME" \
  --services "$SERVICE_NAME" \
  --query "services[0].taskDefinition" \
  --output text)
```

**Create Scoped Application Role:** The role will need a trust policy and a set of minimal container actions, so go ahead and create the two policy files.

```bash
$ cat > /tmp/room44-task-role-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "ecs-tasks.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

$ cat > /tmp/room44-task-role-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": "*"
    }
  ]
}
EOF
```

Once done, create the role.

```bash
$ aws iam create-role \
  --role-name room44-app-task-role \
  --assume-role-policy-document file:///tmp/room44-task-role-trust.json \
  --permissions-boundary arn:aws:iam::$ACCOUNT_ID:policy/Room44-LearnerBoundary

{
    "Role": {
        "Path": "/",
        "RoleName": "room44-app-task-role",
        "RoleId": "AROAZVMTVA56GS6KEYYIT",
        "Arn": "arn:aws:iam::664418977660:role/room44-app-task-role",
[...]
```

Then, attach the scoped policy.

```bash
$ aws iam put-role-policy \
  --role-name room44-app-task-role \
  --policy-name room44-app-inline-policy \
  --policy-document file:///tmp/room44-task-role-policy.json
```

Now, save the role ARN so you can use it later.

```bash
$ TASK_ROLE_ARN=$(aws iam get-role \
  --role-name room44-app-task-role \
  --query 'Role.Arn' \
  --output text)

$ echo $TASK_ROLE_ARN

arn:aws:iam::664418977660:role/room44-app-task-role
```

**Register a New Revision:** Export the current task definition, add the `taskRoleArn`, and register a new and improved version. You should see in the output that the version of the task definition is now `:2`.

**Note:** One command uses `jq` to strip the unnecessary fields from the full task definition output and attach the `taskRoleArn`. `CloudShell` has `jq` installed by default, but if you run the commands from the AttackBox or locally, make sure it is installed.

```bash
$ aws ecs describe-task-definition \
  --task-definition "$TASK_DEF_ARN" \
  --query taskDefinition > /tmp/room44-taskdef.json

$ jq --arg taskRole "$TASK_ROLE_ARN" \
  'del(.taskDefinitionArn,.revision,.status,.requiresAttributes,.compatibilities,.registeredAt,.registeredBy)
  | .taskRoleArn = $taskRole' \
  /tmp/room44-taskdef.json > /tmp/room44-taskdef-updated.json

$ NEW_TASK_DEF_ARN=$(aws ecs register-task-definition \
  --cli-input-json file:///tmp/room44-taskdef-updated.json \
  --query 'taskDefinition.taskDefinitionArn' \
  --output text)

$ echo $NEW_TASK_DEF_ARN

arn:aws:ecs:us-east-1:664418977660:task-definition/room44-app:2
```

**Update the Service:** Now you can register a new and secure task definition revision for the ECS service.

```bash
$ aws ecs update-service \
    --cluster "$CLUSTER_NAME" \
    --service "$SERVICE_NAME" \
    --task-definition "$NEW_TASK_DEF_ARN"

{
    "service": {
        "serviceArn": "arn:aws:ecs:us-east-1:664418977660:service/room44-ecs-cluster/room44-app-svc",
        "serviceName": "room44-app-svc",
        "clusterArn": "arn:aws:ecs:us-east-1:√:cluster/room44-ecs-cluster",
        "loadBalancers": [],
[...]
```

Finally, you can run the verifier function to retrieve the flag.

```bash
$ aws lambda invoke \
    --function-name AWS404-VerifyRemediation \
    --payload '{}' \
    /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "status": "PASS",
    "task_role_check": "PASS - service task definition now has a dedicated taskRoleArn",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> What flag is returned after updating the service to use a task definition with a dedicated task role?
> 

THM{CAUGHT_UP_WITH_FRANK}

### Task 5 - Build It Securely

Patching a running task definition is one step. The stronger approach is to get the identity split right when you register a new task definition: an execution role for the ECS infrastructure, a task role for the application workload, scoped to what the application actually does.

Before writing any IAM resource, understand these four points:

1. What AWS service will assume this role? For both execution and task roles, you can use the `ecs-tasks.amazonaws.com` role.
2. What API actions does the application workload actually need? Is it read-only S3, or something more specific?
3. What specific resources does it access? Is it a named bucket, a path prefix, or account-wide?
4. Are there conditions that should limit access further? Is it source VPC, specific task ARN, or time windows?

For this lab setup, you will have a separate execution role (ECS-managed policy for image pull and log delivery) and a scoped task role (read-only S3), both with the lab permission boundary applied.

Start by grabbing the required environment details.

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
$ echo $ACCOUNT_ID

629510262133
```

**Create Secure Execution Role:** This role will handle only ECS infrastructure actions, such as image pulls and log delivery. It should not introduce application permissions.

```bash
$ aws iam create-role \
    --role-name room44-secure-execution-role \
    --assume-role-policy-document file:///tmp/room44-task-role-trust.json \
    --permissions-boundary arn:aws:iam::$ACCOUNT_ID:policy/Room44-LearnerBoundary

{
    "Role": {
        "Path": "/",
        "RoleName": "room44-secure-execution-role",
        "RoleId": "AROAZFEN4JV23CRTYLIGN",
        "Arn": "arn:aws:iam::629510262133:role/room44-secure-execution-role",
        "CreateDate": "2026-05-11T07:29:19+00:00",
[...]$ aws iam attach-role-policy \
    --role-name room44-secure-execution-role \
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
```

**Create Secure Task Role:** This task role belongs to the application workload and must be scoped to the minimum actions and resources required by the container.

```bash
$ aws iam create-role \
  --role-name room44-secure-task-role \
  --assume-role-policy-document file:///tmp/room44-task-role-trust.json \
  --permissions-boundary arn:aws:iam::$ACCOUNT_ID:policy/Room44-LearnerBoundary

{
    "Role": {
        "Path": "/",
        "RoleName": "room44-secure-task-role",
        "RoleId": "AROAZFEN4JV2TLQWGU6OU",
        "Arn": "arn:aws:iam::629510262133:role/room44-secure-task-role",
        "CreateDate": "2026-05-11T07:31:02+00:00",
[...]$ aws iam put-role-policy \
  --role-name room44-secure-task-role \
  --policy-name room44-secure-task-inline \
  --policy-document file:///tmp/room44-task-role-policy.json
```

**Register Secure Task Definition:** Register a new task definition family with both roles explicitly set so there is no confusion about which identity the workload runs under.

Grab the ARNs for the roles so you can use them in the subsequent commands.

```bash
$ EXEC_ROLE_ARN=$(aws iam get-role \
    --role-name room44-secure-execution-role \
    --query 'Role.Arn' --output text)

$ SECURE_TASK_ROLE_ARN=$(aws iam get-role \
    --role-name room44-secure-task-role \
    --query 'Role.Arn' --output text)
$ echo "Execution Role ARN: $EXEC_ROLE_ARN"

Execution Role ARN: arn:aws:iam::629510262133:role/room44-secure-execution-role$ echo "Task Role ARN: $SECURE_TASK_ROLE_ARN"

Task Role ARN: arn:aws:iam::629510262133:role/room44-secure-task-role
```

Now it is time to create the secure task definition and register it.

```bash
$ cat > /tmp/room44-secure-taskdef.json <<EOF
{
  "family": "room44-secure-app",
  "networkMode": "bridge",
  "requiresCompatibilities": ["EC2"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "$EXEC_ROLE_ARN",
  "taskRoleArn": "$SECURE_TASK_ROLE_ARN",
  "containerDefinitions": [
    {
      "name": "room44-app",
      "image": "public.ecr.aws/docker/library/busybox:latest",
      "essential": true,
      "command": ["sh", "-c", "sleep 3600"]
    }
  ]
}
EOF

$ aws ecs register-task-definition --cli-input-json file:///tmp/room44-secure-taskdef.json

{
    "taskDefinition": {
        "taskDefinitionArn": "arn:aws:ecs:us-east-1:629510262133:task-definition/room44-secure-app:1",
        "containerDefinitions": [
            {
                "name": "room44-app",
                "image": "public.ecr.aws/docker/library/busybox:latest",
[...]
```

**Verify:** Run the verification function to validate the setup and retrieve the flag.

```bash
$ aws lambda invoke \
    --function-name AWS404-VerifySecureBuild \
    --payload '{}' \
    /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "status": "PASS",
    "secure_definition_check": "PASS - room44-secure-app has separate executionRoleArn and taskRoleArn",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> What flag is returned after registering the secure task definition with separate execution and task roles?
> 

THM{CLEAN_AND_LEGIT}

### Task 6 - Conclusion

In this room, you found the container running under borrowed credentials, assigned it a legitimate identity, and built a task definition with every role clearly defined.

**Key Takeaways**

- Never omit `taskRoleArn` on ECS tasks that interact with AWS APIs. Without it, the workload silently inherits the EC2 instance role and its full permissions.
- Keep execution roles and task roles separate; they solve different problems and should never be collapsed into a single identity.
- Scope task roles to the specific API actions and resources the container application actually calls, not to broad managed policies.
- Audit all ECS task definitions for missing `taskRoleArn`; the absence of a field is easy to miss in a review and has significant blast-radius consequences.
- Apply permission boundaries to task roles as a defense-in-depth control, capping what the role can do even if the policy is later broadened.
