# AWS Security 4.2. The Unpatched Instance

### Task 1 - Introduction

An engineer launches an EC2 instance from a two-year-old AMI. It runs fine, serves its purpose, and nobody thinks about it again. No maintenance window is configured. No patching schedule is in place.

In AWS, patching problems are rarely due to tooling issues. Systems Manager Patch Manager, Run Command, and the ability to create golden AMIs exist precisely so patching can be repeatable, auditable, and baked into every deployment. The catch is that someone has to build the process, and in many environments, nobody does.

### Task 2 - Real-World Incident

The UK's National Health Service (NHS) operated one of the largest IT estates in the world in 2017 - tens of thousands of systems spread across hospitals, GP practices, and specialist trusts, many running older versions of Windows that still supported SMBv1, a legacy file-sharing protocol. In March 2017, Microsoft published [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010), a critical patch for a remote code execution vulnerability in SMBv1. The advisory was public, the patch was free, and the fix was widely documented.

**What Happened**

![Attack chain of the attack from the EternalBlue exploit to millions of infected hosts.](https://cdn-images.tryhackme.com/user-uploads/68baea2454c82afe90fd7020/room-content/68baea2454c82afe90fd7020-1782374474271.png)

1. **Exploit development**: A cyberweapon known as EternalBlue, originally developed by the NSA and later leaked by the Shadow Brokers group, targeted the unpatched MS17-010 vulnerability. WannaCry incorporated it as its primary propagation engine.
2. **Automated scanning**: On 12 May 2017, WannaCry began sweeping the internet and internal networks for systems with TCP/445 open and SMBv1 enabled. No user interaction was required - every unpatched system was a valid target.
3. **Initial infection**: Vulnerable systems were exploited remotely over the network. WannaCry installed itself, encrypted the victim's files, and displayed a ransom demand for payment in Bitcoin.
4. **Lateral movement**: The worm spread autonomously across internal networks, reaching any reachable host that had not applied MS17-010.
5. **NHS impact**: Approximately 80 of 236 NHS England trusts were affected. An estimated 19,000 appointments were canceled. Several trusts declared critical incidents and diverted ambulances. Staff reverted to pen and paper for patient records.
6. **Global scale**: WannaCry infected over 200,000 systems across 150 countries within hours. A security researcher discovered a kill-switch domain hardcoded into the malware and registered it, slowing its spread.

**Core Failures**

- **No repeatable patch process**: MS17-010 had been available for two months before the attack. There was no mechanism in place to ensure critical patches were applied on a defined schedule.
- **Legacy protocol not disabled**: SMBv1 remained enabled across the infrastructure despite Microsoft recommending its removal years earlier.
- **No network segmentation**: Flat internal networks allowed WannaCry to move laterally without restriction, amplifying the impact far beyond any initial entry point.
- **Unmanaged host inventory**: Many systems had no active management or monitoring, leaving their patch state unknown until the attack revealed it.

**Answer the questions below**

> What protocol was the core of the attack?
> 

SMB

> What was the name of the exploit used by WannaCry to propagate across unpatched systems?
> 

EternalBlue

### Task 3 - Identification

In this task, you will take on the role of a security analyst and inspect a running EC2 instance to determine its current patch state and quantify the patch debt it is carrying.

Start by setting the account ID and lab instance ID as environment variables.

```bash
$ ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

$ INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Purpose,Values=room-42-lab" "Name=instance-state-name,Values=running" \
    --query "Reservations[0].Instances[0].InstanceId" \
    --output text)

$ echo "Account ID: $ACCOUNT_ID | Instance ID: $INSTANCE_ID"

Account ID: 907591395362 | Instance ID: i-08610dc72b44621f0
```

**Check the Instance:** Before Patch Manager can target an instance, it must be registered as a managed node and have the SSM agent online.

The following command checks whether the instance is managed by Systems Manager.

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

**FINDING:** The instance is registered with Systems Manager, and its agent is currently online.

**Check the Patching State:** Before the patch state can be queried, Patch Manager must run a scan against the instance to build its record. Run the following command to initiate the scan.

```bash
$ SCAN_COMMAND_ID=$(aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name AWS-RunPatchBaseline \
    --parameters Operation=Scan \
    --comment "Room 4.2 identification scan" \
    --query "Command.CommandId" \
    --output text)

$ echo $SCAN_COMMAND_ID
c79484aa-3e7a-48ee-9014-5e21b16d2689
```

It might take some time, usually under 1 minute, for the scan to finish. Poll until the status is `Success`.

```bash
$ aws ssm get-command-invocation \
    --command-id "$SCAN_COMMAND_ID" \
    --instance-id "$INSTANCE_ID" \
    --query "{Status:Status,StatusDetails:StatusDetails}" \
    --output table

------------------------------
|    GetCommandInvocation    |
+----------+-----------------+
|  Status  |  StatusDetails  |
+----------+-----------------+
|  Success |  Success        |
+----------+-----------------+
```

Run the following command to see how many patches are missing, installed, and failed on this instance.

```bash
$ aws ssm describe-instance-patch-states \
  --instance-ids "$INSTANCE_ID" \
  --query "InstancePatchStates[0].{Missing:MissingCount,Installed:InstalledCount,Failed:FailedCount,OperationEnd:OperationEndTime}" \
  --output table

----------------------------------------------------------------
|                DescribeInstancePatchStates                   |
+----------+-----------+----------+----------------------------+
|  Failed  | Installed | Missing  |       OperationEnd         |
+----------+-----------+----------+----------------------------+
|  0       |  142      |  17      |  2026-01-10T04:12:00.000Z  |
+----------+-----------+----------+----------------------------+
```

**FINDING:** The output may vary, but it should show a number of missing patches.

**Note:** The lab uses the latest Amazon AMI. AWS keeps a tight ship when patching AMIs, so there is a slight chance that the image is fully patched and the `Missing` field is `0`.

**Retrieve the Flag:** An EC2 tag hides the flag. Run the following command to retrieve it.

```bash
$ aws ec2 describe-tags \
    --filters "Name=resource-id,Values=$INSTANCE_ID" \
    --query "Tags[?Key=='Flag'].Value" \
    --output text

[REDACTED]
```

**Answer the questions below**

> Which Systems Manager API call shows the current missing patch count for a managed instance?
> 

describe-instance-patch-states

The AWS Systems Manager API call **`describe-instance-patch-states`** is designed to retrieve the high-level patch compliance and summary state for managed instances (such as installed, missing, failed, and pending reboot counts).

> What is the flag for this task?
> 

 THM{BACKDOOR_IDENTIFIED}

### Task 4 - Remediation

You will use Systems Manager Run Command to trigger a patch install operation and verify that the instance reaches a compliant state.

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** `AWS-RunPatchBaseline` is a managed document used by AWS Systems Manager (SSM) to automate patching managed nodes (EC2 instances or on-premises servers).

In this task, you will:

- Run `AWS-RunPatchBaseline` in Install mode against the lab instance.
- Poll the command status until the operation completes.
- Re-check the patch state to confirm the missing count has dropped.

**Run the Patch Baseline Install:** You will need the instance ID, so make sure it is in the appropriate environment variable. The command used to trigger the installation will return a command ID that you will poll later, so it's better to save that as well.

```bash
$ INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Purpose,Values=room-42-lab" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].InstanceId" \
  --output text)

$ PATCH_COMMAND_ID=$(aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name AWS-RunPatchBaseline \
    --parameters Operation=Install \
    --comment "Room 4.2 remediation patch install" \
    --query "Command.CommandId" \
    --output text)

$ echo $PATCH_COMMAND_ID

b5bac689-77a5-4aa4-9283-eb81e2302cc1
```

**Wait and Confirm:** It will take 2-5 minutes for the patching command to run through, so you might need to poll the status multiple times until it shows `Success`.

```bash
$ aws ssm get-command-invocation \
  --command-id "$PATCH_COMMAND_ID" \
  --instance-id "$INSTANCE_ID" \
  --query "{Status:Status,StatusDetails:StatusDetails}" \
  --output table

------------------------------
|    GetCommandInvocation    |
+----------+-----------------+
|  Status  |  StatusDetails  |
+----------+-----------------+
|  Success |  Success        |
+----------+-----------------+
```

**Recheck Instance:** Once the command succeeds, rerun the patch state check to confirm the missing count has dropped. Ideally, it will drop to `0`.

```bash
$ aws ssm describe-instance-patch-states \
    --instance-ids "$INSTANCE_ID" \
    --query "InstancePatchStates[0].{Missing:MissingCount,Installed:InstalledCount,Failed:FailedCount,OperationEnd:OperationEndTime}" \
    --output table

-----------------------------------------------------------------
|                  DescribeInstancePatchStates                  |
+--------+------------+----------+------------------------------+
| Failed | Installed  | Missing  |        OperationEnd          |
+--------+------------+----------+------------------------------+
|  0     |  159       |  0       |  2026-05-06T14:21:00+00:00   |
+--------+------------+----------+------------------------------+
```

Congratulations, you patched the instance! You'll now be able to get your flag for a job well done. The status might take some time to propagate, usually under a minute, so rerun the verification function if it fails on the first pass.

```bash
$ aws lambda invoke \
  --function-name AWS402-VerifyRemediation \
  --payload '{}' \
  /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "status": "PASS",
    "patch_command_check": "PASS - successful AWS-RunPatchBaseline install found for the lab instance",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> What flag is returned after running the verifier function?
> 

THM{NO_MORE_GAMES}

### Task 5 - Build It Securely

Fixing a running instance brings it up to date, but the next instance launched from the same stale AMI starts unpatched.

A secure patching approach requires two things:

- A defined patch baseline that codifies what gets applied and when.
- A golden AMI that bakes a patched state into every future launch.

Before building the patching infrastructure, answer these four questions:

1. Which operating system does the fleet run, and does the baseline need to cover multiple distributions?
2. Which patch classifications and severities are required (e.g., Security only, Bugfix)?
3. How quickly should approved patches be applied after release (e.g., immediately, maintenance window, stabilization window)?
4. Will new instances be launched from a golden AMI, or is in-place patching the only protection?

For this lab, the answers are:

- Amazon Linux 2023.
- Critical/Important/Medium severities for Security and Bugfix patches.
- Immediate approval (ApproveAfterDays=0).
- Golden AMI required.

**Create the Baseline:** A custom patch baseline turns a manual process into a repeatable policy. You will have to define the OS, classifications, severities, and approval timing once; the baseline will apply consistently on every subsequent operation.

```bash
$ PATCH_BASELINE_ID=$(aws ssm create-patch-baseline \
    --name room42-linux-baseline \
    --operating-system AMAZON_LINUX_2023 \
    --approval-rules 'PatchRules=[{PatchFilterGroup={PatchFilters=[{Key=CLASSIFICATION,Values=[Security,Bugfix]},{Key=SEVERITY,Values=[Critical,Important,Medium]}]},ApproveAfterDays=0,ComplianceLevel=CRITICAL}]' \
    --query BaselineId \
    --output text)
$ echo $PATCH_BASELINE_ID

pb-05ed206d2cbb57802
```

**Create Golden Image:** You will use the previously patched instance as a baseline and capture it as a golden AMI. Future deployments launched from this image will start patched at the current level.

```bash
$ aws ec2 create-image \
    --instance-id "$INSTANCE_ID" \
    --name patched-baseline-ami \
    --no-reboot \
    --tag-specifications 'ResourceType=image,Tags=[{Key=Name,Value=patched-baseline-ami},{Key=Purpose,Value=room-42-secure-build}]'

{
    "ImageId": "ami-03676adf504cd0c08"
}
```

[](https://cdn-images.tryhackme.com/room-icons/68d2c1e7ab94268f6271de1d-1771765213861)

**Note:** AMI creation will run in the background and might take several minutes to reach `available` state.

You can check the AMI status by running the following command, but the AMI does not need to be `available` to finish the task.

```bash
$ aws ec2 describe-images \
    --owners self \
    --filters "Name=name,Values=patched-baseline-ami" \
    --query "Images[0].{State:State,ImageId:ImageId}" \
    --output table

--------------------------------------
|           DescribeImages           |
+------------------------+-----------+
|         ImageId        |   State   |
+------------------------+-----------+
|  ami-03676adf504cd0c08 | available |
+------------------------+-----------+
```

**Verify:** Run the verification function to validate the setup and retrieve the flag.

```bash
$ aws lambda invoke \
    --function-name AWS402-VerifySecureBuild \
    --payload '{}' \
    /tmp/out.json && python3 -m json.tool /tmp/out.json

[...]
{
    "patch_baseline_check": "PASS - custom patch baseline room42-linux-baseline found",
    "ami_check": "PASS - AMI patched-baseline-ami found",
    "status": "PASS",
    "flag": "[REDACTED]"
}
```

**Answer the questions below**

> What flag is returned after creating a custom patch baseline and a patched AMI?
> 

THM{CLEAN_LAUNCH_SEQUENCE}

### Task 6 - Conclusion

In this room, you identified an unpatched instance, applied the available fixes, and built a repeatable baseline so future instances start with a patched baseline.

- Never treat patching as a one-off task; build a repeatable process with a defined schedule and verification step.
- Use `AWS-RunPatchBaseline` with Run Command for auditable, on-demand patch operations against Systems Manager-managed instances.
- Always verify patch completion with `get-command-invocation`; submitting a command is not the same as confirming it succeeded.
- Define custom patch baselines to codify which patches are required and how quickly they apply, removing patching from the realm of tribal knowledge.
- Bake patched AMIs as launch baselines so every new instance starts current rather than inheriting debt from a stale image.
