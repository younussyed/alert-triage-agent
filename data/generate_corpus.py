"""Generate a labeled synthetic GuardDuty corpus for triage evaluation.

All values are fabricated. IPs come from RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and RFC 1918 private space,
so nothing here routes to a real host. Account ID is a placeholder.

Labels encode ground truth: what a competent analyst would conclude with
full context. `difficulty` marks cases designed to be genuinely ambiguous.
"""

import json
from pathlib import Path

ACCOUNT = "111111111111"
REGION = "us-east-1"


def finding(
    fid, ftype, title, description, severity, created_at,
    resource, service, region=REGION,
):
    return {
        "Id": fid,
        "Type": ftype,
        "Title": title,
        "Description": description,
        "Severity": severity,
        "CreatedAt": created_at,
        "Region": region,
        "AccountId": ACCOUNT,
        "Resource": resource,
        "Service": service,
    }


def access_key(username, principal_id):
    return {
        "ResourceType": "AccessKey",
        "AccessKeyDetails": {"UserName": username, "PrincipalId": principal_id},
    }


def instance(iid):
    return {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": iid}}


def bucket(name):
    return {"ResourceType": "S3Bucket", "S3BucketDetails": [{"Name": name}]}


def api_action(ip):
    return {"Action": {"AwsApiCallAction": {"RemoteIpDetails": {"IpAddressV4": ip}}}}


def net_action(ip):
    return {
        "Action": {"NetworkConnectionAction": {"RemoteIpDetails": {"IpAddressV4": ip}}}
    }


def probe_action(ip):
    return {"Action": {"PortProbeAction": {"RemoteIpDetails": {"IpAddressV4": ip}}}}


# ---------------------------------------------------------------------------
# (finding, label, reason, difficulty)
# ---------------------------------------------------------------------------
CASES = []


def case(f, label, reason, difficulty="easy"):
    CASES.append((f, label, reason, difficulty))


# --- Recon: mostly noise -----------------------------------------------------
case(
    finding(
        "corpus-0001", "Recon:EC2/PortProbeUnprotectedPort",
        "Unprotected port on i-0a1b2c3d is being probed.",
        "EC2 instance has an unprotected port being probed by a known scanner.",
        2.0, "2026-07-02T14:22:00.000Z",
        instance("i-0a1b2c3d"), probe_action("198.51.100.20"),
    ),
    "benign",
    "Untargeted internet-wide scanning against a single exposed port. "
    "No authentication attempt, no follow-on activity.",
)
case(
    finding(
        "corpus-0002", "Recon:IAMUser/MaliciousIPCaller",
        "API DescribeInstances was invoked from a known malicious IP.",
        "Reconnaissance API invoked from a threat-listed address.",
        5.0, "2026-07-03T11:05:00.000Z",
        access_key("svc-inventory", "AIDACORP001"), api_action("192.0.2.55"),
    ),
    "benign",
    "Long-lived read-only service account performing its routine inventory "
    "sweep. Threat-list hit is a stale shared-hosting entry.",
    "hard",
)
case(
    finding(
        "corpus-0003", "Recon:IAMUser/TorIPCaller",
        "API ListBuckets was invoked from a Tor exit node.",
        "An API commonly used for discovery was invoked from a Tor exit node.",
        5.0, "2026-07-05T03:41:00.000Z",
        access_key("dev-marcus", "AIDACORP002"), api_action("203.0.113.9"),
    ),
    "malicious",
    "Interactive developer credentials used via Tor at 3am. No business "
    "reason for anonymised access; consistent with stolen key usage.",
)
case(
    finding(
        "corpus-0004", "Recon:EC2/PortProbeUnprotectedPort",
        "Unprotected port on i-0deadbeef is being probed.",
        "Multiple ports probed in rapid succession from a single source.",
        2.0, "2026-07-06T09:14:00.000Z",
        instance("i-0deadbeef"), probe_action("198.51.100.21"),
    ),
    "benign",
    "Routine background scanning. Instance sits behind a security group "
    "that denies the probed ports.",
)
case(
    finding(
        "corpus-0005", "Recon:IAMUser/MaliciousIPCaller",
        "API GetCallerIdentity was invoked from a known malicious IP.",
        "Identity enumeration API invoked from a threat-listed address.",
        5.0, "2026-07-08T22:50:00.000Z",
        access_key("ci-deploy", "AIDACORP003"), api_action("192.0.2.77"),
    ),
    "benign",
    "CI runner calls GetCallerIdentity on every pipeline start. Source is "
    "the build vendor's shared egress range, which carries a stale listing.",
    "hard",
)

# --- Credential access -------------------------------------------------------
case(
    finding(
        "corpus-0006", "CredentialAccess:IAMUser/AnomalousBehavior",
        "An API used to gather credentials was invoked anomalously.",
        "GetSecretValue invoked at a volume inconsistent with baseline.",
        7.0, "2026-07-09T02:17:00.000Z",
        access_key("dev-priya", "AIDACORP004"), api_action("203.0.113.44"),
    ),
    "malicious",
    "Bulk secret retrieval at 2am from an unfamiliar IP by a developer "
    "account that normally reads two secrets a week.",
)
case(
    finding(
        "corpus-0007", "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        "Instance role credentials used from an external IP address.",
        "Credentials created for i-0c9d8e7f were used from outside AWS.",
        8.0, "2026-07-10T16:33:00.000Z",
        access_key("i-0c9d8e7f-role", "AIDACORP005"), api_action("203.0.113.101"),
    ),
    "malicious",
    "Instance role credentials should never be used off-instance. Textbook "
    "SSRF or metadata-service theft.",
)
case(
    finding(
        "corpus-0008", "CredentialAccess:IAMUser/AnomalousBehavior",
        "An API used to gather credentials was invoked anomalously.",
        "ListAccessKeys invoked outside normal pattern.",
        7.0, "2026-07-11T13:02:00.000Z",
        access_key("sec-auditor", "AIDACORP006"), api_action("10.20.30.40"),
    ),
    "benign",
    "Security team's quarterly access-key audit, run from the corporate "
    "network during business hours.",
    "hard",
)

# --- Persistence -------------------------------------------------------------
case(
    finding(
        "corpus-0009", "Persistence:IAMUser/AnomalousBehavior",
        "An API used to establish persistence was invoked anomalously.",
        "CreateUser and AttachUserPolicy invoked in rapid succession.",
        7.5, "2026-07-12T04:08:00.000Z",
        access_key("dev-marcus", "AIDACORP002"), api_action("203.0.113.9"),
    ),
    "malicious",
    "Same principal and IP as the Tor recon event, now creating a new admin "
    "identity at 4am. Clear attacker persistence step.",
)
case(
    finding(
        "corpus-0010", "Persistence:IAMUser/NetworkPermissions",
        "An API used to modify network permissions was invoked anomalously.",
        "AuthorizeSecurityGroupIngress opened 0.0.0.0/0 on port 22.",
        6.5, "2026-07-13T15:44:00.000Z",
        access_key("dev-alex", "AIDACORP007"), api_action("10.20.30.55"),
    ),
    "benign",
    "Developer temporarily opened SSH from the office network during a "
    "documented incident bridge. Poor practice, not an intrusion.",
    "hard",
)
case(
    finding(
        "corpus-0011", "Persistence:IAMUser/ResourcePermissions",
        "An API used to change resource permissions was invoked anomalously.",
        "PutBucketPolicy granted cross-account access to an unknown account.",
        7.5, "2026-07-14T23:19:00.000Z",
        bucket("finance-reports-prod"), api_action("203.0.113.150"),
    ),
    "malicious",
    "Cross-account grant on a sensitive bucket to an unrecognised account, "
    "made late at night from an external address.",
)
case(
    finding(
        "corpus-0012", "Persistence:IAMUser/AnomalousBehavior",
        "An API used to establish persistence was invoked anomalously.",
        "CreateAccessKey invoked for an existing service account.",
        7.5, "2026-07-15T10:27:00.000Z",
        access_key("svc-terraform", "AIDACORP008"), api_action("10.20.30.12"),
    ),
    "benign",
    "Scheduled key rotation performed by the platform team from the "
    "corporate range. Old key deactivated minutes later.",
    "hard",
)

# --- Privilege escalation ----------------------------------------------------
case(
    finding(
        "corpus-0013", "PrivilegeEscalation:IAMUser/AdministrativePermissions",
        "An attempt to assign administrative permissions was detected.",
        "AttachUserPolicy attached AdministratorAccess to a low-privilege user.",
        8.0, "2026-07-16T01:52:00.000Z",
        access_key("temp-contractor", "AIDACORP009"), api_action("203.0.113.88"),
    ),
    "malicious",
    "Contractor account self-escalating to full admin at 2am from an "
    "external IP. No change ticket, no approval.",
)
case(
    finding(
        "corpus-0014", "PrivilegeEscalation:IAMUser/AdministrativePermissions",
        "An attempt to assign administrative permissions was detected.",
        "AttachRolePolicy attached a broad policy to a deployment role.",
        8.0, "2026-07-17T14:11:00.000Z",
        access_key("svc-terraform", "AIDACORP008"), api_action("10.20.30.12"),
    ),
    "benign",
    "Infrastructure-as-code apply expanding a deployment role, run by the "
    "usual automation principal from the corporate range in work hours.",
    "hard",
)

# --- Exfiltration ------------------------------------------------------------
case(
    finding(
        "corpus-0015", "Exfiltration:S3/ObjectRead.Unusual",
        "An unusual volume of objects was read from finance-reports-prod.",
        "Object read volume exceeded baseline by two orders of magnitude.",
        7.5, "2026-07-18T02:44:00.000Z",
        bucket("finance-reports-prod"), api_action("203.0.113.150"),
    ),
    "malicious",
    "Mass read of a sensitive bucket at 2am from the same external IP that "
    "modified its policy days earlier. Completes the exfiltration chain.",
)
case(
    finding(
        "corpus-0016", "Exfiltration:S3/ObjectRead.Unusual",
        "An unusual volume of objects was read from analytics-raw-events.",
        "Object read volume exceeded baseline significantly.",
        7.5, "2026-07-19T06:00:00.000Z",
        bucket("analytics-raw-events"), api_action("10.40.1.9"),
    ),
    "benign",
    "Monthly analytics backfill job. Runs from a private subnet, same "
    "6am slot every month, reads the same prefix.",
    "hard",
)
case(
    finding(
        "corpus-0017", "Exfiltration:IAMUser/AnomalousBehavior",
        "An API used for data exfiltration was invoked anomalously.",
        "CreateSnapshot followed by ModifySnapshotAttribute making it public.",
        8.5, "2026-07-20T03:30:00.000Z",
        access_key("temp-contractor", "AIDACORP009"), api_action("203.0.113.88"),
    ),
    "malicious",
    "Snapshotting a volume and making the snapshot public is a well-known "
    "exfiltration path with no legitimate use here.",
)

# --- Crypto mining -----------------------------------------------------------
case(
    finding(
        "corpus-0018", "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "i-0f1e2d3c is querying a domain associated with mining pools.",
        "Instance queried a Bitcoin mining pool domain.",
        8.0, "2026-07-21T18:05:00.000Z",
        instance("i-0f1e2d3c"), net_action("198.51.100.60"),
    ),
    "malicious",
    "Production instance contacting a mining pool. Consistent with "
    "post-compromise resource abuse.",
)
case(
    finding(
        "corpus-0019", "CryptoCurrency:EC2/BitcoinTool.B",
        "i-0research99 is communicating with a mining pool.",
        "Instance is connecting to a Bitcoin mining pool.",
        8.0, "2026-07-22T12:40:00.000Z",
        instance("i-0research99"), net_action("198.51.100.61"),
    ),
    "benign",
    "Blockchain research sandbox that legitimately runs mining software. "
    "Documented exception, isolated account.",
    "hard",
)

# --- Brute force / access ----------------------------------------------------
case(
    finding(
        "corpus-0020", "UnauthorizedAccess:EC2/SSHBruteForce",
        "SSH brute force attacks against i-0a1b2c3d.",
        "Instance is being probed for SSH weak passwords.",
        2.0, "2026-07-23T08:12:00.000Z",
        instance("i-0a1b2c3d"), net_action("198.51.100.30"),
    ),
    "benign",
    "Continuous internet background noise. Key-only authentication is "
    "enforced; no successful logins.",
)
case(
    finding(
        "corpus-0021", "UnauthorizedAccess:EC2/RDPBruteForce",
        "RDP brute force attacks against i-0win0001.",
        "Instance is being probed for RDP weak passwords.",
        2.0, "2026-07-24T20:36:00.000Z",
        instance("i-0win0001"), net_action("198.51.100.31"),
    ),
    "benign",
    "Untargeted scanning. RDP is restricted to a bastion security group.",
)
case(
    finding(
        "corpus-0022", "UnauthorizedAccess:EC2/SSHBruteForce",
        "SSH brute force attacks against i-0jump0001.",
        "Sustained credential attempts against the bastion host.",
        2.0, "2026-07-25T04:55:00.000Z",
        instance("i-0jump0001"), net_action("203.0.113.201"),
    ),
    "malicious",
    "Sustained, targeted attempts against the bastion specifically, from a "
    "single source, followed by a successful authentication.",
    "hard",
)
case(
    finding(
        "corpus-0023", "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
        "Console login succeeded from an unusual location.",
        "Successful console sign-in from a geography not seen before.",
        5.0, "2026-07-26T09:03:00.000Z",
        access_key("dev-priya", "AIDACORP004"), api_action("198.51.100.90"),
    ),
    "benign",
    "Developer travelling; login used MFA and matches their known device "
    "and normal working hours in the new timezone.",
    "hard",
)
case(
    finding(
        "corpus-0024", "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
        "Console login succeeded from an unusual location.",
        "Successful console sign-in from a geography not seen before.",
        5.0, "2026-07-27T02:21:00.000Z",
        access_key("finance-admin", "AIDACORP010"), api_action("203.0.113.212"),
    ),
    "malicious",
    "Privileged finance account, no MFA on the session, 2am, unfamiliar "
    "geography, immediately followed by permission changes.",
)

# --- Policy / defense evasion ------------------------------------------------
case(
    finding(
        "corpus-0025", "Stealth:IAMUser/CloudTrailLoggingDisabled",
        "CloudTrail logging was disabled.",
        "StopLogging was invoked on the organisation trail.",
        8.0, "2026-07-28T03:07:00.000Z",
        access_key("temp-contractor", "AIDACORP009"), api_action("203.0.113.88"),
    ),
    "malicious",
    "Disabling audit logging has no legitimate operational purpose here "
    "and is a classic anti-forensics step.",
)
case(
    finding(
        "corpus-0026", "Stealth:S3/ServerAccessLoggingDisabled",
        "S3 server access logging was disabled on a bucket.",
        "PutBucketLogging removed logging configuration.",
        6.0, "2026-07-29T11:48:00.000Z",
        bucket("legacy-static-assets"), api_action("10.20.30.12"),
    ),
    "benign",
    "Decommissioning a legacy static-assets bucket. Change ticket exists; "
    "performed by automation from the corporate range.",
    "hard",
)
case(
    finding(
        "corpus-0027", "Impact:IAMUser/AnomalousBehavior",
        "An API commonly used to tamper with data was invoked anomalously.",
        "DeleteObjects invoked across multiple prefixes.",
        7.5, "2026-07-30T01:14:00.000Z",
        bucket("customer-uploads-prod"), api_action("203.0.113.212"),
    ),
    "malicious",
    "Bulk deletion in a production bucket overnight from the same external "
    "IP as the finance-admin compromise.",
)

# --- Malware / instance behaviour -------------------------------------------
case(
    finding(
        "corpus-0028", "Backdoor:EC2/C&CActivity.B!DNS",
        "i-0f1e2d3c is querying a domain associated with a known C2 server.",
        "Instance queried a command-and-control domain.",
        8.5, "2026-07-31T19:26:00.000Z",
        instance("i-0f1e2d3c"), net_action("198.51.100.70"),
    ),
    "malicious",
    "C2 beaconing from the same instance later seen mining. Strong "
    "indicator of established compromise.",
)
case(
    finding(
        "corpus-0029", "Trojan:EC2/DNSDataExfiltration",
        "i-0f1e2d3c is exfiltrating data through DNS queries.",
        "Instance is generating high-entropy DNS queries to a single domain.",
        8.0, "2026-08-01T02:03:00.000Z",
        instance("i-0f1e2d3c"), net_action("198.51.100.71"),
    ),
    "malicious",
    "DNS tunnelling from an already-compromised host. Completes the "
    "compromise chain for this instance.",
)
case(
    finding(
        "corpus-0030", "Backdoor:EC2/C&CActivity.B!DNS",
        "i-0secops01 is querying a domain associated with a known C2 server.",
        "Instance queried a flagged domain.",
        8.5, "2026-08-02T15:33:00.000Z",
        instance("i-0secops01"), net_action("198.51.100.72"),
    ),
    "benign",
    "Security team's malware analysis sandbox deliberately resolving C2 "
    "domains. Isolated VPC, documented exception.",
    "hard",
)

# --- Policy findings ---------------------------------------------------------
case(
    finding(
        "corpus-0031", "Policy:S3/BucketBlockPublicAccessDisabled",
        "Block Public Access was disabled on a bucket.",
        "S3 Block Public Access settings were removed.",
        4.0, "2026-08-03T10:19:00.000Z",
        bucket("public-website-assets"), api_action("10.20.30.12"),
    ),
    "benign",
    "Bucket intentionally serves a public static website. Change made by "
    "automation with an approved ticket.",
)
case(
    finding(
        "corpus-0032", "Policy:S3/BucketAnonymousAccessGranted",
        "Anonymous access was granted to a bucket.",
        "Bucket policy now permits unauthenticated read.",
        6.0, "2026-08-04T23:58:00.000Z",
        bucket("customer-uploads-prod"), api_action("203.0.113.212"),
    ),
    "malicious",
    "Production bucket holding customer data opened to anonymous read, "
    "late at night, from a known-compromised principal's IP.",
)
case(
    finding(
        "corpus-0033", "Policy:IAMUser/RootCredentialUsage",
        "The root user credentials were used.",
        "API activity was recorded for the account root user.",
        6.0, "2026-08-05T13:40:00.000Z",
        access_key("root", "AIDAROOT"), api_action("10.20.30.5"),
    ),
    "benign",
    "Annual billing-settings change that genuinely requires root, performed "
    "from the corporate range with MFA during business hours.",
    "hard",
)
case(
    finding(
        "corpus-0034", "Policy:IAMUser/RootCredentialUsage",
        "The root user credentials were used.",
        "API activity was recorded for the account root user.",
        6.0, "2026-08-06T03:52:00.000Z",
        access_key("root", "AIDAROOT"), api_action("203.0.113.240"),
    ),
    "malicious",
    "Root usage at 3am from an unrecognised external IP. Root should never "
    "be used this way; treat as full account compromise.",
)

# --- Discovery / lateral movement -------------------------------------------
case(
    finding(
        "corpus-0035", "Discovery:S3/MaliciousIPCaller",
        "ListBuckets was invoked from a known malicious IP.",
        "Bucket enumeration from a threat-listed address.",
        5.0, "2026-08-07T04:26:00.000Z",
        bucket("unknown"), api_action("203.0.113.150"),
    ),
    "malicious",
    "Bucket enumeration from the IP already tied to the finance-reports "
    "policy change and mass read. Part of the same campaign.",
)
case(
    finding(
        "corpus-0036", "Discovery:IAMUser/AnomalousBehavior",
        "An API commonly used for discovery was invoked anomalously.",
        "DescribeInstances, ListRoles and GetAccountAuthorizationDetails in sequence.",
        5.0, "2026-08-08T09:31:00.000Z",
        access_key("sec-auditor", "AIDACORP006"), api_action("10.20.30.40"),
    ),
    "benign",
    "Security auditor running the scheduled posture assessment from the "
    "corporate network. Matches prior monthly runs exactly.",
)
case(
    finding(
        "corpus-0037", "Discovery:IAMUser/AnomalousBehavior",
        "An API commonly used for discovery was invoked anomalously.",
        "Rapid enumeration of IAM roles and trust policies.",
        5.0, "2026-08-09T02:58:00.000Z",
        access_key("temp-contractor", "AIDACORP009"), api_action("203.0.113.88"),
    ),
    "malicious",
    "Trust-policy enumeration at 3am by the contractor account already "
    "seen escalating privileges. Mapping lateral movement paths.",
)

# --- Edge cases --------------------------------------------------------------
case(
    finding(
        "corpus-0038", "UnauthorizedAccess:EC2/TorClient",
        "i-0build0007 is communicating with a Tor entry node.",
        "Instance established a connection to a Tor network entry node.",
        7.0, "2026-08-10T17:12:00.000Z",
        instance("i-0build0007"), net_action("198.51.100.80"),
    ),
    "benign",
    "Build agent pulling a dependency whose mirror is Tor-hosted. Verified "
    "against the build log; repeats on every pipeline run.",
    "hard",
)
case(
    finding(
        "corpus-0039", "Impact:EC2/AbusedDomainRequest.Reputation",
        "i-0a1b2c3d is querying a low-reputation domain.",
        "Instance queried a domain with a poor reputation score.",
        3.0, "2026-08-11T14:07:00.000Z",
        instance("i-0a1b2c3d"), net_action("198.51.100.85"),
    ),
    "benign",
    "Low-reputation score driven by a shared hosting provider. Domain is a "
    "legitimate vendor API the application calls constantly.",
)
case(
    finding(
        "corpus-0040", "PrivilegeEscalation:IAMUser/AdministrativePermissions",
        "An attempt to assign administrative permissions was detected.",
        "CreateUser followed by AttachUserPolicy with AdministratorAccess.",
        8.0, "2026-08-12T04:44:00.000Z",
        access_key("finance-admin", "AIDACORP010"), api_action("203.0.113.212"),
    ),
    "malicious",
    "Compromised finance-admin creating a fresh admin identity at 4am. "
    "Persistence step following the earlier console compromise.",
)


def main():
    out_dir = Path(__file__).parent
    findings = [c[0] for c in CASES]
    labels = {
        c[0]["Id"]: {
            "label": c[1],
            "reason": c[2],
            "difficulty": c[3],
            "finding_type": c[0]["Type"],
        }
        for c in CASES
    }

    (out_dir / "guardduty_corpus.json").write_text(
        json.dumps(findings, indent=2) + "\n"
    )
    (out_dir / "labels.json").write_text(json.dumps(labels, indent=2) + "\n")

    n = len(CASES)
    mal = sum(1 for c in CASES if c[1] == "malicious")
    hard = sum(1 for c in CASES if c[3] == "hard")
    print(f"{n} findings written")
    print(f"  malicious: {mal} ({mal / n:.0%})")
    print(f"  benign:    {n - mal} ({(n - mal) / n:.0%})")
    print(f"  hard:      {hard} ({hard / n:.0%})")


if __name__ == "__main__":
    main()
