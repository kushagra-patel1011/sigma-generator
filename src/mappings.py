"""ATT&CK telemetry -> Sigma logsource translation tables.

ATT&CK v18 replaced the old ``x_mitre_data_sources`` strings on techniques with
first-class *detection strategies* and *analytics*.  Each analytic points at one
or more log sources shaped like ``{"name": "WinEventLog:Sysmon",
"channel": "EventCode=1"}``.  That pair is the richest machine-readable hint
ATT&CK gives us, and this module turns it into a Sigma ``logsource:`` block plus
the field names a rule for that source should use.

Three tiers of evidence are used, best first:

1. ``log source name + channel``  - e.g. Sysmon EventCode=1 -> ``process_creation``
2. ``log source name`` alone      - e.g. ``AWS:CloudTrail`` -> ``product: aws``
3. ``data component`` name        - e.g. ``Module Load``    -> ``image_load``

Anything that survives all three is reported as unmapped so the caller can say
so out loud rather than emit a confident-looking but wrong rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# --------------------------------------------------------------------------- #
# Confidence tiers
# --------------------------------------------------------------------------- #
CONF_EXACT = 0.95        # log source + event code both recognised
CONF_SOURCE = 0.75       # log source recognised, channel free-text
CONF_COMPONENT = 0.55    # fell back to the ATT&CK data component name
CONF_PLATFORM = 0.25     # only the platform is known
CONF_NONE = 0.0          # telemetry lives outside the defender's log pipeline


@dataclass
class SigmaLogSource:
    """The three Sigma ``logsource`` selectors."""

    category: Optional[str] = None
    product: Optional[str] = None
    service: Optional[str] = None
    definition: Optional[str] = None

    def as_dict(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for key in ("category", "product", "service", "definition"):
            value = getattr(self, key)
            if value:
                out[key] = value
        return out

    def describe(self) -> str:
        return "/".join(v for v in (self.category, self.product, self.service) if v) or "unknown"


@dataclass
class TelemetryMapping:
    """A resolved ATT&CK log source, ready to be shaped into a Sigma rule."""

    logsource: SigmaLogSource
    #: ``fields:`` block - the columns an analyst wants when triaging a hit.
    fields: tuple[str, ...] = ()
    #: Constraints that identify the event type itself (e.g. ``EventID: 7045``).
    base_selection: dict[str, Any] = field(default_factory=dict)
    #: Artefact role -> Sigma field name.  See ``ROLES`` for the vocabulary.
    roles: dict[str, str] = field(default_factory=dict)
    confidence: float = CONF_NONE
    #: Human-readable provenance, printed in the rule's review banner.
    source: str = ""
    notes: tuple[str, ...] = ()

    @property
    def is_usable(self) -> bool:
        return self.confidence > CONF_NONE and bool(self.logsource.as_dict())


#: Artefact roles a mapping may expose.  ``sigma_generator`` places mined
#: artefacts into whichever of these the resolved log source supports.
ROLES = (
    "image",          # the acting process (the thing doing something)
    "parent_image",   # parent process path
    "target_image",   # the process acted upon (e.g. lsass.exe in process access)
    "loaded_image",   # a DLL / driver being loaded
    "access_mask",    # requested process access rights
    "command_line",   # full command line / free-text content
    "script",         # script block or payload body
    "file",           # file path touched by the event
    "registry_key",   # registry key path
    "registry_value", # registry value data
    "pipe",           # named pipe
    "dns_query",      # queried domain
    "destination",    # destination host/IP
    "port",           # destination port
    "service_name",   # Windows service name
    "event_name",     # cloud / SaaS API operation
    "user",           # account name
)


# --------------------------------------------------------------------------- #
# Reusable field sets
# --------------------------------------------------------------------------- #
_PROC_FIELDS = ("Image", "CommandLine", "ParentImage", "User")
_PROC_ROLES = {"image": "Image", "parent_image": "ParentImage", "command_line": "CommandLine", "user": "User"}


def _mapping(
    logsource: SigmaLogSource,
    fields: tuple[str, ...] = (),
    roles: Optional[dict[str, str]] = None,
    base: Optional[dict[str, Any]] = None,
    confidence: float = CONF_EXACT,
    source: str = "",
    notes: tuple[str, ...] = (),
) -> TelemetryMapping:
    return TelemetryMapping(
        logsource=SigmaLogSource(**vars(logsource)),
        fields=fields,
        base_selection=dict(base or {}),
        roles=dict(roles or {}),
        confidence=confidence,
        source=source,
        notes=notes,
    )


# --------------------------------------------------------------------------- #
# Sysmon event ID -> Sigma category
# --------------------------------------------------------------------------- #
SYSMON_EVENTS: dict[int, TelemetryMapping] = {
    1: _mapping(SigmaLogSource(category="process_creation", product="windows"), _PROC_FIELDS, _PROC_ROLES),
    2: _mapping(
        SigmaLogSource(category="file_change", product="windows"),
        ("Image", "TargetFilename"),
        {"image": "Image", "file": "TargetFilename"},
    ),
    3: _mapping(
        SigmaLogSource(category="network_connection", product="windows"),
        ("Image", "DestinationIp", "DestinationPort", "DestinationHostname", "User"),
        {"image": "Image", "destination": "DestinationHostname", "user": "User", "port": "DestinationPort"},
        base={"Initiated": True},
    ),
    5: _mapping(
        SigmaLogSource(category="process_termination", product="windows"),
        ("Image", "User"),
        {"image": "Image", "user": "User"},
    ),
    6: _mapping(
        SigmaLogSource(category="driver_load", product="windows"),
        ("ImageLoaded", "Signature", "Signed"),
        {"loaded_image": "ImageLoaded"},
    ),
    7: _mapping(
        SigmaLogSource(category="image_load", product="windows"),
        ("Image", "ImageLoaded", "Signed", "Signature"),
        {"image": "Image", "loaded_image": "ImageLoaded"},
    ),
    8: _mapping(
        SigmaLogSource(category="create_remote_thread", product="windows"),
        ("SourceImage", "TargetImage", "StartModule", "StartFunction"),
        {"image": "SourceImage", "target_image": "TargetImage"},
    ),
    9: _mapping(
        SigmaLogSource(category="raw_access_thread", product="windows"),
        ("Image", "Device"),
        {"image": "Image", "file": "Device"},
    ),
    10: _mapping(
        SigmaLogSource(category="process_access", product="windows"),
        ("SourceImage", "TargetImage", "GrantedAccess", "CallTrace"),
        # CallTrace holds DLL stack frames, never command text - no content role.
        {"image": "SourceImage", "target_image": "TargetImage", "access_mask": "GrantedAccess"},
    ),
    11: _mapping(
        SigmaLogSource(category="file_event", product="windows"),
        ("Image", "TargetFilename", "User"),
        {"image": "Image", "file": "TargetFilename", "user": "User"},
    ),
    12: _mapping(
        SigmaLogSource(category="registry_add", product="windows"),
        ("Image", "TargetObject", "EventType"),
        {"image": "Image", "registry_key": "TargetObject"},
    ),
    13: _mapping(
        SigmaLogSource(category="registry_set", product="windows"),
        ("Image", "TargetObject", "Details"),
        {"image": "Image", "registry_key": "TargetObject", "registry_value": "Details"},
    ),
    14: _mapping(
        SigmaLogSource(category="registry_rename", product="windows"),
        ("Image", "TargetObject", "NewName"),
        {"image": "Image", "registry_key": "TargetObject"},
    ),
    15: _mapping(
        SigmaLogSource(category="create_stream_hash", product="windows"),
        ("Image", "TargetFilename", "Contents"),
        {"image": "Image", "file": "TargetFilename"},
    ),
    17: _mapping(
        SigmaLogSource(category="pipe_created", product="windows"),
        ("Image", "PipeName"),
        {"image": "Image", "pipe": "PipeName"},
    ),
    18: _mapping(
        SigmaLogSource(category="pipe_created", product="windows"),
        ("Image", "PipeName"),
        {"image": "Image", "pipe": "PipeName"},
    ),
    19: _mapping(
        SigmaLogSource(category="wmi_event", product="windows"),
        ("Operation", "User", "EventNamespace", "Name", "Query"),
        {"command_line": "Query", "user": "User"},
    ),
    20: _mapping(
        SigmaLogSource(category="wmi_event", product="windows"),
        ("Operation", "User", "Name", "Type", "Destination"),
        {"command_line": "Destination", "user": "User"},
    ),
    21: _mapping(
        SigmaLogSource(category="wmi_event", product="windows"),
        ("Operation", "User", "Consumer", "Filter"),
        {"command_line": "Consumer", "user": "User"},
    ),
    22: _mapping(
        SigmaLogSource(category="dns_query", product="windows"),
        ("Image", "QueryName", "QueryResults"),
        {"image": "Image", "dns_query": "QueryName", "destination": "QueryName"},
    ),
    23: _mapping(
        SigmaLogSource(category="file_delete", product="windows"),
        ("Image", "TargetFilename", "User"),
        {"image": "Image", "file": "TargetFilename", "user": "User"},
    ),
    25: _mapping(
        SigmaLogSource(category="process_tampering", product="windows"),
        ("Image", "Type"),
        {"image": "Image"},
    ),
    26: _mapping(
        SigmaLogSource(category="file_delete", product="windows"),
        ("Image", "TargetFilename", "User"),
        {"image": "Image", "file": "TargetFilename", "user": "User"},
    ),
    27: _mapping(
        SigmaLogSource(category="file_block_executable", product="windows"),
        ("Image", "TargetFilename"),
        {"image": "Image", "file": "TargetFilename"},
    ),
    29: _mapping(
        SigmaLogSource(category="file_executable_detected", product="windows"),
        ("Image", "TargetFilename"),
        {"image": "Image", "file": "TargetFilename"},
    ),
}


# --------------------------------------------------------------------------- #
# Windows Security / System / PowerShell channels
# --------------------------------------------------------------------------- #
def _security(event_ids: list[int], fields: tuple[str, ...], roles: dict[str, str]) -> TelemetryMapping:
    base: dict[str, Any] = {"EventID": event_ids[0] if len(event_ids) == 1 else list(event_ids)}
    return _mapping(
        SigmaLogSource(product="windows", service="security"),
        ("EventID",) + fields,
        roles,
        base=base,
    )


_SECURITY_EVENTS: dict[int, Callable[[list[int]], TelemetryMapping]] = {}


def _register_security(ids: tuple[int, ...], fields: tuple[str, ...], roles: dict[str, str]) -> None:
    for event_id in ids:
        _SECURITY_EVENTS[event_id] = lambda selected, f=fields, r=roles: _security(selected, f, r)


_register_security(
    (4624, 4625, 4634, 4647, 4648, 4672, 4776, 4768, 4769, 4771),
    ("SubjectUserName", "TargetUserName", "LogonType", "IpAddress", "WorkstationName"),
    {"user": "TargetUserName", "destination": "IpAddress"},
)
_register_security(
    (4656, 4658, 4660, 4663, 4670),
    ("ObjectName", "ObjectType", "AccessMask", "ProcessName", "SubjectUserName"),
    {"file": "ObjectName", "image": "ProcessName", "user": "SubjectUserName"},
)
_register_security(
    (4657,),
    ("ObjectName", "ObjectValueName", "NewValue", "ProcessName", "SubjectUserName"),
    {"registry_key": "ObjectName", "registry_value": "NewValue", "image": "ProcessName"},
)
_register_security(
    (4697,),
    ("ServiceName", "ServiceFileName", "ServiceStartType", "SubjectUserName"),
    {"service_name": "ServiceName", "image": "ServiceFileName", "command_line": "ServiceFileName"},
)
_register_security(
    (4698, 4699, 4700, 4701, 4702),
    ("TaskName", "TaskContent", "SubjectUserName"),
    {"command_line": "TaskContent", "user": "SubjectUserName"},
)
_register_security(
    (4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4735, 4738, 4740, 4756, 4767, 4781),
    ("TargetUserName", "SubjectUserName", "TargetDomainName"),
    {"user": "TargetUserName"},
)
_register_security(
    (4662, 5136, 5137, 5139, 5141),
    ("ObjectDN", "ObjectClass", "AttributeLDAPDisplayName", "AttributeValue", "SubjectUserName"),
    {"user": "SubjectUserName", "command_line": "AttributeValue"},
)
_register_security(
    (5140, 5142, 5143, 5144, 5145),
    ("ShareName", "ShareLocalPath", "RelativeTargetName", "IpAddress", "SubjectUserName"),
    {"file": "RelativeTargetName", "destination": "IpAddress", "user": "SubjectUserName"},
)
_register_security(
    (4673, 4674, 4985),  # privileged service use / audit state change
    ("ProcessName", "PrivilegeList", "SubjectUserName"),
    {"image": "ProcessName", "user": "SubjectUserName"},
)
_register_security(
    (1102, 4719, 4739, 4907, 4908),
    ("SubjectUserName", "SubjectDomainName"),
    {"user": "SubjectUserName"},
)

SYSTEM_EVENTS: dict[int, TelemetryMapping] = {
    7045: _mapping(
        SigmaLogSource(product="windows", service="system"),
        ("EventID", "ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"),
        {"service_name": "ServiceName", "image": "ImagePath", "command_line": "ImagePath"},
        base={"Provider_Name": "Service Control Manager", "EventID": 7045},
    ),
    7036: _mapping(
        SigmaLogSource(product="windows", service="system"),
        ("EventID", "param1", "param2"),
        {"service_name": "param1"},
        base={"Provider_Name": "Service Control Manager", "EventID": 7036},
    ),
    7040: _mapping(
        SigmaLogSource(product="windows", service="system"),
        ("EventID", "param1", "param2", "param3"),
        {"service_name": "param1"},
        base={"Provider_Name": "Service Control Manager", "EventID": 7040},
    ),
}

POWERSHELL_EVENTS: dict[int, TelemetryMapping] = {
    4103: _mapping(
        SigmaLogSource(category="ps_module", product="windows", definition="Module logging must be enabled"),
        ("ContextInfo", "Payload", "UserId"),
        {"script": "Payload", "command_line": "Payload", "user": "UserId"},
    ),
    4104: _mapping(
        SigmaLogSource(
            category="ps_script",
            product="windows",
            definition="Script block logging must be enabled",
        ),
        ("ScriptBlockText", "UserId", "Computer"),
        {"script": "ScriptBlockText", "command_line": "ScriptBlockText", "user": "UserId"},
    ),
    400: _mapping(
        SigmaLogSource(product="windows", service="powershell-classic"),
        ("EventID", "HostApplication", "EngineVersion", "HostName"),
        {"command_line": "HostApplication"},
        base={"EventID": 400},
    ),
    403: _mapping(
        SigmaLogSource(product="windows", service="powershell-classic"),
        ("EventID", "HostApplication", "EngineVersion"),
        {"command_line": "HostApplication"},
        base={"EventID": 403},
    ),
}


# --------------------------------------------------------------------------- #
# Non-Windows and cloud log sources
# --------------------------------------------------------------------------- #
_LINUX_PROC = _mapping(
    SigmaLogSource(category="process_creation", product="linux"),
    _PROC_FIELDS,
    _PROC_ROLES,
    notes=("Raw auditd deployments use `product: linux / service: auditd` with type=EXECVE instead.",),
)
_MACOS_PROC = _mapping(
    SigmaLogSource(category="process_creation", product="macos"),
    _PROC_FIELDS,
    _PROC_ROLES,
)
_AUDITD_SYSCALL = _mapping(
    SigmaLogSource(product="linux", service="auditd"),
    ("type", "syscall", "exe", "comm", "key", "auid"),
    {"image": "exe", "command_line": "comm", "file": "name", "user": "auid"},
    base={"type": "SYSCALL"},
)
_ZEEK = {
    "conn": _mapping(
        SigmaLogSource(product="zeek", service="conn"),
        ("id.orig_h", "id.resp_h", "id.resp_p", "proto", "service"),
        {"destination": "id.resp_h", "port": "id.resp_p"},
    ),
    "dns": _mapping(
        SigmaLogSource(product="zeek", service="dns"),
        ("id.orig_h", "query", "answers", "qtype_name"),
        {"dns_query": "query", "destination": "query"},
    ),
    "http": _mapping(
        SigmaLogSource(product="zeek", service="http"),
        ("id.orig_h", "host", "uri", "user_agent", "method"),
        {"destination": "host", "command_line": "uri"},
    ),
    "smtp": _mapping(
        SigmaLogSource(product="zeek", service="smtp"),
        ("id.orig_h", "mailfrom", "rcptto", "subject"),
        {"destination": "mailfrom"},
    ),
    "files": _mapping(
        SigmaLogSource(product="zeek", service="files"),
        ("id.orig_h", "filename", "mime_type", "md5"),
        {"file": "filename"},
    ),
}


def _cloud(product: str, service: str, event_field: str, fields: tuple[str, ...], extra_roles: Optional[dict[str, str]] = None,
           base: Optional[dict[str, Any]] = None) -> TelemetryMapping:
    # No command_line alias for the event field: mined cmdlets and flags do not
    # belong in `eventName|contains`.  Sources with a genuine free-text field
    # declare it through extra_roles.
    roles = {"event_name": event_field}
    roles.update(extra_roles or {})
    return _mapping(
        SigmaLogSource(product=product, service=service),
        fields,
        roles,
        base=base,
        confidence=CONF_SOURCE,
    )


CLOUD_SOURCES: dict[str, TelemetryMapping] = {
    "aws:cloudtrail": _cloud(
        "aws", "cloudtrail", "eventName",
        ("eventSource", "eventName", "userIdentity.arn", "sourceIPAddress", "awsRegion"),
        {"user": "userIdentity.arn", "destination": "sourceIPAddress"},
    ),
    "aws:vpcflowlogs": _cloud(
        "aws", "vpcflow", "action",
        ("srcaddr", "dstaddr", "dstport", "action", "protocol"),
        {"destination": "dstaddr", "port": "dstport"},
    ),
    "aws:cloudwatch": _cloud(
        "aws", "cloudwatch", "eventName",
        ("eventName", "eventSource", "userIdentity.arn"),
    ),
    "azure:signinlogs": _cloud(
        "azure", "signinlogs", "operationName",
        ("operationName", "userPrincipalName", "ipAddress", "resultType", "appDisplayName"),
        {"user": "userPrincipalName", "destination": "ipAddress"},
    ),
    "azure:audit": _cloud(
        "azure", "auditlogs", "operationName",
        ("operationName", "initiatedBy", "targetResources", "result"),
        {"user": "initiatedBy"},
    ),
    "azure:activity": _cloud(
        "azure", "activitylogs", "operationName",
        ("operationName", "caller", "resourceId", "resultType"),
        {"user": "caller"},
    ),
    "azure:resource": _cloud(
        "azure", "activitylogs", "operationName",
        ("operationName", "caller", "resourceId"),
        {"user": "caller"},
    ),
    "gcp:audit": _cloud(
        "gcp", "gcp.audit", "protoPayload.methodName",
        ("protoPayload.methodName", "protoPayload.authenticationInfo.principalEmail", "resource.type"),
        {"user": "protoPayload.authenticationInfo.principalEmail"},
    ),
    "m365:unified": _cloud(
        "m365", "audit", "Operation",
        ("Operation", "Workload", "UserId", "ClientIP", "ObjectId"),
        {"user": "UserId", "destination": "ClientIP"},
    ),
    "m365:exchange": _cloud(
        "m365", "exchange", "Operation",
        ("Operation", "UserId", "ClientIP", "Parameters"),
        {"user": "UserId", "command_line": "Parameters"},
    ),
    "m365:signinlogs": _cloud(
        "m365", "signinlogs", "Operation",
        ("Operation", "UserId", "ClientIP"),
        {"user": "UserId", "destination": "ClientIP"},
    ),
    "saas:okta": _cloud(
        "okta", "okta", "eventType",
        ("eventType", "displayMessage", "actor.alternateId", "client.ipAddress", "outcome.result"),
        {"user": "actor.alternateId", "destination": "client.ipAddress"},
    ),
    "saas:github": _cloud(
        "github", "audit", "action",
        ("action", "actor", "repo", "org"),
        {"user": "actor"},
    ),
    "saas:googleworkspace": _cloud(
        "google_workspace", "google_workspace.admin", "eventName",
        ("eventName", "eventService", "actor.email", "ipAddress"),
        {"user": "actor.email", "destination": "ipAddress"},
    ),
    "kubernetes:audit": _cloud(
        "kubernetes", "audit", "verb",
        ("verb", "objectRef.resource", "user.username", "sourceIPs", "requestURI"),
        {"user": "user.username", "command_line": "requestURI"},
    ),
    "kubernetes:apiserver": _cloud(
        "kubernetes", "audit", "verb",
        ("verb", "objectRef.resource", "user.username", "requestURI"),
        {"user": "user.username", "command_line": "requestURI"},
    ),
}


#: ATT&CK log-source name -> mapping, for sources whose channel carries no
#: structured event identifier.
STATIC_SOURCES: dict[str, TelemetryMapping] = {
    "linux:syslog": _mapping(
        SigmaLogSource(product="linux", service="syslog"),
        ("pid", "process", "message"),
        {"command_line": "message"},  # `process` is a bare program name, not a path
        confidence=CONF_SOURCE,
    ),
    "linux:osquery": _mapping(
        SigmaLogSource(product="linux", service="osquery"),
        ("name", "columns.path", "columns.cmdline"),
        {"image": "columns.path", "command_line": "columns.cmdline"},
        confidence=CONF_SOURCE,
        notes=("`service: osquery` is not a SigmaHQ-standard logsource - align it with your pipeline.",),
    ),
    "macos:osquery": _mapping(
        SigmaLogSource(product="macos", service="osquery"),
        ("name", "columns.path", "columns.cmdline"),
        {"image": "columns.path", "command_line": "columns.cmdline"},
        confidence=CONF_SOURCE,
        notes=("`service: osquery` is not a SigmaHQ-standard logsource - align it with your pipeline.",),
    ),
    "macos:endpointsecurity": _mapping(
        SigmaLogSource(category="process_creation", product="macos"),
        _PROC_FIELDS,
        _PROC_ROLES,
        confidence=CONF_SOURCE,
    ),
    "linux:sysmon": _mapping(
        SigmaLogSource(category="process_creation", product="linux"),
        _PROC_FIELDS,
        _PROC_ROLES,
        confidence=CONF_SOURCE,
    ),
    "ebpf:syscalls": _mapping(
        SigmaLogSource(product="linux", service="ebpf"),
        ("syscall", "comm", "exe", "args"),
        {"image": "exe", "command_line": "args"},
        confidence=CONF_SOURCE,
        notes=("`service: ebpf` is not a SigmaHQ-standard logsource - align it with your pipeline.",),
    ),
    "fs:fsusage": _mapping(
        SigmaLogSource(category="file_event", product="macos"),
        ("Image", "TargetFilename"),
        {"image": "Image", "file": "TargetFilename"},
        confidence=CONF_SOURCE,
    ),
    "fs:fsevents": _mapping(
        SigmaLogSource(category="file_event", product="macos"),
        ("Image", "TargetFilename"),
        {"image": "Image", "file": "TargetFilename"},
        confidence=CONF_SOURCE,
    ),
    "fs:fileevents": _mapping(
        SigmaLogSource(category="file_event", product="linux"),
        ("Image", "TargetFilename"),
        {"image": "Image", "file": "TargetFilename"},
        confidence=CONF_SOURCE,
    ),
    "docker:events": _mapping(
        SigmaLogSource(product="docker", service="events"),
        ("Action", "Type", "Actor.Attributes.image"),
        {"event_name": "Action"},  # Actor.Attributes.image is a container image, not a process
        confidence=CONF_SOURCE,
        notes=("`product: docker` is not a SigmaHQ-standard logsource - align it with your pipeline.",),
    ),
    "docker:daemon": _mapping(
        SigmaLogSource(product="docker", service="daemon"),
        ("msg", "container"),
        {"command_line": "msg"},
        confidence=CONF_SOURCE,
        notes=("`product: docker` is not a SigmaHQ-standard logsource - align it with your pipeline.",),
    ),
    "networkdevice:syslog": _mapping(
        SigmaLogSource(product="cisco", service="syslog"),
        ("facility", "mnemonic", "message"),
        {"command_line": "message"},
        confidence=CONF_SOURCE,
        notes=("Vendor-specific: swap `product: cisco` for your network vendor's Sigma logsource.",),
    ),
    "networkdevice:cli": _mapping(
        SigmaLogSource(product="cisco", service="aaa"),
        ("user", "cmd", "privLvl"),
        {"command_line": "cmd", "user": "user"},
        confidence=CONF_SOURCE,
        notes=("Vendor-specific: swap `product: cisco` for your network vendor's Sigma logsource.",),
    ),
    "networkdevice:config": _mapping(
        SigmaLogSource(product="cisco", service="aaa"),
        ("user", "cmd"),
        {"command_line": "cmd", "user": "user"},
        confidence=CONF_SOURCE,
        notes=("Vendor-specific: swap `product: cisco` for your network vendor's Sigma logsource.",),
    ),
    "nsm:firewall": _mapping(
        SigmaLogSource(category="firewall"),
        ("src_ip", "dst_ip", "dst_port", "action"),
        {"destination": "dst_ip", "port": "dst_port"},
        confidence=CONF_SOURCE,
    ),
    "network traffic": _mapping(
        SigmaLogSource(category="network_connection"),
        ("Image", "DestinationIp", "DestinationPort"),
        {"destination": "DestinationHostname", "image": "Image", "port": "DestinationPort"},
        confidence=CONF_PLATFORM,
    ),
    "domain name": _mapping(
        SigmaLogSource(category="dns_query"),
        ("QueryName", "Image"),
        {"dns_query": "QueryName", "destination": "QueryName"},
        confidence=CONF_PLATFORM,
    ),
    "application log": _mapping(
        SigmaLogSource(category="application"),
        ("EventID", "Provider_Name", "Data"),
        {"command_line": "Data"},
        confidence=CONF_PLATFORM,
    ),
    "application:mail": _mapping(
        SigmaLogSource(product="m365", service="exchange"),
        ("Operation", "UserId", "Subject"),
        {"event_name": "Operation", "user": "UserId"},
        confidence=CONF_PLATFORM,
    ),
    "wineventlog:wmi": _mapping(
        SigmaLogSource(product="windows", service="wmi"),
        ("EventID", "Operation", "User"),
        {"command_line": "Operation", "user": "User"},
        confidence=CONF_SOURCE,
    ),
    "wineventlog:application": _mapping(
        SigmaLogSource(product="windows", service="application"),
        ("EventID", "Provider_Name", "Data"),
        {"command_line": "Data"},
        confidence=CONF_SOURCE,
    ),
    "wineventlog:microsoft-windows-codeintegrity/operational": _mapping(
        SigmaLogSource(product="windows", service="codeintegrity-operational"),
        ("EventID", "FileNameBuffer", "ProcessNameBuffer"),
        {"file": "FileNameBuffer", "image": "ProcessNameBuffer"},
        confidence=CONF_SOURCE,
    ),
    "etw:microsoft-windows-kernel-process": _mapping(
        SigmaLogSource(category="process_creation", product="windows"),
        _PROC_FIELDS,
        _PROC_ROLES,
        confidence=CONF_SOURCE,
        notes=("ATT&CK cites raw ETW here; the portable Sigma equivalent is the process_creation category.",),
    ),
}

#: ESXi channels are grouped - the service name is the channel's own suffix.
_ESXI_SERVICES = {"hostd", "vmkernel", "shell", "syslog", "auth", "vpxd", "vobd", "fdm"}

#: SaaS sources ATT&CK names but Sigma has no standard logsource for.
_GENERIC_SAAS = {"saas:slack", "saas:zoom", "saas:box", "saas:dropbox", "saas:salesforce", "saas:atlassian"}

#: Telemetry that does not exist in a defender's log pipeline at all - ATT&CK
#: means "go look at an external data set", which no Sigma rule can express.
EXTERNAL_TELEMETRY = {
    "internet scan", "malware repository", "social media", "domain registration",
    "certificate registration", "passive dns", "response content", "response metadata",
    "host status", "malware content", "malware metadata",
}


# --------------------------------------------------------------------------- #
# Data component fallback table
# --------------------------------------------------------------------------- #
def _component(category: str, fields: tuple[str, ...], roles: dict[str, str]) -> TelemetryMapping:
    return _mapping(
        SigmaLogSource(category=category),
        fields,
        roles,
        confidence=CONF_COMPONENT,
    )


DATA_COMPONENTS: dict[str, TelemetryMapping] = {
    "process creation": _component("process_creation", _PROC_FIELDS, _PROC_ROLES),
    "command execution": _component("process_creation", _PROC_FIELDS, _PROC_ROLES),
    "script execution": _component("process_creation", _PROC_FIELDS, _PROC_ROLES),
    "process metadata": _component("process_creation", _PROC_FIELDS, _PROC_ROLES),
    "process modification": _component("process_access", ("SourceImage", "TargetImage", "GrantedAccess"),
                                       {"image": "SourceImage", "target_image": "TargetImage",
                                        "access_mask": "GrantedAccess"}),
    "process access": _component("process_access", ("SourceImage", "TargetImage", "GrantedAccess", "CallTrace"),
                                 {"image": "SourceImage", "target_image": "TargetImage",
                                  "access_mask": "GrantedAccess"}),
    "process termination": _component("process_termination", ("Image", "User"), {"image": "Image"}),
    "os api execution": _component("process_creation", _PROC_FIELDS, _PROC_ROLES),
    "module load": _component("image_load", ("Image", "ImageLoaded", "Signed"),
                              {"image": "Image", "loaded_image": "ImageLoaded"}),
    "driver load": _component("driver_load", ("ImageLoaded", "Signature", "Signed"),
                              {"loaded_image": "ImageLoaded"}),
    "kernel module load": _component("driver_load", ("ImageLoaded", "Signature"),
                                     {"loaded_image": "ImageLoaded"}),
    "file creation": _component("file_event", ("Image", "TargetFilename", "User"),
                                {"image": "Image", "file": "TargetFilename"}),
    "file modification": _component("file_change", ("Image", "TargetFilename"),
                                    {"image": "Image", "file": "TargetFilename"}),
    "file deletion": _component("file_delete", ("Image", "TargetFilename"),
                                {"image": "Image", "file": "TargetFilename"}),
    "file access": _component("file_access", ("Image", "TargetFilename"),
                              {"image": "Image", "file": "TargetFilename"}),
    "file metadata": _component("file_event", ("Image", "TargetFilename"),
                                {"image": "Image", "file": "TargetFilename"}),
    "windows registry key creation": _component("registry_add", ("Image", "TargetObject"),
                                                {"image": "Image", "registry_key": "TargetObject"}),
    "windows registry key modification": _component("registry_set", ("Image", "TargetObject", "Details"),
                                                    {"image": "Image", "registry_key": "TargetObject",
                                                     "registry_value": "Details"}),
    "windows registry key deletion": _component("registry_delete", ("Image", "TargetObject"),
                                                {"image": "Image", "registry_key": "TargetObject"}),
    "windows registry key access": _component("registry_event", ("Image", "TargetObject"),
                                              {"image": "Image", "registry_key": "TargetObject"}),
    "network connection creation": _component("network_connection",
                                              ("Image", "DestinationIp", "DestinationPort", "DestinationHostname"),
                                              {"image": "Image", "destination": "DestinationHostname",
                                               "port": "DestinationPort"}),
    "network traffic flow": _component("network_connection",
                                       ("Image", "DestinationIp", "DestinationPort"),
                                       {"image": "Image", "destination": "DestinationHostname",
                                        "port": "DestinationPort"}),
    "network traffic content": _component("proxy", ("c-uri", "cs-host", "cs-user-agent", "cs-method"),
                                          {"destination": "cs-host", "command_line": "c-uri"}),
    "network share access": _component("network_connection", ("Image", "DestinationHostname"),
                                       {"image": "Image", "destination": "DestinationHostname"}),
    "named pipe metadata": _component("pipe_created", ("Image", "PipeName"),
                                      {"image": "Image", "pipe": "PipeName"}),
    "active dns": _component("dns_query", ("Image", "QueryName", "QueryResults"),
                             {"image": "Image", "dns_query": "QueryName"}),
    "wmi creation": _component("wmi_event", ("Operation", "User", "Query"),
                               {"command_line": "Query", "user": "User"}),
    "application log content": _component("application", ("EventID", "Provider_Name", "Data"),
                                          {"command_line": "Data"}),
    "firewall rule modification": _component("firewall", ("action", "rule", "src_ip", "dst_ip"),
                                             {"command_line": "rule"}),
    "firewall disable": _component("firewall", ("action", "rule"), {"command_line": "rule"}),
    "firewall enumeration": _component("firewall", ("action", "rule"), {"command_line": "rule"}),
    "firewall metadata": _component("firewall", ("action", "rule"), {"command_line": "rule"}),
}

#: Data components that are really Windows Security-channel events.
_SECURITY_COMPONENTS: dict[str, tuple[int, ...]] = {
    "logon session creation": (4624, 4648),
    "logon session metadata": (4624, 4634),
    "user account authentication": (4624, 4625, 4776),
    "user account creation": (4720,),
    "user account deletion": (4726,),
    "user account modification": (4738, 4728, 4732),
    "user account metadata": (4738,),
    "group modification": (4728, 4732, 4756),
    "group enumeration": (4798, 4799),
    "group metadata": (4728,),
    "active directory object access": (4662,),
    "active directory object creation": (5137,),
    "active directory object deletion": (5141,),
    "active directory object modification": (5136,),
    "active directory credential request": (4768, 4769),
    "scheduled job creation": (4698,),
    "scheduled job modification": (4702,),
    "scheduled job metadata": (4698,),
}

#: Data components that are really Windows System-channel service events.
_SERVICE_COMPONENTS = {"service creation", "service modification", "service metadata"}

#: Cloud/container data components - the platform decides the product.
_CLOUD_COMPONENT_PREFIXES = (
    "cloud ", "instance ", "snapshot ", "volume ", "image ", "pod ", "container ",
    "cluster ", "drive ", "web credential ",
)


# --------------------------------------------------------------------------- #
# Platform -> Sigma product
# --------------------------------------------------------------------------- #
PLATFORM_PRODUCT: dict[str, str] = {
    "windows": "windows",
    "linux": "linux",
    "macos": "macos",
    "network devices": "cisco",
    "network": "cisco",
    "containers": "kubernetes",
    "kubernetes": "kubernetes",
    "iaas": "aws",
    "office suite": "m365",
    "office 365": "m365",
    "identity provider": "azure",
    "azure ad": "azure",
    "saas": "m365",
    "esxi": "esxi",
    "google workspace": "google_workspace",
}

#: Default ``level:`` per ATT&CK tactic (shortnames incl. the v18+ renames).
TACTIC_LEVEL: dict[str, str] = {
    "credential-access": "high",
    "privilege-escalation": "high",
    "lateral-movement": "high",
    "impact": "high",
    "exfiltration": "high",
    "command-and-control": "medium",
    "defense-evasion": "medium",
    "defense-impairment": "medium",
    "stealth": "medium",
    "execution": "medium",
    "persistence": "medium",
    "initial-access": "medium",
    "collection": "low",
    "discovery": "low",
    "reconnaissance": "low",
    "resource-development": "low",
}

LEVEL_ORDER = ("informational", "low", "medium", "high", "critical")


def downgrade_level(level: str, steps: int = 1) -> str:
    try:
        index = LEVEL_ORDER.index(level)
    except ValueError:
        return level
    return LEVEL_ORDER[max(0, index - steps)]


def upgrade_level(level: str, steps: int = 1) -> str:
    try:
        index = LEVEL_ORDER.index(level)
    except ValueError:
        return level
    return LEVEL_ORDER[min(len(LEVEL_ORDER) - 1, index + steps)]


# --------------------------------------------------------------------------- #
# Channel parsing
# --------------------------------------------------------------------------- #
_EVENT_CODE_RE = re.compile(r"Event(?:Code|ID)\s*[=:]\s*([0-9]+(?:\s*,\s*[0-9]+)*)", re.IGNORECASE)
_BARE_CODES_RE = re.compile(r"^\s*([0-9]{3,5}(?:\s*,\s*[0-9]{3,5})*)\s*$")
_CAMEL_EVENT_RE = re.compile(r"\b([A-Z][a-zA-Z0-9]{2,}(?:[A-Z][a-zA-Z0-9]*)+)\b")
_SYSCALL_RE = re.compile(
    r"\b(execve|execveat|open|openat|creat|write|read|connect|sendto|bind|listen|accept"
    r"|ptrace|mmap|mprotect|chmod|chown|unlink|rename|kill|setuid|setgid|socket|clone|fork)\b",
    re.IGNORECASE,
)


def parse_event_codes(channel: Optional[str]) -> list[int]:
    """Pull ``EventCode=1, 3`` style identifiers out of an ATT&CK channel."""
    if not channel:
        return []
    match = _EVENT_CODE_RE.search(channel)
    raw = match.group(1) if match else None
    if raw is None:
        bare = _BARE_CODES_RE.match(channel)
        raw = bare.group(1) if bare else None
    if raw is None:
        return []
    codes: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            codes.append(int(part))
    return codes


def parse_syscalls(channel: Optional[str]) -> list[str]:
    if not channel:
        return []
    seen: list[str] = []
    for match in _SYSCALL_RE.findall(channel):
        value = match.lower()
        if value not in seen:
            seen.append(value)
    return seen


#: CamelCase words that show up in ATT&CK channels but are not API operations.
_NOT_AN_OPERATION = {
    "EventCode", "EventID", "CommandLine", "PowerShell", "TimeWindow", "SignIn",
    "TokenIssued", "MailItemsAccessed", "UserPrincipalName", "FailureReason",
}


def parse_api_operations(channel: Optional[str], limit: int = 8) -> list[str]:
    """Pull cloud/SaaS API operation names (``RunInstances``) out of a channel."""
    if not channel:
        return []
    text = channel
    if "=" in text:  # "Operation=UserLogin" -> "UserLogin"
        text = " ".join(part.split("=", 1)[-1] for part in text.split(","))
    operations: list[str] = []
    for match in _CAMEL_EVENT_RE.findall(text):
        if match in _NOT_AN_OPERATION or match in operations:
            continue
        operations.append(match)
        if len(operations) >= limit:
            break
    return operations


# --------------------------------------------------------------------------- #
# Resolution
# --------------------------------------------------------------------------- #
def _clone(mapping: TelemetryMapping, **overrides: Any) -> TelemetryMapping:
    clone = TelemetryMapping(
        logsource=SigmaLogSource(**vars(mapping.logsource)),
        fields=tuple(mapping.fields),
        base_selection=dict(mapping.base_selection),
        roles=dict(mapping.roles),
        confidence=mapping.confidence,
        source=mapping.source,
        notes=tuple(mapping.notes),
    )
    for key, value in overrides.items():
        setattr(clone, key, value)
    return clone


def _windows_event_mapping(codes: list[int], channel_label: str) -> Optional[TelemetryMapping]:
    """Windows Security channel: 4688 is a category, everything else is EventID."""
    if not codes:
        return None
    if 4688 in codes:
        mapping = _clone(SYSMON_EVENTS[1])
        mapping.source = f"{channel_label} (4688 -> process_creation)"
        mapping.notes = (
            "Security 4688 exposes NewProcessName/ProcessCommandLine natively; the "
            "process_creation category normalises them to Image/CommandLine.",
        )
        return mapping
    known = [code for code in codes if code in _SECURITY_EVENTS]
    if not known:
        return None
    mapping = _SECURITY_EVENTS[known[0]](known)
    mapping.source = f"{channel_label} (EventID {', '.join(str(c) for c in known)})"
    return mapping


def _resolve_by_name(name: str, channel: Optional[str], platform: Optional[str]) -> Optional[TelemetryMapping]:
    key = (name or "").strip().lower()
    if not key:
        return None

    codes = parse_event_codes(channel)

    if key == "wineventlog:sysmon" or key == "windows:sysmon":
        known = [code for code in codes if code in SYSMON_EVENTS]
        if known:
            mapping = _clone(SYSMON_EVENTS[known[0]])
            mapping.source = f"Sysmon EventCode {known[0]}"
            if len(known) > 1:
                extra = ", ".join(str(code) for code in known[1:])
                mapping.notes = mapping.notes + (
                    f"ATT&CK also cites Sysmon EventCode {extra} for this analytic - consider a companion rule.",
                )
            return mapping
        mapping = _clone(SYSMON_EVENTS[1], confidence=CONF_SOURCE)
        mapping.source = "Sysmon (event code not stated by ATT&CK; assumed process creation)"
        return mapping

    if key == "wineventlog:security":
        mapping = _windows_event_mapping(codes, "Windows Security")
        if mapping:
            return mapping
        if codes:
            mapping = _security(codes, ("SubjectUserName", "TargetUserName"), {"user": "TargetUserName"})
            mapping.confidence = CONF_SOURCE
            mapping.source = f"Windows Security (EventID {', '.join(str(c) for c in codes)}, unmodelled)"
            return mapping
        return None

    if key == "wineventlog:system":
        known = [code for code in codes if code in SYSTEM_EVENTS]
        if known:
            mapping = _clone(SYSTEM_EVENTS[known[0]])
            mapping.source = f"Windows System (EventID {known[0]})"
            return mapping
        if codes:
            mapping = _mapping(
                SigmaLogSource(product="windows", service="system"),
                ("EventID", "Provider_Name", "param1", "param2"),
                {"command_line": "param1"},
                base={"EventID": codes[0] if len(codes) == 1 else codes},
                confidence=CONF_SOURCE,
                source=f"Windows System (EventID {', '.join(str(c) for c in codes)})",
            )
            return mapping
        return None

    if key in ("wineventlog:powershell", "wineventlog:powershell/operational"):
        known = [code for code in codes if code in POWERSHELL_EVENTS]
        if known:
            # ATT&CK usually lists the whole 4103-4106 block; script block logging
            # (4104) carries the actual script text, so it wins when offered.
            chosen = next((code for code in (4104, 4103, 400, 403) if code in known), known[0])
            mapping = _clone(POWERSHELL_EVENTS[chosen])
            mapping.source = f"PowerShell EventID {chosen}"
            return mapping
        mapping = _clone(POWERSHELL_EVENTS[4104], confidence=CONF_SOURCE)
        mapping.source = "PowerShell (event id not stated; assumed script block logging)"
        return mapping

    if key in ("auditd:syscall", "auditd:execve", "auditd:path", "auditd:file", "auditd:config_change"):
        syscalls = parse_syscalls(channel)
        if key == "auditd:execve" or "execve" in syscalls:
            mapping = _clone(_LINUX_PROC)
            mapping.source = "auditd execve"
            return mapping
        mapping = _clone(_AUDITD_SYSCALL, confidence=CONF_SOURCE if syscalls else CONF_PLATFORM)
        if syscalls:
            mapping.base_selection = {"type": "SYSCALL", "syscall": syscalls[0] if len(syscalls) == 1 else syscalls}
            mapping.source = f"auditd syscall {', '.join(syscalls)}"
        else:
            mapping.source = "auditd (syscall not stated by ATT&CK)"
        if key == "auditd:path":
            mapping.base_selection = {"type": "PATH"}
            mapping.roles = {"file": "name", "user": "auid"}
        return mapping

    if key == "macos:unifiedlog":
        text = (channel or "").lower()
        if any(word in text for word in ("exec", "process", "launch", "spawn")):
            mapping = _clone(_MACOS_PROC, confidence=CONF_SOURCE)
            mapping.source = "macOS unified log (process events)"
            return mapping
        if any(word in text for word in ("file", "write", "read")):
            mapping = _mapping(
                SigmaLogSource(category="file_event", product="macos"),
                ("Image", "TargetFilename"),
                {"image": "Image", "file": "TargetFilename"},
                confidence=CONF_SOURCE,
                source="macOS unified log (file events)",
            )
            return mapping
        mapping = _mapping(
            SigmaLogSource(product="macos", service="unifiedlog"),
            ("process", "subsystem", "category", "eventMessage"),
            {"command_line": "eventMessage"},
            confidence=CONF_SOURCE,
            source="macOS unified log",
            notes=("`service: unifiedlog` is not a SigmaHQ-standard logsource - align it with your pipeline.",),
        )
        return mapping

    if key.startswith("nsm:"):
        text = (channel or "").lower()
        for log_name, mapping in _ZEEK.items():
            if log_name in text:
                clone = _clone(mapping, confidence=CONF_EXACT, source=f"Zeek {log_name}.log")
                return clone
        clone = _clone(_ZEEK["conn"], confidence=CONF_SOURCE, source="network security monitoring (flow)")
        return clone

    if key.startswith("esxi:"):
        service = key.split(":", 1)[1]
        service = service if service in _ESXI_SERVICES else "syslog"
        return _mapping(
            SigmaLogSource(product="esxi", service=service),
            ("message", "user"),
            {"command_line": "message", "user": "user"},
            confidence=CONF_SOURCE,
            source=f"ESXi {service}",
            notes=("`product: esxi` is not a SigmaHQ-standard logsource - align it with your pipeline.",),
        )

    if key in CLOUD_SOURCES:
        mapping = _clone(CLOUD_SOURCES[key])
        operations = parse_api_operations(channel)
        if operations:
            field_name = mapping.roles.get("event_name")
            if field_name:
                mapping.base_selection = dict(mapping.base_selection)
                mapping.base_selection[field_name] = operations[0] if len(operations) == 1 else operations
                mapping.confidence = CONF_EXACT
        mapping.source = f"{name} ({channel})" if channel else name
        return mapping

    if key in _GENERIC_SAAS:
        vendor = key.split(":", 1)[1]
        return _mapping(
            SigmaLogSource(product=vendor, service="audit"),
            ("action", "actor", "ip_address"),
            {"event_name": "action", "user": "actor"},
            confidence=CONF_PLATFORM,
            source=f"{name} (no standard Sigma logsource)",
            notes=(f"Sigma has no standard logsource for {vendor}; adjust to your ingestion schema.",),
        )

    if key in STATIC_SOURCES:
        mapping = _clone(STATIC_SOURCES[key])
        mapping.source = name
        return mapping

    return None


def _prefix_fallback(name: str, channel: Optional[str], platform: Optional[str]) -> Optional[TelemetryMapping]:
    """Handle log source names ATT&CK invents on the fly.

    ATT&CK is not consistent about log source naming - alongside the ~60 names
    that repeat, there is a long tail like ``GCPAuditLogs:login.googleapis.com``
    or ``WinEventLog:Microsoft-Windows-Shell-Core``.  The vendor prefix is still
    machine-readable, so use it rather than throwing the reference away.
    """
    key = name.strip().lower()
    prefix = key.split(":", 1)[0] if ":" in key else key
    suffix = key.split(":", 1)[1] if ":" in key else ""

    if prefix in ("wineventlog", "windows", "etw"):
        service = re.sub(r"[^a-z0-9]+", "-", suffix).strip("-") or "application"
        codes = parse_event_codes(channel)
        base: dict[str, Any] = {"EventID": codes[0] if len(codes) == 1 else codes} if codes else {}
        return _mapping(
            SigmaLogSource(product="windows", service=service),
            ("EventID", "Provider_Name"),
            {"command_line": "Data"},
            base=base,
            confidence=CONF_SOURCE if codes else CONF_PLATFORM,
            source=f"{name} (channel-specific Windows log)",
            notes=(f"`service: {service}` is derived from the ATT&CK channel name - "
                   "map it to whatever your pipeline calls that Windows channel.",),
        )

    prefix_map = {
        "gcpauditlogs": "gcp:audit",
        "gcp": "gcp:audit",
        "aws": "aws:cloudtrail",
        "azure": "azure:audit",
        "m365": "m365:unified",
        "o365": "m365:unified",
        "kubernetes": "kubernetes:audit",
        "k8s": "kubernetes:audit",
        "okta": "saas:okta",
        "github": "saas:github",
    }
    if prefix in prefix_map:
        mapping = _clone(CLOUD_SOURCES[prefix_map[prefix]], confidence=CONF_PLATFORM)
        operations = parse_api_operations(channel)
        if operations:
            field_name = mapping.roles.get("event_name")
            if field_name:
                mapping.base_selection = {field_name: operations[0] if len(operations) == 1 else operations}
                mapping.confidence = CONF_SOURCE
        mapping.source = f"{name} (matched on the '{prefix}' prefix)"
        return mapping

    if prefix == "saas":
        vendor = re.sub(r"[^a-z0-9_]+", "", suffix) or "saas"
        return _mapping(
            SigmaLogSource(product=vendor, service="audit"),
            ("action", "actor", "ip_address"),
            {"event_name": "action", "user": "actor"},
            confidence=CONF_PLATFORM,
            source=f"{name} (no standard Sigma logsource)",
            notes=(f"Sigma has no standard logsource for {vendor}; adjust to your ingestion schema.",),
        )

    simple = {
        "linux": STATIC_SOURCES["linux:syslog"],
        "macos": STATIC_SOURCES["macos:osquery"],
        "fs": STATIC_SOURCES["fs:fileevents"],
        "nsm": _ZEEK["conn"],
        "docker": STATIC_SOURCES["docker:events"],
        "container": STATIC_SOURCES["docker:events"],
        "networkdevice": STATIC_SOURCES["networkdevice:syslog"],
        "auditd": _AUDITD_SYSCALL,
        "ebpf": STATIC_SOURCES["ebpf:syscalls"],
    }
    if prefix in simple:
        mapping = _clone(simple[prefix], confidence=CONF_PLATFORM)
        mapping.source = f"{name} (matched on the '{prefix}' prefix)"
        # "fs:plist" on a macOS analytic is macOS telemetry, whatever the
        # template it borrowed says.
        platform_product = PLATFORM_PRODUCT.get((platform or "").lower())
        if mapping.logsource.product in ("linux", "macos", "windows") and platform_product in ("linux", "macos", "windows"):
            mapping.logsource.product = platform_product
        return mapping

    return None


def _resolve_by_component(component: Optional[str], platform: Optional[str]) -> Optional[TelemetryMapping]:
    key = (component or "").strip().lower()
    if not key:
        return None
    platform_key = (platform or "").lower()
    windows_ok = platform_key in ("", "windows")
    if key in EXTERNAL_TELEMETRY:
        return TelemetryMapping(
            logsource=SigmaLogSource(),
            confidence=CONF_NONE,
            source=f"data component '{component}' (telemetry lives outside the log pipeline)",
        )

    if key in DATA_COMPONENTS:
        mapping = _clone(DATA_COMPONENTS[key])
        mapping.source = f"data component '{component}'"
        product = PLATFORM_PRODUCT.get((platform or "").lower())
        if product and product in ("windows", "linux", "macos"):
            mapping.logsource.product = product
        return mapping

    # The next two tables are Windows-channel specific: a "User Account
    # Authentication" component on Okta or GCP is not a 4624 event.
    if key in _SECURITY_COMPONENTS and windows_ok:
        codes = list(_SECURITY_COMPONENTS[key])
        mapping = _windows_event_mapping(codes, f"data component '{component}'")
        if mapping:
            mapping.confidence = CONF_COMPONENT
            return mapping

    if key in _SERVICE_COMPONENTS and windows_ok:
        mapping = _clone(SYSTEM_EVENTS[7045], confidence=CONF_COMPONENT)
        mapping.source = f"data component '{component}'"
        return mapping

    if key.startswith(_CLOUD_COMPONENT_PREFIXES):
        product = PLATFORM_PRODUCT.get((platform or "").lower(), "aws")
        service = {"aws": "cloudtrail", "azure": "activitylogs", "gcp": "gcp.audit",
                   "m365": "audit", "kubernetes": "audit"}.get(product, "cloudtrail")
        mapping = _clone(CLOUD_SOURCES.get(f"{product}:cloudtrail", CLOUD_SOURCES["aws:cloudtrail"]))
        mapping.logsource = SigmaLogSource(product=product, service=service)
        mapping.confidence = CONF_COMPONENT
        mapping.source = f"data component '{component}' on {platform or product}"
        return mapping

    return None


#: Last-resort telemetry per ATT&CK platform, used when ATT&CK offers no
#: analytic at all (roughly one technique in six) or names only sources we
#: cannot place.  Each entry is the log an analyst would reach for first.
PLATFORM_FALLBACK: dict[str, TelemetryMapping] = {
    "windows": _mapping(SigmaLogSource(category="process_creation", product="windows"),
                        _PROC_FIELDS, _PROC_ROLES, confidence=CONF_PLATFORM),
    "linux": _mapping(SigmaLogSource(category="process_creation", product="linux"),
                      _PROC_FIELDS, _PROC_ROLES, confidence=CONF_PLATFORM),
    "macos": _mapping(SigmaLogSource(category="process_creation", product="macos"),
                      _PROC_FIELDS, _PROC_ROLES, confidence=CONF_PLATFORM),
    "iaas": _clone(CLOUD_SOURCES["aws:cloudtrail"], confidence=CONF_PLATFORM),
    "identity provider": _clone(CLOUD_SOURCES["azure:signinlogs"], confidence=CONF_PLATFORM),
    "azure ad": _clone(CLOUD_SOURCES["azure:signinlogs"], confidence=CONF_PLATFORM),
    "office suite": _clone(CLOUD_SOURCES["m365:unified"], confidence=CONF_PLATFORM),
    "office 365": _clone(CLOUD_SOURCES["m365:unified"], confidence=CONF_PLATFORM),
    "saas": _clone(CLOUD_SOURCES["m365:unified"], confidence=CONF_PLATFORM),
    "google workspace": _clone(CLOUD_SOURCES["saas:googleworkspace"], confidence=CONF_PLATFORM),
    "containers": _clone(CLOUD_SOURCES["kubernetes:audit"], confidence=CONF_PLATFORM),
    "kubernetes": _clone(CLOUD_SOURCES["kubernetes:audit"], confidence=CONF_PLATFORM),
    "network devices": _clone(STATIC_SOURCES["networkdevice:syslog"], confidence=CONF_PLATFORM),
    "esxi": _mapping(SigmaLogSource(product="esxi", service="syslog"), ("message", "user"),
                     {"command_line": "message", "user": "user"}, confidence=CONF_PLATFORM),
}


def _platform_fallback(platform: Optional[str]) -> TelemetryMapping:
    mapping = PLATFORM_FALLBACK.get((platform or "").lower())
    if mapping is None:
        return TelemetryMapping(
            logsource=SigmaLogSource(),
            confidence=CONF_NONE,
            source="no usable telemetry hint in ATT&CK",
        )
    fallback = _clone(mapping, confidence=CONF_PLATFORM)
    fallback.source = f"platform fallback ({platform})"
    fallback.notes = fallback.notes + (
        "ATT&CK gave no usable telemetry hint for this technique - the log source is a "
        "platform-level guess and needs replacing.",
    )
    return fallback


def resolve_telemetry(
    log_source_name: Optional[str] = None,
    channel: Optional[str] = None,
    data_component: Optional[str] = None,
    platform: Optional[str] = None,
) -> TelemetryMapping:
    """Translate one ATT&CK log source reference into a Sigma logsource.

    Falls back through name -> data component -> platform, and always returns a
    :class:`TelemetryMapping` (possibly an unusable one with ``confidence``
    ``CONF_NONE``) rather than raising.
    """
    if (log_source_name or "").strip().lower() in EXTERNAL_TELEMETRY:
        return TelemetryMapping(
            logsource=SigmaLogSource(),
            confidence=CONF_NONE,
            source=f"'{log_source_name}' (telemetry lives outside the log pipeline)",
        )

    mapping = _resolve_by_name(log_source_name or "", channel, platform)
    if mapping is None:
        mapping = _resolve_by_component(data_component, platform)
    if mapping is None and log_source_name:
        mapping = _prefix_fallback(log_source_name, channel, platform)
    if mapping is None:
        mapping = _platform_fallback(platform)

    # A category-only mapping gains a product when ATT&CK told us the platform.
    product = PLATFORM_PRODUCT.get((platform or "").lower())
    if product and mapping.logsource.category and not mapping.logsource.product:
        if product in ("windows", "linux", "macos"):
            mapping.logsource.product = product

    if not mapping.source:
        mapping.source = log_source_name or data_component or "unknown"
    return mapping
