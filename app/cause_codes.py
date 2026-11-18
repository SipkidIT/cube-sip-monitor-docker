import re

SIP_CAUSE_MAP = {
    200: "Normal Call Clearing",
    400: "Bad Request (Malformed SIP)",
    401: "Unauthorized (Auth Required)",
    403: "Forbidden (Blocked by Carrier/PBX)",
    404: "Invalid / Unallocated Number",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout (No Response)",
    410: "Number Gone / Disconnected",
    415: "Unsupported Media Type",
    480: "Temporarily Unavailable / No Answer",
    481: "Call Leg / Transaction Does Not Exist",
    482: "Loop Detected",
    483: "Too Many Hops",
    484: "Address Incomplete (Missing Digits)",
    485: "Ambiguous Number",
    486: "User Busy",
    487: "Caller Hung Up Before Answer (Canceled)",
    488: "Codec / SDP Media Mismatch",
    491: "Request Pending (Glare)",
    500: "Server Internal Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable / Trunk Congestion",
    504: "Server Gateway Timeout",
    600: "Busy Everywhere",
    603: "Call Declined by Far End",
    604: "Number Does Not Exist Anywhere",
    606: "Session Not Acceptable",
}

Q850_CAUSE_MAP = {
    1: "Unallocated / Invalid Number",
    2: "No Route to Transit Network",
    3: "No Route to Destination",
    16: "Normal Call Clearing",
    17: "User Busy",
    18: "No User Responding (Ring Timeout)",
    19: "No Answer from User",
    20: "Subscriber Absent / Unregistered",
    21: "Call Rejected / Blocked",
    22: "Number Changed",
    27: "Destination Out of Order",
    28: "Invalid / Incomplete Number Format",
    29: "Facility Rejected",
    31: "Normal Unspecified",
    34: "No Circuit / Channel Available",
    38: "Network Out of Order",
    41: "Temporary Failure",
    42: "Switching Equipment Congestion",
    44: "Requested Channel Not Available",
    47: "Resource Unavailable",
    50: "Requested Facility Not Subscribed",
    57: "Bearer Capability Not Authorized",
    58: "Bearer Capability Not Available",
    63: "Service or Option Not Available",
    65: "Bearer Capability Not Implemented (Codec)",
    79: "Service Not Implemented",
    88: "Incompatible Destination (Media/Codec)",
    95: "Invalid Message",
    102: "Recovery on Timer Expiry (Timeout)",
    111: "Protocol Error",
    127: "Interworking Error",
}


def format_disconnect_reason(sip_status: int | None, raw_sip_text: str = "") -> str:
    """Return a human-readable disconnect reason combining SIP status and Q.850 Reason header."""
    q850_code = None
    match = re.search(r"Reason:\s*Q\.850\s*;\s*cause=(\d+)", raw_sip_text, re.IGNORECASE)
    if match:
        q850_code = int(match.group(1))

    sip_desc = SIP_CAUSE_MAP.get(sip_status) if sip_status else None
    q850_desc = Q850_CAUSE_MAP.get(q850_code) if q850_code is not None else None

    if sip_status and q850_code is not None:
        label = q850_desc or sip_desc or "Call Cleared"
        return f"{label} (SIP {sip_status} / Q.850 {q850_code})"
    if sip_status:
        label = sip_desc or "SIP Response"
        return f"{label} (SIP {sip_status})"
    if q850_code is not None:
        label = q850_desc or "Q.850 Cause"
        return f"{label} (Q.850 {q850_code})"
    return "Unknown / In Progress"
