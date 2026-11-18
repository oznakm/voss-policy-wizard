#@MetaDataStart
#@DetailDescriptionStart
###############################################################################
# VOSS INTER-VLAN ACCESS POLICY WIZARD
# Platform : VOSS / Fabric Engine
# Engine   : ExtremeCloud IQ Site Engine / XMC Python
# ACL type : inVlan - ACL ID = VLAN ID
# Author   : Ozan AKMUSTAFAOGLU
# Revision : 4.1
# Date     : November 2026
#
# WHAT IT DOES
#   Controls access between VLANs with an ingress VLAN ACL - type inVlan.
#   Subnets are discovered from show ip interface.
#
# TYPICAL SCENARIO - isolate a user VLAN, allow servers in VLAN 1
#   Step 1  Deny_ACL   Source 12   Destination VLAN ALL
#   Step 2  Allow_ACL  Source 12   Destination VLAN 1   Ports optional
#   Use Source ALL to isolate every user VLAN at once.
#   Run on all gateway switches together so the policy is identical.
#
# ACTIONS
#   Deny_ACL     Blocks the source to the destination.
#                No ports : all traffic.  Ports : only those ports.
#   Allow_ACL    Permits the source to the destination. Allow rules are
#                evaluated BEFORE deny rules, so an allow always wins.
#   Remove_ACL   Removes wizard rules toward the destination. Empty
#                destination or ALL removes every wizard rule, and the ACL
#                itself if nothing else is left.
#   Show_Report  Prints the access matrix. Makes no changes.
#
# FIELD FORMATS
#   VLAN list           12  |  12,15,18  |  20-25  |  ALL
#   Source Host/Subnet  10.30.6.100  |  10.30.6.0/25 - limits the rule to
#                       part of the source instead of the whole source
#   Destination Subnet  10.10.13.0/24  |  10.10.13.50  - overrides Dest VLAN
#   Ports               tcp:443 tcp:3389 udp:53 icmp  - empty means all
#   Excluded VLANs      VLANs never touched by ALL - FW transit, MGMT
#   Subnet Override     12:10.10.12.0/24 13:10.10.13.0/24
#
# RULE ORDER - first match wins
#   ACE 1-99      OWN_...  own subnet, always permitted first
#   ACE 100-899   ALW_ A_  allow rules and R_ automatic return rules
#   ACE 1000-1999 DNY_ D_  deny rules
#   default-action permit  everything else, including internet
#   Rules are recognised by name. Existing rules are never duplicated and
#   ACEs not created by this wizard are never modified.
#
# RETURN TRAFFIC
#   ACLs are stateless. When a port-limited allow from A to B is blocked on
#   the way back by a deny on B, the wizard adds a return rule on B that
#   permits only the replies - same port as source port. Return rules are
#   added and removed automatically on every run.
#
# NOTES
#   - A deny from A to B also breaks connections that B starts toward A,
#     because the replies are dropped on A.
#   - A port ACL takes precedence over a VLAN ACL on the same port.
#   - Verify syntax on your VOSS release. Start with Show_Report and Dry Run.
###############################################################################
#@DetailDescriptionEnd
#@ScriptDescription "VOSS Inter-VLAN Access Policy Wizard"
#
#@SectionStart (description = "1 - Policy")
#@VariableFieldLabel (description = "Action *",
#  type = String,
#  required = yes,
#  validValues = [Deny_ACL,Allow_ACL,Remove_ACL,Show_Report],
#  scope = global
#  )
set var aclAction Show_Report
#@SectionEnd
#
#@SectionStart (description = "2 - Source and Destination")
#@VariableFieldLabel (description = "Source VLAN * - e.g. 12 or 12-15 or ALL",
#  type = String,
#  required = no,
#  scope = global
#  )
set var aclSrcVlan ALL
#@VariableFieldLabel (description = "Source Host/Subnet - optional CIDR or host IP",
#  type = String,
#  required = no,
#  scope = global
#  )
set var aclSrcSubnet none
#@VariableFieldLabel (description = "Destination VLAN - e.g. 13 or 1 or ALL",
#  type = String,
#  required = no,
#  scope = global
#  )
set var aclDstVlan ALL
#@VariableFieldLabel (description = "Destination Subnet - optional CIDR or host IP",
#  type = String,
#  required = no,
#  scope = global
#  )
set var aclDstSubnet none
#@VariableFieldLabel (description = "Ports - optional e.g. tcp:443 udp:53 icmp",
#  type = String,
#  required = no,
#  scope = global
#  )
set var aclPorts none
#@SectionEnd
#
#@SectionStart (description = "3 - Options")
#@VariableFieldLabel (description = "Excluded VLANs - optional e.g. FW transit or MGMT",
#  type = String,
#  required = no,
#  scope = global
#  )
set var aclExcludeVlan none
#@VariableFieldLabel (description = "Subnet Override - optional e.g. 12:10.10.12.0/24",
#  type = String,
#  required = no,
#  scope = global
#  )
set var aclSubnetOverride none
#@SectionEnd
#
#@SectionStart (description = "4 - Execution")
#@VariableFieldLabel (description = "Dry Run * - yes shows the plan only",
#  type = String,
#  required = yes,
#  validValues = [yes,no],
#  scope = global
#  )
set var aclDryRun yes
#@VariableFieldLabel (description = "Save Config *",
#  type = String,
#  required = yes,
#  validValues = [no,yes],
#  scope = global
#  )
set var aclSaveConfig no
#@SectionEnd
#@MetaDataEnd

MODE = "VLAN"
SRC_VAR = "aclSrcVlan"

import re

VERSION = "4.1"
AUTHOR = "Ozan AKMUSTAFAOGLU"

OWN_RANGE = (1, 99)
ALW_RANGE = (100, 899)
DNY_RANGE = (1000, 1999)
PORT_ACL_POOL = (1500, 1799)
ISID_ACL_POOL = (1800, 2047)
LINE = "=" * 78
SUB = "-" * 78
TITLES = {"VLAN": "VOSS Inter-VLAN Access Policy Wizard",
          "PORT": "VOSS Port Access Policy Wizard",
          "ISID": "VOSS I-SID Access Policy Wizard"}

# v3/v4 rule names : ALW_V13_TCP443   DNY_S10_10_13_0_24
OLD_RE = re.compile(r"^(ALW|DNY)_(V\d+|S\d+_\d+_\d+_\d+_\d+)(?:_(TCP\d+|UDP\d+|ICMP))?$")
# v4.1 rule names: A_<src>_<dst>_<port>  D_<src>_<dst>  R_<remote>_<local>_<port>
CODE = r"(?:V\d+|H[0-9A-F]{8}|N[0-9A-F]{10})"
NEW_RE = re.compile(r"^([ADR])_(%s)_(%s)(?:_(T\d+|U\d+|I))?$" % (CODE, CODE))


def out(s=""):
    print(s)


class InputError(Exception):
    pass


class CliError(Exception):
    pass


def var(key, default=""):
    """Safe read from emc_vars. Never writes to emc_vars."""
    try:
        val = emc_vars[key]
    except Exception:
        return default
    if val is None:
        return default
    val = str(val).strip()
    if val == "" or val.lower() in ("none", "null"):
        return default
    return val


###############################################################################
# IP helpers
###############################################################################

IP_RE = r"\d{1,3}(?:\.\d{1,3}){3}"


def ip2int(ip):
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and int(p) <= 255 for p in parts):
        raise InputError("Invalid IP address: %s" % ip)
    n = 0
    for p in parts:
        n = (n << 8) | int(p)
    return n


def int2ip(n):
    return ".".join([str((n >> s) & 0xFF) for s in (24, 16, 8, 0)])


def prefix2mask(prefix):
    return int2ip((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0)


def mask2prefix(mask):
    return bin(ip2int(mask)).count("1")


def network_of(ip, mask):
    return int2ip(ip2int(ip) & ip2int(mask))


def cidr(net, mask):
    p = mask2prefix(mask)
    return net if p == 32 else "%s/%d" % (net, p)


def contains(outer, inner):
    """outer, inner = (net, mask)"""
    return (mask2prefix(outer[1]) <= mask2prefix(inner[1])
            and (ip2int(inner[0]) & ip2int(outer[1])) == ip2int(outer[0]))


###############################################################################
# Input parsing
###############################################################################

def parse_num_list(text, field, lo, hi, allow_all=True, max_items=4094):
    text = (text or "").strip()
    if not text:
        raise InputError("%s is required" % field)
    if text.upper() in ("ALL", "TUMU", "ANY"):
        if not allow_all:
            raise InputError("%s cannot be ALL" % field)
        return "ALL"
    result = set()
    for tok in re.split(r"[,;\s]+", text):
        if not tok:
            continue
        m = re.match(r"^(\d+)-(\d+)$", tok)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if a > b or b - a >= max_items:
                raise InputError("%s: invalid range %s" % (field, tok))
            result.update(range(a, b + 1))
        elif tok.isdigit():
            result.add(int(tok))
        else:
            raise InputError("%s: cannot parse '%s'" % (field, tok))
    for v in result:
        if v < lo or v > hi:
            raise InputError("%s: %d is out of range %d-%d" % (field, v, lo, hi))
    if len(result) > max_items:
        raise InputError("%s: too many values" % field)
    return sorted(result)


def parse_vlan_list(text, field, allow_all=True):
    return parse_num_list(text, field, 1, 4094, allow_all)


def port_sort_key(p):
    return tuple([int(x) for x in p.split("/")])


def parse_port_list(text, field):
    text = (text or "").strip()
    if not text:
        raise InputError("%s is required" % field)
    if text.upper() in ("ALL", "TUMU", "ANY"):
        raise InputError("%s cannot be ALL - list the ports explicitly" % field)
    ports = set()
    for tok in re.split(r"[,;\s]+", text):
        if not tok:
            continue
        m = re.match(r"^(\d+(?:/\d+)?)/(\d+)(?:-(?:\1/)?(\d+))?$", tok)
        if not m:
            raise InputError("%s: cannot parse '%s' - e.g. 1/5 or 1/5-1/8" % (field, tok))
        a = int(m.group(2))
        b = int(m.group(3)) if m.group(3) else a
        if a > b or b - a > 128:
            raise InputError("%s: invalid range %s" % (field, tok))
        for i in range(a, b + 1):
            ports.add("%s/%d" % (m.group(1), i))
    return sorted(ports, key=port_sort_key)


def expand_port_text(text):
    res = set()
    for tok in re.split(r"[,\s]+", text.strip()):
        m = re.match(r"^(\d+(?:/\d+)?)/(\d+)(?:-(?:\d+(?:/\d+)?/)?(\d+))?$", tok)
        if m:
            a = int(m.group(2))
            b = int(m.group(3)) if m.group(3) else a
            for i in range(a, b + 1):
                res.add("%s/%d" % (m.group(1), i))
    return res


def parse_subnet(text, field):
    text = text.strip()
    m = re.match(r"^(%s)(?:/(\d+))?$" % IP_RE, text)
    if not m:
        raise InputError("%s: cannot parse '%s' - e.g. 10.10.13.0/24 or 10.10.13.50" % (field, text))
    prefix = int(m.group(2)) if m.group(2) else 32
    if prefix > 32:
        raise InputError("%s: invalid prefix /%d" % (field, prefix))
    mask = prefix2mask(prefix)
    return network_of(m.group(1), mask), mask


def parse_ports(text):
    """'' -> [None] = all traffic;  'tcp:443 icmp' -> [('tcp','443'),('icmp',None)]"""
    text = (text or "").strip()
    if not text or text.lower() == "any":
        return [None]
    res = []
    for tok in re.split(r"[,;\s]+", text.lower()):
        if not tok:
            continue
        if tok == "icmp":
            p = ("icmp", None)
        else:
            m = re.match(r"^(tcp|udp):(\d+)$", tok)
            if not m or not (1 <= int(m.group(2)) <= 65535):
                raise InputError("Ports: cannot parse '%s' - e.g. tcp:443 udp:53 icmp" % tok)
            p = (m.group(1), m.group(2))
        if p not in res:
            res.append(p)
    return res or [None]


def parse_override(text):
    res = {}
    for tok in re.split(r"[,;\s]+", text or ""):
        if not tok:
            continue
        m = re.match(r"^(\d+)[:=](%s)/(\d+)$" % IP_RE, tok)
        if not m:
            raise InputError("Subnet Override: cannot parse '%s' - e.g. 12:10.10.12.0/24" % tok)
        mask = prefix2mask(int(m.group(3)))
        res[int(m.group(1))] = (network_of(m.group(2), mask), mask)
    return res


# ports: tuple ('tcp','443')  <->  label 'TCP443'  <->  code 'T443'

def port_label(p):
    if p is None:
        return ""
    return p[0].upper() if p[1] is None else "%s%s" % (p[0].upper(), p[1])


def port_code(p):
    if p is None:
        return ""
    return p[0][0].upper() + (p[1] or "")


def label_to_port(label):
    if not label:
        return None
    if label == "ICMP":
        return ("icmp", None)
    return (label[:3].lower(), label[3:])


def code_to_label(c):
    if not c:
        return ""
    if c == "I":
        return "ICMP"
    return {"T": "TCP", "U": "UDP"}[c[0]] + c[1:]


def compress(nums):
    nums = sorted(nums)
    if not nums:
        return ""
    parts, start, prev = [], nums[0], nums[0]
    for n in nums[1:] + [None]:
        if n is not None and n == prev + 1:
            prev = n
            continue
        parts.append(str(start) if start == prev else "%d-%d" % (start, prev))
        if n is not None:
            start = prev = n
    return ",".join(parts)


###############################################################################
# Network objects and rule names
###############################################################################

class Net(object):
    """A VLAN, a subnet or a host used as source or destination of a rule."""

    def __init__(self, net, mask, vlan=None):
        self.net, self.mask, self.vlan = net, mask, vlan

    @property
    def nm(self):
        return (self.net, self.mask)

    @property
    def code(self):
        if self.vlan is not None:
            return "V%d" % self.vlan
        p = mask2prefix(self.mask)
        h = "%08X" % ip2int(self.net)
        return ("H" + h) if p == 32 else ("N%s%02X" % (h, p))

    @property
    def key(self):
        """v3/v4 compatible destination key"""
        if self.vlan is not None:
            return "V%d" % self.vlan
        return "S%s_%d" % (self.net.replace(".", "_"), mask2prefix(self.mask))

    def ident(self):
        return ("V", self.vlan) if self.vlan is not None else ("N", self.net, mask2prefix(self.mask))

    def label(self):
        return ("VLAN %d" % self.vlan) if self.vlan is not None else cidr(self.net, self.mask)


def net_vlan(vlan, subnets):
    net, mask = subnets[vlan]
    return Net(net, mask, vlan)


def decode(code, subnets):
    """Rule code or v3/v4 key -> Net, or None when a VLAN subnet is unknown."""
    if code.startswith("V"):
        v = int(code[1:])
        return net_vlan(v, subnets) if v in subnets else None
    if code.startswith("H"):
        return Net(int2ip(int(code[1:9], 16)), "255.255.255.255")
    if code.startswith("N"):
        return Net(int2ip(int(code[1:9], 16)), prefix2mask(int(code[9:11], 16)))
    p = code[1:].split("_")
    return Net(".".join(p[:4]), prefix2mask(int(p[4])))


def code_text(code, subnets):
    if code.startswith("V"):
        return "VLAN " + code[1:]
    n = decode(code, subnets)
    return n.label() if n else code


def ident_of(code):
    if code.startswith("V"):
        return ("V", int(code[1:]))
    n = decode(code, {})
    return ("N", n.net, mask2prefix(n.mask))


def rule_name(kind, src, dst, port):
    """kind ALW / DNY. Without source keeps the v3/v4 format."""
    if src is None:
        return "%s_%s" % (kind, dst.key) + ("_" + port_label(port) if port else "")
    return "%s_%s_%s" % (kind[0], src.code, dst.code) + ("_" + port_code(port) if port else "")


def return_name(remote, local, port):
    return "R_%s_%s_%s" % (remote.code, local.code, port_code(port))


class Rule(object):
    def __init__(self, ace, kind, src, dst, plabel):
        self.ace, self.kind, self.src, self.dst, self.plabel = ace, kind, src, dst, plabel


def parse_rule(ace, name):
    m = OLD_RE.match(name)
    if m:
        return Rule(ace, m.group(1), None, m.group(2), m.group(3) or "")
    m = NEW_RE.match(name)
    if m:
        kind = {"A": "ALW", "D": "DNY", "R": "RET"}[m.group(1)]
        return Rule(ace, kind, m.group(2), m.group(3), code_to_label(m.group(4) or ""))
    return None


def is_own(name):
    return name == "OWN_SUBNET" or name.startswith("OWN_")


###############################################################################
# CLI
###############################################################################

ERR_RE = re.compile(r"(^|\n)\s*(%|Error|ERROR|Invalid|Cannot|Failed)", re.M)


def cli(cmd):
    r = emc_cli.send(cmd)
    if r is None:
        raise CliError("No response from device: %s" % cmd)
    return r


def show(cmd):
    return cli(cmd).getOutput() or ""


def configure(cmds):
    cli("enable")
    cli("configure terminal")
    try:
        for c in cmds:
            r = cli(c)
            o = r.getOutput() or ""
            if not r.isSuccess() or ERR_RE.search(o):
                out("  FAIL -> " + c)
                out(o)
                raise CliError("Command failed: %s" % c)
            out("  OK   -> " + c)
    finally:
        cli("end")


###############################################################################
# Device state
###############################################################################

def discover_subnets():
    text = show("show ip interface")
    res = {}
    for m in re.finditer(r"^\s*Vlan(\d+)\s+(%s)\s+(%s)" % (IP_RE, IP_RE), text, re.M):
        vid = int(m.group(1))
        if vid not in res:
            res[vid] = (network_of(m.group(2), m.group(3)), m.group(3))
    return res


def discover_isids():
    """{isid: vlan} from 'show vlan i-sid'"""
    text = show("show vlan i-sid")
    res = {}
    for m in re.finditer(r"^\s*(\d{1,4})\s+(\d{1,8})\b", text, re.M):
        vlan, isid = int(m.group(1)), int(m.group(2))
        if isid > 0 and 1 <= vlan <= 4094:
            res[isid] = vlan
    return res


class FilterState(object):
    def __init__(self, text):
        self.acls = set(int(x) for x in re.findall(r"^\s*filter acl (\d+) (?:enable|type|name)", text, re.M))
        self.vlan_to_acl = {}
        for a, v in re.findall(r"^\s*filter acl vlan (\d+) (\d+)", text, re.M):
            self.vlan_to_acl[int(v)] = int(a)
        self.isid_to_acl = {}
        for a, i in re.findall(r"^\s*filter acl i-sid (\d+) (\d+)", text, re.M):
            self.isid_to_acl[int(i)] = int(a)
        self.port_to_acl = {}
        for a, pl in re.findall(r"^\s*filter acl port (\d+) (\S+)", text, re.M):
            for p in expand_port_text(pl):
                self.port_to_acl[p] = int(a)
        self.aces = {}
        for a, e, n in re.findall(r'^\s*filter acl ace (\d+) (\d+) name "?([^"\r\n]+?)"?\s*$', text, re.M):
            self.aces.setdefault(int(a), {})[int(e)] = n.strip()
        for a, e in re.findall(r"^\s*filter acl ace (\d+) (\d+) enable", text, re.M):
            self.aces.setdefault(int(a), {}).setdefault(int(e), "")
        self.reserved = {}
        self.reserved_acls = set()

    def find(self, acl, name):
        for e, n in self.aces.get(acl, {}).items():
            if n == name:
                return e
        return None

    def rules(self, acl):
        res = []
        for e, n in sorted(self.aces.get(acl, {}).items()):
            r = parse_rule(e, n)
            if r:
                res.append(r)
        return res

    def alloc(self, acl, rng):
        used = set(self.aces.get(acl, {}).keys()) | self.reserved.setdefault(acl, set())
        for i in range(rng[0], rng[1] + 1):
            if i not in used:
                self.reserved[acl].add(i)
                return i
        raise InputError("ACL %d has no free ACE ID in range %d-%d" % (acl, rng[0], rng[1]))

    def alloc_acl(self, pool):
        used = self.acls | self.reserved_acls | set(self.vlan_to_acl.values())
        for i in range(pool[0], pool[1] + 1):
            if i not in used:
                self.reserved_acls.add(i)
                return i
        raise InputError("No free ACL ID in range %d-%d" % pool)


def read_filter_config():
    text = show("show running-config module filter")
    if "filter acl" not in text:
        full = show("show running-config")
        text = "\n".join([l for l in full.splitlines() if "filter acl" in l])
    return FilterState(text)


###############################################################################
# Bindings - where an ACL is attached
###############################################################################

class Binding(object):
    def __init__(self, kind, ident, own, title):
        self.kind, self.ident, self.own, self.title = kind, ident, own, title

    def existing_acl(self, st):
        if self.kind == "VLAN":
            return st.vlan_to_acl.get(self.ident)
        if self.kind == "PORT":
            return st.port_to_acl.get(self.ident)
        return st.isid_to_acl.get(self.ident)

    def acl_name(self):
        if self.kind == "VLAN":
            return "ACL_V%d_IN" % self.ident
        if self.kind == "PORT":
            return "ACL_P%s_IN" % self.ident.replace("/", "_")
        return "ACL_I%d_IN" % self.ident

    def create_cmd(self, acl):
        if self.kind == "VLAN":
            return "filter acl %d type inVlan name %s" % (acl, self.acl_name())
        if self.kind == "PORT":
            return "filter acl %d type inPort name %s" % (acl, self.acl_name())
        return "filter acl %d type inVsn matchType both name %s" % (acl, self.acl_name())

    def bind_cmd(self, acl):
        if self.kind == "VLAN":
            return "filter acl vlan %d %d" % (acl, self.ident)
        if self.kind == "PORT":
            return "filter acl port %d %s" % (acl, self.ident)
        return "filter acl i-sid %d %d" % (acl, self.ident)

    def unbind_cmd(self, acl):
        return "no " + self.bind_cmd(acl)

    def _map(self, st):
        return {"VLAN": st.vlan_to_acl, "PORT": st.port_to_acl, "ISID": st.isid_to_acl}[self.kind]

    def mark_bound(self, st, acl):
        self._map(st)[self.ident] = acl

    def unmark(self, st, acl):
        self._map(st).pop(self.ident, None)
        st.acls.discard(acl)
        st.aces.pop(acl, None)

    def other_users(self, st, acl):
        res = []
        res += ["VLAN %d" % v for v, a in st.vlan_to_acl.items() if a == acl and not (self.kind == "VLAN" and v == self.ident)]
        res += ["port %s" % p for p, a in st.port_to_acl.items() if a == acl and not (self.kind == "PORT" and p == self.ident)]
        res += ["I-SID %d" % i for i, a in st.isid_to_acl.items() if a == acl and not (self.kind == "ISID" and i == self.ident)]
        return res


###############################################################################
# Planner
###############################################################################

class Planner(object):
    def __init__(self, state, subnets, isids):
        self.st = state
        self.sn = subnets
        self.isids = isids
        self.groups = []

    # --- low level
    def _ace(self, acl, name, action, dst, port, rng, src=None, src_port=False):
        if len(name) > 32:
            raise InputError("Rule name too long for VOSS: %s" % name)
        ace = self.st.alloc(acl, rng)
        c = ['filter acl ace %d %d name %s' % (acl, ace, name),
             'filter acl ace action %d %d %s count' % (acl, ace, action)]
        if src is not None:
            c.append('filter acl ace ip %d %d src-ip mask %s %s' % (acl, ace, src.net, src.mask))
        c.append('filter acl ace ip %d %d dst-ip mask %s %s' % (acl, ace, dst.net, dst.mask))
        if port:
            c.append('filter acl ace ip %d %d ip-protocol-type eq %s' % (acl, ace, port[0]))
            if port[1]:
                c.append('filter acl ace protocol %d %d %s eq %s'
                         % (acl, ace, "src-port" if src_port else "dst-port", port[1]))
        c.append('filter acl ace %d %d enable' % (acl, ace))
        self.st.aces.setdefault(acl, {})[ace] = name
        return c

    def _del(self, acl, ace):
        self.st.aces.get(acl, {}).pop(ace, None)
        return ['no filter acl ace %d %d' % (acl, ace)]

    def _ensure_acl(self, b, notes, cmds, binds):
        st = self.st
        acl = b.existing_acl(st)
        if acl is None:
            if b.kind == "VLAN":
                acl = b.ident
                if acl > 2048:
                    raise InputError("VLAN %d: ACL ID cannot exceed 2048, bind an ACL to this VLAN manually first" % b.ident)
            else:
                acl = st.alloc_acl(PORT_ACL_POOL if b.kind == "PORT" else ISID_ACL_POOL)
        others = b.other_users(st, acl)
        if others:
            raise InputError("ACL %d is shared with %s - edit it manually or give %s its own ACL"
                             % (acl, ", ".join(others[:3]), b.title))
        if acl not in st.acls:
            notes.append("Create ACL %d  %s" % (acl, b.create_cmd(acl).split(" type ")[1]))
            cmds += [b.create_cmd(acl),
                     'filter acl set %d default-action permit' % acl,
                     'filter acl %d enable' % acl]
            st.acls.add(acl)
        for name, n in b.own:
            if st.find(acl, name) is None:
                notes.append("Permit own subnet %s" % cidr(n.net, n.mask))
                cmds += self._ace(acl, name, "permit", n, None, OWN_RANGE)
        if b.existing_acl(st) != acl:
            binds.append(b.bind_cmd(acl))
            b.mark_bound(st, acl)
            notes.append("Bind ACL %d to %s" % (acl, b.title))
        return acl

    # --- actions
    def _add_rules(self, acl, kind, src, dests, ports, notes, cmds):
        action = "permit" if kind == "ALW" else "deny"
        rng = ALW_RANGE if kind == "ALW" else DNY_RANGE
        src_code = src.code if src is not None else None
        origins = [src] if src is not None else [n for name, n in self._own_of(acl)]
        was_blocked = dict((d.ident(), any(self._blocked(acl, o, d) for o in origins)) for d in dests)
        added, skipped, cleaned = [], [], 0
        for d in dests:
            full_name = rule_name(kind, src, d, None)
            for p in ports:
                name = rule_name(kind, src, d, p)
                if self.st.find(acl, name) is not None or (p and self.st.find(acl, full_name) is not None):
                    skipped.append((d, p))
                    continue
                if p is None:
                    for r in self.st.rules(acl):
                        if (r.kind == kind and r.plabel and r.src == src_code
                                and ident_of(r.dst) == d.ident()):
                            cmds += self._del(acl, r.ace)
                            cleaned += 1
                cmds += self._ace(acl, name, action, d, p, rng, src)
                added.append((d, p))
        verb = "ALLOW" if kind == "ALW" else "DENY "
        frm = ("from %s to " % src.label()) if src is not None else ""
        if added:
            notes.append("%s %s%s" % (verb, frm, summarize(added)))
        if skipped:
            notes.append("Already in place: %s%s" % (frm, summarize(skipped)))
        if cleaned:
            notes.append("Replaced %d port rule(s) with a full rule" % cleaned)
        if kind == "ALW" and added:
            uncovered = [d for d, p in added if not was_blocked[d.ident()]]
            if uncovered:
                notes.append("Info: no deny rule covers %s - traffic was already permitted"
                             % ", ".join(sorted(set(d.label() for d in uncovered))))

    def _remove_rules(self, b, src, dests, ports, notes, cmds, unbinds):
        acl = b.existing_acl(self.st)
        if acl is None:
            notes.append("No policy on %s - nothing to remove" % b.title)
            return
        others = b.other_users(self.st, acl)
        if others:
            raise InputError("ACL %d is shared with %s - edit it manually" % (acl, ", ".join(others[:3])))
        idents = None if dests is None else set(d.ident() for d in dests)
        labels = None if ports == [None] else set(port_label(p) for p in ports)
        removed = []
        for r in self.st.rules(acl):
            if r.kind == "RET":
                continue
            if src is not None and r.src != src.code:
                continue
            if idents is not None and ident_of(r.dst) not in idents:
                continue
            if labels is not None and r.plabel not in labels:
                continue
            cmds += self._del(acl, r.ace)
            removed.append(self.st_name(r))
        if removed:
            notes.append("REMOVE %d rule(s): %s" % (len(removed), shorten(removed)))
        else:
            notes.append("No matching rule found")
        names = self.st.aces.get(acl, {}).values()
        left = [n for n in names if not is_own(n) and not (parse_rule(0, n) and parse_rule(0, n).kind == "RET")]
        rets = [n for n in names if parse_rule(0, n) and parse_rule(0, n).kind == "RET"]
        if not left and not rets:
            notes.append("ACL %d is now empty - unbind and delete" % acl)
            for e, n in sorted(self.st.aces.get(acl, {}).items()):
                cmds += self._del(acl, e)
            unbinds += [b.unbind_cmd(acl), 'no filter acl %d' % acl]
            b.unmark(self.st, acl)
        elif not left:
            notes.append("ACL %d kept - it holds %d return rule(s) for other VLANs" % (acl, len(rets)))

    def st_name(self, r):
        if r.src is None:
            return "%s %s%s" % (r.kind, code_text(r.dst, self.sn), " " + r.plabel if r.plabel else "")
        return "%s %s > %s%s" % (r.kind, code_text(r.src, self.sn), code_text(r.dst, self.sn),
                                 " " + r.plabel if r.plabel else "")

    def add(self, b, action, src, dests, ports):
        notes, cmds, binds, unbinds = [], [], [], []
        if action == "Remove_ACL":
            self._remove_rules(b, src, dests, ports, notes, cmds, unbinds)
        else:
            acl = self._ensure_acl(b, notes, cmds, binds)
            self._add_rules(acl, "ALW" if action == "Allow_ACL" else "DNY", src, dests, ports, notes, cmds)
        self.groups.append((b.title, notes, cmds + binds + unbinds))

    # --- return traffic
    def _own_of(self, acl):
        """Origin subnets of an ACL: [(code, Net)]"""
        st, res = self.st, []
        for v, a in st.vlan_to_acl.items():
            if a == acl and v in self.sn:
                res.append(("V%d" % v, net_vlan(v, self.sn)))
        for i, a in st.isid_to_acl.items():
            v = self.isids.get(i)
            if a == acl and v in self.sn:
                res.append(("V%d" % v, net_vlan(v, self.sn)))
        if any(a == acl for a in st.port_to_acl.values()):
            for n in st.aces.get(acl, {}).values():
                m = re.match(r"^OWN_V(\d+)$", n)
                if m and int(m.group(1)) in self.sn:
                    res.append(("V" + m.group(1), net_vlan(int(m.group(1)), self.sn)))
        return res

    def _blocked(self, acl, sender, target):
        """Would traffic from sender to target be dropped by full rules of acl?"""
        for r in self.st.rules(acl):
            if r.plabel or r.kind == "RET":
                continue
            s = decode(r.src, self.sn) if r.src else None
            d = decode(r.dst, self.sn)
            if d is None or (s is not None and not contains(s.nm, sender.nm)):
                continue
            if contains(d.nm, target.nm):
                return r.kind == "DNY"
        return False

    def _vlan_of(self, n):
        if n.vlan is not None:
            return n.vlan
        best = None
        for v, sn in self.sn.items():
            if contains(sn, n.nm) and (best is None or mask2prefix(sn[1]) > mask2prefix(self.sn[best][1])):
                best = v
        return best

    def reconcile_returns(self):
        """Every port-limited allow whose replies are dropped by a deny on the far
        side gets a return rule there. Return rules no longer needed are removed."""
        st = self.st
        desired, notes, warn = {}, [], set()
        acls = set(st.vlan_to_acl.values()) | set(st.isid_to_acl.values()) | set(st.port_to_acl.values())
        for acl in sorted(acls):
            for r in st.rules(acl):
                if r.kind != "ALW":
                    continue
                remote = decode(r.dst, self.sn)
                if remote is None:
                    continue
                if r.src:
                    origins = [decode(r.src, self.sn)]
                else:
                    origins = [n for c, n in self._own_of(acl)]
                v_r = self._vlan_of(remote)
                acl_r = st.vlan_to_acl.get(v_r)
                if acl_r is None or acl_r == acl:
                    continue
                for o in origins:
                    if o is None or not self._blocked(acl_r, remote, o):
                        continue
                    if not r.plabel:
                        warn.add("ACL %d drops replies from %s to %s - allow specific ports instead"
                                 % (acl_r, remote.label(), o.label()))
                        continue
                    port = label_to_port(r.plabel)
                    desired[(acl_r, return_name(remote, o, port))] = (remote, o, port)
        cmds = []
        for acl in sorted(acls):
            for r in st.rules(acl):
                if r.kind == "RET":
                    name = st.aces[acl][r.ace]
                    if (acl, name) not in desired:
                        cmds += self._del(acl, r.ace)
                        notes.append("REMOVE return rule in ACL %d: %s > %s %s - no longer needed"
                                     % (acl, code_text(r.src, self.sn), code_text(r.dst, self.sn), r.plabel))
        for (acl_r, name), (remote, o, port) in sorted(desired.items()):
            if st.find(acl_r, name) is None:
                cmds += self._ace(acl_r, name, "permit", o, port, ALW_RANGE, remote, src_port=True)
                notes.append("ADD return rule in ACL %d: replies %s %s > %s"
                             % (acl_r, remote.label(), port_label(port), o.label()))
        notes += ["Warning: " + w for w in sorted(warn)]
        if notes:
            self.groups.append(("Return traffic - stateless ACL replies", notes, cmds))


def summarize(pairs):
    by_ports = {}
    for d, p in pairs:
        by_ports.setdefault(port_label(p), []).append(d)
    parts = []
    for pl in sorted(by_ports):
        ds = by_ports[pl]
        vl = [d.vlan for d in ds if d.vlan is not None]
        txt = (["VLAN " + compress(vl)] if vl else []) + [d.label() for d in ds if d.vlan is None]
        parts.append(" ".join(txt) + ("  port " + pl if pl else "  all traffic"))
    return "  |  ".join(parts)


def shorten(items, n=6):
    return ", ".join(items[:n]) + (" ... +%d" % (len(items) - n) if len(items) > n else "")


###############################################################################
# Report
###############################################################################

def fmt_cell(rules, kind, others, subnets):
    full_v, ported, subs, scoped = [], {}, [], []
    for r in rules:
        if r.kind != kind:
            continue
        if r.src:
            scoped.append("%s>%s%s" % (code_text(r.src, subnets), code_text(r.dst, subnets),
                                       " " + r.plabel if r.plabel else ""))
        elif r.plabel:
            ported.setdefault(r.dst, []).append(r.plabel)
        elif r.dst.startswith("V"):
            full_v.append(int(r.dst[1:]))
        else:
            subs.append(code_text(r.dst, subnets))
    parts = []
    if full_v:
        if others and set(others) <= set(full_v):
            parts.append("ALL VLANs")
        else:
            parts.append("VLAN " + compress(full_v))
    parts += subs
    for k in sorted(ported):
        parts.append("%s %s" % (code_text(k, subnets), " ".join(sorted(ported[k]))))
    parts += scoped
    return "; ".join(parts) or "-"


def policy_cells(state, acl, others, subnets):
    rules = state.rules(acl)
    den = fmt_cell(rules, "DNY", others, subnets)
    alw = fmt_cell(rules, "ALW", None, subnets)
    extra = []
    rets = len([r for r in rules if r.kind == "RET"])
    if rets:
        extra.append("+%d return" % rets)
    custom = len([n for n in state.aces.get(acl, {}).values() if not is_own(n) and not parse_rule(0, n)])
    if custom:
        extra.append("+%d custom ACE" % custom)
    if extra:
        alw = (alw + "  " if alw != "-" else "") + " ".join(extra)
    return den, alw


def report(state, subnets, scope, isids):
    out(SUB)
    out("ACCESS MATRIX   default: permit   allow rules are evaluated before deny")
    out(SUB)
    if MODE == "VLAN":
        out("%-6s %-18s %-30s %s" % ("VLAN", "SUBNET", "DENIED", "ALLOWED"))
        for v in sorted(scope):
            acl = state.vlan_to_acl.get(v)
            if acl is None:
                out("%-6d %-18s %-30s %s" % (v, cidr(*subnets[v]), "-", "no policy"))
                continue
            den, alw = policy_cells(state, acl, [u for u in scope if u != v], subnets)
            out("%-6d %-18s %-30s %s" % (v, cidr(*subnets[v]), den, alw))
    elif MODE == "PORT":
        ports = sorted(state.port_to_acl.keys(), key=port_sort_key)
        if not ports:
            out("No port ACL found on this device.")
        out("%-8s %-6s %-30s %s" % ("PORT", "ACL", "DENIED", "ALLOWED"))
        for p in ports:
            acl = state.port_to_acl[p]
            own = [int(n[5:]) for n in state.aces.get(acl, {}).values() if re.match(r"^OWN_V\d+$", n)]
            den, alw = policy_cells(state, acl, [u for u in scope if u not in own], subnets)
            out("%-8s %-6d %-30s %s" % (p, acl, den, alw))
    else:
        out("%-10s %-6s %-18s %-6s %-26s %s" % ("I-SID", "VLAN", "SUBNET", "ACL", "DENIED", "ALLOWED"))
        for i in sorted(set(isids.keys()) | set(state.isid_to_acl.keys())):
            v = isids.get(i)
            sn = cidr(*subnets[v]) if v in subnets else "-"
            acl = state.isid_to_acl.get(i)
            if acl is None:
                out("%-10d %-6s %-18s %-6s %-26s %s" % (i, v or "-", sn, "-", "-", "no policy"))
                continue
            den, alw = policy_cells(state, acl, [u for u in scope if u != v], subnets)
            out("%-10d %-6s %-18s %-6d %-26s %s" % (i, v or "-", sn, acl, den, alw))
    out(SUB)


###############################################################################
# Main
###############################################################################

def set_error():
    try:
        emc_results.setStatus(emc_results.Status.ERROR)
    except Exception:
        pass


def build_sources(subnets, scope, isids):
    """[(Binding, own_vlans)]"""
    res = []
    if MODE == "VLAN":
        src = parse_vlan_list(var(SRC_VAR, ""), "Source VLAN *")
        src = scope if src == "ALL" else src
        bad = [v for v in src if v not in scope]
        if bad:
            raise InputError("Source VLAN %s has no IP interface on this device or is excluded" % compress(bad))
        for v in src:
            res.append((Binding("VLAN", v, [("OWN_SUBNET", net_vlan(v, subnets))],
                                "VLAN %d  %s" % (v, cidr(*subnets[v]))), [v]))
    elif MODE == "PORT":
        ports = parse_port_list(var(SRC_VAR, ""), "Source Port *")
        pv = parse_vlan_list(var("aclPortVlan", ""), "Port VLAN *", allow_all=False)
        miss = [v for v in pv if v not in subnets]
        if miss:
            raise InputError("Port VLAN %s has no IP interface on this device - use Subnet Override" % compress(miss))
        own = [("OWN_V%d" % v, net_vlan(v, subnets)) for v in pv]
        for p in ports:
            res.append((Binding("PORT", p, own, "Port %s  VLAN %s" % (p, compress(pv))), pv))
    else:
        lst = parse_num_list(var(SRC_VAR, ""), "Source I-SID *", 1, 15999999, True, 200)
        if lst == "ALL":
            lst = sorted([i for i, v in isids.items() if v in scope])
            if not lst:
                raise InputError("No I-SID mapped to an in-scope VLAN was found - check show vlan i-sid")
        for i in lst:
            v = isids.get(i)
            own = []
            if v is not None and v in subnets:
                own = [("OWN_SUBNET", net_vlan(v, subnets))]
                title = "I-SID %d  VLAN %d  %s" % (i, v, cidr(*subnets[v]))
            elif v is not None:
                title = "I-SID %d  VLAN %d  subnet unknown" % (i, v)
            else:
                title = "I-SID %d  not mapped to a local VLAN" % i
                out("Note   : I-SID %d is not mapped to a VLAN on this device. It must exist on "
                    "the node before the ACL can be bound." % i)
            res.append((Binding("ISID", i, own, title), [v] if v else []))
    return res


def main():
    action = var("aclAction", "Show_Report")
    if action not in ("Deny_ACL", "Allow_ACL", "Remove_ACL", "Show_Report"):
        raise InputError("Unknown action: %s" % action)
    dry = var("aclDryRun", "yes").lower() != "no"
    save = var("aclSaveConfig", "no").lower() == "yes"
    family = var("family", "")

    out(LINE)
    out("%s v%s  |  Author: %s" % (TITLES[MODE], VERSION, AUTHOR))
    out(LINE)
    out("Device : %s  %s" % (var("deviceIP", "?"), var("deviceName", "")))
    mode = "" if action == "Show_Report" else ("   [DRY RUN]" if dry else "   [APPLY]")
    out("Action : %s%s" % (action, mode))
    out(LINE)

    if family and not re.search(r"VSP|VOSS|Fabric", family, re.I):
        raise InputError("This wizard supports VOSS / Fabric Engine only. Device family: %s" % family)

    cli("terminal more disable")
    cli("enable")

    subnets = discover_subnets()
    subnets.update(parse_override(var("aclSubnetOverride", "")))
    if not subnets:
        raise InputError("No VLAN with an IP interface found. Use Subnet Override to define the "
                         "destination subnets.")
    isids = discover_isids() if MODE == "ISID" else {}
    excl_txt = var("aclExcludeVlan", "")
    excl = parse_vlan_list(excl_txt, "Excluded VLANs", allow_all=False) if excl_txt else []
    scope = sorted([v for v in subnets if v not in excl])
    msg = "Found  : %d VLANs with IP   in scope: %s   excluded: %s" % (
        len(subnets), compress(scope), compress(excl) or "none")
    if MODE == "ISID":
        msg += "   I-SIDs: %d" % len(isids)
    out(msg)

    state = read_filter_config()

    if action == "Show_Report":
        report(state, subnets, scope, isids)
        return

    sources = build_sources(subnets, scope, isids)

    src = None
    src_txt = var("aclSrcSubnet", "")
    if src_txt:
        net, mask = parse_subnet(src_txt, "Source Host/Subnet")
        src = Net(net, mask)
        for b, ov in sources:
            owns = [n for name, n in b.own]
            if owns and not any(contains(n.nm, src.nm) for n in owns):
                raise InputError("Source Host/Subnet %s is not inside %s" % (src.label(), b.title))

    ports = parse_ports(var("aclPorts", ""))
    sub_txt = var("aclDstSubnet", "")
    dst_txt = var("aclDstVlan", "")
    if sub_txt:
        net, mask = parse_subnet(sub_txt, "Destination Subnet")
        fixed, dst_all, dst_list = [Net(net, mask)], False, None
    elif dst_txt:
        fixed = None
        dl = parse_vlan_list(dst_txt, "Destination VLAN")
        dst_all = dl == "ALL"
        dst_list = None if dst_all else dl
        if dst_list:
            badd = [v for v in dst_list if v not in scope]
            if badd:
                raise InputError("Destination VLAN %s has no IP interface on this device or is excluded"
                                 % compress(badd))
    else:
        if action != "Remove_ACL":
            raise InputError("Destination VLAN or Destination Subnet is required for %s" % action)
        fixed, dst_all, dst_list = None, True, None

    if action == "Allow_ACL" and ports != [None] and not sub_txt and not src_txt:
        if not any(p == ("udp", "67") for p in ports):
            out("Note   : udp:67 is not in the port list. If DHCP lives in the destination, "
                "clients cannot renew leases.")

    planner = Planner(state, subnets, isids)
    for b, own_vlans in sources:
        if fixed is not None:
            dests = fixed
        elif dst_all:
            dests = None if action == "Remove_ACL" else [net_vlan(u, subnets) for u in scope if u not in own_vlans]
        else:
            dests = [net_vlan(u, subnets) for u in dst_list if u not in own_vlans]
        if dests is not None and not dests:
            planner.groups.append((b.title, ["Destination equals source - skipped"], []))
            continue
        planner.add(b, action, src, dests, ports)
    planner.reconcile_returns()

    total = sum([len(g[2]) for g in planner.groups])
    out(SUB)
    out("PLAN")
    out(SUB)
    for title, notes, cmds in planner.groups:
        out(title)
        for n in notes:
            out("    - " + n)
    out(SUB)
    out("%d command(s)" % total)

    if total == 0:
        out("No changes needed. The policy is already in the requested state.")
        return

    if dry:
        out(SUB)
        out("COMMANDS   [DRY RUN - nothing was sent]")
        out(SUB)
        for title, notes, cmds in planner.groups:
            if cmds:
                out("# " + title)
                for c in cmds:
                    out(c)
        out(SUB)
        out("Run again with Dry Run = no to apply.")
        return

    out(SUB)
    out("APPLY")
    out(SUB)
    for title, notes, cmds in planner.groups:
        if cmds:
            out("# " + title)
            configure(cmds)

    out("")
    out("RESULT")
    report(read_filter_config(), subnets, scope, isids)
    if save:
        show("save config")
        out("Configuration saved.")
    else:
        out("Note: configuration was NOT saved.")


try:
    main()
except InputError as e:
    out("*** INPUT ERROR: %s" % e)
    out("*** No command was sent to the device.")
    set_error()
except CliError as e:
    out("*** DEVICE ERROR: %s" % e)
    out("*** Execution stopped. Partial changes are possible, run Show_Report to check.")
    set_error()
