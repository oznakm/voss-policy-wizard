#@MetaDataStart
#@DetailDescriptionStart
###############################################################################
# VOSS PORT ACCESS POLICY WIZARD
# Platform : VOSS / Fabric Engine
# Engine   : ExtremeCloud IQ Site Engine / XMC Python
# ACL type : inPort - ACL ID from pool 1500-1799
# Author   : Ozan AKMUSTAFAOGLU
# Revision : 4.0
# Date     : November 2026
#
# WHAT IT DOES
#   Controls what a device on a specific switch port may reach, with an
#   ingress port ACL - type inPort. One ACL per port.
#   Best for devices connected directly to the switch: servers, firewalls,
#   NVRs, printers. On an uplink port it applies to everything behind it.
#
# TYPICAL SCENARIO - port 1/5 may reach only VLAN 1 on HTTPS
#   Step 1  Deny_ACL   Port 1/5  Port VLAN 20   Destination VLAN ALL
#   Step 2  Allow_ACL  Port 1/5  Port VLAN 20   Destination VLAN 1  tcp:443
#   Port VLAN is the VLAN of the device on the port. Its subnet is always
#   permitted and it is skipped by ALL.
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
#   Destination Subnet  10.10.13.0/24  |  10.10.13.50  - overrides Dest VLAN
#   Ports               tcp:443 tcp:3389 udp:53 icmp  - empty means all
#   Excluded VLANs      VLANs never touched by ALL - FW transit, MGMT
#   Subnet Override     12:10.10.12.0/24 13:10.10.13.0/24
#
# RULE ORDER - first match wins
#   ACE 1-99      OWN_...  own subnet, always permitted first
#   ACE 100-899   ALW_...  allow rules
#   ACE 1000-1999 DNY_...  deny rules
#   default-action permit  everything else, including internet
#   Rules are recognised by name. Existing rules are never duplicated and
#   ACEs not created by this wizard are never modified.
#
# NOTES
#   - ACLs are stateless. A deny from A to B also breaks connections that
#     B starts toward A, because the replies are dropped on A.
#   - A port ACL takes precedence over a VLAN ACL on the same port.
#   - Verify syntax on your VOSS release. Start with Show_Report and Dry Run.
###############################################################################
#@DetailDescriptionEnd
#@ScriptDescription "VOSS Port Access Policy Wizard"
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
#@VariableFieldLabel (description = "Source Port * - e.g. 1/5 or 1/5-1/8",
#  type = String,
#  required = no,
#  scope = global
#  )
set var aclSrcPort none
#@VariableFieldLabel (description = "Port VLAN * - VLAN of the device on the port",
#  type = String,
#  required = no,
#  scope = global
#  )
set var aclPortVlan none
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

MODE = "PORT"
SRC_VAR = "aclSrcPort"

import re

VERSION = "4.0"
AUTHOR = "Ozan AKMUSTAFAOGLU"

OWN_RANGE = (1, 99)
ALW_RANGE = (100, 899)
DNY_RANGE = (1000, 1999)
PORT_ACL_POOL = (1500, 1799)
ISID_ACL_POOL = (1800, 2047)
LINE = "=" * 78
SUB = "-" * 78
RULE_RE = re.compile(r"^(ALW|DNY)_(V\d+|S\d+_\d+_\d+_\d+_\d+)(?:_(TCP\d+|UDP\d+|ICMP))?$")
TITLES = {"VLAN": "VOSS Inter-VLAN Access Policy Wizard",
          "PORT": "VOSS Port Access Policy Wizard",
          "ISID": "VOSS I-SID Access Policy Wizard"}


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
    return "%s/%d" % (net, mask2prefix(mask))


def contains(outer_net, outer_mask, inner_net, inner_mask):
    return (mask2prefix(outer_mask) <= mask2prefix(inner_mask)
            and (ip2int(inner_net) & ip2int(outer_mask)) == ip2int(outer_net))


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
    """Running-config port list '1/5,1/7-1/9' -> set of ports. Best effort."""
    res = set()
    for tok in re.split(r"[,\s]+", text.strip()):
        m = re.match(r"^(\d+(?:/\d+)?)/(\d+)(?:-(?:\d+(?:/\d+)?/)?(\d+))?$", tok)
        if m:
            a = int(m.group(2))
            b = int(m.group(3)) if m.group(3) else a
            for i in range(a, b + 1):
                res.add("%s/%d" % (m.group(1), i))
    return res


def parse_subnet(text):
    text = text.strip()
    m = re.match(r"^(%s)(?:/(\d+))?$" % IP_RE, text)
    if not m:
        raise InputError("Destination Subnet: cannot parse '%s' - e.g. 10.10.13.0/24" % text)
    prefix = int(m.group(2)) if m.group(2) else 32
    if prefix > 32:
        raise InputError("Destination Subnet: invalid prefix /%d" % prefix)
    mask = prefix2mask(prefix)
    return network_of(m.group(1), mask), mask


def parse_ports(text):
    """'' -> [None] meaning all traffic; 'tcp:443 icmp' -> [('tcp','443'),('icmp',None)]"""
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


def port_label(p):
    if p is None:
        return ""
    return p[0].upper() if p[1] is None else "%s%s" % (p[0].upper(), p[1])


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
# Destinations and rule names
###############################################################################

class Dest(object):
    def __init__(self, key, net, mask, vlan=None):
        self.key, self.net, self.mask, self.vlan = key, net, mask, vlan

    def label(self):
        return ("VLAN %d" % self.vlan) if self.vlan is not None else cidr(self.net, self.mask)


def dest_vlan(vlan, subnets):
    net, mask = subnets[vlan]
    return Dest("V%d" % vlan, net, mask, vlan)


def dest_subnet(net, mask):
    return Dest("S%s_%d" % (net.replace(".", "_"), mask2prefix(mask)), net, mask)


def key_to_text(key):
    if key.startswith("V"):
        return "VLAN " + key[1:]
    p = key[1:].split("_")
    return "%s/%s" % (".".join(p[:4]), p[4])


def rule_name(kind, dest, port):
    n = "%s_%s" % (kind, dest.key)
    return n + ("_" + port_label(port) if port else "")


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
        self.acl_type = {}
        for a, t in re.findall(r"^\s*filter acl (\d+) type (\w+)", text, re.M):
            self.acl_type[int(a)] = t
        self.vlan_to_acl = {}
        for a, v in re.findall(r"^\s*filter acl vlan (\d+) (\d+)", text, re.M):
            self.vlan_to_acl[int(v)] = int(a)
        self.isid_to_acl = {}
        for a, i in re.findall(r"^\s*filter acl i-sid (\d+) (\d+)", text, re.M):
            self.isid_to_acl[int(i)] = int(a)
        self.port_to_acl = {}
        self.acl_ports = {}
        for a, pl in re.findall(r"^\s*filter acl port (\d+) (\S+)", text, re.M):
            for p in expand_port_text(pl):
                self.port_to_acl[p] = int(a)
                self.acl_ports.setdefault(int(a), set()).add(p)
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
        """[(ace, kind, key, portlabel)] for wizard rules"""
        res = []
        for e, n in self.aces.get(acl, {}).items():
            m = RULE_RE.match(n)
            if m:
                res.append((e, m.group(1), m.group(2), m.group(3) or ""))
        return sorted(res)

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
    """kind VLAN / PORT / ISID. own = list of (name, Dest) always permitted first."""

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

    def mark_bound(self, st, acl):
        if self.kind == "VLAN":
            st.vlan_to_acl[self.ident] = acl
        elif self.kind == "PORT":
            st.port_to_acl[self.ident] = acl
            st.acl_ports.setdefault(acl, set()).add(self.ident)
        else:
            st.isid_to_acl[self.ident] = acl

    def other_users(self, st, acl):
        """Other bindings that share this ACL - editing it would affect them."""
        res = []
        res += ["VLAN %d" % v for v, a in st.vlan_to_acl.items() if a == acl and not (self.kind == "VLAN" and v == self.ident)]
        res += ["port %s" % p for p, a in st.port_to_acl.items() if a == acl and not (self.kind == "PORT" and p == self.ident)]
        res += ["I-SID %d" % i for i, a in st.isid_to_acl.items() if a == acl and not (self.kind == "ISID" and i == self.ident)]
        return res


###############################################################################
# Planner
###############################################################################

def is_own(name):
    return name == "OWN_SUBNET" or name.startswith("OWN_")


class Planner(object):
    def __init__(self, state, subnets):
        self.st = state
        self.sn = subnets
        self.groups = []

    def _ace(self, acl, name, action, dest, port, rng):
        ace = self.st.alloc(acl, rng)
        c = ['filter acl ace %d %d name %s' % (acl, ace, name),
             'filter acl ace action %d %d %s count' % (acl, ace, action),
             'filter acl ace ip %d %d dst-ip mask %s %s' % (acl, ace, dest.net, dest.mask)]
        if port:
            c.append('filter acl ace ip %d %d ip-protocol-type eq %s' % (acl, ace, port[0]))
            if port[1]:
                c.append('filter acl ace protocol %d %d dst-port eq %s' % (acl, ace, port[1]))
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
        for name, d in b.own:
            if st.find(acl, name) is None:
                notes.append("Permit own subnet %s" % cidr(d.net, d.mask))
                cmds += self._ace(acl, name, "permit", d, None, OWN_RANGE)
        if b.existing_acl(st) != acl:
            binds.append(b.bind_cmd(acl))
            b.mark_bound(st, acl)
            notes.append("Bind ACL %d to %s" % (acl, b.title))
        return acl

    def _add_rules(self, acl, kind, dests, ports, notes, cmds):
        action = "permit" if kind == "ALW" else "deny"
        rng = ALW_RANGE if kind == "ALW" else DNY_RANGE
        added, skipped, cleaned = [], [], 0
        for d in dests:
            full_name = rule_name(kind, d, None)
            for p in ports:
                name = rule_name(kind, d, p)
                if len(name) > 32:
                    raise InputError("Rule name too long for VOSS: %s" % name)
                if self.st.find(acl, name) is not None or (p and self.st.find(acl, full_name) is not None):
                    skipped.append((d, p))
                    continue
                if p is None:
                    for e, k, key, pl in self.st.rules(acl):
                        if k == kind and key == d.key and pl:
                            cmds += self._del(acl, e)
                            cleaned += 1
                cmds += self._ace(acl, name, action, d, p, rng)
                added.append((d, p))
        verb = "ALLOW" if kind == "ALW" else "DENY "
        if added:
            notes.append("%s %s" % (verb, summarize(added)))
        if skipped:
            notes.append("Already in place: %s" % summarize(skipped))
        if cleaned:
            notes.append("Replaced %d port rule(s) with a full rule" % cleaned)
        if kind == "ALW" and added:
            denies = [(key, pl) for e, k, key, pl in self.st.rules(acl) if k == "DNY"]
            uncovered = [d for d, p in added if not self._covered(d, denies)]
            if uncovered:
                notes.append("Info: no deny rule covers %s - traffic was already permitted"
                             % ", ".join(sorted(set(d.label() for d in uncovered))))

    def _covered(self, dest, denies):
        for key, pl in denies:
            if pl:
                continue
            if key.startswith("V"):
                v = int(key[1:])
                if v in self.sn and contains(self.sn[v][0], self.sn[v][1], dest.net, dest.mask):
                    return True
            else:
                parts = key[1:].split("_")
                if contains(".".join(parts[:4]), prefix2mask(int(parts[4])), dest.net, dest.mask):
                    return True
        return False

    def _remove_rules(self, b, dests, ports, notes, cmds, unbinds):
        acl = b.existing_acl(self.st)
        if acl is None:
            notes.append("No policy on %s - nothing to remove" % b.title)
            return
        others = b.other_users(self.st, acl)
        if others:
            raise InputError("ACL %d is shared with %s - edit it manually" % (acl, ", ".join(others[:3])))
        keys = None if dests is None else set(d.key for d in dests)
        labels = None if ports == [None] else set(port_label(p) for p in ports)
        removed = []
        for e, k, key, pl in self.st.rules(acl):
            if keys is not None and key not in keys:
                continue
            if labels is not None and pl not in labels:
                continue
            cmds += self._del(acl, e)
            removed.append("%s_%s%s" % (k, key, "_" + pl if pl else ""))
        if removed:
            notes.append("REMOVE %d rule(s): %s" % (len(removed), shorten(removed)))
        else:
            notes.append("No matching rule found")
        left = [n for n in self.st.aces.get(acl, {}).values() if not is_own(n)]
        if not left:
            notes.append("ACL %d is now empty - unbind and delete" % acl)
            for e, n in sorted(self.st.aces.get(acl, {}).items()):
                cmds += self._del(acl, e)
            unbinds += [b.unbind_cmd(acl), 'no filter acl %d' % acl]

    def add(self, b, action, dests, ports):
        notes, cmds, binds, unbinds = [], [], [], []
        if action == "Remove_ACL":
            self._remove_rules(b, dests, ports, notes, cmds, unbinds)
        else:
            acl = self._ensure_acl(b, notes, cmds, binds)
            self._add_rules(acl, "ALW" if action == "Allow_ACL" else "DNY", dests, ports, notes, cmds)
        self.groups.append((b.title, notes, cmds + binds + unbinds))


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

def fmt_rules(items, all_set):
    if not items:
        return "-"
    full_v, ported, subs = [], {}, []
    for key, pl in items:
        if pl:
            ported.setdefault(key, []).append(pl)
        elif key.startswith("V"):
            full_v.append(int(key[1:]))
        else:
            subs.append(key)
    parts = []
    if full_v:
        if all_set and set(all_set) <= set(full_v):
            parts.append("ALL VLANs")
        else:
            parts.append("VLAN " + compress(full_v))
    parts += [key_to_text(k) for k in subs]
    for key in sorted(ported):
        parts.append("%s %s" % (key_to_text(key), " ".join(sorted(ported[key]))))
    return "; ".join(parts)


def policy_cells(state, acl, others):
    rules = state.rules(acl)
    den = fmt_rules([(k, pl) for e, kind, k, pl in rules if kind == "DNY"], others)
    alw = fmt_rules([(k, pl) for e, kind, k, pl in rules if kind == "ALW"], None)
    extra = len([n for n in state.aces.get(acl, {}).values() if not is_own(n) and not RULE_RE.match(n)])
    if extra:
        alw = (alw + "  " if alw != "-" else "") + "+%d custom ACE" % extra
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
            den, alw = policy_cells(state, acl, [u for u in scope if u != v])
            out("%-6d %-18s %-30s %s" % (v, cidr(*subnets[v]), den, alw))
    elif MODE == "PORT":
        ports = sorted(state.port_to_acl.keys(), key=port_sort_key)
        if not ports:
            out("No port ACL found on this device.")
        out("%-8s %-6s %-30s %s" % ("PORT", "ACL", "DENIED", "ALLOWED"))
        for p in ports:
            acl = state.port_to_acl[p]
            own = [int(n[5:]) for n in state.aces.get(acl, {}).values() if re.match(r"^OWN_V\d+$", n)]
            den, alw = policy_cells(state, acl, [u for u in scope if u not in own])
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
            den, alw = policy_cells(state, acl, [u for u in scope if u != v])
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


def build_sources(subnets, scope, isids, excl):
    """Returns (bindings, dest_exclusions_per_binding)"""
    res = []
    if MODE == "VLAN":
        src = parse_vlan_list(var(SRC_VAR, ""), "Source VLAN *")
        src = scope if src == "ALL" else src
        bad = [v for v in src if v not in scope]
        if bad:
            raise InputError("Source VLAN %s has no IP interface on this device or is excluded" % compress(bad))
        for v in src:
            b = Binding("VLAN", v, [("OWN_SUBNET", dest_vlan(v, subnets))],
                        "VLAN %d  %s" % (v, cidr(*subnets[v])))
            res.append((b, [v]))
    elif MODE == "PORT":
        ports = parse_port_list(var(SRC_VAR, ""), "Source Port *")
        pv = parse_vlan_list(var("aclPortVlan", ""), "Port VLAN *", allow_all=False)
        miss = [v for v in pv if v not in subnets]
        if miss:
            raise InputError("Port VLAN %s has no IP interface on this device - use Subnet Override" % compress(miss))
        own = [("OWN_V%d" % v, dest_vlan(v, subnets)) for v in pv]
        for p in ports:
            res.append((Binding("PORT", p, own, "Port %s  VLAN %s" % (p, compress(pv))), pv))
    else:
        txt = var(SRC_VAR, "")
        lst = parse_num_list(txt, "Source I-SID *", 1, 15999999, True, 200)
        if lst == "ALL":
            lst = sorted([i for i, v in isids.items() if v in scope])
            if not lst:
                raise InputError("No I-SID mapped to an in-scope VLAN was found - check show vlan i-sid")
        for i in lst:
            v = isids.get(i)
            own = []
            if v is not None and v in subnets:
                own = [("OWN_SUBNET", dest_vlan(v, subnets))]
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

    sources = build_sources(subnets, scope, isids, excl)

    ports = parse_ports(var("aclPorts", ""))
    sub_txt = var("aclDstSubnet", "")
    dst_txt = var("aclDstVlan", "")
    if sub_txt:
        net, mask = parse_subnet(sub_txt)
        fixed, dst_all, dst_list = [dest_subnet(net, mask)], False, None
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

    if action == "Allow_ACL" and ports != [None] and not sub_txt:
        if not any(p == ("udp", "67") for p in ports):
            out("Note   : udp:67 is not in the port list. If DHCP lives in the destination, "
                "clients cannot renew leases.")

    planner = Planner(state, subnets)
    for b, own_vlans in sources:
        if fixed is not None:
            dests = fixed
        elif dst_all:
            dests = None if action == "Remove_ACL" else [dest_vlan(u, subnets) for u in scope if u not in own_vlans]
        else:
            dests = [dest_vlan(u, subnets) for u in dst_list if u not in own_vlans]
        if dests is not None and not dests:
            planner.groups.append((b.title, ["Destination equals source - skipped"], []))
            continue
        planner.add(b, action, dests, ports)

    total = sum([len(g[2]) for g in planner.groups])
    out(SUB)
    out("PLAN")
    out(SUB)
    for title, notes, cmds in planner.groups:
        out(title)
        for n in notes:
            out("    - " + n)
    out(SUB)
    out("%d command(s) for %d target(s)" % (total, len(planner.groups)))

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
