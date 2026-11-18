#@MetaDataStart
#@DetailDescriptionStart
###############################################################################
# VOSS INTER-VLAN ACCESS POLICY WIZARD
# Platform : VOSS / Fabric Engine gateway switches - 5520
# Engine   : ExtremeCloud IQ Site Engine / XMC Python
# Author   : Ozan AKMUSTAFAOGLU
# Revision : 3.0
# Date     : November 2026
#
# ACTIONS
#   Deny_ACL     Blocks Source VLAN to Destination.
#                No ports  : all traffic is blocked.
#                Ports     : only the given ports are blocked.
#   Allow_ACL    Permits Source VLAN to Destination.
#                Allow rules are evaluated BEFORE deny rules, so an allow
#                always wins. With ports, only those ports are opened.
#   Remove_ACL   Removes wizard rules of Source VLAN toward Destination.
#                Empty Destination or ALL removes every wizard rule and the
#                ACL itself if nothing else is left.
#   Show_Report  Prints the access matrix. Makes no changes.
#
# TYPICAL SCENARIO - isolate a user VLAN, allow servers in VLAN 1
#   Step 1  Deny_ACL   Source 12   Destination VLAN ALL
#   Step 2  Allow_ACL  Source 12   Destination VLAN 1   Ports optional
#   Use Source ALL to isolate every user VLAN at once.
#
# FIELD FORMATS
#   VLAN list           12  |  12,15,18  |  20-25  |  ALL
#   Destination Subnet  10.10.13.0/24  |  10.10.13.50  - overrides Dest VLAN
#   Ports               tcp:443 tcp:3389 udp:53 icmp
#   Excluded VLANs      VLANs never touched by ALL - FW transit, MGMT
#   Subnet Override     12:10.10.12.0/24 13:10.10.13.0/24
#
# HOW IT WORKS
#   Subnets are read from the switch - show ip interface.
#   ACL ID = VLAN ID, type inVlan, default-action permit.
#   ACE 1-99      OWN_SUBNET  own subnet and gateway
#   ACE 100-899   ALW_...     allow rules
#   ACE 1000-1999 DNY_...     deny rules
#   Rules are recognised by name. Existing rules are not duplicated and
#   ACEs not created by this wizard are never modified.
#
# NOTES
#   - Run on all gateway 5520s together so the policy is identical.
#   - ACLs are stateless: a deny from A to B also breaks connections that B
#     starts toward A, because the replies are dropped on A.
#   - When server access is limited to ports, include udp:67 for DHCP and
#     udp:53 for DNS if those services live in the server VLAN.
#   - Dry Run is ON by default. Review the plan, then run with Dry Run = no.
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

import re

ACL_TYPE = "inVlan"
OWN_RANGE = (1, 99)
ALW_RANGE = (100, 899)
DNY_RANGE = (1000, 1999)
LINE = "=" * 78
SUB = "-" * 78
RULE_RE = re.compile(r"^(ALW|DNY)_(V\d+|S\d+_\d+_\d+_\d+_\d+)(?:_(TCP\d+|UDP\d+|ICMP))?$")


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
    om = ip2int(outer_mask)
    return (mask2prefix(outer_mask) <= mask2prefix(inner_mask)
            and (ip2int(inner_net) & om) == ip2int(outer_net))


###############################################################################
# Input parsing
###############################################################################

def parse_vlan_list(text, field):
    text = (text or "").strip()
    if not text:
        raise InputError("%s is required" % field)
    if text.upper() in ("ALL", "TUMU", "ANY"):
        return "ALL"
    result = set()
    for tok in re.split(r"[,;\s]+", text):
        if not tok:
            continue
        m = re.match(r"^(\d+)-(\d+)$", tok)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if a > b:
                raise InputError("%s: invalid range %s" % (field, tok))
            result.update(range(a, b + 1))
        elif tok.isdigit():
            result.add(int(tok))
        else:
            raise InputError("%s: cannot parse '%s'" % (field, tok))
    for v in result:
        if v < 1 or v > 4094:
            raise InputError("%s: VLAN %d is out of range" % (field, v))
    return sorted(result)


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


class FilterState(object):
    def __init__(self, text):
        self.acls = set(int(x) for x in re.findall(r"^\s*filter acl (\d+) (?:enable|type)", text, re.M))
        self.vlan_to_acl = {}
        for a, v in re.findall(r"^\s*filter acl vlan (\d+) (\d+)", text, re.M):
            self.vlan_to_acl[int(v)] = int(a)
        self.aces = {}
        for a, e, n in re.findall(r'^\s*filter acl ace (\d+) (\d+) name "?([^"\r\n]+?)"?\s*$', text, re.M):
            self.aces.setdefault(int(a), {})[int(e)] = n.strip()
        for a, e in re.findall(r"^\s*filter acl ace (\d+) (\d+) enable", text, re.M):
            self.aces.setdefault(int(a), {}).setdefault(int(e), "")
        self.reserved = {}

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


def read_filter_config():
    text = show("show running-config module filter")
    if "filter acl" not in text:
        full = show("show running-config")
        text = "\n".join([l for l in full.splitlines() if "filter acl" in l])
    return FilterState(text)


###############################################################################
# Planner
###############################################################################

class Planner(object):
    def __init__(self, state, subnets):
        self.st = state
        self.sn = subnets
        self.groups = []

    # --- low level
    def _ace(self, acl, name, action, dest, port):
        if name == "OWN_SUBNET":
            rng = OWN_RANGE
        else:
            rng = ALW_RANGE if action == "permit" else DNY_RANGE
        ace = self.st.alloc(acl, rng)
        c = ['filter acl ace %d %d name "%s"' % (acl, ace, name),
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
        return ['filter acl ace %d %d disable' % (acl, ace),
                'no filter acl ace %d %d' % (acl, ace)]

    def _ensure_acl(self, vlan, notes, cmds, binds):
        acl = self.st.vlan_to_acl.get(vlan, vlan)
        if acl > 2048:
            raise InputError("VLAN %d: ACL ID cannot exceed 2048, bind an ACL to this VLAN manually first" % vlan)
        other = [v for v, a in self.st.vlan_to_acl.items() if a == acl and v != vlan]
        if other:
            raise InputError("ACL %d is already bound to VLAN %d, cannot use it for VLAN %d" % (acl, other[0], vlan))
        if acl not in self.st.acls:
            notes.append("Create ACL %d  type %s  default-action permit" % (acl, ACL_TYPE))
            cmds += ['filter acl %d enable' % acl,
                     'filter acl %d type %s name "ACL_V%d_IN"' % (acl, ACL_TYPE, vlan),
                     'filter acl set %d default-action permit' % acl]
            self.st.acls.add(acl)
        if self.st.find(acl, "OWN_SUBNET") is None:
            notes.append("Permit own subnet %s" % cidr(*self.sn[vlan]))
            cmds += self._ace(acl, "OWN_SUBNET", "permit", dest_vlan(vlan, self.sn), None)
        if self.st.vlan_to_acl.get(vlan) != acl:
            binds.append('filter acl vlan %d %d' % (acl, vlan))
            self.st.vlan_to_acl[vlan] = acl
            notes.append("Bind ACL %d to VLAN %d" % (acl, vlan))
        return acl

    # --- actions
    def _add_rules(self, acl, kind, dests, ports, notes, cmds):
        action = "permit" if kind == "ALW" else "deny"
        added, skipped, cleaned = [], [], 0
        for d in dests:
            full_name = rule_name(kind, d, None)
            for p in ports:
                name = rule_name(kind, d, p)
                if self.st.find(acl, name) is not None or (p and self.st.find(acl, full_name) is not None):
                    skipped.append((d, p))
                    continue
                if p is None:
                    for e, k, key, pl in self.st.rules(acl):
                        if k == kind and key == d.key and pl:
                            cmds += self._del(acl, e)
                            cleaned += 1
                cmds += self._ace(acl, name, action, d, p)
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
                net, mask = ".".join(parts[:4]), prefix2mask(int(parts[4]))
                if contains(net, mask, dest.net, dest.mask):
                    return True
        return False

    def _remove_rules(self, vlan, dests, ports, notes, cmds, unbinds):
        acl = self.st.vlan_to_acl.get(vlan)
        if acl is None:
            notes.append("No policy on this VLAN - nothing to remove")
            return
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
        left = [n for n in self.st.aces.get(acl, {}).values() if n != "OWN_SUBNET"]
        if not left:
            notes.append("ACL %d is now empty - unbind and delete" % acl)
            unbinds += ['no filter acl vlan %d %d' % (acl, vlan), 'no filter acl %d' % acl]

    def add(self, vlan, action, dests, ports):
        notes, cmds, binds, unbinds = [], [], [], []
        if action == "Remove_ACL":
            self._remove_rules(vlan, dests, ports, notes, cmds, unbinds)
        else:
            acl = self._ensure_acl(vlan, notes, cmds, binds)
            kind = "ALW" if action == "Allow_ACL" else "DNY"
            self._add_rules(acl, kind, dests, ports, notes, cmds)
        self.groups.append(("VLAN %d  %s" % (vlan, cidr(*self.sn[vlan])), notes, cmds + binds + unbinds))


def summarize(pairs):
    """[(Dest, port)] -> 'VLAN 10-11,13-30  all traffic  |  VLAN 1  ports TCP443'"""
    by_ports = {}
    for d, p in pairs:
        by_ports.setdefault(port_label(p), []).append(d)
    parts = []
    for pl in sorted(by_ports):
        ds = by_ports[pl]
        vl = [d.vlan for d in ds if d.vlan is not None]
        sn = [d.label() for d in ds if d.vlan is None]
        txt = []
        if vl:
            txt.append("VLAN " + compress(vl))
        txt += sn
        parts.append(" ".join(txt) + ("  port " + pl if pl else "  all traffic"))
    return "  |  ".join(parts)


def shorten(items, n=6):
    return ", ".join(items[:n]) + (" ... +%d" % (len(items) - n) if len(items) > n else "")


###############################################################################
# Report
###############################################################################

def report(state, subnets, scope):
    out(SUB)
    out("ACCESS MATRIX   default: permit   allow rules are evaluated before deny")
    out(SUB)
    out("%-6s %-18s %-30s %s" % ("VLAN", "SUBNET", "DENIED", "ALLOWED"))
    for v in sorted(scope):
        acl = state.vlan_to_acl.get(v)
        if acl is None:
            out("%-6d %-18s %-30s %s" % (v, cidr(*subnets[v]), "-", "no policy"))
            continue
        rules = state.rules(acl)
        others = [u for u in scope if u != v]
        den = fmt_rules([(k, pl) for e, kind, k, pl in rules if kind == "DNY"], others)
        alw = fmt_rules([(k, pl) for e, kind, k, pl in rules if kind == "ALW"], None)
        extra = len([n for n in state.aces.get(acl, {}).values()
                     if n != "OWN_SUBNET" and not RULE_RE.match(n)])
        if extra:
            alw = (alw + "  " if alw != "-" else "") + "+%d custom ACE" % extra
        out("%-6d %-18s %-30s %s" % (v, cidr(*subnets[v]), den, alw))
    out(SUB)


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
    for key in subs:
        p = key[1:].split("_")
        parts.append("%s/%s" % (".".join(p[:4]), p[4]))
    for key in sorted(ported):
        if key.startswith("V"):
            name = "VLAN " + key[1:]
        else:
            p = key[1:].split("_")
            name = "%s/%s" % (".".join(p[:4]), p[4])
        parts.append("%s %s" % (name, " ".join(sorted(ported[key]))))
    return "; ".join(parts)


###############################################################################
# Main
###############################################################################

def set_error():
    try:
        emc_results.setStatus(emc_results.Status.ERROR)
    except Exception:
        pass


def main():
    action = var("aclAction", "Show_Report")
    if action not in ("Deny_ACL", "Allow_ACL", "Remove_ACL", "Show_Report"):
        raise InputError("Unknown action: %s" % action)
    dry = var("aclDryRun", "yes").lower() != "no"
    save = var("aclSaveConfig", "no").lower() == "yes"
    family = var("family", "")

    out(LINE)
    out("VOSS Inter-VLAN Access Policy Wizard v3.0  |  Author: Ozan AKMUSTAFAOGLU")
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
        raise InputError("No VLAN with an IP interface found. Run this wizard on the gateway "
                         "switches or use Subnet Override.")
    excl_txt = var("aclExcludeVlan", "")
    excl = parse_vlan_list(excl_txt, "Excluded VLANs") if excl_txt else []
    if excl == "ALL":
        raise InputError("Excluded VLANs cannot be ALL")
    scope = sorted([v for v in subnets if v not in excl])
    out("Found  : %d VLANs with IP   in scope: %s   excluded: %s"
        % (len(subnets), compress(scope), compress(excl) or "none"))

    state = read_filter_config()

    if action == "Show_Report":
        report(state, subnets, scope)
        return

    # --- inputs
    src = parse_vlan_list(var("aclSrcVlan", ""), "Source VLAN *")
    src = scope if src == "ALL" else src
    bad = [v for v in src if v not in scope]
    if bad:
        raise InputError("Source VLAN %s has no IP interface on this device or is excluded"
                         % compress(bad))

    ports = parse_ports(var("aclPorts", ""))
    sub_txt = var("aclDstSubnet", "")
    dst_txt = var("aclDstVlan", "")

    if sub_txt:
        net, mask = parse_subnet(sub_txt)
        fixed = [dest_subnet(net, mask)]
        dst_all, dst_list = False, None
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

    # --- plan
    planner = Planner(state, subnets)
    for v in src:
        if fixed is not None:
            dests = fixed
        elif dst_all:
            dests = None if action == "Remove_ACL" else [dest_vlan(u, subnets) for u in scope if u != v]
        else:
            dests = [dest_vlan(u, subnets) for u in dst_list if u != v]
        if dests is not None and not dests:
            planner.groups.append(("VLAN %d  %s" % (v, cidr(*subnets[v])),
                                   ["Destination equals source - skipped"], []))
            continue
        planner.add(v, action, dests, ports)

    total = sum([len(g[2]) for g in planner.groups])
    out(SUB)
    out("PLAN")
    out(SUB)
    for title, notes, cmds in planner.groups:
        out(title)
        for n in notes:
            out("    - " + n)
    out(SUB)
    out("%d command(s) for %d VLAN(s)" % (total, len(planner.groups)))

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
    report(read_filter_config(), subnets, scope)
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
