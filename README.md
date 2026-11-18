# VOSS Access Policy Wizards

ExtremeCloud IQ Site Engine (XIQ-SE) / XMC Python scripts that manage access control on VOSS / Fabric Engine switches through a simple wizard.

Instead of writing ACL and ACE commands by hand, you choose **who**, **where** and **what**:

> *Deny VLAN 12 to ALL VLANs, then Allow VLAN 12 to VLAN 1 on tcp:443 only.*

The wizard discovers subnets from the switch, reads the existing filter configuration, builds the ACL/ACE commands in the correct order and applies them.

## The three wizards

| Script | ACL type | Source | Use it for |
|---|---|---|---|
| `VOSS_VLAN_Policy_Wizard.py` | `inVlan` | VLAN | Access between user VLANs on the gateway switches |
| `VOSS_Port_Policy_Wizard.py` | `inPort` | Switch port | Devices connected directly to the switch: servers, firewalls, NVRs, printers |
| `VOSS_ISID_Policy_Wizard.py` | `inVsn` | Fabric I-SID | L2 VSNs whose gateway is not on this switch, or the same service mapped to different VLANs on different BEBs |

All three share the same engine, form layout, actions and rule ordering. Only the source field differs.

## Features

- **Four actions:** `Deny_ACL`, `Allow_ACL`, `Remove_ACL`, `Show_Report`
- **Flexible targets:** single VLAN, list, range or `ALL`; optional destination subnet or host IP; optional ports (`tcp:443 udp:53 icmp`)
- **Automatic discovery:** subnets from `show ip interface`, I-SID to VLAN mapping from `show vlan i-sid`
- **Correct rule ordering by design:** allow rules are always evaluated before deny rules
- **Idempotent:** existing rules are detected by name and never duplicated; running the same action twice makes no change
- **Safe:** Dry Run is on by default, all input is validated before anything is sent, execution stops on the first device error
- **Non-destructive:** ACEs not created by the wizard are never modified; shared ACLs are detected and left alone
- **Access matrix report** showing denied and allowed destinations per VLAN, port or I-SID

## Requirements

- ExtremeCloud IQ Site Engine or Extreme Management Center with Python scripting
- VOSS / Fabric Engine switches
- `inVsn` ACLs are not supported on every platform (for example VSP 8600 and XA1400). Check `filter acl <id> type ?` on your switch.

## Installation

1. In XIQ-SE / XMC go to **Tasks > Scripts** and click **Add**.
2. Select **Python** as the script type.
3. Paste the content of the wizard file into the **Content** tab.
4. Under **Network OS**, select VOSS / Fabric Engine.
5. Under **Permissions and Menus**, choose the roles allowed to run it and optionally add it to the device menu.
6. Click **Save**. Repeat for each wizard you want to use.

> Note: the **Import** button only accepts XML exports created by XIQ-SE / XMC. Use **Add** for the `.py` files.

## Form fields

| Field | Description |
|---|---|
| **Action \*** | `Deny_ACL`, `Allow_ACL`, `Remove_ACL` or `Show_Report` |
| **Source \*** | VLAN wizard: `12`, `12,15`, `20-25` or `ALL`<br>Port wizard: `1/5`, `1/5,1/7` or `1/5-1/8`<br>I-SID wizard: `20030`, `20030,20031` or `ALL` |
| **Port VLAN \*** | Port wizard only. VLAN of the device on the port. Its subnet is always permitted |
| Destination VLAN | `13`, `1,2` or `ALL` |
| Destination Subnet | Optional. `10.10.13.0/24` or a host IP. Overrides Destination VLAN |
| Ports | Optional. `tcp:443 tcp:3389 udp:53 icmp`. Empty means all traffic |
| Excluded VLANs | Optional. VLANs never touched by `ALL`, e.g. firewall transit or management |
| Subnet Override | Optional. `12:10.10.12.0/24` for VLANs without an IP interface on this switch |
| **Dry Run \*** | `yes` shows the plan and commands only |
| **Save Config \*** | Saves the configuration after a successful run |

## Examples

### VLAN wizard

| Goal | Steps |
|---|---|
| VLAN 10 must not reach VLAN 20 | `Deny_ACL` · Source `10` · Destination `20` |
| VLAN 30 may reach only VLAN 1 and 2 | 1. `Deny_ACL` · Source `30` · Destination `ALL`<br>2. `Allow_ACL` · Source `30` · Destination `1,2` |
| Same, but VLAN 1 on HTTPS only | Step 2 with Ports `tcp:443` |
| Isolate every user VLAN, allow the server VLAN | The two steps above with Source `ALL` |
| Allow one printer in another VLAN | `Allow_ACL` · Destination Subnet `10.10.13.50` · Ports `tcp:9100` |

### Port wizard

| Goal | Steps |
|---|---|
| Server on port 1/5 (VLAN 20) may reach only VLAN 1 on HTTPS | 1. `Deny_ACL` · Port `1/5` · Port VLAN `20` · Destination `ALL`<br>2. `Allow_ACL` · Port `1/5` · Port VLAN `20` · Destination `1` · Ports `tcp:443` |

### I-SID wizard

| Goal | Steps |
|---|---|
| Camera L2 VSN 20030 may reach only the NVR | 1. `Deny_ACL` · I-SID `20030` · Destination `ALL`<br>2. `Allow_ACL` · I-SID `20030` · Destination Subnet `10.10.1.50` |

## How it works

| Wizard | ACL ID | Created as | Bound with |
|---|---|---|---|
| VLAN | VLAN ID | `filter acl <id> type inVlan` | `filter acl vlan <id> <vlan>` |
| Port | from pool 1500-1799 | `filter acl <id> type inPort` | `filter acl port <id> <port>` |
| I-SID | from pool 1800-2047 | `filter acl <id> type inVsn matchType both` | `filter acl i-sid <id> <isid>` |

Every ACL uses `default-action permit`. Rules are placed in fixed ACE ranges so the evaluation order is always correct:

| ACE ID | Rule | Purpose |
|---|---|---|
| 1-99 | `OWN_...` | Own subnet and gateway, always permitted first |
| 100-899 | `ALW_...` | Allow rules |
| 1000-1999 | `DNY_...` | Deny rules |
| default | permit | Everything else, including internet |

Example ACL after *Deny ALL* + *Allow VLAN 1,2*:

```
ACE 1     OWN_SUBNET  permit  own subnet
ACE 100   ALW_V1      permit  VLAN 1     <- matched first
ACE 101   ALW_V2      permit  VLAN 2
ACE 1000  DNY_V1      deny    VLAN 1     <- never reached while ALW_V1 exists
ACE 1001  DNY_V2      deny    VLAN 2
ACE 1002  DNY_V10     deny    VLAN 10
ACE 1003  DNY_V20     deny    VLAN 20
```

## Important notes

- **ACLs are stateless.** A deny from A to B also breaks connections that B starts toward A, because the replies are dropped on A's ingress ACL.
- **A port ACL takes precedence over a VLAN ACL** on the same port. If you use both wizards, a port with an `inPort` ACL is no longer filtered by the `inVlan` ACL of its VLAN.
- **inVlan in a fabric** is applied where traffic enters the VLAN on a UNI port. Apply the same policy on every gateway / BEB that has hosts in the VLAN.
- **inVsn with `matchType both`** also filters traffic arriving from the fabric (terminating NNI), so a single policy per BEB covers remote hosts in the same I-SID.
- **inPort on an uplink** applies to every device behind that uplink, not to a single device.
- When access to a server VLAN is limited to specific ports, remember `udp:67` (DHCP) and `udp:53` (DNS) if those services run there.
- Verify CLI syntax against your VOSS release before production use. Always start with `Show_Report` and Dry Run.

## Disclaimer

These scripts are provided as-is, without warranty of any kind. Test them in a lab or maintenance window before using them in production. You are responsible for the changes they make to your network.

## Author

**Ozan AKMUSTAFAOGLU**
