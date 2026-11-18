# VOSS Inter-VLAN Access Policy Wizard

An ExtremeCloud IQ Site Engine (XIQ-SE) / XMC Python script that manages inter-VLAN access control on VOSS / Fabric Engine gateway switches through a simple wizard.

Instead of writing ACL and ACE commands by hand, you choose **who**, **where** and **what**:

> *Deny VLAN 12 to ALL VLANs, then Allow VLAN 12 to VLAN 1 on tcp:443 only.*

The wizard discovers the VLAN subnets from the switch, reads the existing filter configuration, builds the ACL/ACE commands in the correct order and applies them.

## Features

- **Four actions:** `Deny_ACL`, `Allow_ACL`, `Remove_ACL`, `Show_Report`
- **Flexible targets:** single VLAN, list, range or `ALL`; optional destination subnet or host IP; optional ports (`tcp:443 udp:53 icmp`)
- **Automatic subnet discovery** from `show ip interface`
- **Correct rule ordering by design:** allow rules are always evaluated before deny rules
- **Idempotent:** existing rules are detected by name and never duplicated; running the same action twice makes no change
- **Safe:** Dry Run is on by default, all input is validated before anything is sent, execution stops on the first device error
- **Non-destructive:** ACEs not created by the wizard are never modified
- **Access matrix report** showing denied and allowed destinations per VLAN

## Requirements

- ExtremeCloud IQ Site Engine or Extreme Management Center with Python scripting
- VOSS / Fabric Engine switches acting as the IP gateway for the VLANs (tested design: VSP/5520 with VRRP)
- Filter ACL support with `type inVlan`

## Installation

1. In XIQ-SE / XMC go to **Tasks > Scripts** and click **Add**.
2. Select **Python** as the script type.
3. Paste the content of `VOSS_VLAN_Policy_Wizard.py` into the **Content** tab.
4. Under **Network OS**, select VOSS / Fabric Engine.
5. Under **Permissions and Menus**, choose the roles allowed to run it and optionally add it to the device menu.
6. Click **Save**.

> Note: the **Import** button only accepts XML exports created by XIQ-SE / XMC. Use **Add** for the `.py` file.

## Usage

Select all gateway switches together so the policy is identical on every device, then run the script.

| Field | Description |
|---|---|
| **Action \*** | `Deny_ACL`, `Allow_ACL`, `Remove_ACL` or `Show_Report` |
| **Source VLAN \*** | `12`, `12,15`, `20-25` or `ALL` |
| Destination VLAN | Same format as Source VLAN |
| Destination Subnet | Optional. `10.10.13.0/24` or a host IP. Overrides Destination VLAN |
| Ports | Optional. `tcp:443 tcp:3389 udp:53 icmp`. Empty means all traffic |
| Excluded VLANs | Optional. VLANs never touched by `ALL`, e.g. firewall transit or management |
| Subnet Override | Optional. `12:10.10.12.0/24` if discovery is not sufficient |
| **Dry Run \*** | `yes` shows the plan and commands only |
| **Save Config \*** | Saves the configuration after a successful run |

### Examples

| Goal | Steps |
|---|---|
| VLAN 10 must not reach VLAN 20 | `Deny_ACL` · Source `10` · Destination `20` |
| VLAN 30 may reach only VLAN 1 and 2 | 1. `Deny_ACL` · Source `30` · Destination `ALL`<br>2. `Allow_ACL` · Source `30` · Destination `1,2` |
| Same, but VLAN 1 on HTTPS only | Step 2 with Ports `tcp:443` |
| Isolate every user VLAN, allow the server VLAN | The two steps above with Source `ALL` |
| Allow one printer in another VLAN | `Allow_ACL` · Destination Subnet `10.10.13.50` · Ports `tcp:9100` |

## How it works

Each VLAN gets an ingress ACL (`ACL ID = VLAN ID`, `type inVlan`, `default-action permit`). Rules are placed in fixed ACE ranges so the evaluation order is always correct:

| ACE ID | Rule | Purpose |
|---|---|---|
| 1-99 | `OWN_SUBNET` | Own subnet and gateway, always permitted first |
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
- **Fabric / SPB:** `inVlan` ACLs are applied where traffic enters the VLAN on a UNI port. Apply the same policy on every gateway / BEB that has hosts in the VLAN.
- When access to a server VLAN is limited to specific ports, remember `udp:67` (DHCP) and `udp:53` (DNS) if those services run there.
- Verify CLI syntax against your VOSS release before production use. Always start with `Show_Report` and Dry Run.

## Disclaimer

This script is provided as-is, without warranty of any kind. Test it in a lab or maintenance window before using it in production. You are responsible for the changes it makes to your network.

## Author

**Ozan AKMUSTAFAOGLU**
