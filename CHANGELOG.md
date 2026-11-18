# Changelog

## v4.1 - November 2026

### Added
- **Source Host/Subnet** field: limit Allow, Deny and Remove to a single host or part of the source, e.g. one PC to one server on RDP.
- **Automatic return rules:** when a port-limited allow is blocked on the way back by a deny on the destination VLAN, a reply-only rule (`R_...`, source port match) is created there. Return rules are reconciled on every run, so the order of allows and denies does not matter, and they are removed when no longer needed.
- Warning when an allow without ports would have its replies dropped on the far side.
- Report shows host-scoped rules and the number of return rules per VLAN.

### Changed
- New compact rule names for host-scoped and return rules (`A_`, `D_`, `R_` with hex-encoded addresses) to stay within the 32 character VOSS limit.

### Fixed
- The "no deny rule covers" information is now evaluated before the new allow rule is added.

### Compatible
- Rule names from v3.0 and v4.0 are unchanged and still recognised.

## v4.0 - November 2026

### Added
- **Port Policy Wizard** (`VOSS_Port_Policy_Wizard.py`) using `inPort` ACLs, one ACL per port, ACL IDs from pool 1500-1799.
- **I-SID Policy Wizard** (`VOSS_ISID_Policy_Wizard.py`) using `inVsn` ACLs with `matchType both`, bound with `filter acl i-sid`, ACL IDs from pool 1800-2047.
- I-SID to VLAN discovery from `show vlan i-sid` and an I-SID access matrix report.
- Detection of ACLs shared by several VLANs, ports or I-SIDs; such ACLs are never modified.

### Changed
- All three wizards now share one engine, form layout and rule ordering.
- ACLs are created in documented order: `type ... name ...`, then `default-action`, then `enable`.
- ACE names are sent without quotes.
- Rules are deleted directly with `no filter acl ace`.
- When an ACL becomes empty, its own-subnet ACE is removed explicitly before the ACL is deleted.

### Compatible
- ACLs created by v3.0 are recognised and managed by the v4.0 VLAN wizard without changes.

## v3.0 - November 2026

- Initial public release of the Inter-VLAN Access Policy Wizard (`inVlan`).
