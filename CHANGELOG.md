# Changelog

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
