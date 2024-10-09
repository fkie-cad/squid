## Additional Vulnerability Types
- Exim-specific
  - ACL bypass
- SMTP-specific
  - Directory traversal when storing attachments

## Existing Exim Harnesses
- Profuzzbench
  - StateAFL, AFLNet, AFLnwe
  - Packet-based mutations with AFLs havoc mutators
  - Dictionary of some SMTP commands (non-exhaustive) 
  - poor corpus

