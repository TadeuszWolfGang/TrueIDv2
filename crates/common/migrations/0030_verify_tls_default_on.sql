-- Security remediation: TLS certificate verification is now ON by default for
-- firewall targets (was OFF, enabling MITM credential harvesting on PAN-OS
-- keygen and FortiGate token flows). Existing targets with verify_tls=0 are
-- migrated to the secure default; operators relying on self-signed certs must
-- explicitly re-disable verification per target.
UPDATE firewall_targets SET verify_tls = 1 WHERE verify_tls = 0;
