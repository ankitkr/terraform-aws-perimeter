# Roadmap

v1 covers the endpoints and checks most small teams need. This is what may come next. Nothing
here has a date: what ships depends on what users actually run into. Open an issue if one of
these matters to you, or if something isn't here.

## Planned

Gaps that users will hit. They fit v1's model: a new endpoint type is one more inventory
function, and Slack interaction reuses the pattern from
[terraform-aws-devboxes](https://github.com/ankitkr/terraform-aws-devboxes).

- **More endpoint types:**
  - App Runner and Amplify hosts;
  - AppSync APIs;
  - Transfer Family SFTP servers;
  - Cognito hosted-UI domains;
  - Amazon MQ and MSK public access;
  - Client VPN endpoints;
  - Global Accelerator;
  - Redshift.
- **Slack commands:** `perimeter-status` lists the current findings, and
  `perimeter-scan <endpoint>` rescans one endpoint on demand.
- **A Rescan button** on finding notifications.
- **A weekly digest:** one message with the current perimeter and what changed during the week.
- **Organization discovery:** scan every active account in an AWS Organization instead of listing
  accounts by hand.
- **IPv6 scanning:** v1 analyses IPv6 security group rules and routes but only scans IPv4. Scanning
  IPv6 needs the scanner to run inside a dual-stack VPC.

## Considered

Depth rather than coverage. These will be weighed against the complexity they add.

- **Network Access Analyzer as an optional cross-check:** AWS's own path analysis, run only on
  flagged findings (about $0.002 per network interface), to confirm the module's explanation.
- **Transit Gateway, Gateway Load Balancer and Network Firewall paths:** v1 marks paths through them
  as unverified.
- **TLS checks on open HTTPS ports:** certificate expiry, old protocol versions.
- **Light service fingerprinting** beyond the first 256 bytes of a banner.

## Not planned

Other tools already do these well, or they change what the module is.

- UDP scanning.
- Web application vulnerability scanning.
- Automatic remediation: exposure is declared in code, and fixes belong there too.
- Azure and Google Cloud.
