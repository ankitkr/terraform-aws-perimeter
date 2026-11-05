# Security

Please report a vulnerability privately through
[GitHub's security advisories](https://github.com/ankitkr/terraform-aws-perimeter/security/advisories/new),
not in a public issue. You'll get a reply within a week.

## What the module can do, by design

- **It reads.** In every account the planner and tripwire functions assume `<name>-member`,
  which lists network configuration and endpoints with named read actions, and can change
  nothing. Some of those listings carry more than the inventory uses, and the role can read
  them: Lambda environment variables (`lambda:ListFunctions`), CloudFront origin custom headers
  (`cloudfront:ListDistributions`), and API Gateway stage variables (`apigateway:GET` on
  `/restapis/*` and `/apis/*`). If you keep secrets there, the scanner account can read them.
  The role can't read instance user data, Lightsail access details (keys and passwords),
  API Gateway API keys, or S3 object contents. Its trust policy admits only the scanner account's
  `<name>-planner` and `<name>-tripwire` roles (`ArnEquals` on `aws:PrincipalArn`), plus the
  external ID when you set one.
- **It scans only your addresses.** The scanner connects only to IPv4 addresses that the
  planner found on a network interface or Lightsail instance in a listed account. Each batch's
  verify step re-checks every address with `DescribeNetworkInterfaces` (or Lightsail's
  `GetInstance`) right before the batch scans, and stamps the batch with an expiry 10 minutes
  after that check. The scanner refuses a batch past its expiry and starts no connection
  attempt after it, so every connection goes to an address proven to be yours less than 10
  minutes earlier. Batches are cut so that their worst case fits that window. It refuses private,
  shared, loopback and link-local addresses, and HTTP hosts that aren't AWS hostnames
  (`*.cloudfront.net`, `*.amazonaws.com`, `*.on.aws`). It reads at most 256 bytes from an open
  port and sends nothing.
- **The scanner's role can only write its own logs.** Its only resource-policy grant is to the
  state machine's role.
- **The functions write only** their DynamoDB table, their S3 bucket, their SNS topic, and (the
  tripwire) executions of their state machine.
- **The Slack channel** can only display notifications. Its role and guardrail allow reading the
  CloudWatch data Amazon Q uses to render them, nothing else.
- **Alerts and the inventory document** contain endpoint ids, addresses, ports, rule ids,
  banners, and the caller and source IP of tripwire events. The bucket is private, encrypted
  and TLS-only. Treat the Slack channel and the bucket as sensitive: together they map your
  attack surface.

## What to know and protect

- **The scanner can be invoked by any principal in the scanner account whose IAM policies allow
  `lambda:InvokeFunction` on it.** Lambda resource policies can't deny same-account callers. The
  proof in a batch is a format check, not a signature, so such a caller could point the scanner
  at any global IPv4 address, at up to 500 attempts per second. Keep the scanner account to
  security administrators, as you would for any security tooling.
- **Write access to the event bus.** The bus accepts `PutEvents` only from the listed accounts
  and only with the tripwire event sources. Whatever reaches it, the worst outcome is a
  misleading tripwire alert and a targeted run (at most one per distinct event id) that rescans
  endpoints the planner itself finds in that account. An event can't make the scanner touch an
  address the planner didn't find, and the tripwire starts runs only for listed accounts.
- **The DynamoDB table** holds the configuration the functions act on, including `expected`.
  Write access to it can silence alerts. Keep it to the module and your administrators.
- **`expected` is code.** A pull request that adds an entry silences an alert; review those like
  firewall changes.
