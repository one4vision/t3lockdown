# TYPO3 extension ``t3lockdown``

![Total downloads](https://typo3-badges.dev/badge/t3lockdown/downloads/shields.svg)
![TYPO3 extension](https://typo3-badges.dev/badge/t3lockdown/extension/shields.svg)
![Stability](https://typo3-badges.dev/badge/t3lockdown/stability/shields.svg)
![TYPO3 versions](https://typo3-badges.dev/badge/t3lockdown/typo3/shields.svg)
![Latest version](https://typo3-badges.dev/badge/t3lockdown/version/shields.svg)
<!-- Generated with 🧡 at typo3-badges.dev -->

T3LockDown protects TYPO3 installations against suspicious requests such as SQL injection, cross-site scripting, 
and malicious header payloads by inspecting incoming requests before they reach application logic. The extension 
can log attacks to the database, send alert emails, rate-limit abusive traffic, and temporarily block IP addresses 
after repeated attack attempts.

## Purpose

The extension is intended for administrators who want an additional request-level protection layer in TYPO3. It 
focuses on practical mitigation: detect suspicious payloads, record what happened, alert administrators, and 
optionally enforce temporary IP blocking when a threshold is reached.

## Installation

Install the extension with Composer in the TYPO3 project and activate it in the TYPO3 backend. TYPO3 extension 
configuration is managed through `ext_conf_template.txt`, and the saved values are stored in TYPO3 system settings 
for runtime use.

```bash
composer require one4vision/t3lockdown
```

After installation, open the TYPO3 backend and configure the extension in **Admin Tools > Settings > Extension Configuration**.

## Configuration areas

The extension configuration is grouped into several administrator-friendly sections in `ext_conf_template.txt`.

| Area | Purpose |
|---|---|
| Detection | Enables SQL injection, XSS, header, and cookie inspection. |
| Blocking | Controls whether repeated attacks should lead to temporary IP blocking and defines thresholds. |
| Notifications | Defines whether alert emails are sent and which sender/recipient addresses are used. |
| Rate limiting | Limits repeated requests inside a configurable time window. |
| Header inspection | Defines allowed header exceptions and headers that should be skipped during inspection. |
| Lists | Maintains blacklists, whitelists, and URL whitelists. |

## Key settings

### Detection

- `checkSqlInjAttacks`: Enables SQL injection pattern detection.
- `checkXss`: Enables XSS payload detection.
- `checkHeaders`: Enables inspection of HTTP headers.
- `checkCookieVars`: Includes cookie values in payload inspection.
- `logAttacksInDB`: Stores attack attempts in the database for later review.

### Blocking

- `blockRequests`: Enables temporary IP blocking after repeated attack attempts.
- `maxCountAttemptsForBlock`: Number of detected attacks before an IP is blocked.
- `attemptIntervalInSeconds`: Time window used to count attempts.
- `blockDelayInSeconds`: Duration of the temporary block.

### Notifications

- `sendMailEveryRequest`: Sends an alert for every detected attack.
- `sendBlockMail`: Sends an additional alert when an IP is blocked.
- `mailFrom`: Preferred sender address for alerts.
- `mailFromName`: Preferred sender name for alerts.
- `blockMailTo`: Comma-separated recipient list.

If `mailFrom` is empty, the extension should fall back to TYPO3's global `MAIL.defaultMailFromAddress`.  
If `mailFromName` is empty, it should fall back to `MAIL.defaultMailFromName`, and finally to `T3LockDown` as a last-resort display name.

### Rate limiting

- `rateLimitingEnabled`: Enables request throttling.
- `rateLimitMaxRequests`: Maximum number of requests allowed in the configured window.
- `rateLimitSecondsWindow`: Length of the rate-limit window in seconds.

### Header inspection

- `allowedHeaderExceptions`: Comma-separated list of allowed substrings that should not trigger header alerts.
- `ignoreHeaderStringParsing`: Comma-separated list of header names that should be skipped entirely.

### Lists

- `blackList`: Always blocked IPs, supports wildcard matching when implemented by the extension.
- `whiteList`: Always allowed IPs.
- `urlWhiteList`: Allowed request paths that bypass lockdown checks.

## Email behavior

The extension uses TYPO3's Mail API for sending alert emails. A practical fallback strategy for sender data is:

1. Use the sender address and name defined in T3LockDown.
2. Fall back to TYPO3 global mail defaults.
3. Use `T3LockDown` as final sender name if no global name is defined.

Administrators should ensure that TYPO3 global mail transport is configured correctly; otherwise alert delivery 
may fail even when the extension configuration is valid.

## Logging and response behavior

When a request is identified as malicious, the extension can log details such as request method, URL, IP address, 
matched rules, and additional request context into the database. A blocked request should return a visible HTTP 
403 response with a human-readable message instead of an empty response body, which improves both user feedback 
and operational debugging.

## TYPO3 backend module

The extension also provides a TYPO3 backend module for administrators to review logged attacks centrally. This 
module can be used to inspect recorded attack entries, review request details, identify attack types such as SQL 
injection, XSS, and header attacks, and monitor activity over time through aggregated backend views.

The backend module is especially useful for operational monitoring because it complements email alerts with a 
persistent analysis interface inside TYPO3. It gives administrators direct access to logged request data such as 
timestamps, methods, IP addresses, request URIs, user agents, and attack classifications without requiring direct 
database access.

## Recommended defaults

The following baseline is suitable for most productive installations.

| Setting | Recommended value |
|---|---|
| `checkSqlInjAttacks` | `1` |
| `checkXss` | `1` |
| `checkHeaders` | `1` |
| `logAttacksInDB` | `1` |
| `blockRequests` | `1` |
| `sendMailEveryRequest` | `1` |
| `sendBlockMail` | `1` |
| `rateLimitingEnabled` | `1` |
| `ignoreHeaderStringParsing` | empty |
| `allowedHeaderExceptions` | `force-revalidate` only if this is known to prevent real false positives |

## Configuration example

An example extension configuration could look like this:

```php
$GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['t3lockdown'] = [
    'checkSqlInjAttacks' => '1',
    'checkHeaders' => '1',
    'checkXss' => '1',
    'logAttacksInDB' => '1',
    'blockRequests' => '1',
    'maxCountAttemptsForBlock' => '3',
    'attemptIntervalInSeconds' => '300',
    'blockDelayInSeconds' => '900',
    'sendBlockMail' => '1',
    'sendMailEveryRequest' => '1',
    'mailFrom' => 'security@example.org',
    'mailFromName' => 'T3LockDown',
    'blockMailTo' => 'admin@example.org',
    'rateLimitingEnabled' => '1',
    'rateLimitMaxRequests' => '30',
    'rateLimitSecondsWindow' => '60',
    'allowedHeaderExceptions' => 'force-revalidate',
    'ignoreHeaderStringParsing' => '',
    'urlWhiteList' => '/tiles',
];
```