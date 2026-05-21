<?php

namespace Extension14v\T3lockdown\Security\Configuration;

/**
 * Central configuration for the lockdown security layer.
 */
final readonly class LockdownConfiguration
{
    public function __construct(
        public readonly bool $checkCookieVars,
        public readonly bool $checkSqlInjAttacks,
        public readonly bool $checkHeaders,
        public readonly bool $checkXss,
        public readonly bool $logAttacksInDb,
        public readonly bool $blockRequests,
        public readonly int $attemptIntervalInSeconds,
        public readonly int $maxCountAttemptsForBlock,
        public readonly int $blockDelayInSeconds,
        public readonly bool $sendBlockMail,
        public readonly bool $sendMailEveryRequest,
        public readonly string $mailFrom,
        public readonly string $mailFromName,
        public readonly array $blockMailTo,
        public readonly array $blackList,
        public readonly array $whiteList,
        public readonly array $urlWhiteList,
        public readonly bool $rateLimitingEnabled,
        public readonly int $rateLimitSecondsWindow,
        public readonly int $rateLimitMaxRequests,
        public readonly array $allowedHeaderExceptions,
        public readonly array $ignoreHeaderStringParsing,
    ) {
    }
}