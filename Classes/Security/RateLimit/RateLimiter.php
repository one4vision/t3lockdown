<?php

namespace Extension14v\T3lockdown\Security\RateLimit;

use Extension14v\T3lockdown\Security\Configuration\LockdownConfiguration;
use TYPO3\CMS\Core\Cache\CacheManager;

/**
 * Checks and tracks request rates per IP address using TYPO3 cache.
 */
final readonly class RateLimiter
{
    public function __construct(
        private readonly LockdownConfiguration $configuration,
        private readonly CacheManager $cacheManager,
    ) {
    }

    public function isLimited(string $ip): bool
    {
        if (!$this->configuration->rateLimitingEnabled) {
            return false;
        }

        $cache = $this->cacheManager->getCache('t3lockdown_rate_limit');
        $key   = 'ratelimit_' . md5($ip);

        /** @var array{count: int, timestamp: int}|false $data */
        $data = $cache->get($key);
        $now  = time();
        $window = $this->configuration->rateLimitSecondsWindow;
        $limit  = $this->configuration->rateLimitMaxRequests;

        if (is_array($data)) {
            if (($now - $data['timestamp']) >= $window) {
                // Zeitfenster abgelaufen - neu starten
                $data = ['count' => 1, 'timestamp' => $now];
            } else {
                $data['count']++;
            }
        } else {
            $data = ['count' => 1, 'timestamp' => $now];
        }

        $cache->set($key, $data, [], $window);
        return $data['count'] > $limit;
    }
}