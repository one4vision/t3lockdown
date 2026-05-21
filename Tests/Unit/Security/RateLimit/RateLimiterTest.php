<?php

declare(strict_types=1);

namespace Extension14v\T3lockdown\Tests\Unit\Security\RateLimit;

use Extension14v\T3lockdown\Security\Configuration\LockdownConfiguration;
use Extension14v\T3lockdown\Security\RateLimit\RateLimiter;
use PHPUnit\Framework\TestCase;
use TYPO3\CMS\Core\Cache\CacheManager;

final class RateLimiterTest extends TestCase
{
    public function testIsLimitedReturnsFalseWhenDisabled(): void
    {
        $configuration = new LockdownConfiguration(
            checkCookieVars: false,
            checkSqlInjAttacks: true,
            checkHeaders: false,
            checkXss: true,
            logAttacksInDb: false,
            blockRequests: true,
            attemptIntervalInSeconds: 300,
            maxCountAttemptsForBlock: 3,
            blockDelayInSeconds: 900,
            sendBlockMail: false,
            sendMailEveryRequest: false,
            mailFrom: '',
            blockMailTo: [],
            blackList: [],
            whiteList: [],
            urlWhiteList: [],
            rateLimitingEnabled: false,
            rateLimitSecondsWindow: 60,
            rateLimitMaxRequests: 30,
            allowedHeaderExceptions: [],
            ignoreHeaderStringParsing: [],
        );

        $cacheManager = $this->createMock(CacheManager::class);

        $subject = new RateLimiter($configuration, $cacheManager);

        self::assertFalse($subject->isLimited('192.168.1.42'));
    }

    public function testIsLimitedReturnsFalseBelowLimit(): void
    {
        $configuration = new LockdownConfiguration(
            checkCookieVars: false,
            checkSqlInjAttacks: true,
            checkHeaders: false,
            checkXss: true,
            logAttacksInDb: false,
            blockRequests: true,
            attemptIntervalInSeconds: 300,
            maxCountAttemptsForBlock: 3,
            blockDelayInSeconds: 900,
            sendBlockMail: false,
            sendMailEveryRequest: false,
            mailFrom: '',
            blockMailTo: [],
            blackList: [],
            whiteList: [],
            urlWhiteList: [],
            rateLimitingEnabled: true,
            rateLimitSecondsWindow: 60,
            rateLimitMaxRequests: 30,
            allowedHeaderExceptions: [],
            ignoreHeaderStringParsing: [],
        );

        $cache = $this->createMock(\TYPO3\CMS\Core\Cache\Frontend\FrontendInterface::class);
        $cache->expects(self::once())
            ->method('get')
            ->willReturn([
                'count' => 5,
                'timestamp' => time(),
            ]);

        $cache->expects(self::once())
            ->method('set')
            ->with(
                self::stringStartsWith('ratelimit_'),
                self::isType('array'),
                [],
                60
            );

        $cacheManager = $this->createMock(CacheManager::class);
        $cacheManager->expects(self::once())
            ->method('getCache')
            ->with('t3lockdown_rate_limit')
            ->willReturn($cache);

        $subject = new RateLimiter($configuration, $cacheManager);

        self::assertFalse($subject->isLimited('192.168.1.42'));
    }

    public function testIsLimitedReturnsTrueAboveLimit(): void
    {
        $configuration = new LockdownConfiguration(
            checkCookieVars: false,
            checkSqlInjAttacks: true,
            checkHeaders: false,
            checkXss: true,
            logAttacksInDb: false,
            blockRequests: true,
            attemptIntervalInSeconds: 300,
            maxCountAttemptsForBlock: 3,
            blockDelayInSeconds: 900,
            sendBlockMail: false,
            sendMailEveryRequest: false,
            mailFrom: '',
            blockMailTo: [],
            blackList: [],
            whiteList: [],
            urlWhiteList: [],
            rateLimitingEnabled: true,
            rateLimitSecondsWindow: 60,
            rateLimitMaxRequests: 30,
            allowedHeaderExceptions: [],
            ignoreHeaderStringParsing: [],
        );

        $cache = $this->createMock(\TYPO3\CMS\Core\Cache\Frontend\FrontendInterface::class);
        $cache->expects(self::once())
            ->method('get')
            ->willReturn([
                'count' => 30,
                'timestamp' => time(),
            ]);

        $cache->expects(self::once())
            ->method('set');

        $cacheManager = $this->createMock(CacheManager::class);
        $cacheManager->expects(self::once())
            ->method('getCache')
            ->with('t3lockdown_rate_limit')
            ->willReturn($cache);

        $subject = new RateLimiter($configuration, $cacheManager);

        self::assertTrue($subject->isLimited('192.168.1.42'));
    }
}