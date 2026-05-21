<?php
namespace Extension14v\T3lockdown\Tests\Unit\Security\Inspection;

use Extension14v\T3lockdown\Security\Configuration\LockdownConfiguration;
use Extension14v\T3lockdown\Security\Inspection\HeaderInspector;
use PHPUnit\Framework\TestCase;

final class HeaderInspectorTest extends TestCase
{
    public function testHarmlessHeadersDoNotCreateMatches(): void
    {
        $configuration = new LockdownConfiguration(
            checkCookieVars: false,
            checkSqlInjAttacks: true,
            checkHeaders: true,
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
            allowedHeaderExceptions: ['force-revalidate'],
            ignoreHeaderStringParsing: ['referer', 'http-referer'],
        );

        $subject = new HeaderInspector($configuration);

        $result = $subject->inspect([
            'x-custom-header' => ['hello-world'],
        ]);

        self::assertFalse($result->hasMatches());
        self::assertSame([], $result->getMatches());
    }

    public function testDetectsSuspiciousHeaderValue(): void
    {
        $configuration = new LockdownConfiguration(
            checkCookieVars: false,
            checkSqlInjAttacks: true,
            checkHeaders: true,
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
            allowedHeaderExceptions: ['force-revalidate'],
            ignoreHeaderStringParsing: ['referer', 'http-referer'],
        );

        $subject = new HeaderInspector($configuration);

        $result = $subject->inspect([
            'x-custom-header' => ['eval(base64_decode("abc"))'],
        ]);

        self::assertTrue($result->hasMatches());
        self::assertCount(1, $result->getMatches());
        self::assertContains('header', $result->getAttackTypes());
        self::assertSame('header', $result->getMatches()[0]->type);
        self::assertSame('x-custom-header', $result->getMatches()[0]->fieldName);
    }
}