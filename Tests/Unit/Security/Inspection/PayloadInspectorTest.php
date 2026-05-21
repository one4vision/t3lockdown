<?php
namespace Extension14v\T3lockdown\Tests\Unit\Security\Inspection;

use Extension14v\T3lockdown\Security\Configuration\LockdownConfiguration;
use Extension14v\T3lockdown\Security\Inspection\PayloadInspector;
use PHPUnit\Framework\TestCase;

final class PayloadInspectorTest extends TestCase
{
    public function testHarmlessInputDoesNotCreateMatches(): void
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

        $subject = new PayloadInspector($configuration);

        $result = $subject->inspect([
            'q' => 'hello world',
        ]);

        self::assertFalse($result->hasMatches());
        self::assertSame([], $result->getMatches());
    }

    public function testDetectsScriptTagAsXss(): void
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

        $subject = new PayloadInspector($configuration);

        $result = $subject->inspect([
            'comment' => '<script>alert(1)</script>',
        ]);

        self::assertTrue($result->hasMatches());
        self::assertCount(1, $result->getMatches());
        self::assertSame(['xss'], $result->getAttackTypes());
        self::assertSame('xss', $result->getMatches()[0]->type);
        self::assertSame('comment', $result->getMatches()[0]->fieldName);
    }

    public function testDetectsUnionSelectAsSqlInjection(): void
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

        $subject = new PayloadInspector($configuration);

        $result = $subject->inspect([
            'q' => '1 union select username, password from be_users',
        ]);

        self::assertTrue($result->hasMatches());
        self::assertContains('sql', $result->getAttackTypes());
        self::assertSame('sql', $result->getMatches()[0]->type);
    }

    public function testInspectSkipsExtbaseWhitelistedParameter(): void
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

        $subject = new PayloadInspector($configuration);

        $result = $subject->inspect([
            'tx_news_pi1[news]' => '\'" OR 1=1 --',
        ]);

        self::assertFalse($result->hasMatches());
    }
}