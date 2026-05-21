<?php

declare(strict_types=1);

namespace Extension14v\T3lockdown\Tests\Unit\Security\Blocklist;

use Extension14v\T3lockdown\Security\Blocklist\BlocklistService;
use Extension14v\T3lockdown\Security\Configuration\LockdownConfiguration;
use PHPUnit\Framework\TestCase;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

final class BlocklistServiceTest extends TestCase
{
    public function testIsWhitelistedRecognizesExactIp(): void
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
            whiteList: ['127.0.0.1'],
            urlWhiteList: [],
            rateLimitingEnabled: false,
            rateLimitSecondsWindow: 60,
            rateLimitMaxRequests: 30,
            allowedHeaderExceptions: [],
            ignoreHeaderStringParsing: [],
        );

        $connectionPool = $this->createMock(ConnectionPool::class);

        $subject = new BlocklistService($configuration, $connectionPool);

        self::assertTrue($subject->isWhitelisted('127.0.0.1'));
        self::assertFalse($subject->isWhitelisted('127.0.0.2'));
    }

    public function testIsWhitelistedRecognizesCidrRange(): void
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
            whiteList: ['192.168.1.0/24'],
            urlWhiteList: [],
            rateLimitingEnabled: false,
            rateLimitSecondsWindow: 60,
            rateLimitMaxRequests: 30,
            allowedHeaderExceptions: [],
            ignoreHeaderStringParsing: [],
        );

        $connectionPool = $this->createMock(ConnectionPool::class);

        $subject = new BlocklistService($configuration, $connectionPool);

        self::assertTrue($subject->isWhitelisted('192.168.1.42'));
        self::assertFalse($subject->isWhitelisted('192.168.2.42'));
    }

    public function testBlockIpInsertsDatabaseRecord(): void
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

        $connection = $this->createMock(Connection::class);
        $connection->expects(self::once())
            ->method('insert')
            ->with(
                'tx_t3lockdown_domain_model_blockips',
                self::callback(static function (array $data): bool {
                    return $data['pid'] === 0
                        && $data['remote_ip'] === '192.168.1.42'
                        && $data['block_minutes'] === 15
                        && isset($data['attack_date']);
                })
            );

        $connectionPool = $this->createMock(ConnectionPool::class);
        $connectionPool->expects(self::once())
            ->method('getConnectionForTable')
            ->with('tx_t3lockdown_domain_model_blockips')
            ->willReturn($connection);

        $subject = new BlocklistService($configuration, $connectionPool);

        $subject->blockIp('192.168.1.42', 15);
    }

    public function testIsTemporarilyBlockedReturnsTrueWhenBlockExists(): void
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

        $result = $this->createMock(\Doctrine\DBAL\Result::class);
        $result->expects(self::once())
            ->method('fetchOne')
            ->willReturn(1);

        $queryBuilder = $this->createMock(\TYPO3\CMS\Core\Database\Query\QueryBuilder::class);
        $queryBuilder->expects(self::once())
            ->method('count')
            ->with('uid')
            ->willReturnSelf();
        $queryBuilder->expects(self::once())
            ->method('from')
            ->with('tx_t3lockdown_domain_model_blockips')
            ->willReturnSelf();
        $queryBuilder->expects(self::once())
            ->method('where')
            ->with(
                'remote_ip = :ip',
                'attack_date >= :since',
            )
            ->willReturnSelf();
        $queryBuilder->expects(self::exactly(2))
            ->method('setParameter')
            ->willReturnSelf();
        $queryBuilder->expects(self::once())
            ->method('executeQuery')
            ->willReturn($result);

        $connection = $this->createMock(\TYPO3\CMS\Core\Database\Connection::class);
        $connection->expects(self::once())
            ->method('createQueryBuilder')
            ->willReturn($queryBuilder);

        $connectionPool = $this->createMock(\TYPO3\CMS\Core\Database\ConnectionPool::class);
        $connectionPool->expects(self::once())
            ->method('getConnectionForTable')
            ->with('tx_t3lockdown_domain_model_blockips')
            ->willReturn($connection);

        $subject = new BlocklistService($configuration, $connectionPool);

        self::assertTrue($subject->isTemporarilyBlocked('192.168.1.42'));
    }
}