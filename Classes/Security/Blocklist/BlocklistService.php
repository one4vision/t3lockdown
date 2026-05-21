<?php

namespace Extension14v\T3lockdown\Security\Blocklist;

use Extension14v\T3lockdown\Security\Configuration\LockdownConfiguration;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Manages IP whitelists, blacklists, temporary blocks.
 */
final readonly class BlocklistService
{
    public function __construct(
        private readonly LockdownConfiguration $configuration,
        private readonly ConnectionPool $connectionPool,
    ) {
    }

    public function isWhitelisted(string $ip): bool
    {
        return $this->isIpInList($ip, $this->configuration->whiteList);
    }

    public function isBlacklisted(string $ip): bool
    {
        return $this->isIpInList($ip, $this->configuration->blackList);
    }

    public function isTemporarilyBlocked(string $ip): bool
    {
        $blockInterval = time() - $this->configuration->blockDelayInSeconds;
        $checkDate     = (new \DateTimeImmutable('now', new \DateTimeZone('Europe/Berlin')))
            ->setTimestamp($blockInterval);

        $connection = $this->connectionPool->getConnectionForTable('tx_t3lockdown_domain_model_blockips');
        $count = (int)$connection
            ->createQueryBuilder()
            ->count('uid')
            ->from('tx_t3lockdown_domain_model_blockips')
            ->where(
                'remote_ip = :ip',
                'attack_date >= :since',
            )
            ->setParameter('ip', $ip)
            ->setParameter('since', $checkDate->format('Y-m-d H:i:s'))
            ->executeQuery()
            ->fetchOne();
        return $count > 0;
    }

    public function blockIp(string $ip, int $blockMinutes): void
    {
        $connection = $this->connectionPool->getConnectionForTable('tx_t3lockdown_domain_model_blockips');
        $now        = (new \DateTimeImmutable('now', new \DateTimeZone('Europe/Berlin')))->format('Y-m-d H:i:s');
        $connection->insert('tx_t3lockdown_domain_model_blockips', [
            'pid'          => 0,
            'attack_date'   => $now,
            'remote_ip'     => $ip,
            'block_minutes' => $blockMinutes,
        ]);
    }

    private function isIpInList(string $ip, array $list): bool
    {
        foreach ($list as $entry) {
            if ($entry === $ip) {
                return true;
            }
            // CIDR support
            if (str_contains($entry, '/') && $this->ipMatchesCidr($ip, $entry)) {
                return true;
            }
        }

        return false;
    }

    private function ipMatchesCidr(string $ip, string $cidr): bool
    {
        [$range, $bits] = explode('/', $cidr, 2);
        $bits = (int)$bits;
        $ipLong    = ip2long($ip);
        $rangeLong = ip2long($range);
        if ($ipLong === false || $rangeLong === false) {
            return false;
        }
        $mask = $bits > 0 ? (~0 << (32 - $bits)) : 0;
        return ($ipLong & $mask) === ($rangeLong & $mask);
    }
}