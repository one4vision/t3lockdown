<?php

namespace Extension14v\T3lockdown\Security\Logging;

use Extension14v\T3lockdown\Security\Configuration\LockdownConfiguration;
use Extension14v\T3lockdown\Security\Inspection\InspectionResult;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Log\LogManager;

/**
 * Persists attack detection results to the TYPO3 log and database.
 */
final readonly class AttackLogger
{
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly LockdownConfiguration $configuration,
        private readonly ConnectionPool $connectionPool,
        LogManager $logManager,
    ) {
        $this->logger = $logManager->getLogger(__CLASS__);
    }

    public function log(
        InspectionResult $result,
        ServerRequestInterface $request,
        string $ip,
    ): void {
        $serverParams = $request->getServerParams();
        $uri          = (string)$request->getUri();
        $host         = (string)($serverParams['HTTP_HOST'] ?? 'unknown');
        $method       = $request->getMethod();
        $userAgent    = (string)($serverParams['HTTP_USER_AGENT'] ?? '');
        $scriptFile   = (string)($serverParams['SCRIPT_FILENAME'] ?? '');
        $attackTypes  = implode(',', $result->getAttackTypes());
        $attackDate   = new \DateTimeImmutable('now', new \DateTimeZone('Europe/Berlin'));

        $this->logger->warning('T3Lockdown: Possible attack detected', [
            'ip'          => $ip,
            'host'        => $host,
            'uri'         => $uri,
            'method'      => $method,
            'attackTypes' => $attackTypes,
            'matches'     => array_map(
                static fn($m) => [
                    'type'      => $m->type,
                    'rule'      => $m->ruleName,
                    'field'     => $m->fieldName,
                    'fromHeader' => $m->fromHeader,
                ],
                $result->getMatches()
            ),
        ]);

        if (!$this->configuration->logAttacksInDb) {
            return;
        }

        $this->persistToDatabase(
            result: $result,
            ip: $ip,
            host: $host,
            uri: $uri,
            method: $method,
            userAgent: $userAgent,
            scriptFile: $scriptFile,
            attackTypes: $attackTypes,
            attackDate: $attackDate,
            queryParams: $request->getQueryParams(),
            html: $this->buildAttackBody($result, $request, $ip, $host),
        );
    }

    public function countRecentAttempts(string $ip, \DateTimeImmutable $since): int
    {
        $connection = $this->connectionPool->getConnectionForTable('tx_t3lockdown_domain_model_attempts');

        return (int)$connection
            ->createQueryBuilder()
            ->count('uid')
            ->from('tx_t3lockdown_domain_model_attempts')
            ->where(
                'remote_ip = :ip',
                'attack_date >= :since',
            )
            ->setParameter('ip', $ip)
            ->setParameter('since', $since->format('Y-m-d H:i:s'))
            ->executeQuery()
            ->fetchOne();
    }

    private function persistToDatabase(
        InspectionResult $result,
        string $ip,
        string $host,
        string $uri,
        string $method,
        string $userAgent,
        string $scriptFile,
        string $attackTypes,
        \DateTimeImmutable $attackDate,
        array $queryParams,
        string $html,
    ): void {
        $connection = $this->connectionPool->getConnectionForTable('tx_t3lockdown_domain_model_attempts');

        $matchSummary = array_map(
            static fn($m) => sprintf('[%s] %s on field "%s"', $m->type, $m->ruleName, $m->fieldName),
            $result->getMatches()
        );

        $connection->insert('tx_t3lockdown_domain_model_attempts', [
            'pid'           => 0,
            'attack_date'    => $attackDate->format('Y-m-d H:i:s'),
            't3host'        => $host,
            'request_file'   => $scriptFile,
            'request_method' => $method,
            'input_vars'     => json_encode($queryParams, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE),
            'remote_ip'      => $ip,
            'useragent'     => $userAgent,
            'details'       => $html,
            'request_url'    => $uri,
            'from_header'    => (int)$result->hasType('header'),
            'attack_types'   => $attackTypes,
        ]);
    }

    private function buildAttackBody(
        InspectionResult $result,
        ServerRequestInterface $request,
        string $ip,
        string $host,
    ): string {
        $date   = (new \DateTimeImmutable('now', new \DateTimeZone('Europe/Berlin')))->format('d.m.Y H:i:s');
        $uri    = htmlspecialchars((string)$request->getUri(), ENT_QUOTES | ENT_HTML5);
        $method = htmlspecialchars($request->getMethod(), ENT_QUOTES | ENT_HTML5);
        $safeIp = htmlspecialchars($ip, ENT_QUOTES | ENT_HTML5);

        $rows = '';
        foreach ($result->getMatches() as $match) {
            $rows .= sprintf(
                '<tr>
                    <td style="padding:4px 8px;border:1px solid #ddd">%s</td>
                    <td style="padding:4px 8px;border:1px solid #ddd">%s</td>
                    <td style="padding:4px 8px;border:1px solid #ddd">%s</td>
                    <td style="padding:4px 8px;border:1px solid #ddd">%s</td>
                </tr>',
                htmlspecialchars($match->type, ENT_QUOTES | ENT_HTML5),
                htmlspecialchars($match->ruleName, ENT_QUOTES | ENT_HTML5),
                htmlspecialchars($match->fieldName, ENT_QUOTES | ENT_HTML5),
                htmlspecialchars($match->fieldValue, ENT_QUOTES | ENT_HTML5),
            );
        }

        return <<<HTML
        <div>
            <h2 style="color:#c0392b">T3Lockdown &mdash; Possible Attack Detected</h2>
            <table style="border-collapse:collapse;margin-bottom:16px">
                <tr><td style="padding:4px 8px;font-weight:bold">Date</td><td style="padding:4px 8px">{$date}</td></tr>
                <tr><td style="padding:4px 8px;font-weight:bold">Host</td><td style="padding:4px 8px">{$host}</td></tr>
                <tr><td style="padding:4px 8px;font-weight:bold">IP</td><td style="padding:4px 8px">{$safeIp}</td></tr>
                <tr><td style="padding:4px 8px;font-weight:bold">Method</td><td style="padding:4px 8px">{$method}</td></tr>
                <tr><td style="padding:4px 8px;font-weight:bold">URL</td><td style="padding:4px 8px">{$uri}</td></tr>
            </table>

            <h3>Detected Patterns</h3>
            <table style="border-collapse:collapse;width:100%">
                <thead>
                    <tr style="background:#f2f2f2">
                        <th style="padding:4px 8px;border:1px solid #ddd;text-align:left">Type</th>
                        <th style="padding:4px 8px;border:1px solid #ddd;text-align:left">Rule</th>
                        <th style="padding:4px 8px;border:1px solid #ddd;text-align:left">Field</th>
                        <th style="padding:4px 8px;border:1px solid #ddd;text-align:left">Value (excerpt)</th>
                    </tr>
                </thead>
                <tbody>{$rows}</tbody>
            </table>
        </div>
        HTML;
    }
}