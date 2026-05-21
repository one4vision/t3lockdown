<?php

namespace Extension14v\T3lockdown\Security\Notification;

use Extension14v\T3lockdown\Security\Configuration\LockdownConfiguration;
use Extension14v\T3lockdown\Security\Inspection\InspectionResult;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Mime\Address;
use TYPO3\CMS\Core\Log\LogManager;
use TYPO3\CMS\Core\Mail\MailMessage;

/**
 * Sends alert notifications for detected attacks and IP blocks.
 */
final readonly class NotificationService
{
    private readonly LoggerInterface $logger;
    public function __construct(
        private readonly LockdownConfiguration $configuration,
        LogManager $logManager,
    ) {
        $this->logger = $logManager->getLogger(__CLASS__);
    }

    public function sendAttackAlert(
        InspectionResult $result,
        ServerRequestInterface $request,
        string $ip,
    ): void {
        if (!$this->configuration->sendMailEveryRequest) {
            $this->logger->warning('T3LockDown mail skipped: sendMailEveryRequest is false');
            return;
        }

        if ($this->configuration->blockMailTo === []) {
            $this->logger->warning('T3LockDown mail skipped: no recipients configured');
            return;
        }

        $host        = (string)($request->getServerParams()['HTTP_HOST'] ?? 'unknown');
        $isHeader    = $result->hasType('header');
        $subject     = sprintf(
            'T3LOCKDOWN: Possible attack detected on %s%s',
            $host,
            $isHeader ? ' [HEADER ATTACK]' : '',
        );

        $this->send($subject, $this->buildAttackMailBody($result, $request, $ip, $host));
    }

    public function sendBlockAlert(
        InspectionResult $result,
        ServerRequestInterface $request,
        string $ip,
        int $blockMinutes,
    ): void {
        if (!$this->configuration->sendBlockMail) {
            return;
        }

        if ($this->configuration->blockMailTo === []) {
            return;
        }

        $host     = (string)($request->getServerParams()['HTTP_HOST'] ?? 'unknown');
        $isHeader = $result->hasType('header');
        $subject  = sprintf(
            'T3LOCKDOWN: IP %s blocked for %d minutes on %s%s',
            $ip,
            $blockMinutes,
            $host,
            $isHeader ? ' [HEADER ATTACK]' : '',
        );

        $this->send($subject, $this->buildAttackMailBody($result, $request, $ip, $host));
    }

    private function buildAttackMailBody(
        InspectionResult $result,
        ServerRequestInterface $request,
        string $ip,
        string $host,
    ): string {
        $date   = (new \DateTimeImmutable('now', new \DateTimeZone('Europe/Berlin')))->format('d.m.Y H:i:s');
        $uri    = htmlspecialchars((string)$request->getUri(), ENT_QUOTES | ENT_HTML5);
        $method = htmlspecialchars($request->getMethod(), ENT_QUOTES | ENT_HTML5);
        $safeIp = htmlspecialchars($ip, ENT_QUOTES | ENT_HTML5);
        $safeHost = htmlspecialchars($host, ENT_QUOTES | ENT_HTML5);

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
        <!DOCTYPE html>
        <html lang="de">
        <head><meta charset="UTF-8"><title>T3Lockdown Alert</title></head>
        <body style="font-family:Arial,sans-serif;font-size:13px;color:#333">
            <h2 style="color:#c0392b">T3Lockdown &mdash; Possible Attack Detected</h2>
            <table style="border-collapse:collapse;margin-bottom:16px">
                <tr><td style="padding:4px 8px;font-weight:bold">Date</td><td style="padding:4px 8px">{$date}</td></tr>
                <tr><td style="padding:4px 8px;font-weight:bold">Host</td><td style="padding:4px 8px">{$safeHost}</td></tr>
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
        </body>
        </html>
        HTML;
    }

    private function send(string $subject, string $htmlBody): void
    {
        if ($this->configuration->mailFrom === '') {
            $this->logger->warning('T3LockDown mail skipped: mailFrom is empty');
            return;
        }

        if ($this->configuration->blockMailTo === []) {
            $this->logger->warning('T3LockDown mail skipped: no recipients configured');
            return;
        }

        try {
            $mail = new MailMessage();
            $mail->from(new Address(
                $this->configuration->mailFrom,
                $this->configuration->mailFromName
            ));
            $mail->subject($subject);
            $mail->html($htmlBody);

            foreach ($this->configuration->blockMailTo as $recipient) {
                $mail->addTo(new Address($recipient));
            }

            $mail->send();
        } catch (\Throwable $exception) {
            $this->logger->error('T3LockDown mail sending failed', [
                'subject' => $subject,
                'from' => $this->configuration->mailFrom,
                'to' => $this->configuration->blockMailTo,
                'error' => $exception->getMessage(),
            ]);
        }
    }
}