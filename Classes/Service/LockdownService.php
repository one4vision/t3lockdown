<?php

namespace Extension14v\T3lockdown\Service;

use Extension14v\T3lockdown\Exception\RequestNotAllowedException;
use Extension14v\T3lockdown\Security\Blocklist\BlocklistService;
use Extension14v\T3lockdown\Security\Configuration\LockdownConfiguration;
use Extension14v\T3lockdown\Security\Inspection\HeaderInspector;
use Extension14v\T3lockdown\Security\Inspection\InputNormalizer;
use Extension14v\T3lockdown\Security\Inspection\InspectionResult;
use Extension14v\T3lockdown\Security\Inspection\PayloadInspector;
use Extension14v\T3lockdown\Security\Logging\AttackLogger;
use Extension14v\T3lockdown\Security\Notification\NotificationService;
use Extension14v\T3lockdown\Security\RateLimit\RateLimiter;
use Psr\Http\Message\ServerRequestInterface;

final readonly class LockdownService
{
    public function __construct(
        private readonly LockdownConfiguration $configuration,
        private readonly PayloadInspector $payloadInspector,
        private readonly HeaderInspector $headerInspector,
        private readonly InputNormalizer $inputNormalizer,
        private readonly RateLimiter $rateLimiter,
        private readonly AttackLogger $attackLogger,
        private readonly NotificationService $notificationService,
        private readonly BlocklistService $blocklistService,
    ) {
    }

    public function handle(ServerRequestInterface $request): void
    {
        $ip = (string)($request->getServerParams()['REMOTE_ADDR'] ?? '');

        // Whitelisted path - skip all checks
        if ($this->isWhitelistedPath($request)) {
            return;
        }

        // IP whitelist - explicitly allowed, skip all checks
        if ($this->configuration->whiteList !== [] && $this->blocklistService->isWhitelisted($ip)) {
            return;
        }

        // IP blacklist - explicitly blocked
        if ($this->configuration->blackList !== [] && $this->blocklistService->isBlacklisted($ip)) {
            throw new RequestNotAllowedException(
                'Your IP address has been blocked on our system.',
                time(),
            );
        }

        // Check if IP is already blocked from a previous attack
        if ($this->configuration->blockRequests && $this->blocklistService->isTemporarilyBlocked($ip)) {
            throw new RequestNotAllowedException(
                'Your IP address has been blocked due to attack attempts on our system.',
                time(),
            );
        }

        // Rate limiting
        if ($this->rateLimiter->isLimited($ip)) {
            throw new RequestNotAllowedException('Too many requests.', time());
        }

        // Run inspection
        $result = $this->inspect($request);
        if (!$result->hasMatches()) {
            return;
        }

        // Log and notify
        $this->attackLogger->log($result, $request, $ip);
        $this->notificationService->sendAttackAlert($result, $request, $ip);

        // Check if block threshold is reached
        if ($this->configuration->blockRequests) {
            $since = new \DateTimeImmutable(
                '-' . $this->configuration->attemptIntervalInSeconds . ' seconds',
                new \DateTimeZone('Europe/Berlin'),
            );
            $attemptCount = $this->attackLogger->countRecentAttempts($ip, $since);
            if ($attemptCount >= $this->configuration->maxCountAttemptsForBlock) {
                $blockMinutes = intdiv($this->configuration->blockDelayInSeconds, 60);
                $this->blocklistService->blockIp($ip, $blockMinutes);
                $this->notificationService->sendBlockAlert($result, $request, $ip, $blockMinutes);
            }
        }
        throw new RequestNotAllowedException('No attacking allowed.', time());
    }

    private function inspect(ServerRequestInterface $request): InspectionResult
    {
        $params = $request->getQueryParams();

        // Merge POST params if available
        $parsedBody = $request->getParsedBody();
        if (is_array($parsedBody)) {
            $params = array_merge($params, $parsedBody);
        }

        // Merge cookie params if configured
        if ($this->configuration->checkCookieVars) {
            $params = array_merge($params, $request->getCookieParams());
        }

        $result = $this->payloadInspector->inspect(
            $this->inputNormalizer->normalizeArray($params),
        );

        if ($this->configuration->checkHeaders) {
            $headerResult = $this->headerInspector->inspect(
                $this->inputNormalizer->normalizeHeaders($request->getHeaders())
            );
            foreach ($headerResult->getMatches() as $match) {
                $result = $result->withMatch($match);
            }
        }
        return $result;
    }

    private function isWhitelistedPath(ServerRequestInterface $request): bool
    {
        $path = $request->getUri()->getPath();

        foreach ($this->configuration->urlWhiteList as $urlPattern) {
            if (str_starts_with($path, $urlPattern)) {
                return true;
            }
        }

        // eID requests are always whitelisted
        $query = $request->getUri()->getQuery();
        if ($query !== '' && str_contains($query, 'eID')) {
            return true;
        }
        return false;
    }
}