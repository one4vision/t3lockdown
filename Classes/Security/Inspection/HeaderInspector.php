<?php

namespace Extension14v\T3lockdown\Security\Inspection;

use Extension14v\T3lockdown\Security\Configuration\LockdownConfiguration;

/**
 * Inspects request headers for suspicious patterns.
 */
final readonly class HeaderInspector
{
    private readonly array $ignoredSafeHeaders;
    private readonly array $headerPatterns;

    public function __construct(
        private readonly LockdownConfiguration $configuration,
    ) {
        $this->headerPatterns = [
            'xss_tag' => '/<\s*(svg|img|iframe|script|object|embed|body|video|audio)\b/i',
            'xss_event' => '/on(?:load|error|click|mouse(?:over|enter)|focus|animationstart|pointerdown)\s*=/i',
            'xss_js' => '/(?:javascript|data\s*:text\/html)/i',
            'xss_script_words' => '/(?:document\.cookie|window\.location|eval\s*\(|settimeout\s*\(|setinterval\s*\()/i',
        ];

        $this->ignoredSafeHeaders = [
            'accept',
            'accept-encoding',
            'accept-language',
            'connection',
            'content-length',
            'content-type',
            'host',
            'pragma',
            'priority',
            'sec-fetch-dest',
            'sec-fetch-mode',
            'sec-fetch-site',
            'x-requested-with',
        ];
    }

    public function inspect(array $headers): InspectionResult
    {
        $result = new InspectionResult();
        foreach ($headers as $headerName => $headerValues) {
            $headerNameLower = strtolower((string)$headerName);

            if (in_array($headerNameLower, $this->ignoredSafeHeaders, true)) {
                continue;
            }

            if (in_array($headerNameLower, $this->configuration->ignoreHeaderStringParsing, true)) {
                continue;
            }

            foreach ($headerValues as $headerValue) {
                $normalizedValue = $this->normalizeValue((string)$headerValue);
                if ($this->isAllowedException($normalizedValue)) {
                    continue;
                }
                foreach ($this->headerPatterns as $patternName => $pattern) {
                    if (preg_match($pattern, $normalizedValue) === 1) {
                        $result = $result->withMatch(new AttackMatch(
                            type: 'header',
                            ruleName: $patternName,
                            fieldName: $headerNameLower,
                            fieldValue: $this->truncate($normalizedValue),
                            fromHeader: true,
                        ));
                        break;
                    }
                }
            }
        }
        return $result;
    }

    private function normalizeValue(string $value): string
    {
        if ($this->isHexString($value)) {
            return hex2bin($value) ?: $value;
        }
        if ($this->isBase64String($value)) {
            return base64_decode($value, true) ?: $value;
        }
        return $value;
    }

    private function isAllowedException(string $value): bool
    {
        foreach ($this->configuration->allowedHeaderExceptions as $exception) {
            if (stripos($value, (string)$exception) !== false) {
                return true;
            }
        }
        return false;
    }

    private function isHexString(string $value): bool
    {
        return ctype_xdigit($value) && (strlen($value) % 2 === 0);
    }

    private function isBase64String(string $value): bool
    {
        if (strlen($value) % 4 !== 0) {
            return false;
        }
        if (!preg_match('/^[A-Za-z0-9+\/]{4,}={0,2}$/', $value)) {
            return false;
        }
        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            return false;
        }
        return base64_encode($decoded) === $value;
    }

    private function truncate(string $value, int $maxLength = 200): string
    {
        if (mb_strlen($value) <= $maxLength) {
            return $value;
        }
        return mb_substr($value, 0, $maxLength) . '…';
    }
}