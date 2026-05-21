<?php

namespace Extension14v\T3lockdown\Security\Inspection;

use Extension14v\T3lockdown\Security\Configuration\LockdownConfiguration;

/**
 * Inspects request payload for SQL injection and XSS patterns.
 */
final readonly class PayloadInspector
{
    private readonly array $sqlMetaCheckPatterns;
    private readonly array $sqlKeywordCheckPatterns;
    private readonly array $xssCheckPatterns;
    private readonly array $extbaseWhitelistPatterns;

    public function __construct(
        private readonly LockdownConfiguration $configuration,
    ) {
        $this->sqlMetaCheckPatterns = [
            'SQL meta-characters' => '/(\%27)|(\')|(\-\-)|(\%23)|(\#)/ix',
            'SQL meta-characters with assignment' => '/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i',
            'Typical SQL injection attack' => '/\w*((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix',
        ];

        $this->sqlKeywordCheckPatterns = [
            'UNION SELECT' => '/\bunion\b(?:\/\*.*?\*\/|\s)+(?:all(?:\/\*.*?\*\/|\s)+|distinct(?:\/\*.*?\*\/|\s)+)?select\b/i',
            'Boolean AND 1=1' => '/\band\s+\d+\s*=\s*\d+\b/i',
            'Boolean OR 1=1' => '/\bor\s+\d+\s*=\s*\d+\b/i',
            'information_schema' => '/\binformation_schema(?:\.\w+)?\b/i',
            'table_schema' => '/\btable_schema\b/i',
            'be_users table' => '/\bbe_users\b/i',
            'xp_cmdshell' => '/\bxp_cmdshell\b/i',
            'EXEC keyword' => '/\bexec(?:ute)?\s+(?:xp_|sp_)?[a-z0-9_]+/i',
            'CONCAT keyword' => '/\bconcat\s*\(/i',
            'SLEEP function' => '/\bsleep\s*\(/i',
            'BENCHMARK function' => '/\bbenchmark\s*\(/i',
            'LOAD_FILE function' => '/\bload_file\s*\(/i',
            'INTO OUTFILE' => '/\binto\s+outfile\b/i',
            'INTO DUMPFILE' => '/\binto\s+dumpfile\b/i',
        ];

        $this->xssCheckPatterns = [
            'Basic script tag' => '/<script\b/i',
            'Inline event handlers' => '/\bon\w+\s*=/i',
            'javascript: pseudo-protocol' => '/javascript:/i',
            'img tag with JS event' => '/<img[^>]+on\w+/i',
            'iframe tag' => '/<iframe\b/i',
            'object tag' => '/<object\b/i',
            'embed tag' => '/<embed\b/i',
            'document.cookie access' => '/document\.cookie/i',
            'SVG with JS event' => '/<svg[^>]+on\w+/i',
        ];

        $this->extbaseWhitelistPatterns = [
            '/tx_[a-z0-9_]+\[__referrer\]/i',
            '/tx_[a-z0-9_]+\[__trustedProperties\]/i',
            '/tx_[a-z0-9_]+\[arguments\]/i',
            '/^action$/i',
            '/^controller$/i',
            '/^extension$/i',
        ];
    }

    public function inspect(array $params): InspectionResult
    {
        $result = new InspectionResult();
        foreach ($params as $fieldName => $fieldValue) {
            if ($this->isExtbaseWhitelistedParameterRecursive((string)$fieldName, $fieldValue)) {
                continue;
            }
            $result = $this->inspectValue($result, (string)$fieldName, $fieldValue, false);
        }
        return $result;
    }

    private function inspectValue(
        InspectionResult $result,
        string $fieldName,
        mixed $value,
        bool $fromHeader,
    ): InspectionResult {
        if (is_array($value)) {
            foreach ($value as $subKey => $subValue) {
                $result = $this->inspectValue(
                    $result,
                    $fieldName . '[' . $subKey . ']',
                    $subValue,
                    $fromHeader,
                );
            }
            return $result;
        }

        $checkString = (string)$value;
        if ($this->configuration->checkSqlInjAttacks) {
            $result = $this->checkSqlKeywords($result, $fieldName, $checkString, $fromHeader);
            $result = $this->checkSqlMeta($result, $fieldName, $checkString, $fromHeader);
        }
        if ($this->configuration->checkXss) {
            $result = $this->checkXss($result, $fieldName, $checkString, $fromHeader);
        }
        return $result;
    }

    private function checkSqlKeywords(
        InspectionResult $result,
        string $fieldName,
        string $value,
        bool $fromHeader,
    ): InspectionResult {
        foreach ($this->sqlKeywordCheckPatterns as $ruleName => $pattern) {
            if (preg_match($pattern, $value) === 1) {
                $result = $result->withMatch(new AttackMatch(
                    type: 'sql',
                    ruleName: $ruleName,
                    fieldName: $fieldName,
                    fieldValue: $this->truncate($value),
                    fromHeader: $fromHeader,
                ));
            }
        }

        return $result;
    }

    private function checkSqlMeta(
        InspectionResult $result,
        string $fieldName,
        string $value,
        bool $fromHeader,
    ): InspectionResult {
        $hasMeta = false;

        foreach ($this->sqlMetaCheckPatterns as $ruleName => $pattern) {
            if (preg_match($pattern, $value) === 1) {
                $hasMeta = true;
                break;
            }
        }

        if (!$hasMeta) {
            return $result;
        }

        foreach ($this->sqlKeywordCheckPatterns as $ruleName => $pattern) {
            if (preg_match($pattern, $value) === 1) {
                $result = $result->withMatch(new AttackMatch(
                    type: 'sql',
                    ruleName: $ruleName,
                    fieldName: $fieldName,
                    fieldValue: $this->truncate($value),
                    fromHeader: $fromHeader,
                ));
            }
        }
        return $result;
    }

    private function checkXss(
        InspectionResult $result,
        string $fieldName,
        string $value,
        bool $fromHeader,
    ): InspectionResult {
        foreach ($this->xssCheckPatterns as $ruleName => $pattern) {
            if (preg_match($pattern, $value) === 1) {
                $result = $result->withMatch(new AttackMatch(
                    type: 'xss',
                    ruleName: $ruleName,
                    fieldName: $fieldName,
                    fieldValue: $this->truncate($value),
                    fromHeader: $fromHeader,
                ));
            }
        }
        return $result;
    }

    private function truncate(string $value, int $maxLength = 200): string
    {
        if (mb_strlen($value) <= $maxLength) {
            return $value;
        }
        return mb_substr($value, 0, $maxLength) . '…';
    }

    private function isExtbaseWhitelistedParameter(string $paramName): bool
    {
        foreach ($this->extbaseWhitelistPatterns as $pattern) {
            if (preg_match($pattern, $paramName) === 1) {
                return true;
            }
        }
        return false;
    }

    private function isExtbaseWhitelistedParameterRecursive(string $key, mixed $value): bool
    {
        if ($this->isExtbaseWhitelistedParameter($key)) {
            return true;
        }
        if (is_array($value)) {
            foreach ($value as $subKey => $subValue) {
                if ($this->isExtbaseWhitelistedParameterRecursive((string)$subKey, $subValue)) {
                    return true;
                }
            }
        }
        return false;
    }
}