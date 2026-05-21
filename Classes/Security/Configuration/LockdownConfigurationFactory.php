<?php

namespace Extension14v\T3lockdown\Security\Configuration;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Builds the lockdown configuration from TYPO3 extension settings.
 */
final class LockdownConfigurationFactory
{
    public function createFromExtensionConfiguration(): LockdownConfiguration
    {
        $config = $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['t3lockdown'] ?? [];
        return new LockdownConfiguration(
            checkCookieVars: (bool)($config['checkCookieVars'] ?? false),
            checkSqlInjAttacks: (bool)($config['checkSqlInjAttacks'] ?? true),
            checkHeaders: (bool)($config['checkHeaders'] ?? false),
            checkXss: (bool)($config['checkXss'] ?? false),
            logAttacksInDb: (bool)($config['logAttacksInDB'] ?? true),
            blockRequests: (bool)($config['blockRequests'] ?? true),
            attemptIntervalInSeconds: (int)($config['attemptIntervalInSeconds'] ?? 300),
            maxCountAttemptsForBlock: (int)($config['maxCountAttemptsForBlock'] ?? 3),
            blockDelayInSeconds: (int)($config['blockDelayInSeconds'] ?? 900),
            sendBlockMail: (bool)($config['sendBlockMail'] ?? true),
            sendMailEveryRequest: (bool)($config['sendMailEveryRequest'] ?? true),
            mailFrom: $this->resolveMailFrom($config),
            mailFromName: $this->resolveMailFromName($config),
            blockMailTo: GeneralUtility::trimExplode(',', (string)($config['blockMailTo'] ?? ''), true),
            blackList: GeneralUtility::trimExplode(',', (string)($config['blackList'] ?? ''), true),
            whiteList: GeneralUtility::trimExplode(',', (string)($config['whiteList'] ?? ''), true),
            urlWhiteList: GeneralUtility::trimExplode(',', (string)($config['urlWhiteList'] ?? ''), true),
            rateLimitingEnabled: (bool)($config['rateLimitingEnabled'] ?? false),
            rateLimitSecondsWindow: (int)($config['rateLimitSecondsWindow'] ?? 60),
            rateLimitMaxRequests: (int)($config['rateLimitMaxRequests'] ?? 30),
            allowedHeaderExceptions: GeneralUtility::trimExplode(',', (string)($config['allowedHeaderExceptions'] ?? 'force-revalidate'),true),
            ignoreHeaderStringParsing: GeneralUtility::trimExplode(',', (string)($config['ignoreHeaderStringParsing'] ?? ''),true),
        );
    }

    private function resolveMailFrom(array $config): string
    {
        $configuredMailFrom = trim((string)($config['mailFrom'] ?? ''));
        if ($configuredMailFrom !== '') {
            return $configuredMailFrom;
        }
        $defaultMailFrom = trim((string)($GLOBALS['TYPO3_CONF_VARS']['MAIL']['defaultMailFromAddress'] ?? ''));
        if ($defaultMailFrom !== '') {
            return $defaultMailFrom;
        }
        return '';
    }

    private function resolveMailFromName(array $config): string
    {
        $configuredMailFromName = trim((string)($config['mailFromName'] ?? ''));
        if ($configuredMailFromName !== '') {
            return $configuredMailFromName;
        }
        $defaultMailFromName = trim((string)($GLOBALS['TYPO3_CONF_VARS']['MAIL']['defaultMailFromName'] ?? ''));
        if ($defaultMailFromName !== '') {
            return $defaultMailFromName;
        }
        return 'T3Lockdown';
    }
}