<?php
use TYPO3\CMS\Core\Cache\Backend\SimpleFileBackend;

if (!isset($GLOBALS['TYPO3_CONF_VARS']['SYS']['caching']['cacheConfigurations']['t3lockdown_rate_limit'])) {
    $GLOBALS['TYPO3_CONF_VARS']['SYS']['caching']['cacheConfigurations']['t3lockdown_rate_limit'] = [
        'backend' => SimpleFileBackend::class,
        'options'  => ['defaultLifetime' => 60],
        'groups'   => ['system'],
    ];
}