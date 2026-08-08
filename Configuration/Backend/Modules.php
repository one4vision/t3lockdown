<?php
use Extension14v\T3lockdown\Controller\BackendController;

return [
    'site_t3lockdown' => [
        'parent' => 'system',
        'access' => 'admin',
        'workspaces' => 'live',
        'path' => '/module/t3lockdown',
        'labels' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang_t3lockdown.xlf',
        'iconIdentifier' => 'module-t3lockdown',
        'extensionName' => 'T3lockdown',
        'controllerActions' => [
            BackendController::class => ['list'],
        ]
    ],
];
