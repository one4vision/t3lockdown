<?php
use Extension14v\T3lockdown\Middleware\Lockdown;

return [
    'frontend' => [
        'extension14v/t3lockdown/lockdown' => [
            'target' => Lockdown::class,
            'before' => [
                'typo3/cms-frontend/site',
			],
        ],
    ]
];
