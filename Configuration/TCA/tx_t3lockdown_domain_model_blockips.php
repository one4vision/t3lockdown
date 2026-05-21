<?php
return [
    'ctrl' => [
        'title' => 'Blocked IP-Addresses',
        'label' => 'attack_date',
        'tstamp' => 'tstamp',
        'crdate' => 'crdate',
        'sortby' => 'sorting',
        'versioningWS' => false,
        'languageField' => 'sys_language_uid',
        'transOrigPointerField' => 'l10n_parent',
        'transOrigDiffSourceField' => 'l10n_diffsource',
        'delete' => 'deleted',
        'rootLevel' => -1,
        'enablecolumns' => [
            'disabled' => 'hidden',
        ],
        'searchFields' => 'attack_date,remote_ip,block_minutes,from_attempt',
        'iconfile' => 'EXT:t3lockdown/Resources/Public/Icons/db_entry.gif'
    ],
    'types' => [
        '1' => ['showitem' => 'attack_date,remote_ip,block_minutes,from_attempt, --div--;LLL:EXT:frontend/Resources/Private/Language/locallang_ttc.xlf:tabs.access, sys_language_uid, l10n_parent, l10n_diffsource, hidden'],
    ],
    'columns' => [
        'sys_language_uid' => [
            'exclude' => true,
            'label' => 'LLL:EXT:lang/locallang_general.xlf:LGL.language',
            'config' => ['type' => 'language'],
        ],
        'l10n_parent' => [
            'displayCond' => 'FIELD:sys_language_uid:>:0',
            'label' => 'LLL:EXT:lang/locallang_general.xlf:LGL.l18n_parent',
            'config' => [
                'type' => 'select',
                'renderType' => 'selectSingle',
                'default' => 0,
                'items' => [
                    ['label' => '', 'value' => 0],
                ],
                'foreign_table' => 'tx_t3lockdown_domain_model_blockips',
                'foreign_table_where' => 'AND tx_t3lockdown_domain_model_blockips.pid=###CURRENT_PID### AND tx_t3lockdown_domain_model_blockips.sys_language_uid IN (-1,0)',
            ],
        ],
        'l10n_diffsource' => [
            'config' => [
                'type' => 'passthrough',
            ],
        ],
        'hidden' => [
            'exclude' => true,
            'label' => 'LLL:EXT:lang/locallang_general.xlf:LGL.hidden',
            'config' => [
                'type' => 'check',
                'items' => [
                    '1' => [
                        'label' => 'LLL:EXT:lang/Resources/Private/Language/locallang_core.xlf:labels.enabled'
                    ]
                ],
            ],
        ],

        'attack_date' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.block.attack_date',
            'config' => [
                'dbType' => 'datetime',
                'type' => 'datetime',
                'size' => 12,
                'default' => null,
                'readOnly' => true
            ],
        ],
        'remote_ip' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.block.client_ip_address',
            'config' => [
                'type' => 'input',
                'size' => 30,
                'eval' => 'trim',
                'readOnly' => true
            ]
        ],
        'block_minutes' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.block.block_minutes',
            'config' => [
                'type' => 'input',
                'size' => 30,
                'eval' => 'trim',
                'readOnly' => true
            ]
        ],
        'from_attempt' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.block.from_attempt',
            'config' => [
                'type' => 'input',
                'size' => 30,
                'eval' => 'trim',
                'readOnly' => true
            ]
        ],
    
    ],
];
