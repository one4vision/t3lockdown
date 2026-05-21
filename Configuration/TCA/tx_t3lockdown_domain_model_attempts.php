<?php
return [
    'ctrl' => [
        'title' => 'Attack Attempts',
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
        'searchFields' => 'attack_date,t3host,request_file,request_url,request_method,remote_ip,details,attack_types',
        'iconfile' => 'EXT:t3lockdown/Resources/Public/Icons/db_entry.gif'
    ],
    'types' => [
        '1' => ['showitem' => 'attack_date,attack_types,t3host,from_header,request_file,request_url,request_method,input_vars,remote_ip,useragent,details, --div--;LLL:EXT:frontend/Resources/Private/Language/locallang_ttc.xlf:tabs.access, sys_language_uid, l10n_parent, l10n_diffsource, hidden'],
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
                'foreign_table' => 'tx_t3lockdown_domain_model_attempts',
                'foreign_table_where' => 'AND tx_t3lockdown_domain_model_attempts.pid=###CURRENT_PID### AND tx_t3lockdown_domain_model_attempts.sys_language_uid IN (-1,0)',
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
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.attempts.attack_date',
            'config' => [
                'dbType' => 'datetime',
                'type' => 'datetime',
                'size' => 12,
                'default' => null,
                'readOnly' => true
            ],
        ],
        'attack_types' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.attempts.attack_types',
            'config' => [
                'type' => 'input',
                'size' => 30,
                'eval' => 'trim',
                'readOnly' => true
            ]
        ],
        'from_header' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.attempts.header_attack',
            'config' => [
                'type' => 'check'
            ],
        ],
        't3host' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.attempts.host',
            'config' => [
                'type' => 'input',
                'size' => 30,
                'eval' => 'trim',
                'readOnly' => true
            ]
        ],
        'request_file' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.attempts.request_file',
            'config' => [
                'type' => 'input',
                'size' => 30,
                'eval' => 'trim',
                'readOnly' => true
            ]
        ],
        'request_url' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.attempts.request_url',
            'config' => [
                'type' => 'text',
                'cols' => 30,
                'rows' => 5,
                'eval' => 'trim',
                'readOnly' => true
            ]
        ],
        'request_method' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.attempts.request_method',
            'config' => [
                'type' => 'input',
                'size' => 10,
                'eval' => 'trim',
                'readOnly' => true
            ]
        ],
        'input_vars' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.attempts.input_vars',
            'config' => [
                'type' => 'text',
                'cols' => 30,
                'rows' => 5,
                'eval' => 'trim',
                'readOnly' => true
            ]
        ],
        'remote_ip' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.attempts.remote_ip',
            'config' => [
                'type' => 'input',
                'size' => 30,
                'eval' => 'trim',
                'readOnly' => true
            ]
        ],
        'useragent' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.attempts.useragent',
            'config' => [
                'type' => 'input',
                'size' => 30,
                'eval' => 'trim',
                'readOnly' => true
            ]
        ],
        'details' => [
            'exclude' => false,
            'label' => 'LLL:EXT:t3lockdown/Resources/Private/Language/locallang.xlf:labels.attempts.details',
            'config' => [
                'type' => 'text',
                'enableRichtext' => true,
                'readOnly' => true
            ]
        ],
    
    ],
];
