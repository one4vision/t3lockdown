<?php
$EM_CONF[$_EXTKEY] = [
	'title' => 'T3Lockdown',
	'description' => 'Protects TYPO3 against SQL injection, XSS, malicious headers, abusive requests, and repeated attacks with logging, alerts, rate limiting, temporary IP blocking, and backend analysis tools.',
	'category' => 'services',
	'author' => 'Oliver Busch',
	'author_email' => 'oliver.busch@one4vision.de',
    'author_company' => 'one4vision GmbH',
	'state' => 'stable',
	'version' => '6.0.1',
    'constraints' => [
        'depends' => [
            'typo3' => '13.4.20-14.3.99'
        ],
        'conflicts' => [],
        'suggests' => [],
    ],
];
