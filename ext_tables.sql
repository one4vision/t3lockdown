CREATE TABLE tx_t3lockdown_domain_model_attempts
(
    attack_date datetime null,
    t3host varchar(255) DEFAULT '' NOT NULL,
    request_file varchar(255) DEFAULT '' NOT NULL,
    request_url text NULL,
    request_method varchar(255) DEFAULT ''  NOT NULL,
    input_vars text null,
    remote_ip varchar(255) DEFAULT '' NOT NULL,
    useragent text NULL,
    details text NULL,
    from_header tinyint(1) DEFAULT 0 NOT NULL,
    attack_types varchar(255) DEFAULT '' NOT NULL
);

CREATE TABLE tx_t3lockdown_domain_model_blockips (
    attack_date datetime null,
    remote_ip varchar(255) DEFAULT '' NOT NULL,
    block_minutes numeric(8,3) DEFAULT 0.000 NOT NULL,
    from_attempt int(11) DEFAULT 0 NOT NULL
);