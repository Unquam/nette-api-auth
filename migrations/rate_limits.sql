CREATE TABLE `rate_limits` (
    `key`    VARCHAR(100) NOT NULL COMMENT 'token_id or ip address',
    `hits`   INT          NOT NULL DEFAULT 1,
    `window` DATETIME     NOT NULL COMMENT 'current time window start',

    PRIMARY KEY (`key`),
    KEY `window` (`window`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;