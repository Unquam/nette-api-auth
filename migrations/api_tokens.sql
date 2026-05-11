CREATE TABLE `api_tokens` (
    `id`          INT          NOT NULL AUTO_INCREMENT,
    `user_id`     INT          NOT NULL,
    `token`       VARCHAR(64)  NOT NULL,
    `name`        VARCHAR(100) NOT NULL,
    `is_live`     TINYINT(1)   NOT NULL DEFAULT 0,
    `scopes`      TEXT         NULL     COMMENT 'comma separated list of scopes, NULL = all scopes allowed',
    `last_used`   DATETIME     NULL,
    `expires_at`  DATETIME     NULL     COMMENT 'NULL = unlimited',
    `created_at`  DATETIME     NOT NULL,

    PRIMARY KEY (`id`),
    UNIQUE KEY `token` (`token`),
    KEY `user_id` (`user_id`),
    KEY `expires_at` (`expires_at`),
    FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;