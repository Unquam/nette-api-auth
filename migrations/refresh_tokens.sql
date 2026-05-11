CREATE TABLE `refresh_tokens` (
    `id`           INT         NOT NULL AUTO_INCREMENT,
    `user_id`      INT         NOT NULL,
    `token`        VARCHAR(64) NOT NULL,
    `api_token_id` INT         NOT NULL,
    `expires_at`   DATETIME    NULL     COMMENT 'NULL = unlimited',
    `created_at`   DATETIME    NOT NULL,

    PRIMARY KEY (`id`),
    UNIQUE KEY `token` (`token`),
    KEY `user_id` (`user_id`),
    KEY `api_token_id` (`api_token_id`),
    KEY `expires_at` (`expires_at`),
    FOREIGN KEY (`user_id`) REFERENCES `api_users` (`id`) ON DELETE CASCADE,
    FOREIGN KEY (`api_token_id`) REFERENCES `api_tokens` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;