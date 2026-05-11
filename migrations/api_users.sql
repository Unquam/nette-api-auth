CREATE TABLE `api_users` (
    `id`         INT          NOT NULL AUTO_INCREMENT,
    `email`      VARCHAR(255) NOT NULL,
    `password`   VARCHAR(255) NOT NULL,
    `role`       VARCHAR(50)  NOT NULL DEFAULT 'user',
    `created_at` DATETIME     NOT NULL,

    PRIMARY KEY (`id`),
    UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;