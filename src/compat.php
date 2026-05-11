<?php

declare(strict_types=1);

// Nette 3.0 uses Context, 3.1+ uses Explorer as primary class
if (!class_exists('Nette\Database\Explorer') && class_exists('Nette\Database\Context')) {
    class_alias('Nette\Database\Context', 'Nette\Database\Explorer');
}