<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

function getSettings(array $options = []): array
{
    $defaults = require __DIR__ . '/../src/defaults.php';

    return array_replace_recursive($defaults, $options);
}
