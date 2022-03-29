<?php

declare(strict_types=1);

namespace Chuck\Cli;

use Chuck\ConfigInterface;


interface CommandInterface
{
    public function run(ConfigInterface $config): string|int;
}
