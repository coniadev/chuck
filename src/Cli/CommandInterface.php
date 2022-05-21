<?php

declare(strict_types=1);

namespace Chuck\Cli;

use Chuck\App;


interface CommandInterface
{
    public function run(App $app): string|int;
}
