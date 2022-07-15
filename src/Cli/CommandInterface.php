<?php

declare(strict_types=1);

namespace Conia\Chuck\Cli;

use Conia\Chuck\App;

interface CommandInterface
{
    public function run(App $app): string|int;
}
