<?php

declare(strict_types=1);

use Chuck\App;
use Chuck\Cli\CommandInterface;


class ErrorScript implements CommandInterface
{
    public function run(App $app): string|int
    {
        trigger_error('script error');
        return 1;
    }
}

return new ErrorScript();
