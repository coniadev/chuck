<?php

declare(strict_types=1);

use Psy\Shell as PsyShell;

class Shell extends Chuck\Cli\Command
{
    public static string $group = 'General';
    public static string $title = 'Start an interactive shell/repl';

    public function run(Chuck\ConfigInterface $config, string ...$args): void
    {
        $shell = new PsyShell();
        $shell->run();
    }
}

return new Shell();
