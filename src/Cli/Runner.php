<?php

declare(strict_types=1);

namespace Conia\Chuck\Cli;

use \ErrorException;
use Conia\Chuck\App;


class Runner
{
    public static function getScripts(array $scriptDirs): array
    {
        $scripts = [];

        foreach ($scriptDirs as $scriptDir) {
            $scripts = array_merge(
                $scripts,
                array_filter(glob($scriptDir . DIRECTORY_SEPARATOR . '*.php'), 'is_file')
            );
        }

        $list = array_unique(
            array_map(
                function ($script) {
                    return basename($script, '.php');
                },
                $scripts
            )
        );

        asort($list);

        return $list;
    }

    public static function showHelp(array $scriptDirs): void
    {
        echo "\nAvailable commands:\n\n";

        foreach (self::getScripts($scriptDirs) as $script) {
            echo "  $script\n";
        }
    }

    public static function showCommands(array $scriptDirs): void
    {
        foreach (self::getScripts($scriptDirs) as $script) {
            echo "$script\n";
        }
    }

    protected static function runCommand(App $app, CommandInterface $cmd): string|int
    {
        return $cmd->run($app);
    }

    public static function run(App $app, array $scriptDirs = []): string|int
    {
        try {
            $config = $app->config();

            // add the custom script dir first to allow
            // overriding of builtin scripts.
            $scriptDirs = array_merge($scriptDirs, $config->scripts()->get());

            if (isset($_SERVER['argv'][1])) {
                $script = $_SERVER['argv'][1] . '.php';

                if ($_SERVER['argv'][1] === 'commands') {
                    self::showCommands($scriptDirs);
                    return 0;
                } else {
                    foreach ($scriptDirs as $scriptDir) {
                        $file = $scriptDir . DIRECTORY_SEPARATOR . $script;

                        if (is_file($file)) {
                            return self::runCommand($app, require $file);
                        }
                    }
                    echo "\nCommand not found.\n";
                    return 1;
                }
            } else {
                self::showHelp($scriptDirs);
                return 0;
            }
        } catch (ErrorException $e) {
            echo "\nError while running command '";
            echo (string)($_SERVER['argv'][1] ?? '<no command given>');
            echo "'.\n\n    Error message: " . $e->getMessage() . "\n";

            return 1;
        }
    }
}
