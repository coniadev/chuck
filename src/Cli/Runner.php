<?php

declare(strict_types=1);

namespace Chuck\Cli;

use \ErrorException;
use Chuck\App;
use Chuck\ConfigInterface;


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

    private static function setupErrorHandler(): void
    {
        set_error_handler(function (
            int $level,
            string $message,
            string $file = '',
            int $line = 0,
        ): bool {
            if ($level & error_reporting()) {
                throw new ErrorException($message, $level, $level, $file, $line);
            }

            return false;
        }, E_ALL);
    }

    protected static function runCommand(App $app, CommandInterface $cmd): string|int
    {
        return $cmd->run($app);
    }

    public static function run(App $app): string|int
    {
        self::setupErrorHandler();
        $config = $app->config();

        // add the custom script dir first to allow
        // overriding of builtin scripts.
        $scriptDirs = $config->scripts()->get();

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
                echo "\nphp run: Command not found.\n";
                return 1;
            }
        } else {
            self::showHelp($scriptDirs);
            return 0;
        }
    }
}
