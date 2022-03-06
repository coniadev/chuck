<?php

declare(strict_types=1);

namespace Chuck\Cli;

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

    public static function run(
        \Chuck\ConfigInterface $config,
    ): mixed {
        $ds = DIRECTORY_SEPARATOR;

        // add the custom script dir first to allow
        // overriding of builtin scripts.
        $scriptDirs = $config->scripts();
        $scriptDirs[] = realpath(__DIR__ . $ds . '..' . $ds . '..' . $ds . 'bin');

        if (isset($_SERVER['argv'][1])) {
            $script = $_SERVER['argv'][1] . '.php';

            if ($_SERVER['argv'][1] === 'commands') {
                self::showCommands($scriptDirs);
            } else {
                foreach ($scriptDirs as $scriptDir) {
                    if (!is_string($scriptDir)) {
                        continue;
                    }

                    $file = $scriptDir . DIRECTORY_SEPARATOR . $script;

                    if (is_file($file)) {
                        $cmd = require $file;

                        return $cmd->run($config, ...array_slice($_SERVER['argv'], 2));
                    }
                }
                echo "\nphp run: Command not found.\n";
                return null;
            }
        } else {
            self::showHelp($scriptDirs);
        }
    }
}
