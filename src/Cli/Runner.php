<?php

declare(strict_types=1);

namespace Chuck\Cli;

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

    /**
     * PHP native `getopt` stops after the first "non-option" argument
     * which in our case is the command: `php run <command>`
     */
    protected static function getopts(): array
    {
        $opts = [];
        $key = null;

        foreach ($_SERVER['argv'] as $arg) {
            if (str_starts_with($arg, '-')) {
                $key = ltrim($arg, '-');

                if (!isset($opts[$key])) {
                    $opts[$key] = true;
                }
            } else {
                if ($key) {
                    if ($opts[$key] === true) {
                        $opts[$key] = $arg;
                    } else {
                        if (!is_array($opts[$key])) {
                            $opts[$key] = [$opts[$key]];
                        }
                        $opts[$key][] = $arg;
                    }
                }
            }
        }

        return $opts;
    }

    protected static function runCommand(ConfigInterface $config, CommandInterface $cmd): mixed
    {
        return $cmd->run($config, self::getopts());
    }

    public static function run(ConfigInterface $config): mixed
    {
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
                        return self::runCommand($config, require $file);
                    }
                }
                echo "\nphp run: Command not found.\n";
                return null;
            }
        } else {
            self::showHelp($scriptDirs);
            return null;
        }
    }
}
