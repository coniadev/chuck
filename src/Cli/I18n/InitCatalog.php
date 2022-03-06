<?php

declare(strict_types=1);

namespace Chuck\Cli\I18n;

use Chuck\Cli\Command;
use Chuck\ConfigInterface;


class InitCatalog extends Command
{
    public static string $group = 'I18N';
    public static string $title = 'Extract gettext() calls from source files';
    public static string $desc = 'pass the locale e. g. `php run init-catalog en`';

    public function run(ConfigInterface $config, string ...$args): void
    {
        $rootDir = $config->path()->root;
        $command = $args[0] ?? null;

        if ($command === 'theme') {
            $path = "$rootDir/www/theme/locale";
            $appName = 'theme';
            $locale = $args[1];
        } else {
            $path = "$rootDir/locale";
            $appName = 'elearn';
            $locale = $args[0];
        }

        passthru("mkdir -p $path/$locale/LC_MESSAGES");
        passthru(
            "msginit " .
                "  --locale $locale " .
                "  --input $path/$appName.pot " .
                "  --output $path/$locale/LC_MESSAGES/$appName.po"
        );
    }
}

return new InitCatalog();
