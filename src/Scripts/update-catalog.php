<?php

declare(strict_types=1);

class UpdateCatalog extends Chuck\Cli\Command
{
    public static string $group = 'General';
    public static string $title = 'Run test suite';

    public function run(Chuck\ConfigInterface $config, string ...$args): void
    {
        $rootDir = $config->path->root;
        $command = $args[0] ?? null;

        if ($command === 'theme') {
            $path = "$rootDir/www/theme/locale";
            $appName = 'theme';
        } else {
            $path = "$rootDir/locale";
            $appName = 'elearn';
        }

        $localeDirs = array_filter(glob("$path/*"), 'is_dir');
        $locales = array_map(fn ($dir) => basename($dir), $localeDirs);

        $command = $args[0] ?? null;

        foreach ($locales as $locale) {
            passthru(
                "msgmerge " .
                    "  --no-fuzzy-matching" .
                    "  --update $path/$locale/LC_MESSAGES/$appName.po" .
                    "  $path/$appName.pot"
            );
        };
    }
}

return new UpdateCatalog();
