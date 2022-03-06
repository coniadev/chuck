<?php

declare(strict_types=1);

namespace Chuck\Cli\I18n;

use Chuck\Cli\Command;
use Chuck\ConfigInterface;


class CompileCatalog extends Command
{
    public static string $group = 'I18N';
    public static string $title = 'Compile *.po files to *.mo files';
    public static string $desc = '';

    public function run(ConfigInterface  $config,  string  ...$args): void
    {
        $rootDir = $config->path()->root;
        $command = $args[0] ?? null;

        if ($command === 'theme') {
            $path = "$rootDir/www/theme/locale";
            $outDir = "$rootDir/www/theme/locale";
            $appName = 'theme';
        } else {
            $path = "$rootDir/locale";
            $outDir = "$rootDir/www/locale";
            if ($command === null) {
                $appName = 'elearn';
            } else {
                $appName = $args[0];
            }
        }

        $localeDirs = array_filter(glob("$path/*"), 'is_dir');
        $locales = array_map(fn ($dir) => basename($dir), $localeDirs);

        foreach ($locales as $locale) {
            $inputFile = "$path/$locale/LC_MESSAGES/$appName.po";
            echo "Compile locale '$locale'\n";
            echo "  $inputFile\n";

            passthru(
                "msgfmt $inputFile " .
                    "--output-file=$path/$locale/LC_MESSAGES/$appName.mo"

            );

            $outFile = "$outDir/$locale/messages.json";
            echo "Compile '$locale' json file for frontend\n";
            echo "  $outFile\n";

            if (!is_dir("$outDir/$locale")) {
                mkdir("$outDir/$locale", 0755, true);
            }

            passthru(
                "node_modules/.bin/po2json-gettextjs " .
                    "$path/$locale/LC_MESSAGES/$appName.po $outFile"

            );
        };
    }
}
