<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use Chuck\ConfigInterface;


trait GetsMigrations
{
    protected function getMigrations(ConfigInterface $config): array
    {
        $migrations = [];

        foreach ($config->migrations() as $path) {
            $migrations = array_merge(
                $migrations,
                array_filter(glob("$path/*.php"), 'is_file'),
                array_filter(glob("$path/*.sql"), 'is_file'),
                array_filter(glob("$path/*.tpql"), 'is_file'),
            );
        }

        // Sort by file name instead of full path
        uasort($migrations, function ($a, $b) {
            if (basename($a) == basename($b)) {
                return 0;
            }
            return (basename($a) < basename($b)) ? -1 : 1;
        });

        return $migrations;
    }
}
