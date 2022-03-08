<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use Chuck\Cli\{CommandInterface, Opts};
use Chuck\ConfigInterface;


class Add implements CommandInterface
{
    public static string $group = 'Database';
    public static string $title = 'Initialize a new migrations';
    public static string $desc;

    public function run(ConfigInterface $config): mixed
    {
        return $this->add($config);
    }

    protected function add(ConfigInterface $config): ?string
    {
        $opts = new Opts();
        $fileName = $opts->get('-f', $opts->get('--file', ''));

        if (empty($fileName)) {
            $fileName = readline('Name of the migration: ');
        }

        $fileName = str_replace(' ', '-', $fileName);
        $fileName = str_replace('_', '-', $fileName);
        $fileName = strtolower($fileName);
        $ext = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

        if (!$ext) {
            $fileName .= '.sql';
        } else {
            if (!in_array($ext, ['sql', 'php', 'tpql'])) {
                echo "Wrong file extension '$ext'. Use 'sql', 'php' or 'tpql' instead.\nAborting.\n";
                return null;
            }
        }

        $migrations = $config->migrations();
        // Get the last migrations directory from the list
        $migrationDir = end($migrations);

        if ($migrationDir !== false && strpos($migrationDir, '/vendor') !== false) {
            echo "The migrations directory is inside './vendor'.\n  -> $migrationDir\nAborting.\n";
            return null;
        }

        $timestamp = date('ymd-His', time());

        if (is_dir($migrationDir) && is_writable($migrationDir)) {
            $migration = $migrationDir . DIRECTORY_SEPARATOR . $timestamp . '-' . $fileName;
            $f = fopen($migration, 'w');

            if ($ext === 'php') {
                fwrite($f, $this->getPhpContent($fileName, $timestamp));
            } elseif ($ext === 'tpql') {
                fwrite($f, $this->getTpqlContent());
            }

            fclose($f);
            echo "Migration created:\n$migration\n";

            return $migration;
        } else {
            echo "Migrations directory does not exits or not writable\n  -> $migrationDir\nAborting. \n";
            return null;
        }
    }

    protected function getPhpContent(string $fileName, string $timestamp): string
    {
        // Translates what-is-up.sql into WhatIsUp
        $className = implode(
            '',
            explode(
                '-',
                explode(
                    '.',
                    ucwords($fileName, '-')
                )[0]
            )
        ) . '_' . str_replace('-', '_', $timestamp);

        return "<?php

declare(strict_types=1);

use Chuck\Database\{Database, Migration};


class $className extends Migration
{
    public function run(Database \$db): void
    {
        \$db->execute('')->run();
        \$result = \$db->execute('')->all(PDO::FETCH_ASSOC);
    }
}

return new $className();
";
    }

    protected function getTpqlContent(): string
    {
        return "<?php if (\$driver === 'pgsql') : ?>

<?php else : ?>

<?php endif ?>
";
    }
}
