<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use Chuck\Cli\Command;
use Chuck\ConfigInterface;


class Add extends Command
{
    public static string $group = 'Database';
    public static string $title = 'Initialize a new migrations';
    public static string $desc;

    public function run(ConfigInterface $config, string ...$args): mixed
    {
        return $this->add($config, $args);
    }

    protected function add(ConfigInterface $config, array $args): ?string
    {
        if (count($args) > 0) {
            $fileName = $args[0];
        } else {
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

        $ts = date('ymd-His', time());

        if (is_dir($migrationDir) && is_writable($migrationDir)) {
            $migration = $migrationDir . DIRECTORY_SEPARATOR . $ts . '-' . $fileName;
            $f = fopen($migration, 'w');

            if ($ext === 'php') {
                fwrite($f, $this->getPhpContent($fileName));
            } elseif ($ext === 'tpql') {
                fwrite($f, $this->getTpqlContent());
            }

            fclose($f);
            echo "Migration created:\n$migration\n";

            return $migration;
        } else {
            echo "No migration directory available or not writable\n  -> $migrationDir\nAborting. \n";

            return null;
        }
    }

    protected function getPhpContent(string $fileName): string
    {
        // Translates what-is-up.sql into WhatIsUp
        $className = implode('', explode('-', explode('.', ucwords($fileName, '-'))[0]));

        return "<?php

declare(strict_types=1);

class $className
{
    public function run(PDO \$db): void
    {
        \$db->execute('');
        \$result = \$db->query('SELECT 1', PDO::FETCH_ASSOC)->fetch();
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
