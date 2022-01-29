<?php

declare(strict_types=1);

namespace Chuck\Cli;

use Chuck\Plugin;

abstract class Command
{
    public static string $group;
    public static string $title;
    public static string $desc;
    protected ?Plugin $plugin = null;

    public function setPlugin(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    protected function arg(int $index): ?string
    {
        return $_SERVER['argv'][$index] ?? null;
    }

    public function run(\Chuck\ConfigInterface $config, string ...$args): void
    {
        throw new \ErrorException('Not implemented');
    }

    protected function db(\Chuck\ConfigInterface $config): \PDO
    {
        $db = $config->get('db');
        $dbms = $db['dbms'];
        $host = $db['host'];
        $port = $db['port'];
        $dbname = $db['name'];
        $username = $db['user'];
        $password = $db['pass'];

        $conn = new \PDO(
            "$dbms:host=$host;port=$port;dbname=$dbname",
            $username,
            $password
        );

        // Always throw an exception when an error occures
        $conn->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        // Allow getting the number of rows
        $conn->setAttribute(\PDO::ATTR_CURSOR, \PDO::CURSOR_SCROLL);

        return $conn;
    }
}
