<?php

declare(strict_types=1);

namespace Chuck\Cli;

use \ErrorException;
use \PDO;
use Chuck\ConfigInterface;


abstract class Command
{
    public static string $group;
    public static string $title;
    public static string $desc;

    protected function arg(int $index): ?string
    {
        return $_SERVER['argv'][$index] ?? null;
    }

    public function run(ConfigInterface $config, string ...$args): mixed
    {
        throw new ErrorException('Not implemented');
    }

    protected function db(ConfigInterface $config): PDO
    {
        $db = $config->get('db');
        $dbms = $db['dbms'];
        $host = $db['host'];
        $port = $db['port'];
        $dbname = $db['name'];
        $username = $db['user'];
        $password = $db['pass'];

        $conn = new PDO(
            "$dbms:host=$host;port=$port;dbname=$dbname",
            $username,
            $password
        );

        // Always throw an exception when an error occures
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        // Allow getting the number of rows
        $conn->setAttribute(PDO::ATTR_CURSOR, PDO::CURSOR_SCROLL);

        return $conn;
    }
}
