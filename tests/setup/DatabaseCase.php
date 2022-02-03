<?php

declare(strict_types=1);

namespace Chuck\Tests;

use \PDO;

use Chuck\Config;
use Chuck\Model\Database;
use Chuck\Tests\TestCase;


class DatabaseCase extends TestCase
{
    public function __construct(?string $name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);

        $this->createTestDb();
    }

    protected function getDbFile(): string
    {
        return sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'chuck_test_db.sqlite3';
    }

    protected function getDsn(): string
    {
        return 'sqlite:' . $this->getDbFile();
    }

    public function getConfig(array $options = []): Config
    {
        $ds = DIRECTORY_SEPARATOR;

        return parent::getConfig(
            [
                'db' => [
                    'dsn' => $this->getDsn()
                ],
                'path' => [
                    'sql' => [
                        __DIR__ . $ds . '..' . $ds . 'fixtures' . $ds . 'sql' . $ds . 'default',
                    ],
                ]
            ],
        );
    }

    public function createTestDb(): void
    {
        $dbfile = $this->getDbFile();

        if (file_exists($dbfile)) {
            unlink($dbfile);
        }

        $db = new PDO($this->getDsn());

        $commands = ['
            CREATE TABLE IF NOT EXISTS users (
                user INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
        ', '
            CREATE TABLE IF NOT EXISTS albums (
                album INTEGER PRIMARY KEY,
                year  INTEGER NOT NULL,
                title  VARCHAR (255) NOT NULL
            )
        ', "
            INSERT INTO albums
                (year, title)
            VALUES
                (1987,  'Scream Bloody Gore'),
                (1988,  'Leprosy'),
                (1990,  'Spiritual Healing'),
                (1991,  'Human'),
                (1993,  'Individual Thought Patterns'),
                (1995,  'Symbolic'),
                (1998,  'The Sound of Perseverance')
        ", "
            INSERT INTO users
                (name)
            VALUES
                ('Chuck Schuldiner'),
                ('Rick Rozz'),
                ('Kam Lee')
        "];
        // execute the sql commands to create new tables
        foreach ($commands as $command) {
            $db->exec($command);
        }
    }

    public function getDb(?array $options = []): Database
    {
        return new Database($this->getConfig($options));
    }
}
