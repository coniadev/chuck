<?php

declare(strict_types=1);

namespace Chuck\Testing;

use \PDO;
use Chuck\Testing\TestCase;

class DatabaseCase extends TestCase
{
    public function __construct(?string $name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);

        $this->createTestDb();
        print "hans";
    }

    public function getTestDbDsn(): string
    {
        return 'sqlite:' . sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'chuck_test_db.sqlite3';
    }

    public function createTestDb(): void
    {
        $dbfile = $this->getTestDbDsn();

        if (file_exists($dbfile)) {
            unlink($dbfile);
        }

        $db = new PDO("$dbfile");

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
}
