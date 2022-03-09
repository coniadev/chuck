<?php

declare(strict_types=1);

namespace Chuck\Tests\Setup;

use \PDO;

use Chuck\Config;
use Chuck\Database\Database;
use Chuck\Tests\Setup\{TestCase, C};


class DatabaseCase extends TestCase
{
    protected static function getDbFile(): string
    {
        return sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'chuck_test_db.sqlite3';
    }

    protected static function getDsn(): string
    {
        return 'sqlite:' . self::getDbFile();
    }

    public static function createTestDb(): void
    {
        $dbfile = self::getDbFile();

        if (is_file($dbfile)) {
            unlink($dbfile);
        }

        $db = new PDO(self::getDsn());

        $commands = [
            "
                CREATE TABLE migrations (
                    migration TEXT PRIMARY KEY
                )
            ", "
                CREATE TABLE members (
                    member INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    joined INTEGER NOT NULL,
                    left INTEGER
                )
            ", "
                INSERT INTO members
                    (name, joined, left)
                VALUES
                    ('Chuck Schuldiner', 1983, NULL),
                    ('Rick Rozz', 1983, 1989),
                    ('Chris Reifert', 1986, 1987),
                    ('Terry Butler', 1987, 1990),
                    ('Bill Andrews', 1987, 1990),
                    ('Paul Masdival', 1989, 1992),
                    ('James Murphy', 1989, 1990),
                    ('Sean Reinert', 1991, 1992),
                    ('Steve DiGiorgio', 1991, 1995),
                    ('Scott Carino', 1991, 1992),
                    ('Gene Hoglan', 1993, 1995),
                    ('Andy LaRocque', 1993, 1993),
                    ('Bobby Koelble', 1995, 1995),
                    ('Kelly Conlon', 1995, 1995),
                    ('Shannon Hamm', 1997, 2001),
                    ('Scott Clendenin', 1997, 2001),
                    ('Richard Christy', 1997, 2001)
            ", "
                CREATE TABLE albums (
                    album INTEGER PRIMARY KEY,
                    year  INTEGER NOT NULL,
                    title  VARCHAR (255) NOT NULL
                )
            ", "
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
                CREATE TABLE contributions (
                    album INTEGER NOT NULL,
                    member  INTEGER NOT NULL,
                    PRIMARY KEY(album, member)
                )
            ", "
                INSERT INTO contributions
                    (album, member)
                VALUES
                    (1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6), (1, 7),
                    (2, 2),
                    (3, 1),
                    (4, 3),
                    (5, 2), (5, 3),
                    (6, 4),
                    (7, 3),
                    (8, 4),
                    (9, 4), (9, 5),
                    (10, 4),
                    (11, 4), (11, 5),
                    (12, 5),
                    (13, 6),
                    (14, 6),
                    (15, 7),
                    (16, 7),
                    (17, 7)
            ", "CREATE TABLE typetest (id INTEGER PRIMARY KEY, val)"
        ];
        // execute the sql commands to create new tables
        foreach ($commands as $command) {
            $db->exec($command);
        }
    }

    public function config(array $options = []): Config
    {
        $prefix = __DIR__ . C::DS . '..' . C::DS . 'Fixtures' . C::DS . 'sql' . C::DS;

        return parent::config(
            array_replace_recursive(
                [
                    'db' => ['dsn' => $this->getDsn()],
                    'sql' => $prefix . 'default',
                    'sql.additional' => [
                        'sqlite' =>  $prefix . 'additional',
                        'all' => $prefix . 'default',
                    ]
                ],
                $options,
            )
        );
    }

    public function getDb(
        ?array $options = [],
        string $sql = Config::DEFAULT
    ): Database {
        return new Database($this->config($options)->db(Config::DEFAULT, $sql));
    }
}
