<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Setup;

use PDO;
use Throwable;
use Conia\Chuck\Config;
use Conia\Chuck\Config\Connection;
use Conia\Chuck\Database\Database;
use Conia\Chuck\Tests\Setup\{TestCase, C};

class DatabaseCase extends TestCase
{
    public function config(
        bool $debug = false,
        string $dsn = null,
        bool $additionalDirs = false,
        array|string $migrations = null,
    ): Config {
        $config = parent::config(debug: $debug);

        $migrations = $migrations ??  C::root() . C::DS . 'migrations';

        $dsn = $dsn ?: $this->getDsn();
        $sql = $this->getSqlDirs($additionalDirs);
        $conn = new Connection($dsn, $sql, migrations: $migrations);
        $conn->setMigrationsTable(str_starts_with($dsn, 'pgsql') ? 'public.migrations' : 'migrations');
        $config->addConnection($conn);

        return $config;
    }

    public function getSqlDirs($additionalDirs = false): array|string
    {
        $prefix = __DIR__ . C::DS . '..' . C::DS . 'Fixtures' . C::DS . 'sql' . C::DS;

        return $additionalDirs ?
            [
                $prefix . 'default',
                [
                    'sqlite' =>  $prefix . 'additional',
                    'all' => $prefix . 'default',
                ]
            ] : $prefix . 'default';
    }

    public function getDb(
        bool $additionalDirs = false,
    ): Database {
        return new Database($this->config(additionalDirs: $additionalDirs)->connection());
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

    protected static function getServerDsns(): array
    {
        $dbPgsqlHost = getenv("DB_PGSQL_HOST") ?: "localhost";
        // MySQL tries to use a local socket when host=localhost
        // is specified which does not work with WSL2/Windows.
        $dbMysqlHost = getenv("DB_MYSQL_HOST") ?: "127.0.0.1";
        $dbName = getenv("DB_NAME") ?: "chuck_test_db";
        $dbUser = getenv("DB_USER") ?: "chuck_test_user";
        $dbPassword = getenv("DB_PASSWORD") ?: "chuck_test_password";

        return [
            [
                'transactions' => true,
                'dsn' => "pgsql:host=$dbPgsqlHost;dbname=$dbName;user=$dbUser;password=$dbPassword",
            ], [
                'transactions' => false,
                'dsn' => "mysql:host=$dbMysqlHost;dbname=$dbName;user=$dbUser;password=$dbPassword",
            ],
        ];
    }

    public static function getAvailableDsns(bool $transactionsOnly = false): array
    {
        $dsns = [['transactions' => true, 'dsn' => 'sqlite:' . self::getDbFile()]];

        foreach (self::getServerDsns() as $dsn) {
            try {
                new PDO($dsn['dsn']);
                $dsns[] = $dsn;
            } catch (Throwable) {
                continue;
            }
        }

        if ($transactionsOnly) {
            return array_map(
                fn ($dsn) => $dsn['dsn'],
                array_filter($dsns, fn ($dsn) => $dsn['transactions'] === true),
            );
        }


        return array_map(fn ($dsn) => $dsn['dsn'], $dsns);
    }

    public static function cleanUpTestDbs(): void
    {
        @unlink(self::getDbFile());

        foreach (self::getServerDsns() as $dsn) {
            try {
                $conn = new PDO($dsn['dsn']);
                $conn->prepare('DROP TABLE IF EXISTS migrations')->execute();
                $conn->prepare('DROP TABLE IF EXISTS genres')->execute();
                $conn = null;
            } catch (Throwable) {
                continue;
            }
        }
    }

    protected static function getDbFile(): string
    {
        return sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'chuck_test_db.sqlite3';
    }

    protected static function getDsn(): string
    {
        return 'sqlite:' . self::getDbFile();
    }
}
