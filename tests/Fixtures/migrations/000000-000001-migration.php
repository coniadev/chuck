<?php

declare(strict_types=1);

use Chuck\ConfigInterface;
use Chuck\Database\DatabaseInterface;
use Chuck\Database\MigrationInterface;


class TestMigration_1 implements MigrationInterface
{
    public function run(DatabaseInterface $db, ConfigInterface $config): void
    {
        $driver = $db->getPdoDriver();

        switch ($driver) {
            case 'sqlite';
                $db->execute('ALTER TABLE albums ADD COLUMN name_sqlite TEXT;')->run();
                $db->execute("INSERT INTO albums (id, name_sqlite) VALUES (1, 'Human');")->run();
                break;
            case 'pgsql';
                $db->execute('ALTER TABLE albums ADD COLUMN name_pgsql TEXT;')->run();
                $db->execute("INSERT INTO albums (id, name_pgsql) VALUES (1, 'Human');")->run();
                break;
            case 'mysql';
                $db->execute('ALTER TABLE albums ADD COLUMN name_mysql TEXT;')->run();
                $db->execute("INSERT INTO albums (id, name_mysql) VALUES (1, 'Human');")->run();
                break;
        }

        $result = $db->execute(
            "SELECT id, name_$driver FROM albums WHERE id = 1"
        )->all(PDO::FETCH_ASSOC);

        assert(count($result) === 1);

        switch ($driver) {
            case 'sqlite';
                $result = $db->execute("PRAGMA table_info('albums')")->all();
                assert($result[1]['name'] === 'name_sqlite');
                break;
            case 'pgsql';
                $result = $db->execute(
                    "SELECT count(*) AS exists FROM information_schema.columns " .
                        "WHERE table_schema='public' " .
                        "AND table_name='albums' " .
                        "AND column_name='name_pgsql'"
                )->one();

                assert($result['exists'] === 1);
                break;
            case 'mysql';
                $result = $db->execute(
                    "SHOW COLUMNS FROM albums WHERE Field = 'name_mysql'"
                )->one();

                assert($result['Field'] ?? false === 'name_mysql');
                break;
        }
    }
}

return new TestMigration_1();
