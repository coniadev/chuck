Contributing
============

## Tests:

Run `pest`.

With coverage and static analyzer:

    pest --coverage && psalm --no-cache --show-info=true

Note: Running the test suite will create temporary files. We try to clean up, but in 
case of failing tests they might remain in the file system:

Note: Coverage is measured with pcov. Xdebug does report some PHP 8 match 
expressions as uncovered.

Note: Full coverage is only reported if all three supported PDO drivers are installed
which are sqlite, pgsql and mysql, and the test databases are set up.

### Create test databases:

SQLite will be created automatically in the system's temp directory.

PostgreSQL

```
    CREATE DATABASE chuck_test_db;
    CREATE ROLE chuck_test_user LOGIN PASSWORD 'chuck_test_password';
    GRANT ALL PRIVILEGES ON DATABASE chuck_test_db TO chuck_test_user;
```

MariaDB/MySQL

```
    CREATE DATABASE chuck_test_db;
    CREATE USER chuck_test_user@localhost IDENTIFIED BY 'chuck_test_password';
    GRANT ALL ON chuck_test_db.* TO chuck_test_user@localhost;
```


## Psalm and suppressing InaccessibleProperty/MissingConstructor

At the time of writing Psalm does not support readonly properties which 
are not initialized in the constructor. The maintainers suggest to 
suppress errors is the only appropriate way. Recheck on occasion.

- https://github.com/vimeo/psalm/issues/7608


## TODO

list temporary paths.

- sqlite test db

