Contributing
============



## Style Guide

All pull requests must adhere to the 
[PSR-12 standard](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-12-extended-coding-style-guide.md).

## Unit Testing

All pull requests must be accompanied by passing unit tests, complete code coverage and 
static analysis running without errors.
Chuck uses **Pest** for testing and **Psalm** as static analyzer.

* ([Learn more about Pest](https://pestphp.com/)
* ([Learn more about Psalm](https://psalm.dev/)

Run the test suit with `./vendor/bin/pest` or `./vendor/bin/pest --coverage`.

###  Test suite requirements

* Install PHP 8.1+ with the required extensions (see a Ubuntu example below)
* PostgreSQL and MySQL/MariaDB for full coverage. 
* Composer (https://getcomposer.org/download/)
* Clone this repository
* Then `composer install`

Ubuntu 22.04 LTS example:

    apt install php8.1-cli php8.1-sqlite3 php8.1-pgsql php8.1-mysql \
        php8.1-gd php8.1-pcov php8.1-curl php8.1-xml php8.1-zip

The database servers:

    apt install mariadb-server postgresql sqlite3 

### Coverage

Coverage relies on the PHP extension `pcov`. 

Note: Full coverage may only be reported if all three supported PDO drivers are installed
which are sqlite, pgsql and mysql, and all test databases are set up. See next section.

### Create test databases:

SQLite will be created automatically in the system's temp directory.

PostgreSQL:

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

### Temporary files

Running the test suite will create some temporary files. We try to clean them up, but in 
case of failing tests they might remain in the file system:

* TODO: list them

## Static analysis

Chuck uses Psalm as static analyzer. Currently set to level 1 and `reportMixedIssues="false"`

Run:

    ./vendor/bin/psalm --no-cache

### Psalm and suppressing readonly property errors

At the time of writing Psalm does not support readonly properties which 
are not initialized in the constructor. The maintainers suggest to 
suppress errors is the only appropriate way. Recheck on occasion. Possible Errors:

* InaccessibleProperty
* MissingConstructor
* RedundantPropertyInitializationCheck
* See: https://github.com/vimeo/psalm/issues/7608
