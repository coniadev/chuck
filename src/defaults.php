<?php

namespace Chuck;


return [
    'devel' => false,

    // The develompent server port
    'devport' => 1983,

    'locales' => [],
    'default_locale' => null,
    'loglevel' => 'DEBUG',

    'minimum_password_entropy' => 40.0,
    'password_algorithm' => PASSWORD_ARGON2ID,

    // This value will be added to the current time()
    // as expiry date for sessions.
    'session' => [
        'expire' => 60 * 60 * 24 * 7,

        // Indicates wether a custom session handler is used
        'custom' => false,

        // The custom handler.
        // Must implement \Chuck\Model\SessionInterface
        'model' => null,
    ],

    // mth values will be initialized with
    // default values in Config::getPathDefaults
    'path' => [
        'root' => null,
        'migrations' => null,
        'sql' => null,
        'public' => null,

        // If set, file logging will be activated
        'log' => null,

        // Additional custom `php run` scripts:
        'scripts' => null,
    ],

    'templates' => [
        // 'folder' => 'path',
    ],

    // database credentials
    'db' => [
        'dsn' => null,       // The PDO connection string. See:
        //                        PostgreSQL: https://www.php.net/manual/de/ref.pdo-pgsql.connection.php
        //                        MySQL: https://www.php.net/manual/de/ref.pdo-mysql.connection.php
        //                        Sqlite: https://www.php.net/manual/de/ref.pdo-sqlite.connection.php
        //                      and others
        'options' => null,   // optional, array with PDO options passed to new \PDO(...)
        'fetchMode' => null, // optional, Defaults to PDO::FETCH_BOTH,
        'print' => false,    // Print interpolated sql to stdout
        'memcachedPrefix' => 'chucksql', // Should be set to a application version number or the like
    ],

    // Memcached configuration
    'memcached' => null,
    // Example: [
    //    'implementation' => null,  // optional, either 'Memcached' or 'Memcache'
    //                               // if not given uses what is available or throws error
    //    'host' => null,            // optional, defaults to 'localhost'
    //    'port' => null,            // optional, defaults to 11211
    //    'expire' => null,          // optional, defaults to 0 which means never expire
    //],
];
