<?php

namespace Chuck;

return [
    'appname' => 'chuckapp',                // Internal identifier, will be used in `php run` scripts for example
    'host' => null,                         // If set will be used when generating URLs from routes for example
    'env' => null,                          // the current environment, e. g. 'development', 'production'
    'debug' => false,                       // Whether it should show Whoops messages
    'port' => 1983,                         // The develompent server port

    'log.level' => 'DEBUG',                 // The default log level (Log middleware must be added)
    'log.path' => null,                     // Path where the logfiles are written to

    'locales.list' => [],                   // Array of locales, ['en_US', 'de_DE], optionally with names ['de' => 'Deutsch, 'en => ...]
    'locales.default' => null,

    'password.minimumEtropy' => 40.0,       // Aproximately a password with about 12 thorougly mixed characters
    'password.algorithm' => null,           // Uses what is available if not set, prefers ARGON2

    'session.name' => 'chuck_session',      //
    'session.expire' => 60 * 60 * 24 * 7,   // This value will be added to the current time()

    // 'path.root' => null,                 // The root folder of the application, defaults to where composer.json is located
    // 'path.public' => null,               // Path to the public directory, defaults to <path.root>/public

    // Special paths:
    // <id> is a custom identifier, usually your apps name (appname) or the name of a lib/plugin
    // should be absolute, like __DIR__ . '/path/to/files',
    //
    // 'migrations.<id>' => null,           // Paths to database migrations
    // 'sql.<id>' => null,                  // Paths to SQL scripts
    // 'scripts.<id>' => null,              // Additional custom `php run` script paths:
    // 'templates.<id>' => null,            // Path to templates

    // 'db.dsn' => null,                    // The PDO connection string. See:
    //                                      //     PostgreSQL: https://www.php.net/manual/de/ref.pdo-pgsql.connection.php
    //                                      //     MySQL: https://www.php.net/manual/de/ref.pdo-mysql.connection.php
    //                                      //     Sqlite: https://www.php.net/manual/de/ref.pdo-sqlite.connection.php
    //                                      // and others
    // 'db.options' => null,                // optional, array with PDO options passed to new \PDO(...)
    // 'db.fetchMode' => null,              // optional, Defaults to PDO::FETCH_BOTH,
    // 'db.debug' => false,                 // Print interpolated sql to stdout
    // 'db.memcachedPrefix' => null,        // Should be set to a application version number or the like

    // Memcached configuration
    // 'memcached.implementation' => null,  // optional, either 'Memcached' or 'Memcache'
    //                                      // if not given uses what is available or throws error
    // 'memcached.host' => null,            // optional, defaults to 'localhost'
    // 'memcached.port' => null,            // optional, defaults to 11211
    // 'memcached.expire' => null,          // optional, defaults to 0 which means never expire
];
