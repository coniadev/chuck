<?php

namespace Chuck;


return [
    // Must be set in app config
    'appname' => null,

    // e. g. 'example.com'. Must be set in app config
    'hostname' => null,
    // e. g. 'https://www.example.com'. Must be set in app config
    'url' => null,

    'devel' => false,

    // The develompent server port
    'devport' => 1983,

    // The permission required for every request
    'default_permission' => null,
    'locales' => [],
    'default_locale' => null,
    'loglevel' => 'DEBUG',

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

    // Default classes used by Chuck
    'di' => [
        'Request' => Request::class,
        'Response' => Response::class,
        'Router' => Router::class,
        'Error' => Error::class,
        'Session' => Session::class,
        'Model' => Model\Model::class,
        'Template' => Template::class,
        'Log' => Log::class,

        // Set if you want to use authentication.
        // Must implement \Chuck\Model\AuthInterface
        'Auth' => null,
    ],

    'renderer' => [
        'string' => Renderer\StringRenderer::class,
        'json' => Renderer\JsonRenderer::class,
        'template' => Renderer\TemplateRenderer::class,
    ],

    // database credentials
    'db' => [
        // The PDO connection string. See:
        //   PostgreSQL: https://www.php.net/manual/de/ref.pdo-pgsql.connection.php
        //   MySQL: https://www.php.net/manual/de/ref.pdo-mysql.connection.php
        //   Sqlite: https://www.php.net/manual/de/ref.pdo-sqlite.connection.php
        // and others
        'dsn' => null,
        'options' => null, // Array with PDO options passed to new \PDO(...)
        'fetchMode' => null, // Defaults to PDO::FETCH_DEFAULT,
        'print' => false, // Print interpolated sql to stdout
    ],

    // Memcached configuration
    'memcached' => null,
    // Example: [
    //    'host' => 'localhost',
    //    'port' => 11211,
    //    'expire' => 86400,  // 1 day
    //],
];
