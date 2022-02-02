<?php

namespace Chuck;

return [
    // must be set in app config
    'appname' => null,

    // e. g. 'example.com'. Must be set in app config
    'hostname' => null,
    // e. g. 'https://www.example.com'. Must be set in app config
    'url' => null,

    'devel' => false,

    // the develompent server port
    'devport' => 1983,

    // the permission required for every request
    'default_permission' => null,
    'locales' => [],
    'default_locale' => null,
    'loglevel' => 'DEBUG',

    // this value will be added to the current time()
    // as expiry date for sessions.
    'session' => [
        'expire' => 60 * 60 * 24 * 7,

        // indicates wether a custom session handler is used
        'custom' => false,

        // the custom handler.
        // must implement \Chuck\Model\SessionInterface
        'model' => null,
    ],

    // path values will be initialized with
    // default values in Config::getPathDefaults
    'path' => [
        'root' => null,
        'migrations' => null,
        'sql' => null,
        'public' => null,

        // if set, file logging will be activated
        'log' => null,

        // additional custom `php run` scripts:
        'scripts' => null,
    ],

    'templates' => [
        // 'folder' => 'path',
    ],

    // default classes
    'di' => [
        'Request' => Request::class,
        'Response' => Response::class,
        'Router' => Router::class,
        'Error' => Error::class,
        'Session' => Session::class,
        'Model' => Model\Model::class,
        'Template' => Template::class,
        'Log' => Log::class,

        // set if you want to use authentication
        // must implement \Chuck\Model\AuthInterface
        'Auth' => null,
    ],

    'renderer' => [
        'string' => Renderer\StringRenderer::class,
        'json' => Renderer\JsonRenderer::class,
        'template' => Renderer\TemplateRenderer::class,
    ],

    // database credentials
    'db' => [
        'dbms' => null,  // 'pgsql', 'sqlite', or 'mysql' etc.
        'host' => null,  // 'localhost' '192.168.13.13'
        'port' => null,  // PostgreSQL: 5432, MySQL 3306
        'name' => null,  // the name of the database
        'user' => null,  // the username
        'password' => null,  // tha password
        'fetchMode' => null,
        'print' => false, // print interpolated sql to stdout

        // if `true` the values in the settings above
        // are considered ENVIRONMENT_VARIABLES from
        // which the actual values are read at runtime
        'fromenv' => false
        // Example:
        // [
        //     'fromenv' => true,
        //     'user' => 'DB_USER',
        //     'pass' => 'DB_PASS;
        //     ...
        // ]
        // Chuck now tries to read the database user's name
        // and password from the env vars DB_USER and DB_PASS
    ],

    // memcached configuration
    'memcached' => null,
    //example: [
    //    'use' => false,
    //    'host' => 'localhost',
    //    'port' => 11211,
    //    'expire' => 86400,  // 1 day
    //],
];
