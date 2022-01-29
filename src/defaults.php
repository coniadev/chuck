<?php

namespace Chuck;

use Request;
use Response;
use Router;
use Error;
use Model\Model;
use Template;
use Log;
use Renderer\{StringRenderer, JsonRenderer, TemplateRenderer};

return [
    // must be set in app config
    'appname' => null,

    // e. g. 'example.com'. Must be set in app config
    'hostname' => null,

    // e. g. 'https://www.example.com'. Must be set in app config
    'url' => null,
    'namespace' => 'App',
    'devel' => false,
    // print interpolated sql to stdout
    'print_sql' => false,

    // the develompent server port
    'devport' => 2323,

    // the permission required for every request
    'default_permission' => null,
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
        'string' => StringRenderer::class,
        'json' => JsonRenderer::class,
        'template' => TemplateRenderer::class,
    ],

    // database credentials
    'db' => [
        'dbms' => null,  // 'pgsql', 'sqlite', or 'mysql' etc.
        'host' => null,  // 'localhost' '192.168.13.13'
        'port' => null,  // PostgreSQL: 5432, MySQL 3306
        'name' => null,  // the name of the database
        'user' => null,  // the username
        'pass' => null,  // tha password

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

    'sanitizer' => [
        'extensions' => [
            // a, b, br, blockquote, div, del, em, figcaption,
            // figure, h1, h2, h3, h4, h5, h6, i, p, q, small,
            // span, strong, sub, sup
            'basic',

            // dd, dl, dt, li, ol, ul
            'list',

            //'block',   // section, article, aside
            //'code',    // pre, code
            //'details', // allows the insertion of view/hide blocks: details, summary
            //'extra',   // abbr, caption, hr, rp, rt, ruby
            //'headfoot',// header, footer
            //'iframe',  // iframe
            //'image',   // img
            //'nav',     // nav
            //'table',   // table, thead, tbody, tfoot, tr, td, th
        ],
    ],
];
