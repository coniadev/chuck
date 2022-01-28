<?php

return [
    'appname' => null, // must be set in app config
    'hostname' => null, // e. g. 'example.com'. Must be set in app config
    'url' => null, // e. g. 'https://www.example.com'. Must be set in app config
    'namespace' => 'App',
    'devel' => false,
    'print_sql' => false, // print interpolated sql to stdout
    'devport' => 2323, // the develompent server port
    'default_permission' => null, // the permission required for every request
    'default_locale' => null,
    'loglevel' => 'DEBUG',

    'plugins' => [],

    // this value will be added to the current time()
    // as expiry date for sessions.
    'session' => [
        'expire' => 60 * 60 * 24 * 7,
        'custom' => false, // indicates wether a custom session handler is used
        'model' => null, // the custom handler.
        // must implement \Chuck\Model\SessionInterface
    ],

    // path values will be initialized with
    // default values in Config::getPathDefaults
    'path' => [
        'app' => null,
        'root' => null,
        'migrations' => null,
        'sql' => null,
        'templates' => null,
        'public' => null,
        'log' => null,          // if set, file logging will be activated
        'scripts' => null,      // additional custom `php run` scripts:
    ],

    // default classes
    'di' => [
        'Request' => '\Chuck\Request',
        'Response' => '\Chuck\Response',
        'Router' => '\Chuck\Router',
        'Error' => '\Chuck\Error',
        'Session' => '\Chuck\Session',
        'Model' => '\Chuck\Model\Model',
        'Template' => '\Chuck\Template',
        'Log' => '\Chuck\Log',
        'Auth' => null,         // set if you want to use authentication
        // must implement \Chuck\Model\AuthInterface
    ],

    'renderer' => [
        'string' => '\Chuck\Renderer\StringRenderer',
        'json' => '\Chuck\Renderer\JsonRenderer',
        'template' => '\Chuck\Renderer\TemplateRenderer',
    ],

    // memcached configuration
    'memcached' => null, // [
    //    'use' => false,
    //    'host' => 'localhost',
    //    'port' => 11211,
    //    'expire' => 86400,  // 1 day
    //],

    'sanitizer' => [
        'extensions' => [
            'basic',     // a, b, br, blockquote, div, del, em, figcaption,
            //              figure, h1, h2, h3, h4, h5, h6, i, p, q, small,
            //              span, strong, sub, sup
            'list',      // dd, dl, dt, li, ol, ul

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
