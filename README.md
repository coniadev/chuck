Chuck framework
===============


Default:

```php
    use Chuck\{App, Route};

    $app = App::create(__DIR__ . '/config.php');
    $app->add(Route::get('index', '/', function (Request $request) {}));
    $app->run();
```

Delarative:

```php
    use Chuck\{App, Config, Router, Route, Request};

    $config = new Config(__DIR__ . '/config.php');
    $router = new Router();
    $route = (new Route('index', '/', function (Request $request) {}))->method('GET');
    $router->add($route);
    $app = new App(new Request($router, $config));
    $app->run();
```

Add middleware:


```php
    use Chuck\{App, Route, RequestInterface};

    class Middleware {
        public function __invoke(RequestInterface $request, callable $next) {
            // ... do something before the next
            $request = $next($request);
            // ... do something after the next
            return $request;
        }
    }

    $app = App::create(__DIR__ . '/config.php');
    $app->reqister(new Middleware());

    // Route specific middleware
    $app->add(Route::get('index', '/', function (Request $request) {}))->reqister(function (RequestInterface $request, callable $next): $request {
        return $next($request);
    });
    $app->run();
```


Routes:


```php
    
    $app->addRoute([
        'name' => 'admin:index',
        'route' => '/admin/',
        'view' => '\App\Controller\Admin\Home::index',
        'permission' => 'backend',
        'renderer' => 'template:admin/index',
    ]);


    $app->group(new Group('admin:', '/admin/', function (Group $group) {
        $group->add(Route::get(())
    })->middleware(new Permission('admin'))->render('json')->namespace('\Chuck\');
```


Docs:

- Middlewares which run code after the $next call should check if the result
  of $next is a response and return immediately if so.


Config

```
namespace Chuck;

return [
    'app' => 'chuckapp',                  // Internal identifier, will be used in `php run` scripts for example
                                          // Also used internally for sessions/i18n/memcache prefix or other purposes

    'path.root' => null,                  // The root folder of the application, defaults to where composer.json is located
    'path.public' => null,                // Path to the public directory, defaults to <path.root>/public
    'path.assets' => null,                // Path to asset files used Chuck\Assets if set. Should be writable.
    'path.cache' => null,                 // Path to cache files. By default used by Chuck\Assets. Must be writable.

    'env' => null,                        // the current environment, e. g. 'development', 'production'
    'debug' => false,                     // Whether it should show Whoops messages
    'port' => 1983,                       // The develompent server port
    'secret' => null                      // Used for password hashing or creating unique keys. Must be retained if you migrate your site.

    'host' => null,                       // www.example.com
                                          // Can be used in scripts or your app
                                          // Will be created from $_SERVER if not set.
    'origin' => null,                     // e. g. 'https://www.example.com:8080'
                                          // Used for generating URLs from routes for example
                                          // Will be created from $_SERVER if not set.

    'log.level' => Logger::DEBUG,         // The default log level (Log middleware must be added)
    'log.file' => null,                   // Path where the logfiles are written to


    'locales.list' => [],                 // Array of locales, ['en_US', 'de_DE], optionally with names ['de' => 'Deutsch, 'en => ...]
    'locales.default' => null,


    'password.algorithm' => null,         // Uses what is available if not set, prefers ARGON2
    'password.entropy' => 40.0,           // Password strength entropy. 40.0 is aproximately a password with
                                          // at least 12 mixed characters.

    'session.name' => null,               // Cookie name sent to the browser
    'session.expire' => 60 * 60 * 24 * 7, // This value will be added to the current time()

    'templates' => null,                  // Path to templates
    'templates.<id>' => null,             // Path to templates
   
    // Default SQL scripts    -> new Database($config);
    'sql' => [
        'all' => '/path/to/sql/scripts/all',
        'pgsql' => '/path/to/sql',
        'mysql' => '/path/to/sql/scripts/pgsql',
    ],
    // Additonal namespace SQL scripts    -> new Database($config, sql: 'myapp');
    'sql.myapp' => [
        'all' => '/path/to/sql/scripts/all',
        'pgsql' => '/path/to/sql/scripts/pgsql'
    ],
    
    'migrations' => null,                 // Paths to database migrations. There should be only one without id
    'migrations.<id>' => null,            // If you want to use multiple directories you must provide ids

    // The default database connection   -> new Database($config);
    'db' => [
        'dsn' => 'sqlite => ...',         // The PDO connection string. See:
                                          //     PostgreSQL: https://www.php.net/manual/de/ref.pdo-pgsql.connection.php
                                          //     MySQL: https://www.php.net/manual/de/ref.pdo-mysql.connection.php
                                          //     Sqlite: https://www.php.net/manual/de/ref.pdo-sqlite.connection.php
                                          // and others
        'username' => null,               // optional
        'password' => null,               // optional
        'options' => null,                // optional, array with PDO options passed to new \PDO(...)
        'fetchmode' => null,              // optional, Defaults to PDO::FETCH_BOTH,
        'print' => false,                 // Print interpolated sql to stdout
        'sql' => []                       // TODO: connection specific sql paths. Overwrites general settings
        'migrations' => []                // TODO: connection specific migrations. Overwrites general settings
    ],

    // Optional: additional database connections   -> new Database($config, connection: 'mycon');
    'db.mycon' => [
        'dsn' => 'psql => ...',
        'username' => null,
        'password' => null,
    ],
                                          
    'memcached' => [
        'implementation' => 'hans',       // optional, either 'Memcached' or 'Memcache'
                                          // if not given uses what is available or throws error
        'host' => null,                   // optional, defaults to 'localhost'
        'port' => null,                   // optional, defaults to 11211
        'expire' => null,                 // optional, defaults to 0 which means never expire
    ]

    'scripts' => null,                    // Path to scripts executed by `php run`
];
```

