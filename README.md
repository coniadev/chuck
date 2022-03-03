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
    'path.root' => null,                  // The root folder of the application, defaults to where composer.json is located
    'path.public' => null,                // Path to the public directory, defaults to <path.root>/public
    'path.assets' => null,                // Path to asset files used Chuck\Assets if set. Should be writable.
    'path.cache' => null,                 // Path to cache files. By default used by Chuck\Assets. Must be writable.

    'appname' => 'chuckapp',              // Internal identifier, will be used in `php run` scripts for example
                                          // Also used internally for sessions/i18n/memcache prefix or other purposes
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


    // Special paths:
    // <id> is a custom identifier, usually your apps name (appname) or the name of a lib/plugin
    // should be absolute, like __DIR__ . '/path/to/files',
    
    'scripts.<id>' => null,               // Additional custom `php run` script paths:
    'templates.<id>' => null,             // Path to templates
   
    // Database paths:

    'sql.<platform>' => '/path/to/sql',   // Platform can be "all" or the PDO driver like "pgsql", "mysql"
                                          // or "sqlite". You can add multiple platforms. Example:
    'sql.all' => '/path/to/sql/scripts/all',
    'sql.pgsql' => '/path/to/sql/scripts/pgsql',
    
    'sql.<id>.<platform>' => null,        // Add an ID if you write a lib or have multiple directories
                                             Example:
         'sql.myapp.all' => '/path/to/sql/scripts/all',
         'sql.myapp.pgsql' => '/path/to/sql/scripts/pgsql',
    
    'migrations' => null                  // If you only use a single migrations path
    'migrations.<id>' => null,            // Paths to database migrations with an added id, if you
                                             plan to have multiple migration directories.


    'db.default.dsn' => 'sqlite:...',     // The PDO connection string. See:
                                          //     PostgreSQL: https://www.php.net/manual/de/ref.pdo-pgsql.connection.php
                                          //     MySQL: https://www.php.net/manual/de/ref.pdo-mysql.connection.php
                                          //     Sqlite: https://www.php.net/manual/de/ref.pdo-sqlite.connection.php
                                          // and others
    'db.default.username' => null,        // optional
    'db.default.password' => null,        // optional
    'db.default.options' => null,         // optional, array with PDO options passed to new \PDO(...)
    'db.default.fetchMode' => null,       // optional, Defaults to PDO::FETCH_BOTH,
    'db.default.debug' => false,          // Print interpolated sql to stdout
    'db.default.memcachedPrefix' => null, // Should be set to a application version number or the like
    
     Additional database connections:
    'db.<name>.dsn' => null,              // The PDO connection string. See:
    'db.<name>.username' => null,         // optional
    'db.<name>.password' => null,         // optional


    'memcached.implementation' => null,   // optional, either 'Memcached' or 'Memcache'
                                          // if not given uses what is available or throws error
    'memcached.host' => null,             // optional, defaults to 'localhost'
    'memcached.port' => null,             // optional, defaults to 11211
    'memcached.expire' => null,           // optional, defaults to 0 which means never expire
];
