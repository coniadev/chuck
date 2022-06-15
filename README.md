Chuck framework
===============


Default:

```php
    use Chuck\{App, Config, Route};

    $app = App::create(new Config('chuck'));
    $app->add(Route::get('index', '/', function (Request $request) {}));
    $app->run();
```

## Manually:

```php
    use Chuck\{App, Config, Router, Route, Request};

    $config = new Config('chuck');
    $router = new Router();
    $route = (new Route('index', '/', function (Request $request) {}))->method('GET');
    $router->add($route);
    $app = new App(new Request($config, $router));
    $app->run();
```

## Middleware:

```php
    use Chuck\{App, Route, RequestInterface};

    class Middleware {
        public function __invoke(RequestInterface $request, callable $next) {
            // ... do something before the next
            $resujlt = $next($request);
            // ... do something after the next
            return $result;
        }
    }

    $app = App::create(__DIR__ . '/config.php');
    $app->middleware(new Middleware());

    // Route specific middleware
    $app->add(
        Route::get('index', '/', function (Request $request) {}))->middleware(
            function (RequestInterface $request, callable $next): $request {
            return $next($request);
        })
    );
    $app->run();
```


## Routes:


```php
    // Single route
    $route = Route::get('index', '/', function (Request $request) {
        return [1, 2, 3];
    })->renderer('json');
    $app->add($route);


    // Route groups
    $app->group(new Group('admin:', '/admin/', function (Group $group) {
        $group->add(Route::get(...);
        $group->add(Route::post(...);
    });
```


## Config

```
    Add config example.
```


## Psalm and suppressing InaccessibleProperty/MissingConstructor

At the time of writing Psalm does not support readonly properties which 
are not initialized in the constructor. The maintainers suggest to 
suppress errors is the only appropriate way. Recheck on occasion.

- https://github.com/vimeo/psalm/issues/7608


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

## TODO

list temporary paths.

- sqlite test db
