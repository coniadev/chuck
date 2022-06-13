Chuck framework
===============


Default:

```php
    use Chuck\{App, Route};

    $app = App::create(__DIR__ . '/config.php');
    $app->add(Route::get('index', '/', function (Request $request) {}));
    $app->run();
```

## Delarative:

```php
    use Chuck\{App, Config, Router, Route, Request};

    $config = new Config(__DIR__ . '/config.php');
    $router = new Router();
    $route = (new Route('index', '/', function (Request $request) {}))->method('GET');
    $router->add($route);
    $app = new App(new Request($router, $config));
    $app->run();
```

## Add middleware:


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


## Routes:


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

## Create test databases:

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

## Docs:

- Middlewares which run code after the $next call should check if the result
  of $next is a response and return immediately if so.


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
which are sqlite, pgsql and mysql.

TODO: list temporary paths.
- sqlite test db
