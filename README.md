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
