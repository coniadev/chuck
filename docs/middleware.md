### Middleware:

```php
    use Conia\Chuck\{App, Config, Route, Request};

    class Middleware {
        public function __invoke(Request $request, callable $next) {
            // ... do something before the next
            $resujlt = $next($request);
            // ... do something after the next
            return $result;
        }
    }

    $app = App::create(new Config('chuck'));
    $app->middleware(new Middleware());

    // Route specific middleware
    $app->route('/', function (Request $request) {})->middleware(
        function (Request $request, callable $next): $request {
        return $next($request);
    });
    $app->run();
```

