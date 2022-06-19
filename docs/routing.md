# Routing

```php
    // Single route
    $route = Route::get('index', '/', function (Request $request) {
        return [1, 2, 3];
    })->render('json');
    $app->addRoute($route);

    $route = (new Route('index', '/', function (Request $request) {}))->method('GET','POST');


    // Route groups
    $app->group(new Group('admin:', '/admin/', function (Group $group) {
        $group->add(Route::get(...);
        $group->add(Route::post(...);
    });
```

