<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Benchmark;

use Conia\Chuck\App;
use Conia\Chuck\Config;
use Conia\Chuck\Psr\Guzzle;
use Conia\Chuck\Psr\Laminas;
use Conia\Chuck\Psr\Nyholm;
use Conia\Chuck\Request;
use Conia\Chuck\Routing\Group;
use Conia\Chuck\Routing\Route;
use Conia\Chuck\Tests\Fixtures\TestClassInject;
use Conia\Chuck\Tests\Fixtures\TestController;
use Conia\Chuck\Tests\Fixtures\TestMiddlewareBench;

/**
 * @Iterations(1)
 */
class AppBench
{
    /**
     * @Revs(1000)
     */
    public function benchAppInit()
    {
        App::create(new Config('chuck'));
    }

    /**
     * @Revs(1000)
     * @BeforeMethods({"initIndexRequest"})
     */
    public function benchSimpleApp()
    {
        $app = App::create();
        $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::textView');
        ob_start();
        $app->run();
        ob_end_clean();
    }

    /**
     * @Revs(1000)
     * @BeforeMethods({"initAlbumRequest"})
     */
    public function benchLargeApp()
    {
        $app = App::create();
        $app->register('injected', new Config('injected'));

        // Change order to see the differences
        $app->register(Factory::class, Guzzle::class);
        $app->register(Factory::class, Laminas::class);
        $app->register(Factory::class, Nyholm::class);

        $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::textView');
        $app->route('/zasdfas/{name}/abc/{year:\d+}d', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zkjfakk/{name}/abc/{year:\d+}lasjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zasdfla/{name}/abc/{year:\d+}jsdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zaklsfj/{name}/abc/{year:\d+}a/342342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zalkdfj/{name}/abc/{year:\d+}aslkdjf/32342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zbasdfa/{name}/abc/{year:\d+}sd', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zbkjfak/{name}/abc/{year:\d+}klasjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zbasdfl/{name}/abc/{year:\d+}ajsdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zbaklsf/{name}/abc/{year:\d+}ja/342342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zbalkdf/{name}/abc/{year:\d+}jaslkdjf/32342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zabasdf/{name}/abc/{year:\d+}asd', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zabkjfa/{name}/abc/{year:\d+}kklasjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zabasdf/{name}/abc/{year:\d+}lajsdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zabakls/{name}/abc/{year:\d+}fja/342342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zabalkd/{name}/abc/{year:\d+}fjaslkdjf/32342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcasdfa/{name}/abc/{year:\d+}sd', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zckjfak/{name}/abc/{year:\d+}klasjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcasdfl/{name}/abc/{year:\d+}ajsdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcaklsf/{name}/abc/{year:\d+}ja/342342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcalkdf/{name}/abc/{year:\d+}jaslkdjf/32342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcbasdf/{name}/abc/{year:\d+}asd', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcbkjfa/{name}/abc/{year:\d+}kklasjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcbasdf/{name}/abc/{year:\d+}lajsdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcbakls/{name}/abc/{year:\d+}fja/342342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcbalkd/{name}/abc/{year:\d+}fjaslkdjf/32342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcabasd/{name}/abc/{year:\d+}fasd', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcabkjf/{name}/abc/{year:\d+}akklasjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcabasd/{name}/abc/{year:\d+}flajsdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcabakl/{name}/abc/{year:\d+}sfja/342342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/zcabalk/{name}/abc/{year:\d+}dfjaslkdjf/32342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/asdfasd/{name}/abc/{year:\d+}', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/kjfakkl/{name}/abc/{year:\d+}asjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/asdflaj/{name}/abc/{year:\d+}sdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/aklsfja/{name}/abc/{year:\d+}/342342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/alkdfja/{name}/abc/{year:\d+}slkdjf/32342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/basdfas/{name}/abc/{year:\d+}d', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/bkjfakk/{name}/abc/{year:\d+}lasjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/basdfla/{name}/abc/{year:\d+}jsdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/baklsfj/{name}/abc/{year:\d+}a/342342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/balkdfj/{name}/abc/{year:\d+}aslkdjf/32342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/abasdfa/{name}/abc/{year:\d+}sd', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/abkjfak/{name}/abc/{year:\d+}klasjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/abasdfl/{name}/abc/{year:\d+}ajsdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/abaklsf/{name}/abc/{year:\d+}ja/342342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/abalkdf/{name}/abc/{year:\d+}jaslkdjf/32342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/casdfas/{name}/abc/{year:\d+}d', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/ckjfakk/{name}/abc/{year:\d+}lasjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/casdfla/{name}/abc/{year:\d+}jsdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/caklsfj/{name}/abc/{year:\d+}a/342342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/calkdfj/{name}/abc/{year:\d+}aslkdjf/32342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/cbasdfa/{name}/abc/{year:\d+}sd', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/cbkjfak/{name}/abc/{year:\d+}klasjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/cbasdfl/{name}/abc/{year:\d+}ajsdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/cbaklsf/{name}/abc/{year:\d+}ja/342342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/cbalkdf/{name}/abc/{year:\d+}jaslkdjf/32342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/cabasdf/{name}/abc/{year:\d+}asd', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/cabkjfa/{name}/abc/{year:\d+}kklasjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/cabasdf/{name}/abc/{year:\d+}lajsdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/cabakls/{name}/abc/{year:\d+}fja/342342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->route('/cabalkd/{name}/abc/{year:\d+}fjaslkdjf/32342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
        $app->post(
            '/balbums/{name}/{year}',
            fn (Request $request, int $year, string $name) => ['year' => $year, 'name' => $name]
        )->render('json');
        $app->group('/albums', function (Group $group) {
            $ctrl = TestController::class;
            $group->addRoute(Route::get('/{name}', "{$ctrl}::albumName"));
            $group->route('/zasdfas/{name}/abc/{year:\d+}d', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
            $group->route('/zkjfakk/{name}/abc/{year:\d+}lasjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
            $group->route('/zasdfla/{name}/abc/{year:\d+}jsdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
            $group->route('/zaklsfj/{name}/abc/{year:\d+}a/342342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
            $group->route('/zalkdfj/{name}/abc/{year:\d+}aslkdjf/32342', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
            $group->route('/zbasdfa/{name}/abc/{year:\d+}sd', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
            $group->route('/zbkjfak/{name}/abc/{year:\d+}klasjdf', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
            $group->route('/zbasdfl/{name}/abc/{year:\d+}ajsdf/1212', fn () => null)->method('GET', 'POST')->middleware(TestMiddlewareBench::class);
            $group->post(
                '/{name}/{year}',
                fn (Request $request, int $year, string $name, TestClassInject $tc) => [
                    'year' => $year,
                    'name' => $name,
                ]
            )->render('json');
        })->render('json')->middleware(TestMiddlewareBench::class);


        ob_start();
        $app->run();
        ob_end_clean();
    }

    public function initIndexRequest()
    {
        $_SERVER['HTTP_HOST'] = 'www.example.com';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';
        $_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
    }

    public function initAlbumRequest()
    {
        $_SERVER['HTTP_HOST'] = 'www.example.com';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['REQUEST_URI'] = '/albums/symbolic/1995';
        $_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
    }
}
