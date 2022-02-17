<?php

declare(strict_types=1);

use Chuck\Tests\DatabaseCase;
use Chuck\Tests\Helper;
use Chuck\Model\Database;

uses(DatabaseCase::class);

const ds = DIRECTORY_SEPARATOR;
const ADDITIONAL_SCRIPTS = __DIR__ . ds . 'fixtures' . ds . 'sql' . ds . 'expand';
const NUMBER_OF_ALBUMS = 7;
const NUMBER_OF_MEMBERS = 17;


test('Database connection', function () {
    $db = new Database($this->config());

    expect($db->getConn())->toBeInstanceOf(\PDO::class);
});


test('Add script dir outside of root directory', function () {
    $db = $this->getDb();
    $db->addScriptDir('/etc');
})->throws(\InvalidArgumentException::class);


test('Set whether it should print sql to stdout', function () {
    $db = $this->getDb();

    expect($db->shouldPrintQuery())->toBe(false);
    $db->setPrintQuery(true);
    expect($db->shouldPrintQuery())->toBe(true);
});


test('Database init set fetch mode via method', function () {
    $db = new Database($this->config());

    $result = $db->defaultFetchMode(\PDO::FETCH_ASSOC);

    expect($db->getFetchmode())->toBe(\PDO::FETCH_ASSOC);
    expect($result)->toBeInstanceOf(Database::class);
});


test('Fetch all :: Query::all()', function () {
    $db = $this->getDb();
    $result = $db->members->list()->all();

    expect(count($result))->toBe(NUMBER_OF_MEMBERS);
});


test('Get row count :: Query::len()', function () {
    // SQLite unlike MySQL/Postgres always returns 0.
    // So this tests does not check for correct result
    // but if the code runs without errors.
    $db = $this->getDb();
    $result = $db->members->list()->len();

    expect($result)->toBe(0);
});


test('Fetch one :: Query::one()', function () {
    $db = $this->getDb();
    $result = $db->members->list()->one();

    expect($result['name'] ?? null)->toBeTruthy();
});


test('Run only queries :: Query::run()', function () {
    $db = $this->getDb();

    $db->members->add('Tim Aymar', 1998, 2001)->run();
    expect(count($db->members->list()->all()))->toBe(NUMBER_OF_MEMBERS + 1);
    $db->members->delete(['name' => 'Tim Aymar'])->run();
    expect(count($db->members->list()->all()))->toBe(NUMBER_OF_MEMBERS);
});


test('Transactions begin/commit', function () {
    $db = $this->getDb();

    $db->begin();
    $db->members->add('Tim Aymar', 1998, 2001)->run();
    $db->commit();
    expect(count($db->members->list()->all()))->toBe(NUMBER_OF_MEMBERS + 1);

    $db->members->delete(['name' => 'Tim Aymar'])->run();

    $db->begin();
    $db->members->add('Tim Aymar', 1998, 2001)->run();
    $db->rollback();
    expect(count($db->members->list()->all()))->toBe(NUMBER_OF_MEMBERS);
});


test('Query with positional parameters', function () {
    $db = $this->getDb();
    $result = $db->members->byId(2)->one();
    expect($result['name'])->toBe('Rick Rozz');

    // arguments can also be passed as array
    $result = $db->members->byId([4])->one();
    expect($result['name'])->toBe('Terry Butler');
});


test('Query with named parameters', function () {
    $db = $this->getDb();
    $result = $db->members->activeFromTo([
        'from' => 1990,
        'to' => 1995,
    ])->all();

    expect(count($result))->toBe(7);
});


test('Query with string parameters', function () {
    $db = $this->getDb();
    $query = $db->types->test([
        'val' => 'Death',
    ]);

    expect((string)$query)->toBe("SELECT * FROM typetest WHERE val = 'Death';\n");
});


test('Query with boolean parameters', function () {
    $db = $this->getDb();
    $query = $db->types->test([
        'val' => true,
    ]);

    expect((string)$query)->toBe("SELECT * FROM typetest WHERE val = true;\n");
});


test('Query with NULL parameters', function () {
    $db = $this->getDb();
    $query = $db->types->test([
        'val' => null,
    ]);

    expect((string)$query)->toBe("SELECT * FROM typetest WHERE val = NULL;\n");
});


test('Query with array parameters', function () {
    $db = $this->getDb();
    $query = $db->types->test([
        'val' => [1, 2, 3],
    ]);

    expect((string)$query)->toBe("SELECT * FROM typetest WHERE val = '[1,2,3]';\n");
});


test('Query with invalid type parameters', function () {
    $db = $this->getDb();
    $obj = new stdClass();
    $obj->name = 'Death';
    $db->types->test([
        'val' => $obj,
    ]);
})->throws(\InvalidArgumentException::class);


test('Template query', function () {
    $db = $this->getDb([
        'db.fetchMode' => \PDO::FETCH_ASSOC,
    ]);

    $result = $db->members->joined(['year' => 1983])->one();
    expect(count($result))->toBe(3);

    $result = $db->members->joined(['year' => 1983, 'interestedInNames' => true])->one();
    expect(count($result))->toBe(4);
});


test('Template query with positional args', function () {
    $db = $this->getDb();

    $db->members->joined(1983);
})->throws(\InvalidArgumentException::class);


test('Template query with no SQL args', function () {
    $db = $this->getDb();

    $result = $db->members->ordered(['order' => 'asc'])->all();
    expect($result[0]['name'])->toBe('Andy LaRocque');

    $result = $db->members->ordered(['order' => 'desc'])->all();
    expect($result[0]['name'])->toBe('Terry Butler');
});


test('Expand script dirs :: query from default', function () {
    $db = new Database($this->config());
    $db->addScriptDir(ADDITIONAL_SCRIPTS);

    $result = $db->members->list()->all();
    expect(count($result))->toBe(NUMBER_OF_MEMBERS);
});


test('Script instance', function () {
    $db = $this->getDb();

    $byId = $db->members->byId;
    expect($byId(5)->one()['name'])->toBe('Bill Andrews');
});


test('Query printing named parameters', function () {
    $db = $this->getDb();
    $db->setPrintQuery(true);

    ob_start();
    $result = $db->members->joined([
        'year' => 1997,
        'testPrinting' => true,
        'interestedInNames' => true,
    ])->one();
    $output = ob_get_contents();
    ob_end_clean();

    expect($result['name'])->toBe('Shannon Hamm');
    expect($output)->toContain('Emotions :year');
    expect($output)->toContain('mantas, -- :year');
    expect($output)->toContain("' :year");
    expect($output)->toContain('Secret Face :year');
    expect($output)->toContain('joined = 1997');
});


test('Query printing positional parameters', function () {
    $db = $this->getDb();
    $db->setPrintQuery(true);

    ob_start();
    $result = $db->members->left(2001)->one();
    $output = ob_get_contents();
    ob_end_clean();

    expect($result['name'])->toBe('Shannon Hamm');
    expect($output)->toContain('Emotions ?');
    expect($output)->toContain('mantas, -- ?');
    expect($output)->toContain("' ?");
    expect($output)->toContain('Secret Face ?');
    expect($output)->toContain('WHERE left = 2001');
});


test('Expand script dirs :: query from expanded', function () {
    $db = new Database($this->config());
    $db->addScriptDir(ADDITIONAL_SCRIPTS);

    $result = $db->members->byName(['name' => 'Rick Rozz'])->one();
    expect($result['member'])->toBe(2);
});


test('Expand script dirs :: query from expanded new namespace', function () {
    $db = new Database($this->config());
    $db->addScriptDir(ADDITIONAL_SCRIPTS);

    $result = $db->albums->list()->all();
    expect(count($result))->toBe(7);
});


test('Multiple Query->one calls', function () {
    $db = new Database($this->config());
    $query = $db->members->activeFromTo([
        'from' => 1990,
        'to' => 1995,
    ]);

    $i = 0;
    $result = $query->one();
    while ($result) {
        $i++;
        $result = $query->one();
    }

    expect($i)->toBe(7);
});


test('Databse::execute', function () {
    $db = new Database($this->config());
    $query = 'SELECT * FROM albums';

    expect(count($db->execute($query)->all()))->toBe(7);
});


test('Databse::execute with args', function () {
    $db = new Database($this->config());
    $queryQmark = 'SELECT name FROM members WHERE joined = ? AND left = ?';
    $queryNamed = 'SELECT name FROM members WHERE joined = :joined AND left = :left';

    expect(
        $db->execute($queryQmark, [1991, 1992])->one()['name']
    )->toBe('Sean Reinert');

    expect(
        $db->execute($queryQmark, 1991, 1992)->one()['name']
    )->toBe('Sean Reinert');

    expect(
        $db->execute($queryNamed, ['left' => 1992, 'joined' => 1991])->one()['name']
    )->toBe('Sean Reinert');
});


test('Script dir shadowing', function () {
    $db = $this->getDb();

    // The query in the default dir uses positional parameters
    // and returns the field `left` additionally to `member` and `name`.
    $result = $db->members->byId(2)->one();
    expect($result['name'])->toBe('Rick Rozz');
    expect($result['left'])->toBe(1989);

    // The query in the expand dir uses named parameters
    // and additionally returns the field `joined` in contrast
    // to the default dir, which returns the field `left`.
    $db->addScriptDir(ADDITIONAL_SCRIPTS);
    // Named parameter queries also support positional arguments
    $result = $db->members->byId(3)->one();
    expect($result['name'])->toBe('Chris Reifert');
    expect($result['joined'])->toBe(1986);
    // Passed named args
    $result = $db->members->byId(['member' => 4])->one();
    expect($result['name'])->toBe('Terry Butler');
    expect($result['joined'])->toBe(1987);
});


test('Accessing non-existent namespace (Folder)', function () {
    $db = $this->getDb();
    $db->doesNotExist;
})->throws(\UnexpectedValueException::class);


test('Accessing non-existent script/query', function () {
    $db = $this->getDb();
    $db->members->doesNotExist;
})->throws(\UnexpectedValueException::class);


test('With Memcached', function () {
    $db = $this->getDb([
        'memcached.host' => 'localhost',
        'memcached.port' => 11211,
        'memcached.expire' => 1,
        'db.memcachedPrefix' => 'chucksql',
    ]);

    $db->members->list()->all();
    $mc = $db->getMemcached();
    $db->members->list()->all();
    expect($mc->getConn())->toBeInstanceOf(\Memcached::class);
    expect($mc->get('chucksql/members/list'))->toBe("SELECT member, name, joined, left FROM members;\n");
})->skip(!Helper::memcachedExtensionLoaded());
