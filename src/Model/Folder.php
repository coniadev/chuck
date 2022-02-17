<?php

declare(strict_types=1);

namespace Chuck\Model;


class Folder
{
    protected $db;
    protected $folder;

    public function __construct(Database $db, string $folder)
    {
        $this->db = $db;
        $this->folder = $folder;
    }

    protected function scriptPath(string $key, bool $isTemplate): bool|string
    {
        $ext = $isTemplate ? '.tpql' : '.sql';

        foreach ($this->db->getScriptDirs() as $path) {
            $result = $path . DIRECTORY_SEPARATOR .
                $this->folder . DIRECTORY_SEPARATOR .
                $key . $ext;

            if (file_exists($result)) {
                return $result;
            }
        }

        return false;
    }

    protected function readScript(string $key): string|false
    {
        $script = $this->scriptPath($key, false);

        if ($script && is_string($script)) {
            return file_get_contents($script);
        }

        return false;
    }

    protected function fromCache(
        \Chuck\Memcached $mc,
        string $key,
    ): string|false {
        $memKey = $this->db->getMemcachedPrefix() . '/' . $this->folder . '/' . $key;
        $stmt = $mc->get($memKey);

        if (!$stmt) {
            $stmt = $this->readScript($key);

            if ($stmt) {
                $mc->set($memKey, $stmt,);
            }
        }

        return $stmt;
    }

    protected function getScript(string $key): Script
    {
        $mc = $this->db->getMemcached();

        if ($mc) {
            $stmt = $this->fromCache($mc, $key);
        } else {
            $stmt = $this->readScript($key);
        }

        if ($stmt) {
            return new Script($this->db, $stmt, false);
        }

        // If $stmt is not truthy until now,
        // assume the script is a dnyamic sql template
        $dynStmt = $this->scriptPath($key, true);

        if ($dynStmt && is_string($dynStmt)) {
            return new Script($this->db, $dynStmt, true);
        }

        throw new \UnexpectedValueException('SQL script does not exist');
    }

    public function __get(string $key): Script
    {
        return $this->getScript($key);
    }

    public function __call(string $key, mixed $args): Query
    {
        $script = $this->getScript($key);

        return $script->invoke(...$args);
    }
}
