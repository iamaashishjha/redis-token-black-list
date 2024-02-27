<?php

namespace GeniusSystems\RedisTokenBlackList\Tests\Unit;

use RedisClient\RedisClient;
use PHPUnit\Framework\TestCase;

class RedisTokenBlackListManagerTest extends TestCase
{
    protected $redis;
    public function setUp(): void
    {
        $this->redis = new RedisClient(["server"  => "127.0.0.1:6379"]);
    }
}
