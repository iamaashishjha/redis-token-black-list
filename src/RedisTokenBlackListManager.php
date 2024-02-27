<?php

namespace GeniusSystems\RedisTokenBlackList;

use Carbon\Carbon;
use Defuse\Crypto\Crypto;
use RedisClient\RedisClient;
use Lcobucci\JWT\Configuration;
use Illuminate\Support\Facades\DB;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use GeniusSystems\RedisTokenBlackList\Contracts\RedisTokenBlackListContract;
use GeniusSystems\RedisTokenBlackList\Exceptions\RedisTokenKeyExistsException;
use GeniusSystems\RedisTokenBlackList\Constants\RedisTokenBlackListManagerConstants;

class RedisTokenBlackListManager implements RedisTokenBlackListContract
{
    private $redis, $redisServerUrl;

    public function __construct()
    {
        $this->redisServerUrl = env('GS_ACCESS_TOKEN_REDIS_HOST', '127.0.0.1') . ':' . env('GS_ACCESS_TOKEN_REDIS_PORT', '6379');
        $this->redis = new RedisClient(["server" => $this->redisServerUrl]);
    }

    public function hsetRedisData(string $key, string|array $fieldArr, ?string $value = null): void
    {
        if (is_array($fieldArr)) {
            foreach ($fieldArr as $fieldKey => $value) {
                if ($fieldKey === RedisTokenBlackListManagerConstants::EXPIRESAT) {
                    if (!$value instanceof Carbon) {
                        $value = Carbon::parse($value);
                    }
                    $this->redis->hSet($key, $fieldKey, $value->toDateTimeString());
                    $ttl = Carbon::now()->diffInSeconds($value);
                    $this->redis->expire($key, $ttl);
                } else {
                    $this->redis->hSet($key, $fieldKey, $value);
                }
            }
        } else {
            $this->redis->hSet($key, $fieldArr, $value);
        }
    }

    public function revokeAllTokensViaAccessToken(string $accessToken): void
    {
        try {
            [$accessTokenId, $userId] = $this->getTokenDetailsFromAccessToken($accessToken);
            $this->revokeTokensForUser($userId, $accessTokenId);
        } catch (\Throwable $th) {
            // dd($th);
            // throw $th;
            return;
        }
    }

    public function revokeAllTokensViaUserIdAndClientId(int $userId, int $clientId): void
    {
        try {
            $this->revokeTokensForUser($userId, null, $clientId);
        } catch (\Throwable $th) {
            // dd($th);
            // throw $th;
            return;
        }
    }

    public function revokeUserAccessToken(string $accessToken): void
    {
        try {
            [$accessTokenId, $userId, $expiryDate] = $this->getTokenDetailsFromAccessToken($accessToken);
            $tokenData = ['id' => $accessTokenId, 'user_id' => $userId, 'expires_at' => $expiryDate];
            $redisOauthAccessTokenKey = RedisTokenBlackListManagerConstants::ACCESSTOKENKEYPREFIX . ":{$userId}:{$accessTokenId}";
            $this->hsetRedisData($redisOauthAccessTokenKey, $tokenData);
            $this->removeUserAllSessions($userId);
        } catch (\Throwable $th) {
            return;
        }
    }

    public function validateAccessToken(string $bearerToken): void
    {
        try {
            [$accessTokenId, $userId] = $this->getTokenDetailsFromAccessToken($bearerToken);
            $redisOauthAccessTokenKey = RedisTokenBlackListManagerConstants::ACCESSTOKENKEYPREFIX . ":{$userId}:{$accessTokenId}";
            $redisOauthAccessTokenExists = $this->redis->exists($redisOauthAccessTokenKey);
            if ($redisOauthAccessTokenExists) {
                throw new RedisTokenKeyExistsException();
            }
        } catch (RedisTokenKeyExistsException $e) {
            // dd($e);
            throw $e;
        } catch (\Throwable $th) {
            // dd($th);
            return;
        }
    }

    public function validateRefreshToken(string $refreshToken): void
    {
        try {
            [$refreshTokenId, $userId] = $this->getTokenDetailsFromRefreshToken($refreshToken);
            $redisOauthRefreshTokenKey = RedisTokenBlackListManagerConstants::REFRESHTOKENKEYPREFIX . ":{$userId}:{$refreshTokenId}";
            $redisOauthRefreshTokenExists = $this->redis->exists($redisOauthRefreshTokenKey);
            if ($redisOauthRefreshTokenExists) {
                throw new RedisTokenKeyExistsException();
            }
        } catch (RedisTokenKeyExistsException $e) {
            // dd($e);
            throw $e;
        } catch (\Throwable $th) {
            // dd($th);
            return;
        }
    }

    private function getTokensFromDb(int $userId, ?string $accessTokenId = null, ?int $clientId = null): array
    {
        if ($accessTokenId) {
            $currentAccessToken = DB::table('oauth_access_tokens')->where('id', $accessTokenId)->first();
            $allAccessTokens = DB::table('oauth_access_tokens')->where([
                ['client_id', $currentAccessToken->client_id],
                ['user_id', $userId],
                ['expires_at', '>=', Carbon::today()]
            ])->select('id', 'expires_at')->get();
        } elseif ($clientId) {
            $allAccessTokens = DB::table('oauth_access_tokens')->where([
                ['client_id', $clientId],
                ['user_id', $userId],
                ['expires_at', '>=', Carbon::today()]
            ])->select('id', 'expires_at')->get();
        } else {
            throw new \InvalidArgumentException("Either Access token id or Client id must be provided to get tokens from database.");
        }

        $allAccessTokenIds = $allAccessTokens->pluck('id')->toArray();
        $allRefreshTokens = DB::table('oauth_refresh_tokens')->whereIn('access_token_id', $allAccessTokenIds)->where([
            ['revoked', false],
            ['expires_at', '>=', Carbon::today()]
        ])->select('id', 'expires_at')->get();

        return [$allAccessTokens->toArray(), $allRefreshTokens->toArray()];
    }

    private function getTokenDetailsFromAccessToken(string $bearerToken): array
    {
        $signer = new Sha256();
        $signingKey = InMemory::file(storage_path('oauth-private.key'));
        $verificationKey = InMemory::file(storage_path('oauth-public.key'));
        // Create the configuration with the signer and keys
        $config = Configuration::forAsymmetricSigner($signer, $signingKey, $verificationKey);
        $parsedToken = $config->parser()->parse($bearerToken);

        $accessTokenId = $parsedToken->claims()->get('jti');
        $expiryDate = $parsedToken->claims()->get('exp');

        // $userId = $parsedToken->claims()->get('sub');

        $userId = $parsedToken->claims()->get('params')['id'];

        return [$accessTokenId, $userId, $expiryDate];
    }

    private function getTokenDetailsFromRefreshToken(string $refreshToken): array
    {
        $encryptionKey = app('encrypter')->getKey();
        $tokenParams = Crypto::decryptWithPassword($refreshToken, $encryptionKey);
        $tokenParams = json_decode($tokenParams, true);
        $refreshTokenId = $tokenParams['refresh_token_id'];
        $userId = $tokenParams['user_id'];
        return [$refreshTokenId, $userId];
    }

    private function addTokensToBlackList(array $tokensArr, int $userId, string $keySuffix): void
    {
        foreach ($tokensArr as $singleToken) {
            $tokenData = ['id' => $singleToken->id, 'user_id' => $userId, 'expires_at' => $singleToken->expires_at];
            $redisOauthAccessTokenKey = $keySuffix . ":{$userId}:{$singleToken->id}";
            if (!$this->redis->exists($redisOauthAccessTokenKey)) {
                $this->hsetRedisData($redisOauthAccessTokenKey, $tokenData);
            }
        }
    }

    private function removeUserAllSessions(int $userId): void
    {
        $sessionKeyPattern = RedisTokenBlackListManagerConstants::SESSIONKEYPREFIX . ":{$userId}";
        $allSessionIds = $this->redis->smembers($sessionKeyPattern);

        if (!blank($allSessionIds)) {
            foreach ($allSessionIds as $sessionId) {
                $redisSessionKey = "{$sessionKeyPattern}:{$sessionId}";
                $this->redis->del($sessionKeyPattern);
                $this->redis->del($redisSessionKey);
            }
        }
    }

    private function revokeTokensForUser(int $userId, ?string $accessTokenId = null, ?int $clientId = null): void
    {
        [$accessTokens, $refreshTokens] = $this->getTokensFromDb($userId, $accessTokenId, $clientId);
        $this->addTokensToBlackList($accessTokens, $userId, RedisTokenBlackListManagerConstants::ACCESSTOKENKEYPREFIX);
        $this->addTokensToBlackList($refreshTokens, $userId, RedisTokenBlackListManagerConstants::REFRESHTOKENKEYPREFIX);
        $this->removeUserAllSessions($userId);
    }
}
