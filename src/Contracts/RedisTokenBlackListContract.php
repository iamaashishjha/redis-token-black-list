<?php

namespace GeniusSystems\RedisTokenBlackList\Contracts;

/**
 * Interface RedisTokenBlackListContract
 *
 * This interface defines methods for managing and revoking access tokens in a Redis token blacklist.
 */
interface RedisTokenBlackListContract
{
    /**
     * Store data in Redis hash.
     *
     * @param string $key The key under which to store the hash.
     * @param string|array $fieldArr The field(s) to set in the hash.
     * @param string|null $value The value to set for the field (optional) if $fieldArr is array else if $fielArr is string required.
     *
     * @return void
     */
    public function hsetRedisData(string $key, string|array $fieldArr, ?string $value = null): void;

    /**
     * Revoke the access token associated with the provided bearer token.
     *
     * @param string $bearerToken The bearer token to revoke.
     *
     * @return void
     */
    public function revokeUserAccessToken(string $bearerToken): void;

    /**
     * Revoke all tokens (both access and refresh) associated with the provided access token.
     *
     * @param string $bearerToken The access token used to revoke all associated tokens.
     *
     * @return void
     */
    public function revokeAllTokensViaAccessToken(string $bearerToken): void;

    /**
     * Revoke all tokens (both access and refresh) associated with the specified user and client.
     *
     * @param int $userId The user ID for whom to revoke tokens.
     * @param int $clientId The client ID for which to revoke tokens.
     *
     * @return void
     */
    public function revokeAllTokensViaUserIdAndClientId(int $userId, int $clientId): void;

    /**
     * Validate the provided access token.
     *
     * @param string $bearerToken The access token to validate.
     *
     * @return void
     */
    public function validateAccessToken(string $bearerToken): void;

    /**
     * Validate the provided refresh token.
     *
     * @param string $bearerToken The refresh token to validate.
     *
     * @return void
     */
    public function validateRefreshToken(string $bearerToken): void;
}
