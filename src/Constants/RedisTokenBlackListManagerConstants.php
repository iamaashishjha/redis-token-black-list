<?php

namespace GeniusSystems\RedisTokenBlackList\Constants;

class RedisTokenBlackListManagerConstants
{
    const ACCESSTOKENKEYPREFIX = "oauth_access_tokens";
    const REFRESHTOKENKEYPREFIX = "oauth_refresh_tokens";
    const SESSIONKEYPREFIX = "sessions";
    const EXPIRESAT = "expires_at";
}
