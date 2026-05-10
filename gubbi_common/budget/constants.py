"""Budget constants shared across Gubbi services."""

from __future__ import annotations

from typing import Final

PRE_CHARGE_CENTS: Final[int] = 50
PRE_CHARGE_LUA: Final[str] = """
local key = KEYS[1]
local estimated = tonumber(ARGV[1])
local used = tonumber(redis.call('HGET', key, 'used_cents') or '0')
local cap  = tonumber(redis.call('HGET', key, 'cap_cents') or '0')
if used == nil then used = 0 end
if cap == nil then cap = 0 end
if used + estimated > cap then return 0 end
redis.call('HINCRBY', key, 'used_cents', estimated)
local dirty_member = KEYS[2] .. ':' .. KEYS[3]
redis.call('SADD', 'budget:dirty', dirty_member)
redis.call('EXPIRE', key, 3600)
return 1
"""
