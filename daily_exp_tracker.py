# -*- coding: utf-8 -*-
"""
Daily EXP Tracker — enforces a hard daily EXP cap (default 50,000).
Persists to daily_exp.json, auto-resets at midnight Bangladesh time (UTC+6).
"""
import json
import os
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

BD_TZ = timezone(timedelta(hours=6))
DAILY_EXP_FILE = "daily_exp.json"
DAILY_EXP_CAP = int(os.environ.get("DAILY_EXP_CAP", "50000"))

_lock = asyncio.Lock()


def _today_str() -> str:
    return datetime.now(BD_TZ).strftime("%Y-%m-%d")


def seconds_until_reset() -> float:
    now = datetime.now(BD_TZ)
    tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(60.0, (tomorrow - now).total_seconds())


def _load() -> Dict[str, Any]:
    if not os.path.exists(DAILY_EXP_FILE):
        return {}
    try:
        with open(DAILY_EXP_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save(data: Dict[str, Any]):
    try:
        tmp = DAILY_EXP_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, DAILY_EXP_FILE)
    except Exception:
        pass


def _entry_for(data, key, today):
    entry = data.get(key)
    if not isinstance(entry, dict) or entry.get("date") != today:
        entry = {"date": today, "exp_gained_today": 0}
    return entry


async def get_today_exp(account_id: str) -> int:
    async with _lock:
        data = _load()
        entry = _entry_for(data, str(account_id), _today_str())
        return int(entry.get("exp_gained_today", 0))


async def add_exp(account_id: str, exp_gain: int) -> int:
    if exp_gain <= 0:
        return await get_today_exp(account_id)
    async with _lock:
        data = _load()
        key = str(account_id)
        today = _today_str()
        entry = _entry_for(data, key, today)
        entry["exp_gained_today"] = int(entry.get("exp_gained_today", 0)) + int(exp_gain)
        data[key] = entry
        _save(data)
        return entry["exp_gained_today"]


async def is_cap_reached(account_id: str) -> bool:
    return (await get_today_exp(account_id)) >= DAILY_EXP_CAP


async def get_status(account_id: str) -> Dict[str, Any]:
    gained = await get_today_exp(account_id)
    return {
        "date": _today_str(),
        "exp_gained_today": gained,
        "cap": DAILY_EXP_CAP,
        "remaining": max(0, DAILY_EXP_CAP - gained),
        "reached": gained >= DAILY_EXP_CAP,
    }


def remove_account(account_id: str):
    data = _load()
    if str(account_id) in data:
        del data[str(account_id)]
        _save(data)


def clear_all():
    try:
        with open(DAILY_EXP_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, indent=2)
    except Exception:
        pass