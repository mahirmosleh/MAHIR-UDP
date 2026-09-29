# -*- coding: utf-8 -*-
"""
FreeFire Level Up Bot - ARAFAT CODEX Dashboard
Embedded Async Web Server (aiohttp)
"""
import asyncio
import json
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from aiohttp import web

try:
    import daily_exp_tracker
except Exception:
    daily_exp_tracker = None

# ==================== ACCOUNT CAP ====================
MAX_ACCOUNTS = int(os.environ.get("MAX_ACCOUNTS", "50"))

# ==================== BANGLADESH TIMEZONE (UTC+6) ====================
BD_TZ = timezone(timedelta(hours=6))


def bd_now_str() -> str:
    return datetime.now(BD_TZ).strftime("%H:%M:%S")


class BotState:
    def __init__(self):
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.logs: List[Dict[str, Any]] = []
        self.max_logs = 200
        self.total_matches = 0
        self.total_gained_exp = 0
        self.start_time = time.time()
        self.account_workers: Dict[str, asyncio.Task] = {}
        self.refresh_callbacks: Dict[str, Any] = {}
        self.account_credentials: Dict[str, Dict[str, Any]] = {}
        self._target_triggered: set = set()

    def log(self, message: str, level: str = "info", uid: Optional[str] = None):
        entry = {
            "time": bd_now_str(),
            "level": level,
            "message": message,
            "uid": uid,
        }
        self.logs.append(entry)
        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

    def register_account(self, uid, nickname, region, level, exp, likes=0,
                         target_level=0, target_matches=0):
        uid_str = str(uid)

        if uid_str not in self.accounts and len(self.accounts) >= MAX_ACCOUNTS:
            self.log(
                f"REJECTED {uid_str} — cap reached ({len(self.accounts)}/{MAX_ACCOUNTS})",
                "warning", uid_str
            )
            return False

        if uid_str not in self.accounts:
            self.accounts[uid_str] = {
                "uid": uid_str,
                "nickname": nickname or f"Player_{uid_str[:6]}",
                "region": region or "BD",
                "level": level or 1,
                "initial_exp": exp,
                "current_exp": exp,
                "gained_exp": 0,
                "likes": likes or 0,
                "status": "ONLINE",
                "matches_played": 0,
                "active_matches": 0,
                "last_match_time": None,
                "last_updated": bd_now_str(),
                "target_level": int(target_level) if target_level else 0,
                "target_matches": int(target_matches) if target_matches else 0,
                "stop_reason": "",
            }
        else:
            acc = self.accounts[uid_str]
            if nickname:
                acc["nickname"] = nickname
            if region:
                acc["region"] = region
            if level:
                acc["level"] = level
            if target_level:
                acc["target_level"] = int(target_level)
            if target_matches:
                acc["target_matches"] = int(target_matches)
            acc["current_exp"] = exp
            acc["gained_exp"] = max(0, exp - acc["initial_exp"])
            acc["likes"] = likes
            acc["status"] = "ONLINE"
            acc["last_updated"] = bd_now_str()

        self.recalc_totals()
        self._check_target(uid_str)
        return True

    def update_exp(self, uid: str, current_exp: int, level: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            acc = self.accounts[uid_str]
            old_exp = acc["current_exp"]
            acc["current_exp"] = current_exp
            if level is not None and level > 0:
                acc["level"] = level
            acc["gained_exp"] = max(0, current_exp - acc["initial_exp"])
            acc["last_updated"] = bd_now_str()
            diff = current_exp - old_exp
            if diff > 0:
                self.log(
                    f"Account {acc['nickname']} ({uid_str}) gained +{diff} EXP! "
                    f"Total: +{acc['gained_exp']}",
                    "success", uid_str
                )
            self.recalc_totals()
            self._check_target(uid_str)

    def _check_target(self, uid_str: str):
        """Log only — the functional loop does the actual stop+finish+pause."""
        acc = self.accounts.get(uid_str)
        if not acc:
            return

        target_lvl = int(acc.get("target_level", 0) or 0)
        target_mt = int(acc.get("target_matches", 0) or 0)

        if target_lvl > 0 and int(acc.get("level", 1)) >= target_lvl:
            key = f"lv_{uid_str}"
            if key not in self._target_triggered:
                self._target_triggered.add(key)
                self.log(
                    f"🎯 {acc.get('nickname')} ({uid_str}) hit Target Level {target_lvl} "
                    f"— finishing running matches, then pausing",
                    "success", uid_str
                )

        if target_mt > 0 and int(acc.get("matches_played", 0)) >= target_mt:
            key = f"mt_{uid_str}"
            if key not in self._target_triggered:
                self._target_triggered.add(key)
                self.log(
                    f"🎯 {acc.get('nickname')} ({uid_str}) hit Target {target_mt} matches "
                    f"— finishing running matches, then pausing",
                    "success", uid_str
                )

    def update_status(self, uid: str, status: str, active_matches: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            self.accounts[uid_str]["status"] = status
            if active_matches is not None:
                self.accounts[uid_str]["active_matches"] = active_matches
            self.accounts[uid_str]["last_updated"] = bd_now_str()

    def increment_match(self, uid: str):
        uid_str = str(uid)
        self.total_matches += 1
        if uid_str in self.accounts:
            self.accounts[uid_str]["matches_played"] += 1
            self.accounts[uid_str]["last_match_time"] = bd_now_str()
            self.accounts[uid_str]["last_updated"] = bd_now_str()
            self.log(
                f"Account {self.accounts[uid_str]['nickname']} finished Match "
                f"#{self.accounts[uid_str]['matches_played']}",
                "info", uid_str
            )
            self._check_target(uid_str)

    def recalc_totals(self):
        self.total_gained_exp = sum(acc.get("gained_exp", 0) for acc in self.accounts.values())


bot_state = BotState()

TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "templates", "index.html"
)


async def handle_index(request: web.Request) -> web.Response:
    if os.path.exists(TEMPLATE_PATH):
        with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = "<h1>templates/index.html not found!</h1>"
    return web.Response(text=content, content_type="text/html", charset="utf-8")


async def handle_get_stats(request: web.Request) -> web.Response:
    accounts_data = list(bot_state.accounts.values())

    if daily_exp_tracker is not None:
        for a in accounts_data:
            try:
                st = await daily_exp_tracker.get_status(str(a.get("uid", "")))
                a["daily_exp_today"] = st["exp_gained_today"]
                a["daily_exp_cap"] = st["cap"]
                a["daily_exp_remaining"] = st["remaining"]
                a["daily_exp_reached"] = st["reached"]
            except Exception:
                a["daily_exp_today"] = 0
                a["daily_exp_cap"] = daily_exp_tracker.DAILY_EXP_CAP
                a["daily_exp_remaining"] = daily_exp_tracker.DAILY_EXP_CAP
                a["daily_exp_reached"] = False

    accounts_data.sort(key=lambda x: x.get("gained_exp", 0), reverse=True)
    return web.json_response({
        "total_accounts": len(bot_state.accounts),
        "max_accounts": MAX_ACCOUNTS,
        "total_matches": bot_state.total_matches,
        "total_gained_exp": bot_state.total_gained_exp,
        "daily_exp_cap": (daily_exp_tracker.DAILY_EXP_CAP if daily_exp_tracker else 50000),
        "accounts": accounts_data,
        "logs": bot_state.logs[-60:],
    })


async def handle_add_account(request: web.Request) -> web.Response:
    try:
        data = await request.json()

        if len(bot_state.accounts) >= MAX_ACCOUNTS:
            return web.json_response({
                "status": "error",
                "error": f"Maximum {MAX_ACCOUNTS} accounts allowed"
            })

        accounts_file = "accounts.json"
        existing = []
        if os.path.exists(accounts_file):
            try:
                with open(accounts_file, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        target_level = int(data.get("target_level", 0) or 0)
        target_matches = int(data.get("target_matches", 0) or 0)

        if "uid" in data and "password" in data:
            uid = str(data["uid"]).strip()
            pwd = str(data["password"]).strip()
            if not uid or not pwd:
                return web.json_response({"status": "error", "error": "UID & Password required"})
            existing = [acc for acc in existing if str(acc.get("uid")) != uid]
            existing.append({
                "uid": uid, "password": pwd,
                "target_level": target_level,
                "target_matches": target_matches,
            })
        elif "token" in data:
            token = str(data["token"]).strip()
            if not token:
                return web.json_response({"status": "error", "error": "Token required"})
            existing = [acc for acc in existing if acc.get("token") != token]
            existing.append({
                "token": token,
                "target_level": target_level,
                "target_matches": target_matches,
            })
        else:
            return web.json_response({"status": "error", "error": "Invalid payload"})

        with open(accounts_file, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

        bot_state.log(
            f"New account added (Target: Lv.{target_level or 'MAX'} / "
            f"{target_matches or '∞'} matches)",
            "success"
        )
        cb = bot_state.refresh_callbacks.get("on_account_added")
        result = None
        if cb:
            payload = dict(data)
            payload["target_level"] = target_level
            payload["target_matches"] = target_matches
            try:
                result = await cb(payload)
            except Exception as e:
                print(f"[ADD] Callback error: {e}")
        return web.json_response({"status": "ok", "result": result})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_upload_guest_file(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        accounts_list = data.get("accounts", [])
        target_level = int(data.get("target_level", 0) or 0)
        target_matches = int(data.get("target_matches", 0) or 0)

        if not isinstance(accounts_list, list):
            return web.json_response({"status": "error", "error": "Invalid format"})

        accounts_file = "accounts.json"
        existing = []
        if os.path.exists(accounts_file):
            try:
                with open(accounts_file, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        valid_items = []
        for item in accounts_list:
            if not isinstance(item, dict):
                continue
            uid = str(item.get("uid", "")).strip()
            pwd = str(item.get("password", "")).strip()
            if not uid or not pwd:
                continue
            existing = [a for a in existing if str(a.get("uid")) != uid]
            existing.append({
                "uid": uid, "password": pwd,
                "target_level": target_level,
                "target_matches": target_matches,
            })
            valid_items.append({"uid": uid, "password": pwd})

        with open(accounts_file, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

        cb = bot_state.refresh_callbacks.get("on_account_added")
        added_count = 0
        skipped_count = 0
        skipped_details = []

        if cb:
            for item in valid_items:
                if len(bot_state.accounts) >= MAX_ACCOUNTS:
                    skipped_count += 1
                    skipped_details.append(f"{item['uid']}: cap reached")
                    continue
                try:
                    result = await cb({
                        "uid": item["uid"],
                        "password": item["password"],
                        "target_level": target_level,
                        "target_matches": target_matches,
                    })
                    if result and result.get("added"):
                        added_count += 1
                    else:
                        skipped_count += 1
                        if result and result.get("reason"):
                            skipped_details.append(f"{item['uid']}: {result['reason']}")
                except Exception as e:
                    print(f"[UPLOAD] Callback error for {item['uid']}: {e}")
                    skipped_count += 1

        bot_state.log(
            f"File upload → {added_count} added, {skipped_count} skipped",
            "success"
        )
        return web.json_response({
            "status": "ok",
            "added": added_count,
            "skipped": skipped_count,
            "skipped_details": skipped_details,
        })
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_refresh_account(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        uid = str(data.get("uid")).strip()
        cb = bot_state.refresh_callbacks.get("on_refresh_account")
        if cb:
            asyncio.create_task(cb(uid))
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_restart_account(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        uid = str(data.get("uid")).strip()
        if not uid:
            return web.json_response({"status": "error", "error": "UID required"})
        cb = bot_state.refresh_callbacks.get("on_restart_account")
        if cb:
            asyncio.create_task(cb(uid))
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_delete_account(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        uid = str(data.get("uid", "")).strip()
        if not uid:
            return web.json_response({"status": "error", "error": "UID required"})
        cb = bot_state.refresh_callbacks.get("on_delete_account")
        if cb:
            asyncio.create_task(cb(uid))
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_toggle_pause(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        uid = str(data.get("uid", "")).strip()
        if not uid:
            return web.json_response({"status": "error", "error": "UID required"})
        cb = bot_state.refresh_callbacks.get("on_toggle_pause")
        if cb:
            res = await cb(uid)
            return web.json_response({"status": "ok", "result": res})
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_delete_all(request: web.Request) -> web.Response:
    try:
        cb = bot_state.refresh_callbacks.get("on_delete_all")
        if cb:
            asyncio.create_task(cb())
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def handle_restart_all(request: web.Request) -> web.Response:
    try:
        cb = bot_state.refresh_callbacks.get("on_restart_all")
        if cb:
            asyncio.create_task(cb())
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)})


async def start_web_dashboard(host: str = "0.0.0.0", port: int = 5000):
    app = web.Application()
    app.router.add_get("/", handle_index)
    app.router.add_get("/api/stats", handle_get_stats)
    app.router.add_post("/api/account/add", handle_add_account)
    app.router.add_post("/api/account/upload", handle_upload_guest_file)
    app.router.add_post("/api/account/refresh", handle_refresh_account)
    app.router.add_post("/api/account/restart", handle_restart_account)
    app.router.add_post("/api/account/delete", handle_delete_account)
    app.router.add_post("/api/account/toggle_pause", handle_toggle_pause)
    app.router.add_post("/api/account/delete_all", handle_delete_all)
    app.router.add_post("/api/account/restart_all", handle_restart_all)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"\033[92m[+] Dashboard running on http://localhost:{port}\033[0m")
    print(f"\033[92m[+] Max Accounts: {MAX_ACCOUNTS}\033[0m")