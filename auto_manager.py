# auto_manager.py
# ==================== ARAFAT CODEX — AUTO LEVEL QUEUE ====================
"""
Auto-level mode workflow:
  1. Put accounts in auto.json
  2. On startup, prompted for target level (e.g. 21)
  3. Bot loads first batch (up to MAX_ACCOUNTS) from queue
  4. When an account hits target level:
       - Saved to {target}lvl.json
       - Removed from auto.json
       - Removed from bot
       - Next pending account auto-loaded
"""
import asyncio
import json
import os
import time

from dashboard_server import bot_state, MAX_ACCOUNTS


CHECK_INTERVAL = 15.0
GRADUATE_COOLDOWN = 4.0


class AutoLevelManager:
    def __init__(self, target_level: int, auto_file="auto.json"):
        self.target_level = int(target_level)
        self.auto_file = auto_file
        self.locked_file = f"{self.target_level}lvl.json"
        self._task = None
        self._stop = asyncio.Event()
        self._loader_cb = None
        self._adding_lock = asyncio.Lock()

    # ---------- file I/O ----------
    def _read_json(self, path):
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, list) else []
        except Exception as e:
            print(f"[AUTO] read {path} failed: {e}")
            return []

    def _write_json(self, path, data):
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, path)
        except Exception as e:
            print(f"[AUTO] write {path} failed: {e}")

    def pending(self):
        return self._read_json(self.auto_file)

    def _remove_from_queue(self, account):
        q = self.pending()
        uid = str(account.get("uid", "")).strip()
        token = account.get("token")
        new_q = []
        for item in q:
            same_uid = uid and str(item.get("uid", "")).strip() == uid
            same_tok = token and item.get("token") == token
            if same_uid or same_tok:
                continue
            new_q.append(item)
        self._write_json(self.auto_file, new_q)

    def _save_completed(self, record):
        done = self._read_json(self.locked_file)
        done.append(record)
        self._write_json(self.locked_file, done)

    # ---------- graduation ----------
    def _find_graduated(self):
        target = self.target_level
        return [
            uid for uid, acc in list(bot_state.accounts.items())
            if int(acc.get("level", 0) or 0) >= target
        ]

    def _creds_for(self, uid):
        creds = bot_state.account_credentials.get(uid)
        if creds:
            return creds
        for _, c in bot_state.account_credentials.items():
            if str(c.get("auth_uid", "")) == str(uid):
                return c
            if str(c.get("account_id", "")) == str(uid):
                return c
        return {}

    async def _monitor(self):
        print(f"[AUTO] Monitor started — target Lv{self.target_level}")
        try:
            bot_state.log(
                f"[AUTO] Auto-level ACTIVE — target Lv{self.target_level}",
                "success",
            )
        except Exception:
            pass

        while not self._stop.is_set():
            try:
                for uid in self._find_graduated():
                    await self._graduate(uid)
            except Exception as e:
                print(f"[AUTO] tick error: {e}")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=CHECK_INTERVAL)
            except asyncio.TimeoutError:
                pass

    async def _graduate(self, uid):
        acc = bot_state.accounts.get(uid, {})
        creds = self._creds_for(uid)

        rec = {
            "uid": uid,
            "nickname": acc.get("nickname", ""),
            "region": acc.get("region", "BD"),
            "level": acc.get("level", 0),
            "exp": acc.get("current_exp", 0),
            "matches_played": acc.get("matches_played", 0),
            "graduated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if creds.get("auth_type") == "guest":
            rec["uid"] = creds.get("auth_uid", uid)
            rec["password"] = creds.get("auth_password", "")
        elif creds.get("auth_type") == "token":
            rec["token"] = creds.get("auth_token", "")

        self._save_completed(rec)

        try:
            bot_state.log(
                f"[AUTO] UID {uid} ({acc.get('nickname','?')}) → "
                f"Lv{self.target_level} saved to {self.locked_file}",
                "success",
            )
        except Exception:
            pass

        queue_ref = {
            "uid": creds.get("auth_uid", uid) if creds else uid,
            "token": creds.get("auth_token") if creds else None,
        }

        # Cancel worker + remove from state
        try:
            t = bot_state.account_workers.pop(uid, None)
            if t and not t.done():
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
        except Exception:
            pass

        bot_state.accounts.pop(uid, None)
        bot_state.account_credentials.pop(uid, None)

        self._remove_from_queue(queue_ref)
        await asyncio.sleep(GRADUATE_COOLDOWN)
        await self._load_next()

    async def _load_next(self):
        async with self._adding_lock:
            if not self._loader_cb:
                return
            if len(bot_state.accounts) >= MAX_ACCOUNTS:
                try:
                    bot_state.log(
                        f"[AUTO] Bot full ({len(bot_state.accounts)}/{MAX_ACCOUNTS})",
                        "warning",
                    )
                except Exception:
                    pass
                return
            q = self.pending()
            if not q:
                try:
                    bot_state.log(
                        "[AUTO] auto.json empty — nothing more to load",
                        "warning",
                    )
                except Exception:
                    pass
                return
            nxt = q[0]
            try:
                await self._loader_cb(nxt)
                try:
                    bot_state.log(
                        f"[AUTO] Loaded next: {nxt.get('uid') or 'token'}",
                        "info",
                    )
                except Exception:
                    pass
            except Exception as e:
                try:
                    bot_state.log(f"[AUTO] Failed to load next: {e}", "error")
                except Exception:
                    pass

    async def prime(self, loader_cb):
        self._loader_cb = loader_cb
        q = self.pending()
        try:
            bot_state.log(
                f"[AUTO] Priming — {len(q)} pending, target Lv{self.target_level}",
                "info",
            )
        except Exception:
            pass
        slots = max(0, MAX_ACCOUNTS - len(bot_state.accounts))
        for item in q[:slots]:
            try:
                await loader_cb(item)
            except Exception as e:
                print(f"[AUTO] prime load failed: {e}")

    def start(self):
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._monitor())

    def stop(self):
        self._stop.set()


def prompt_target_level() -> int:
    while True:
        try:
            raw = input("\n[AUTO] Enter target level (e.g. 21, or 0 to disable): ").strip()
            if not raw:
                continue
            lvl = int(raw)
            if lvl < 0:
                continue
            return lvl
        except (ValueError, EOFError):
            print("[AUTO] Invalid — enter a number.")


async def init_auto_manager_if_enabled(loader_cb):
    if not os.path.exists("auto.json"):
        return None
    try:
        with open("auto.json", "r", encoding="utf-8") as f:
            q = json.load(f)
        if not isinstance(q, list) or not q:
            return None
    except Exception:
        return None

    loop = asyncio.get_running_loop()
    print(f"\n{'='*60}")
    print(f"  AUTO-LEVEL MODE DETECTED — {len(q)} accounts in auto.json")
    print(f"{'='*60}")

    target = await loop.run_in_executor(None, prompt_target_level)
    if target <= 0:
        print("[AUTO] Auto mode disabled.")
        return None

    mgr = AutoLevelManager(target_level=target)
    await mgr.prime(loader_cb)
    mgr.start()
    return mgr