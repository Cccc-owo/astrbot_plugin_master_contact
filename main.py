"""Master Contact Plugin — 用户与 Master 之间的消息中转插件。

转发路径: 回复转发(on_reply_to_bot) / 转发模式(on_send_mode_message) / 私聊直发(on_private_chat_fallback)
Handler 优先级: command > ReplyToBotFilter > ALL (send_mode 与 fallback 通过 _send_collectors 互斥)

_sessions[sid] = {
    user_umo, user_name, user_id, is_private,
    last_activity, paused, unclaimed_count,
    master_umo?, master_sender_id?  # 接入后设置
}
_user_sessions[user_umo] = sid  # 反向索引
_send_collectors[umo] = {
    sid, is_master,
    started_at,  # 最后成功转发时间（空闲超时用）
    count,       # 已转发条数（统计用）
}
"""

import contextlib
import json
import re
import secrets
import sqlite3
import time

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.event.filter import EventMessageType
from astrbot.api.star import Context, Star, register
from astrbot.core.message.components import At, Image, Plain, Reply
from astrbot.core.message.message_event_result import MessageChain
from astrbot.core.star.filter.custom_filter import CustomFilter
from astrbot.core.star.star_tools import StarTools

SESSION_TAG_RE = re.compile(r"\[联系#(\w+)\]")
_GROUP_FORWARD_TYPES = (Plain, Image)  # 群聊仅转发这些类型（私聊不限制）

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    data TEXT NOT NULL
)
"""


class ReplyToBotFilter(CustomFilter):
    """仅当消息是回复 bot 消息时通过。"""

    def filter(self, event: AstrMessageEvent, cfg) -> bool:
        for msg in event.get_messages():
            if isinstance(msg, Reply) and str(msg.sender_id) == str(event.get_self_id()):
                return True
        return False


@register("astrbot_plugin_master_contact", "Cccc_", "简易的联系 Master 插件", "0.1.0")
class MasterContactPlugin(Star):
    # ========== 初始化 / 生命周期 ==========

    def __init__(self, context: Context, config: dict | None = None):
        super().__init__(context, config)
        self.context: Context = context
        self.config = config or {}
        self._sessions: dict[str, dict] = {}
        self._user_sessions: dict[str, str] = {}
        self._send_collectors: dict[str, dict] = {}
        self._db: sqlite3.Connection | None = None

    async def initialize(self):
        db_path = StarTools.get_data_dir() / "sessions.db"
        self._db = sqlite3.connect(str(db_path))
        self._db.execute(_CREATE_TABLE_SQL)
        self._db.commit()
        self._load_sessions()

    async def terminate(self):
        if self._db:
            self._db.close()
            self._db = None

    # ========== DB ==========

    def _load_sessions(self):
        self._sessions = {}
        if not self._db:
            return
        for row in self._db.execute("SELECT sid, data FROM sessions"):
            self._sessions[row[0]] = json.loads(row[1])
        self._rebuild_index()

    def _save_session(self, sid: str):
        if not self._db:
            return
        data = json.dumps(self._sessions[sid], ensure_ascii=False)
        self._db.execute("INSERT OR REPLACE INTO sessions (sid, data) VALUES (?, ?)", (sid, data))
        self._db.commit()

    def _delete_session(self, sid: str):
        if not self._db:
            return
        self._db.execute("DELETE FROM sessions WHERE sid = ?", (sid,))
        self._db.commit()

    # ========== 会话管理 ==========

    def _rebuild_index(self):
        self._user_sessions = {info["user_umo"]: sid for sid, info in self._sessions.items()}

    def _remove_session(self, sid: str) -> dict | None:
        """移除会话并清理索引和 DB。"""
        session = self._sessions.pop(sid, None)
        if session:
            self._user_sessions.pop(session["user_umo"], None)
            self._delete_session(sid)
        return session

    def _generate_session_id(self) -> str:
        for _ in range(100):
            sid = secrets.token_hex(2)
            if sid not in self._sessions:
                return sid
        raise RuntimeError("无法生成唯一会话 ID")

    def _clean_expired_sessions(self) -> list[str]:
        timeout = self.config.get("session_timeout", 1440)
        if timeout <= 0:
            return []
        now = time.time()
        expired = []
        for sid, info in list(self._sessions.items()):
            if info.get("paused"):
                continue
            if now - info["last_activity"] > timeout * 60:
                expired.append(sid)
        for sid in expired:
            self._remove_session(sid)
        self._clean_expired_collectors()
        return expired

    def _clean_collectors_for_session(self, sid: str):
        for umo in [u for u, c in self._send_collectors.items() if c["sid"] == sid]:
            del self._send_collectors[umo]

    def _clean_expired_collectors(self) -> list[str]:
        expired = [umo for umo, c in self._send_collectors.items() if c["sid"] not in self._sessions]
        for umo in expired:
            del self._send_collectors[umo]
        return expired

    # ========== 配置 / 身份 ==========

    def _get_master_sessions(self) -> list[str]:
        val = self.config.get("master_sessions", [])
        if isinstance(val, str):
            return [v.strip() for v in val.split(",") if v.strip()]
        if isinstance(val, list):
            return [str(v).strip() for v in val if str(v).strip()]
        return []

    def _is_master(self, event: AstrMessageEvent) -> bool:
        return event.unified_msg_origin in self._get_master_sessions()

    def _get_forward_timeout(self) -> int:
        return max(0, int(self.config.get("forward_timeout", 300)))

    # ========== 消息构建 ==========

    def _tag(self, sid: str) -> str:
        return f"[联系#{sid}]"

    def _user_msg(self, sid: str, hint: str) -> str:
        """tag + 换行 + 提示文本。"""
        return f"{self._tag(sid)}\n{hint}"

    def _prepend_text(self, prefix: str, components: list) -> list:
        """合并相邻 Plain 以避免换行符丢失。"""
        if components and isinstance(components[0], Plain):
            return [Plain(prefix + components[0].text)] + components[1:]
        return [Plain(prefix)] + components

    def _append_text(self, components: list, suffix: str) -> list:
        """合并相邻 Plain 以避免换行符丢失。"""
        if components and isinstance(components[-1], Plain):
            return components[:-1] + [Plain(components[-1].text + suffix)]
        return components + [Plain(suffix)]

    def _user_chain(self, sid: str, hint: str, components: list, *, from_master: bool = False) -> MessageChain:
        """构建用户侧消息链：tag + 内容 + 分隔线 + 提示。"""
        label = f"{self._tag(sid)} Master\n" if from_master else f"{self._tag(sid)}\n"
        parts = self._prepend_text(label, components)
        parts = self._append_text(parts, "\n------\n" + hint)
        chain = MessageChain()
        chain.chain.extend(parts)
        return chain

    def _build_master_chain(self, event: AstrMessageEvent, sid: str, components: list) -> MessageChain:
        """构建 Master 侧消息链：header + 内容 + 分隔线 + 回复提示。"""
        header = self._build_header(event, sid)
        parts = self._prepend_text(header + "\n", components)
        parts = self._append_text(parts, "\n------\n回复本条消息以回复用户")
        chain = MessageChain()
        chain.chain.extend(parts)
        return chain

    def _build_header(self, event: AstrMessageEvent, sid: str) -> str:
        user_name = event.get_sender_name()
        user_id = event.get_sender_id()
        umo = event.unified_msg_origin
        umo_parts = umo.split(":")
        platform = umo_parts[0] if umo_parts else ""

        parts = [f"[联系#{sid}]", "来自"]

        master_sessions = self._get_master_sessions()
        master_platforms = {s.split(":")[0] for s in master_sessions if s}
        if platform and platform not in master_platforms:
            parts.append(f"[{platform}]")

        if not event.is_private_chat():
            group_id = umo_parts[2] if len(umo_parts) > 2 else "?"
            parts.append(f"群聊({group_id})")
        else:
            parts.append("私聊")

        parts.append(f"{user_name}({user_id})")
        return " ".join(parts)

    # ========== 消息提取 / 解析 ==========

    def _is_wake_command(self, event: AstrMessageEvent) -> bool:
        raw_text = ""
        for _m in event.get_messages():
            if isinstance(_m, Plain):
                raw_text += _m.text
        raw_text = raw_text.strip()
        for prefix in self.context.get_config().get("wake_prefix", []):
            if prefix and raw_text.startswith(prefix):
                return True
        return False

    def _extract_forward_components(self, event: AstrMessageEvent) -> list:
        """过滤 Reply/At，群聊仅保留 Plain/Image，全空返回 []。"""
        is_group = not event.is_private_chat()
        components = []
        for msg in event.get_messages():
            if isinstance(msg, (Reply, At)):
                continue
            if is_group and not isinstance(msg, _GROUP_FORWARD_TYPES):
                continue
            components.append(msg)
        if all(isinstance(c, Plain) and not c.text.strip() for c in components):
            return []
        return components

    def _extract_sid_from_reply(self, reply_comp: Reply) -> str | None:
        """从 Reply 中提取会话 ID，优先 message_str，fallback chain。"""
        text = reply_comp.message_str or ""
        match = SESSION_TAG_RE.search(text)
        if match:
            return match.group(1)
        if reply_comp.chain:
            for comp in reply_comp.chain:
                if isinstance(comp, Plain):
                    match = SESSION_TAG_RE.search(comp.text)
                    if match:
                        return match.group(1)
        return None

    # ========== 发送 ==========

    async def _send_to_master(self, chain: MessageChain, target_umo: str = "") -> bool:
        """指定 target_umo 时单发，否则广播给所有主人。"""
        if target_umo:
            try:
                return bool(await self.context.send_message(target_umo, chain))
            except Exception as e:
                logger.error(f"发送给主人 ({target_umo}) 失败: {e}")
                return False
        targets = self._get_master_sessions()
        if not targets:
            return False
        success = False
        for umo in targets:
            try:
                result = await self.context.send_message(umo, chain)
                if result:
                    success = True
            except Exception as e:
                logger.error(f"发送给主人 ({umo}) 失败: {e}")
        return success

    async def _safe_send(self, umo: str, chain: MessageChain) -> None:
        """发送消息，静默忽略异常。"""
        with contextlib.suppress(Exception):
            await self.context.send_message(umo, chain)

    async def _forward_user_to_master(self, event: AstrMessageEvent, sid: str) -> str:
        """转发用户消息给 Master，空消息返回 ""。"""
        session = self._sessions[sid]
        unclaimed = not session.get("master_umo")
        limit = self.config.get("unclaimed_limit", 3)

        # 空消息不消耗限流配额、不更新活跃时间
        components = self._extract_forward_components(event)
        if not components:
            return ""

        # 未接入时限流
        if unclaimed and limit > 0:
            count = session.get("unclaimed_count", 0)
            if count >= limit:
                return self._user_msg(sid, f"消息未发送。已达上限（{limit} 条），请等待 Master 接入后再发送。")

        session["last_activity"] = time.time()
        if unclaimed:
            session["unclaimed_count"] = session.get("unclaimed_count", 0) + 1
        self._save_session(sid)

        chain = self._build_master_chain(event, sid, components)

        sent = await self._send_to_master(chain, session.get("master_umo", ""))
        if not sent:
            return self._user_msg(sid, "转发失败，请稍后重试。")
        if unclaimed:
            count = session.get("unclaimed_count", 0)
            if limit > 0 and count == 1:
                return self._user_msg(sid, f"已转发给 Master，等待回复。Master 接入前最多可发送 {limit} 条消息。")
            if limit > 0 and count >= limit:
                return self._user_msg(sid, f"已转发（最后一条）。已达上限（{limit} 条），请等待 Master 接入后再发送。")
        return self._user_msg(sid, "已转发给 Master。")

    async def _end_forward_mode(self, collector: dict) -> None:
        """发送转发结束通知给对方。"""
        sid = collector["sid"]
        session = self._sessions.get(sid)
        if not session:
            return
        if collector["is_master"]:
            suffix = MessageChain().message(self._tag(sid) + " Master\n已结束转发消息。")
            await self._safe_send(session["user_umo"], suffix)
        else:
            master_umo = session.get("master_umo", "")
            suffix = MessageChain().message(self._tag(sid) + "\n已结束转发消息。\n------\n回复本条消息以回复用户")
            await self._send_to_master(suffix, master_umo)

    # ========== 子命令 ==========

    @filter.command_group("contact", alias={"联系主人"})
    def contact_group(self):
        """联系 Master"""

    @contact_group.command("start")
    async def handle_start(self, event: AstrMessageEvent):
        """发起联系会话"""
        if self._is_master(event):
            yield event.plain_result("该命令仅限用户使用。").stop_event()
            return

        if not self._get_master_sessions():
            yield event.plain_result("未配置 Master，无法使用此功能。请联系管理员配置。").stop_event()
            return

        umo = event.unified_msg_origin
        self._clean_expired_sessions()

        if umo in self._user_sessions:
            sid = self._user_sessions[umo]
            if sid in self._sessions:
                hint = (
                    "你已有一个活跃的联系会话，直接发送消息即可继续。"
                    if event.is_private_chat()
                    else "你已有一个活跃的联系会话，回复本条消息即可继续。"
                )
                yield event.plain_result(self._user_msg(sid, hint)).stop_event()
                return

        sid = self._generate_session_id()
        self._sessions[sid] = {
            "user_umo": umo,
            "user_name": event.get_sender_name(),
            "user_id": str(event.get_sender_id()),
            "is_private": event.is_private_chat(),
            "last_activity": time.time(),
            "paused": False,
            "unclaimed_count": 0,
        }
        self._user_sessions[umo] = sid
        self._save_session(sid)

        hint = (
            "已开始联系 Master，直接发送消息即可。发送 /contact end 结束联系。"
            if event.is_private_chat()
            else "已开始联系 Master，回复本条消息即可发送。发送 /contact end 结束联系。"
        )
        yield event.plain_result(self._user_msg(sid, hint)).stop_event()

    @contact_group.command("end")
    async def handle_end(self, event: AstrMessageEvent, sid: str = ""):
        """结束联系会话"""
        umo = event.unified_msg_origin
        is_master = self._is_master(event)

        if umo in self._user_sessions:
            user_sid = self._user_sessions[umo]
            session = self._remove_session(user_sid)
            if session:
                self._clean_collectors_for_session(user_sid)
                master_umo = session.get("master_umo", "")
                if master_umo:
                    await self._safe_send(
                        master_umo,
                        MessageChain().message(f"{self._tag(user_sid)}\n用户已结束联系会话。"),
                    )
            yield event.plain_result(self._user_msg(user_sid, "联系会话已结束。")).stop_event()
            return

        if is_master:
            if sid and sid in self._sessions:
                session = self._remove_session(sid)
                assert session is not None
                self._clean_collectors_for_session(sid)
                await self._safe_send(
                    session["user_umo"],
                    MessageChain().message(self._user_msg(sid, "Master 已结束联系会话。")),
                )
                yield event.plain_result(f"{self._tag(sid)}\n已结束与 {session['user_name']} 的联系会话。").stop_event()
                return
            if sid:
                yield event.plain_result(f"会话 #{sid} 不存在。").stop_event()
                return
            yield event.plain_result("用法: /contact end <ID>").stop_event()
            return

        yield event.plain_result("你当前没有活跃的联系会话。").stop_event()

    @contact_group.command("forward")
    async def handle_forward(self, event: AstrMessageEvent):
        """进入/结束转发模式"""
        umo = event.unified_msg_origin
        is_master = self._is_master(event)

        # 提取 "forward" 后的参数（done 或会话 ID）
        parts = event.message_str.strip().split()
        arg = parts[2] if len(parts) > 2 else ""

        # /contact forward done
        if arg == "done":
            collector = self._send_collectors.pop(umo, None)
            if not collector:
                yield event.plain_result("你当前不在转发模式中。").stop_event()
                return
            sid = collector["sid"]
            await self._end_forward_mode(collector)
            yield event.plain_result(self._user_msg(sid, "已结束转发模式。")).stop_event()
            return

        # /contact forward [ID]
        if not is_master and event.is_private_chat():
            yield event.plain_result("私聊中无需使用转发模式，直接发送消息即可转发。").stop_event()
            return

        if umo in self._send_collectors:
            sid = self._send_collectors[umo]["sid"]
            yield event.plain_result(
                self._user_msg(sid, "你已在转发模式中。发送 /contact forward done 结束。")
            ).stop_event()
            return

        if is_master:
            if arg:
                if arg not in self._sessions:
                    yield event.plain_result(f"会话 #{arg} 不存在。").stop_event()
                    return
                sid = arg
            elif len(self._sessions) == 1:
                sid = next(iter(self._sessions))
            elif not self._sessions:
                yield event.plain_result("当前没有活跃的联系会话。").stop_event()
                return
            else:
                yield event.plain_result("当前有多个活跃会话，请指定会话 ID: /contact forward <ID>").stop_event()
                return
        else:
            sid = self._user_sessions.get(umo)
            if not sid or sid not in self._sessions:
                yield event.plain_result("你当前没有活跃的联系会话，请先发送 /contact start 发起联系。").stop_event()
                return

        session = self._sessions[sid]
        self._send_collectors[umo] = {
            "sid": sid,
            "is_master": is_master,
            "started_at": time.time(),
            "count": 0,
        }

        if is_master and not session.get("master_umo"):
            session["master_umo"] = event.unified_msg_origin
            session["unclaimed_count"] = 0
            self._save_session(sid)

        if is_master:
            prefix = MessageChain().message(f"{self._tag(sid)} Master\n开始转发消息：")
            await self._safe_send(session["user_umo"], prefix)
        else:
            header = self._build_header(event, sid)
            prefix = MessageChain().message(f"{header}\n开始转发消息：")
            await self._send_to_master(prefix, session.get("master_umo", ""))

        target = "用户" if is_master else "Master"
        yield event.plain_result(
            self._user_msg(sid, f"已进入转发模式，发送的消息将直接转发给 {target}。\n发送 /contact forward done 结束。")
        ).stop_event()

    @contact_group.command("list")
    async def handle_list(self, event: AstrMessageEvent):
        """查看活跃会话（仅 Master）"""
        if not self._is_master(event):
            yield event.plain_result("该命令仅限 Master 使用。").stop_event()
            return

        self._clean_expired_sessions()
        if not self._sessions:
            yield event.plain_result("当前没有活跃的联系会话。").stop_event()
            return
        lines = ["当前活跃的联系会话:"]
        for s_id, info in self._sessions.items():
            flags = ""
            if info.get("paused"):
                flags += " [不超时]"
            if info.get("master_umo"):
                flags += " [已接入]"
            else:
                flags += " [待接入]"
            lines.append(f"  #{s_id} - {info['user_name']}({info['user_id']}){flags}")
        lines.append("\n/contact end <ID> 结束会话")
        lines.append("/contact pause <ID> 暂停自动超时")
        lines.append("/contact resume <ID> 恢复自动超时")
        yield event.plain_result("\n".join(lines)).stop_event()

    @contact_group.command("pause")
    async def handle_pause(self, event: AstrMessageEvent, sid: str = ""):
        """暂停会话超时（仅 Master）"""
        if not self._is_master(event):
            yield event.plain_result("该命令仅限 Master 使用。").stop_event()
            return
        if not sid:
            yield event.plain_result("用法: /contact pause <ID>").stop_event()
            return
        session = self._sessions.get(sid)
        if not session:
            yield event.plain_result(f"会话 #{sid} 不存在。").stop_event()
            return
        session["paused"] = True
        self._save_session(sid)
        yield event.plain_result(f"{self._tag(sid)}\n已暂停自动超时。").stop_event()

    @contact_group.command("resume")
    async def handle_resume(self, event: AstrMessageEvent, sid: str = ""):
        """恢复会话超时（仅 Master）"""
        if not self._is_master(event):
            yield event.plain_result("该命令仅限 Master 使用。").stop_event()
            return
        if not sid:
            yield event.plain_result("用法: /contact resume <ID>").stop_event()
            return
        session = self._sessions.get(sid)
        if not session:
            yield event.plain_result(f"会话 #{sid} 不存在。").stop_event()
            return
        session["paused"] = False
        session["last_activity"] = time.time()
        self._save_session(sid)
        yield event.plain_result(f"{self._tag(sid)}\n已恢复自动超时。").stop_event()

    # ========== 事件 Handler ==========

    @filter.custom_filter(ReplyToBotFilter)
    async def on_reply_to_bot(self, event: AstrMessageEvent):
        """回复 bot 消息时触发转发（优先级高于 ALL）。"""
        if self._is_wake_command(event):
            return

        self._clean_expired_sessions()

        reply_comp = None
        for m in event.get_messages():
            if isinstance(m, Reply):
                reply_comp = m
                break
        if not reply_comp:
            return

        if self._is_master(event):
            # Master → user
            sid = self._extract_sid_from_reply(reply_comp)
            if not sid:
                return

            session = self._sessions.get(sid)
            if not session:
                yield event.plain_result("该联系会话已过期或不存在。").stop_event()
                return

            # 空消息不触发 claim
            components = self._extract_forward_components(event)
            if not components:
                return

            # claim_by_sender: true 按 sender_id 判断归属，否则按 UMO
            if self.config.get("claim_by_sender", False):
                claim_key = "master_sender_id"
                claim_val = str(event.get_sender_id())
            else:
                claim_key = "master_umo"
                claim_val = event.unified_msg_origin
            claimed_by = session.get(claim_key)
            if claimed_by and claimed_by != claim_val:
                yield event.plain_result(f"{self._tag(sid)}\n该会话已由其他 Master 接入。").stop_event()
                return
            if not claimed_by:
                session[claim_key] = claim_val
                session["unclaimed_count"] = 0
            if not session.get("master_umo"):
                session["master_umo"] = event.unified_msg_origin
            session["last_activity"] = time.time()
            self._save_session(sid)

            hint = "直接发送消息即可回复" if session.get("is_private") else "回复本条消息以回复 Master"
            chain = self._user_chain(sid, hint, components, from_master=True)

            try:
                sent = await self.context.send_message(session["user_umo"], chain)
            except Exception:
                logger.error(f"转发消息给用户失败 (sid={sid})")
                sent = False
            if sent:
                yield event.plain_result(f"{self._tag(sid)}\n已转发给用户。").stop_event()
            else:
                yield event.plain_result(f"{self._tag(sid)}\n转发失败，请检查配置。").stop_event()

        else:
            # User → master
            umo = event.unified_msg_origin
            sid = self._user_sessions.get(umo)

            # 私聊有活跃会话时由 on_private_chat_fallback 处理
            if event.is_private_chat() and sid and sid in self._sessions:
                return

            if not sid or sid not in self._sessions:
                if self._extract_sid_from_reply(reply_comp):
                    yield event.plain_result(
                        "联系会话已过期或已结束，如有需要请重新发送 /contact start 发起联系。"
                    ).stop_event()
                return

            hint = await self._forward_user_to_master(event, sid)
            if hint:
                yield event.plain_result(hint).stop_event()

    @filter.event_message_type(EventMessageType.ALL)
    async def on_send_mode_message(self, event: AstrMessageEvent):
        """转发模式拦截（与 fallback 通过 _send_collectors 互斥）。"""
        umo = event.unified_msg_origin
        collector = self._send_collectors.get(umo)
        if not collector:
            return

        # 空闲超时: started_at 在每次成功转发后重置
        forward_timeout = self._get_forward_timeout()
        if forward_timeout > 0 and time.time() - collector["started_at"] > forward_timeout:
            sid = collector["sid"]
            count = collector["count"]
            await self._end_forward_mode(collector)
            del self._send_collectors[umo]
            yield event.plain_result(self._user_msg(sid, f"转发模式已超时，共转发 {count} 条消息。")).stop_event()
            return

        if self._is_wake_command(event):
            return

        components = self._extract_forward_components(event)
        if not components:
            return

        sid = collector["sid"]
        session = self._sessions.get(sid)
        if not session:
            del self._send_collectors[umo]
            yield event.plain_result(self._user_msg(sid, "联系会话已过期，转发模式已取消。")).stop_event()
            return

        session["last_activity"] = time.time()
        self._save_session(sid)

        content_chain = MessageChain()
        content_chain.chain.extend(components)

        if collector["is_master"]:
            try:
                sent = await self.context.send_message(session["user_umo"], content_chain)
            except Exception:
                logger.error(f"转发消息给用户失败 (sid={sid})")
                sent = False
        else:
            sent = await self._send_to_master(content_chain, session.get("master_umo", ""))

        if sent:
            collector["count"] += 1
            collector["started_at"] = time.time()

        if not sent:
            yield event.plain_result("转发失败。").stop_event()
        else:
            yield event.plain_result("已转发。").stop_event()

    @filter.event_message_type(EventMessageType.ALL)
    async def on_private_chat_fallback(self, event: AstrMessageEvent):
        """私聊用户有活跃会话时自动转发。"""
        if not event.is_private_chat():
            return
        if self._is_master(event):
            return
        if self._is_wake_command(event):
            return
        if event.unified_msg_origin in self._send_collectors:
            return
        components = self._extract_forward_components(event)
        if not components:
            return

        umo = event.unified_msg_origin
        sid = self._user_sessions.get(umo)
        if not sid or sid not in self._sessions:
            return

        hint = await self._forward_user_to_master(event, sid)
        if hint:
            yield event.plain_result(hint).stop_event()
