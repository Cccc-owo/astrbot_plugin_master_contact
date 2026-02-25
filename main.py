import contextlib
import json
import re
import secrets
import sqlite3
import time

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register
from astrbot.core.message.components import At, Image, Plain, Reply
from astrbot.core.message.message_event_result import MessageChain
from astrbot.core.star.filter.custom_filter import CustomFilter
from astrbot.core.star.star_tools import StarTools

SESSION_TAG_RE = re.compile(r"\[联系#(\w+)\]")

_GROUP_FORWARD_TYPES = (Plain, Image)

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


@register("astrbot_plugin_master_contact", "Cccc_", "简易的联系主人插件", "0.1.0")
class MasterContactPlugin(Star):
    def __init__(self, context: Context, config: dict | None = None):
        super().__init__(context, config)
        self.context: Context = context
        self.config = config or {}
        self._sessions: dict[str, dict] = {}
        self._user_sessions: dict[str, str] = {}
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

    # --- DB helpers ---

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

    # --- Internal helpers ---

    def _rebuild_index(self):
        self._user_sessions = {info["user_umo"]: sid for sid, info in self._sessions.items()}

    def _generate_session_id(self) -> str:
        for _ in range(100):
            sid = secrets.token_hex(2)
            if sid not in self._sessions:
                return sid
        raise RuntimeError("无法生成唯一会话 ID")

    def _get_master_session(self) -> str | None:
        val = self.config.get("master_session", "")
        return val if val else None

    def _get_master_admin_id(self) -> str | None:
        admins = self.context.get_config().get("admins_id", [])
        return str(admins[0]) if admins else None

    def _is_master(self, event: AstrMessageEvent) -> bool:
        master_session = self._get_master_session()
        if master_session:
            return event.unified_msg_origin == master_session
        admin_id = self._get_master_admin_id()
        if admin_id:
            return str(event.get_sender_id()) == admin_id
        return False

    async def _send_to_master(self, chain: MessageChain) -> bool:
        master_session = self._get_master_session()
        if master_session:
            return await self.context.send_message(master_session, chain)
        admin_id = self._get_master_admin_id()
        if admin_id:
            try:
                await StarTools.send_message_by_id("PrivateMessage", admin_id, chain)
                return True
            except Exception as e:
                logger.error(f"发送给主人失败: {e}")
                return False
        return False

    def _clean_expired_sessions(self) -> list[str]:
        timeout = self.config.get("session_timeout", 10)
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
            umo = self._sessions[sid]["user_umo"]
            del self._sessions[sid]
            self._user_sessions.pop(umo, None)
            self._delete_session(sid)
        return expired

    def _build_header(self, event: AstrMessageEvent, sid: str) -> str:
        user_name = event.get_sender_name()
        user_id = event.get_sender_id()
        umo = event.unified_msg_origin
        umo_parts = umo.split(":")
        platform = umo_parts[0] if umo_parts else ""

        parts = [f"[联系#{sid}]", "来自"]

        master_session = self._get_master_session()
        master_platform = master_session.split(":")[0] if master_session else "aiocqhttp"
        if platform and platform != master_platform:
            parts.append(f"[{platform}]")

        if not event.is_private_chat():
            group_id = umo_parts[2] if len(umo_parts) > 2 else "?"
            parts.append(f"群聊({group_id})")
        else:
            parts.append("私聊")

        parts.append(f"{user_name}({user_id}):")
        return " ".join(parts)

    def _tag(self, sid: str) -> str:
        return f"[联系#{sid}]"

    def _user_msg(self, sid: str, hint: str, content: str = "") -> str:
        """构建用户侧消息。有 content 时使用分隔格式，否则只有标记+提示。"""
        tag = self._tag(sid)
        if content:
            return f"{tag}\n{content}\n------\n{hint}"
        return f"{tag} {hint}"

    def _extract_forward_components(self, event: AstrMessageEvent) -> list:
        is_group = not event.is_private_chat()
        components = []
        for msg in event.get_messages():
            if isinstance(msg, (Reply, At)):
                continue
            if is_group and not isinstance(msg, _GROUP_FORWARD_TYPES):
                continue
            components.append(msg)
        return components

    # --- Command handlers ---

    @filter.command("contact", alias={"联系主人"})
    async def contact_master(self, event: AstrMessageEvent):
        """联系主人，建立消息转发通道"""
        if not self._get_master_session() and not self._get_master_admin_id():
            yield event.plain_result("未配置主人，无法使用此功能。请联系管理员配置。").stop_event()
            return

        if self._is_master(event):
            yield event.plain_result("你就是主人，无需联系自己。").stop_event()
            return

        umo = event.unified_msg_origin
        self._clean_expired_sessions()

        if umo in self._user_sessions:
            sid = self._user_sessions[umo]
            if sid in self._sessions:
                yield event.plain_result(
                    self._user_msg(sid, "你已有一个活跃的联系会话，回复此消息即可继续。")
                ).stop_event()
                return

        sid = self._generate_session_id()
        self._sessions[sid] = {
            "user_umo": umo,
            "user_name": event.get_sender_name(),
            "user_id": str(event.get_sender_id()),
            "last_activity": time.time(),
            "paused": False,
        }
        self._user_sessions[umo] = sid
        self._save_session(sid)

        text = event.message_str.strip()
        media = [c for c in self._extract_forward_components(event) if not isinstance(c, Plain)]
        if text or media:
            header = self._build_header(event, sid)
            chain = MessageChain().message(f"{header}\n{text}" if text else header)
            chain.chain.extend(media)
            sent = await self._send_to_master(chain)
            if sent:
                yield event.plain_result(
                    self._user_msg(sid, "已转发给主人，回复此消息继续发送。发送 /contactend 结束联系。", text)
                ).stop_event()
            else:
                yield event.plain_result(self._user_msg(sid, "已建立联系会话，但消息转发失败，请重试。")).stop_event()
        else:
            yield event.plain_result(
                self._user_msg(sid, "已开始联系主人，回复此消息发送内容给主人。发送 /contactend 结束联系。")
            ).stop_event()

    @filter.command("contactend", alias={"结束联系"})
    async def end_contact(self, event: AstrMessageEvent):
        """结束联系会话"""
        umo = event.unified_msg_origin

        # User ending their own session
        if umo in self._user_sessions:
            sid = self._user_sessions.pop(umo)
            self._sessions.pop(sid, None)
            self._delete_session(sid)
            yield event.plain_result(self._user_msg(sid, "联系会话已结束。")).stop_event()
            return

        # Master operations
        if self._is_master(event):
            args = event.message_str.strip().split()
            # /contactend pause <id> — pause auto-timeout for a session
            if len(args) >= 2 and args[0] == "pause":
                sid = args[1]
                session = self._sessions.get(sid)
                if session:
                    session["paused"] = True
                    self._save_session(sid)
                    yield event.plain_result(f"已暂停会话 #{sid} 的自动超时。").stop_event()
                else:
                    yield event.plain_result(f"会话 #{sid} 不存在。").stop_event()
                return

            # /contactend resume <id> — resume auto-timeout for a session
            if len(args) >= 2 and args[0] == "resume":
                sid = args[1]
                session = self._sessions.get(sid)
                if session:
                    session["paused"] = False
                    session["last_activity"] = time.time()
                    self._save_session(sid)
                    yield event.plain_result(f"已恢复会话 #{sid} 的自动超时。").stop_event()
                else:
                    yield event.plain_result(f"会话 #{sid} 不存在。").stop_event()
                return

            # /contactend <id> — end a specific session
            sid = args[0] if args else ""
            if sid and sid in self._sessions:
                session = self._sessions.pop(sid)
                self._user_sessions.pop(session["user_umo"], None)
                self._delete_session(sid)
                with contextlib.suppress(Exception):
                    await self.context.send_message(
                        session["user_umo"],
                        MessageChain().message(self._user_msg(sid, "主人已结束联系会话。")),
                    )
                yield event.plain_result(f"已结束与 {session['user_name']} 的联系会话。").stop_event()
                return

            # /contactend — list sessions
            if self._sessions:
                lines = ["当前活跃的联系会话:"]
                for s_id, info in self._sessions.items():
                    status = " [已暂停]" if info.get("paused") else ""
                    lines.append(f"  #{s_id} - {info['user_name']}({info['user_id']}){status}")
                lines.append("\n/contactend <ID> 结束会话")
                lines.append("/contactend pause <ID> 暂停自动超时")
                lines.append("/contactend resume <ID> 恢复自动超时")
                yield event.plain_result("\n".join(lines)).stop_event()
            else:
                yield event.plain_result("当前没有活跃的联系会话。").stop_event()
            return

        yield event.plain_result("你当前没有活跃的联系会话。").stop_event()

    # --- Reply forwarding handler ---

    @filter.custom_filter(ReplyToBotFilter())
    async def on_reply_to_bot(self, event: AstrMessageEvent):
        """处理回复 bot 消息的转发"""
        # Skip command messages: check original text (before WakingCheckStage strips prefix)
        raw_text = ""
        for _m in event.get_messages():
            if isinstance(_m, Plain):
                raw_text += _m.text
        raw_text = raw_text.strip()
        wake_prefixes = self.context.get_config().get("wake_prefix", [])
        for prefix in wake_prefixes:
            if prefix and raw_text.startswith(prefix):
                return

        self._clean_expired_sessions()

        # Find Reply component
        reply_comp = None
        for m in event.get_messages():
            if isinstance(m, Reply):
                reply_comp = m
                break
        if not reply_comp:
            return

        if self._is_master(event):
            # Master replying → route to user
            reply_text = reply_comp.message_str or ""
            match = SESSION_TAG_RE.search(reply_text)
            if not match:
                return

            sid = match.group(1)
            session = self._sessions.get(sid)
            if not session:
                yield event.plain_result("该联系会话已过期或不存在。").stop_event()
                return

            # Master replied → reset timeout
            session["last_activity"] = time.time()
            self._save_session(sid)

            # Forward master's message with session tag (excluding Reply/At)
            components = [m for m in event.get_messages() if not isinstance(m, (Reply, At))]
            chain = MessageChain().message(self._tag(sid) + " ")
            chain.chain.extend(components)

            sent = await self.context.send_message(session["user_umo"], chain)
            if sent:
                yield event.plain_result("已转发给用户。").stop_event()
            else:
                yield event.plain_result("转发失败，请检查配置。").stop_event()

        else:
            # User replying → forward to master
            umo = event.unified_msg_origin
            sid = self._user_sessions.get(umo)
            if not sid or sid not in self._sessions:
                # Check if replying to a message from this plugin
                reply_text = reply_comp.message_str or ""
                if SESSION_TAG_RE.search(reply_text):
                    yield event.plain_result(
                        "联系会话已过期或已结束，如有需要请重新发送 /contact 发起联系。"
                    ).stop_event()
                return

            # Update activity timestamp
            self._sessions[sid]["last_activity"] = time.time()
            self._save_session(sid)

            header = self._build_header(event, sid)
            chain = MessageChain().message(header + "\n")
            chain.chain.extend(self._extract_forward_components(event))

            sent = await self._send_to_master(chain)
            if not sent:
                yield event.plain_result(self._user_msg(sid, "转发失败，请等待主人检查。")).stop_event()
