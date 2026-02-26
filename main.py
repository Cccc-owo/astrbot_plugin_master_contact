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

_GROUP_FORWARD_TYPES = (Plain, Image)

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    data TEXT NOT NULL
)
"""

_HELP_USER = """\
/contact start [消息] - 联系 Master（可附带首条消息）
/contact send <n> - 接下来 n 条消息直接转发
/contact cancel - 取消发送模式
/contact end - 结束当前联系会话
/contact help - 显示此帮助"""

_HELP_MASTER = """\
/contact list - 查看活跃会话
/contact send <n> [ID] - 接下来 n 条消息直接转发
/contact cancel - 取消发送模式
/contact end <ID> - 结束指定会话
/contact pause <ID> - 暂停会话自动超时
/contact resume <ID> - 恢复会话自动超时
/contact help - 显示此帮助"""


class ReplyToBotFilter(CustomFilter):
    """仅当消息是回复 bot 消息时通过。"""

    def filter(self, event: AstrMessageEvent, cfg) -> bool:
        for msg in event.get_messages():
            if isinstance(msg, Reply) and str(msg.sender_id) == str(event.get_self_id()):
                return True
        return False


@register("astrbot_plugin_master_contact", "Cccc_", "简易的联系 Master 插件", "0.1.0")
class MasterContactPlugin(Star):
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

    def _remove_session(self, sid: str) -> dict | None:
        """移除会话并清理索引和 DB，返回被移除的 session dict。"""
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

    def _get_master_sessions(self) -> list[str]:
        """返回配置的主人 UMO 列表。"""
        val = self.config.get("master_sessions", [])
        if isinstance(val, str):
            return [v.strip() for v in val.split(",") if v.strip()]
        if isinstance(val, list):
            return [str(v).strip() for v in val if str(v).strip()]
        return []

    def _is_master(self, event: AstrMessageEvent) -> bool:
        return event.unified_msg_origin in self._get_master_sessions()

    async def _send_to_master(self, chain: MessageChain, target_umo: str = "") -> bool:
        """发送消息给主人。指定 target_umo 时只发给该主人，否则广播给所有主人。"""
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

    async def _clean_expired_sessions(self) -> list[str]:
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
            session = self._remove_session(sid)
            if session:
                tag = self._tag(sid)
                with contextlib.suppress(Exception):
                    await self.context.send_message(
                        session["user_umo"],
                        MessageChain().message(f"{tag} 联系会话已超时。"),
                    )
                master_umo = session.get("master_umo", "")
                if master_umo:
                    with contextlib.suppress(Exception):
                        await self.context.send_message(
                            master_umo,
                            MessageChain().message(f"{tag} 联系会话已超时。"),
                        )
        self._clean_expired_collectors()
        return expired

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

    def _tag(self, sid: str) -> str:
        return f"[联系#{sid}]"

    def _user_msg(self, sid: str, hint: str) -> str:
        """构建用户侧纯提示消息（无转发内容）。"""
        return f"{self._tag(sid)} {hint}"

    def _prepend_text(self, prefix: str, components: list) -> list:
        """在组件列表前插入文本，如果首个组件是 Plain 则合并，否则插入新 Plain。"""
        if components and isinstance(components[0], Plain):
            return [Plain(prefix + components[0].text)] + components[1:]
        return [Plain(prefix)] + components

    def _append_text(self, components: list, suffix: str) -> list:
        """在组件列表后追加文本，如果末尾组件是 Plain 则合并，否则追加新 Plain。"""
        if components and isinstance(components[-1], Plain):
            return components[:-1] + [Plain(components[-1].text + suffix)]
        return components + [Plain(suffix)]

    def _user_chain(self, sid: str, hint: str, components: list) -> MessageChain:
        """构建用户侧带内容的消息链：标签 + 原样内容 + 分隔线 + 提示。"""
        parts = self._prepend_text(self._tag(sid) + "\n", components)
        parts = self._append_text(parts, "\n------\n" + hint)
        chain = MessageChain()
        chain.chain.extend(parts)
        return chain

    def _is_wake_command(self, event: AstrMessageEvent) -> bool:
        """检查消息是否以唤醒前缀开头（即为命令消息）。"""
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
        is_group = not event.is_private_chat()
        components = []
        for msg in event.get_messages():
            if isinstance(msg, (Reply, At)):
                continue
            if is_group and not isinstance(msg, _GROUP_FORWARD_TYPES):
                continue
            components.append(msg)
        return components

    def _extract_sid_from_reply(self, reply_comp: Reply) -> str | None:
        """从 Reply 组件中提取会话 ID，优先 message_str，fallback chain。"""
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

    # --- Command handler ---

    @filter.command("contact", alias={"联系主人"})
    async def handle_contact(self, event: AstrMessageEvent):
        """联系 Master，发送 /contact help 获取详细帮助"""
        # message_str still contains command name after WakingCheckStage;
        # skip it to get the actual subcommand and arguments.
        args = event.message_str.strip().split()
        args = args[1:] if args and args[0] in ("contact", "联系主人") else args
        sub = args[0] if args else ""

        is_master = self._is_master(event)

        # --- help ---
        if sub == "help":
            text = _HELP_MASTER if is_master else _HELP_USER
            yield event.plain_result(text).stop_event()
            return

        # --- end ---
        if sub == "end":
            yield await self._handle_end(event, args[1:], is_master)
            return

        # --- master-only subcommands ---
        if sub == "list":
            if is_master:
                yield await self._handle_list(event)
            else:
                yield event.plain_result("该命令仅限 Master 使用。").stop_event()
            return

        if sub == "pause":
            if is_master:
                yield self._handle_set_pause(event, args[1:], paused=True)
            else:
                yield event.plain_result("该命令仅限 Master 使用。").stop_event()
            return

        if sub == "resume":
            if is_master:
                yield self._handle_set_pause(event, args[1:], paused=False)
            else:
                yield event.plain_result("该命令仅限 Master 使用。").stop_event()
            return

        if sub == "send":
            yield self._handle_send(event, args[1:], is_master)
            return

        if sub == "cancel":
            yield self._handle_cancel(event)
            return

        if sub == "start":
            if is_master:
                yield event.plain_result("该命令仅限用户使用。").stop_event()
            else:
                yield await self._handle_start(event)
            return

        # --- default: /contact → help ---
        text = _HELP_MASTER if is_master else _HELP_USER
        if sub:
            yield event.plain_result(f'未知子命令 "{sub}"。\n{text}').stop_event()
        else:
            yield event.plain_result(text).stop_event()

    # --- Subcommand implementations ---

    async def _handle_start(self, event: AstrMessageEvent):
        """用户发起联系会话。"""
        if not self._get_master_sessions():
            return event.plain_result("未配置 Master，无法使用此功能。请联系管理员配置。").stop_event()

        umo = event.unified_msg_origin
        await self._clean_expired_sessions()

        if umo in self._user_sessions:
            sid = self._user_sessions[umo]
            if sid in self._sessions:
                return event.plain_result(
                    self._user_msg(sid, "你已有一个活跃的联系会话，回复此消息即可继续。")
                ).stop_event()

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

        # Build content to forward: strip command prefix from text, keep non-text as-is
        raw = event.message_str.strip()
        for cmd in ("contact", "联系主人"):
            if raw == cmd:
                raw = ""
                break
            if raw.startswith(cmd + " "):
                raw = raw[len(cmd) :].strip()
                break
        if raw == "start":
            raw = ""
        elif raw.startswith("start "):
            raw = raw[len("start") :].strip()
        non_text = [c for c in self._extract_forward_components(event) if not isinstance(c, Plain)]
        has_content = bool(raw or non_text)

        if has_content:
            # Build components: stripped text + non-text originals
            components: list = []
            if raw:
                components.append(Plain(raw))
            components.extend(non_text)

            # Forward to master: header + components + hint
            header = self._build_header(event, sid)
            parts = self._prepend_text(header + "\n", components)
            parts = self._append_text(parts, "\n------\n回复本条消息以回复用户")
            chain = MessageChain()
            chain.chain.extend(parts)
            sent = await self._send_to_master(chain)
            if sent:
                # Echo to user: tag + components + separator + hint
                result = event.chain_result(
                    self._user_chain(
                        sid, "已转发给 Master，回复此消息继续发送。发送 /contact end 结束联系。", components
                    ).chain
                )
                return result.stop_event()
            else:
                return event.plain_result(self._user_msg(sid, "已建立联系会话，但消息转发失败，请重试。")).stop_event()
        else:
            return event.plain_result(
                self._user_msg(sid, "已开始联系 Master，回复此消息发送内容给 Master。发送 /contact end 结束联系。")
            ).stop_event()

    async def _handle_end(self, event: AstrMessageEvent, args: list[str], is_master: bool):
        """结束联系会话。"""
        umo = event.unified_msg_origin

        # User ending their own session
        if umo in self._user_sessions:
            sid = self._user_sessions[umo]
            session = self._remove_session(sid)
            if session:
                master_umo = session.get("master_umo", "")
                if master_umo:
                    with contextlib.suppress(Exception):
                        await self.context.send_message(
                            master_umo,
                            MessageChain().message(f"{self._tag(sid)} 用户已结束联系会话。"),
                        )
            return event.plain_result(self._user_msg(sid, "联系会话已结束。")).stop_event()

        # Master ending a specific session
        if is_master:
            sid = args[0] if args else ""
            if sid and sid in self._sessions:
                session = self._remove_session(sid)
                assert session is not None
                with contextlib.suppress(Exception):
                    await self.context.send_message(
                        session["user_umo"],
                        MessageChain().message(self._user_msg(sid, "Master 已结束联系会话。")),
                    )
                return event.plain_result(f"已结束与 {session['user_name']} 的联系会话。").stop_event()
            if sid:
                return event.plain_result(f"会话 #{sid} 不存在。").stop_event()
            return event.plain_result("用法: /contact end <ID>").stop_event()

        return event.plain_result("你当前没有活跃的联系会话。").stop_event()

    async def _handle_list(self, event: AstrMessageEvent):
        """主人查看活跃会话列表。"""
        await self._clean_expired_sessions()
        if not self._sessions:
            return event.plain_result("当前没有活跃的联系会话。\n发送 /contact help 查看可用命令。").stop_event()
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
        return event.plain_result("\n".join(lines)).stop_event()

    def _handle_set_pause(self, event: AstrMessageEvent, args: list[str], paused: bool):
        """主人暂停/恢复会话自动超时。"""
        sid = args[0] if args else ""
        cmd = "pause" if paused else "resume"
        if not sid:
            return event.plain_result(f"用法: /contact {cmd} <ID>").stop_event()
        session = self._sessions.get(sid)
        if not session:
            return event.plain_result(f"会话 #{sid} 不存在。").stop_event()
        session["paused"] = paused
        if not paused:
            session["last_activity"] = time.time()
        self._save_session(sid)
        action = "暂停" if paused else "恢复"
        return event.plain_result(f"已{action}会话 #{sid} 的自动超时。").stop_event()

    def _get_send_max(self) -> int:
        return max(1, int(self.config.get("send_max", 20)))

    def _get_send_timeout(self) -> int:
        return max(0, int(self.config.get("send_timeout", 300)))

    def _handle_send(self, event: AstrMessageEvent, args: list[str], is_master: bool):
        """进入发送模式，接下来 n 条消息直接转发。"""
        umo = event.unified_msg_origin

        if umo in self._send_collectors:
            return event.plain_result("你已在发送模式中，请继续发送消息或 /contact cancel 取消。").stop_event()

        # Parse count
        if not args or not args[0].isdigit():
            usage = "用法: /contact send <n>" + (" [ID]" if is_master else "")
            return event.plain_result(usage).stop_event()
        count = int(args[0])
        send_max = self._get_send_max()
        if count < 1 or count > send_max:
            return event.plain_result(f"消息条数须在 1-{send_max} 之间。").stop_event()

        # Resolve session
        if is_master:
            sid_arg = args[1] if len(args) > 1 else ""
            if sid_arg:
                if sid_arg not in self._sessions:
                    return event.plain_result(f"会话 #{sid_arg} 不存在。").stop_event()
                sid = sid_arg
            elif len(self._sessions) == 1:
                sid = next(iter(self._sessions))
            elif not self._sessions:
                return event.plain_result("当前没有活跃的联系会话。").stop_event()
            else:
                return event.plain_result("当前有多个活跃会话，请指定会话 ID: /contact send <n> <ID>").stop_event()
        else:
            sid = self._user_sessions.get(umo)
            if not sid or sid not in self._sessions:
                return event.plain_result("你当前没有活跃的联系会话，请先发送 /contact start 发起联系。").stop_event()

        self._send_collectors[umo] = {
            "sid": sid,
            "remaining": count,
            "total": count,
            "is_master": is_master,
            "started_at": time.time(),
        }
        target = "用户" if is_master else "Master"
        return event.plain_result(
            self._user_msg(
                sid, f"进入发送模式，接下来发送的 {count} 条消息将直接转发给 {target}。发送 /contact cancel 取消。"
            )
        ).stop_event()

    def _handle_cancel(self, event: AstrMessageEvent):
        """取消发送模式。"""
        umo = event.unified_msg_origin
        collector = self._send_collectors.pop(umo, None)
        if not collector:
            return event.plain_result("你当前不在发送模式中。使用 /contact send <n> 进入发送模式。").stop_event()
        sid = collector["sid"]
        sent = collector["total"] - collector["remaining"]
        return event.plain_result(
            self._user_msg(sid, f"已取消发送模式（已转发 {sent}/{collector['total']} 条）。")
        ).stop_event()

    def _clean_expired_collectors(self) -> list[str]:
        """清理超时的 send 收集器，返回被清理的 UMO 列表。"""
        now = time.time()
        send_timeout = self._get_send_timeout()
        expired = [
            umo for umo, c in self._send_collectors.items() if send_timeout > 0 and now - c["started_at"] > send_timeout
        ]
        for umo in expired:
            del self._send_collectors[umo]
        return expired

    async def _forward_user_to_master(self, event: AstrMessageEvent, sid: str) -> str:
        """用户消息转发给 Master，返回提示文本。"""
        session = self._sessions[sid]
        session["last_activity"] = time.time()
        self._save_session(sid)

        header = self._build_header(event, sid)
        components = self._extract_forward_components(event)
        parts = self._prepend_text(header + "\n", components)
        parts = self._append_text(parts, "\n------\n回复本条消息以回复用户")
        chain = MessageChain()
        chain.chain.extend(parts)

        sent = await self._send_to_master(chain, session.get("master_umo", ""))
        if not sent:
            return self._user_msg(sid, "转发失败，请等待 Master 检查。")
        if not session.get("master_umo"):
            return self._user_msg(sid, "已转发给 Master。Master 暂未接入会话，请耐心等待。")
        return self._user_msg(sid, "已转发给 Master。")

    # --- Reply forwarding handler ---

    @filter.custom_filter(ReplyToBotFilter)
    async def on_reply_to_bot(self, event: AstrMessageEvent):
        """处理回复 bot 消息的转发"""
        if self._is_wake_command(event):
            return

        await self._clean_expired_sessions()

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
            sid = self._extract_sid_from_reply(reply_comp)
            if not sid:
                return

            session = self._sessions.get(sid)
            if not session:
                yield event.plain_result("该联系会话已过期或不存在。").stop_event()
                return

            # Master replied → claim session and reset timeout
            if self.config.get("claim_by_sender", False):
                claim_key = "master_sender_id"
                claim_val = str(event.get_sender_id())
            else:
                claim_key = "master_umo"
                claim_val = event.unified_msg_origin
            claimed_by = session.get(claim_key)
            if claimed_by and claimed_by != claim_val:
                yield event.plain_result("该会话已由其他 Master 接入。").stop_event()
                return
            if not claimed_by:
                session[claim_key] = claim_val
            if not session.get("master_umo"):
                session["master_umo"] = event.unified_msg_origin
            session["last_activity"] = time.time()
            self._save_session(sid)

            # Forward master's message with session tag
            components = self._extract_forward_components(event)
            hint = "回复本条消息发送内容给 Master"
            chain = self._user_chain(sid, hint, components)

            try:
                sent = await self.context.send_message(session["user_umo"], chain)
            except Exception:
                logger.error(f"转发消息给用户失败 (sid={sid})")
                sent = False
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
                if self._extract_sid_from_reply(reply_comp):
                    yield event.plain_result(
                        "联系会话已过期或已结束，如有需要请重新发送 /contact start 发起联系。"
                    ).stop_event()
                return

            hint = await self._forward_user_to_master(event, sid)
            yield event.plain_result(hint).stop_event()

    # --- Send-mode message interceptor ---

    @filter.event_message_type(EventMessageType.ALL)
    async def on_send_mode_message(self, event: AstrMessageEvent):
        """在发送模式下拦截消息并转发。"""
        umo = event.unified_msg_origin
        collector = self._send_collectors.get(umo)
        if not collector:
            return

        # Check timeout
        if self._get_send_timeout() > 0 and time.time() - collector["started_at"] > self._get_send_timeout():
            sent = collector["total"] - collector["remaining"]
            del self._send_collectors[umo]
            yield event.plain_result(
                self._user_msg(collector["sid"], f"发送模式已超时（已转发 {sent}/{collector['total']} 条）。")
            ).stop_event()
            return

        # Skip command messages
        if self._is_wake_command(event):
            return

        sid = collector["sid"]
        session = self._sessions.get(sid)
        if not session:
            del self._send_collectors[umo]
            yield event.plain_result("联系会话已过期，发送模式已取消。").stop_event()
            return

        is_master = collector["is_master"]
        remaining = collector["remaining"]
        total = collector["total"]
        is_first = remaining == total
        is_last = remaining == 1  # Note: when total==1, both is_first and is_last are True

        # Update session activity
        session["last_activity"] = time.time()
        self._save_session(sid)

        components = self._extract_forward_components(event)
        content_chain = MessageChain()
        content_chain.chain.extend(components)
        _FALLBACK = MessageChain().message("[本消息存在异常，转发失败]")

        if is_master:
            target_umo = session["user_umo"]
            send = self.context.send_message

            # Prefix: independent message before first content
            if is_first:
                prefix = MessageChain().message(f"{self._tag(sid)} Master 发来了 {total} 条消息如下：")
                await send(target_umo, prefix)

            # Content: always sent as-is, fallback on failure
            try:
                await send(target_umo, content_chain)
            except Exception:
                logger.error(f"转发消息给用户失败 (sid={sid})")
                await send(target_umo, _FALLBACK)

            # Suffix: independent message after last content
            if is_last:
                suffix = MessageChain().message(self._tag(sid) + "\n------\n回复本条消息发送内容给 Master")
                sent = await send(target_umo, suffix)
            else:
                sent = True
        else:
            master_umo = session.get("master_umo", "")
            send_master = self._send_to_master

            # Prefix
            if is_first:
                header = self._build_header(event, sid)
                prefix = MessageChain().message(f"{header} 发来了 {total} 条消息如下：")
                await send_master(prefix, master_umo)

            # Content: always sent as-is, fallback on failure
            ok = await send_master(content_chain, master_umo)
            if not ok:
                logger.error(f"转发消息给 Master 失败 (sid={sid})")
                await send_master(_FALLBACK, master_umo)

            # Suffix
            if is_last:
                suffix = MessageChain().message(self._tag(sid) + "\n------\n回复本条消息以回复用户")
                sent = await send_master(suffix, master_umo)
            else:
                sent = True

        collector["remaining"] -= 1
        if collector["remaining"] <= 0:
            del self._send_collectors[umo]
            target = "用户" if is_master else "Master"
            yield event.plain_result(
                self._user_msg(sid, f"发送模式已完成，{total} 条消息已转发给 {target}。")
            ).stop_event()
        elif sent:
            yield event.plain_result(
                self._user_msg(sid, f"({collector['remaining']}/{total}) 继续发送，无需回复直接发送即可。")
            ).stop_event()
        else:
            yield event.plain_result(self._user_msg(sid, "转发失败。")).stop_event()

    # --- Private chat fallback ---

    @filter.event_message_type(EventMessageType.ALL)
    async def on_private_chat_fallback(self, event: AstrMessageEvent):
        """私聊用户有活跃会话时，非命令消息直接转发给 Master。"""
        if not event.is_private_chat():
            return
        if self._is_master(event):
            return
        if self._is_wake_command(event):
            return
        # 已被 send mode 处理的消息不再处理
        if event.unified_msg_origin in self._send_collectors:
            return

        umo = event.unified_msg_origin
        sid = self._user_sessions.get(umo)
        if not sid or sid not in self._sessions:
            return

        hint = await self._forward_user_to_master(event, sid)
        yield event.plain_result(hint).stop_event()
