<p align="center">
  <img src="https://github.com/Cccc-owo/astrbot-plugin-master-contact/raw/refs/heads/master/logo.png" width="120" height="120" alt="Master Contact Logo">
</p>

<h1 align="center">联系 Master</h1>

<p align="center">
  简易的联系主人插件，适用于 <a href="https://github.com/AstrBotDevs/AstrBot">AstrBot</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/AstrBot-v4.5.0+-blue" alt="AstrBot">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
</p>

---

## 功能

- 用户通过 `/contact start` 命令发起与 Master 的联系会话
- 通过回复 bot 消息实现双向消息转发
- 私聊用户有活跃会话时直接发送消息即可转发，无需回复
- 转发模式：`/contact forward` 进入持续转发，消息原样转发无需逐条回复
- 支持多 Master 配置，广播通知 + 首位回复自动接入
- Master 接入前限流，防止消息轰炸
- 会话自动超时清理，支持暂停/恢复超时
- 群聊场景仅转发文本和图片，私聊转发全部内容
- 基于 SQLite 持久化存储，重启不丢失会话

## 使用

发送以下命令（前缀跟随 AstrBot 唤醒前缀设置，以 `/` 为例）：

### 用户命令

| 命令 | 说明 |
|------|------|
| `/contact start` | 发起联系会话 |
| `/contact forward` | 进入转发模式，消息原样转发（群聊用） |
| `/contact forward done` | 结束转发模式 |
| `/contact end` | 结束当前联系会话 |
| `/contact` | 显示命令帮助 |

别名：`/联系主人`

发起联系后，**回复 bot 消息**即可继续发送内容给 Master。私聊用户直接发送消息即可自动转发。群聊用户也可以使用 `/contact forward` 进入转发模式，直接发送消息无需回复。

### Master 命令

| 命令 | 说明 |
|------|------|
| `/contact list` | 查看活跃会话列表 |
| `/contact forward [ID]` | 进入转发模式 |
| `/contact forward done` | 结束转发模式 |
| `/contact end <ID>` | 结束指定会话 |
| `/contact pause <ID>` | 暂停会话自动超时 |
| `/contact resume <ID>` | 恢复会话自动超时 |
| `/contact` | 显示命令帮助 |

Master 通过**回复转发消息**来回复用户。首位回复的 Master 自动接入该会话。

## 安装

通过 GitHub 仓库地址安装：

```
https://github.com/Cccc-owo/astrbot-plugin-master-contact
```

## 配置

所有配置均可在 AstrBot Dashboard 中修改。

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `master_sessions` | Master 的会话标识列表 (unified_msg_origin) | `[]` |
| `session_timeout` | 会话超时时间（分钟），0 表示不超时 | `1440` |
| `forward_timeout` | 转发模式超时时间（秒），0 表示不超时 | `300` |
| `claim_by_sender` | 按发送者 ID 锁定会话归属（适用于多 Master 共用群聊） | `false` |
| `unclaimed_limit` | Master 接入前用户最多可发送的消息条数，0 表示不限制 | `3` |

使用 AstrBot 内置的 `sid` 命令可查询当前会话的 unified_msg_origin。

## 许可证

[MIT](LICENSE)
