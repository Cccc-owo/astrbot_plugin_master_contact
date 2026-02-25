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
- 发送模式：`/contact send <n>` 连续发送 n 条消息直接转发，无需逐条回复
- 支持附带首条消息直接发起联系
- 支持多 Master 配置，广播通知 + 首位回复自动接入
- 会话自动超时清理，支持暂停/恢复超时
- 群聊场景仅转发文本和图片，私聊转发全部内容
- 基于 SQLite 持久化存储，重启不丢失会话

## 使用

发送以下命令（前缀跟随 AstrBot 唤醒前缀设置，以 `/` 为例）：

### 用户命令

| 命令 | 说明 |
|------|------|
| `/contact` | 显示帮助 |
| `/contact start` | 发起联系会话 |
| `/contact start [消息]` | 发起联系并附带首条消息 |
| `/contact send <n>` | 进入发送模式，接下来 n 条消息直接转发 |
| `/contact cancel` | 取消发送模式 |
| `/contact end` | 结束当前联系会话 |
| `/contact help` | 显示帮助 |

别名：`/联系主人`

发起联系后，**回复 bot 消息**即可继续发送内容给 Master。也可以使用 `/contact send <n>` 进入发送模式，直接发送消息无需回复。

### Master 命令

| 命令 | 说明 |
|------|------|
| `/contact` | 显示帮助 |
| `/contact list` | 查看活跃会话列表 |
| `/contact send <n> [ID]` | 进入发送模式，接下来 n 条消息直接转发 |
| `/contact cancel` | 取消发送模式 |
| `/contact end <ID>` | 结束指定会话 |
| `/contact pause <ID>` | 暂停会话自动超时 |
| `/contact resume <ID>` | 恢复会话自动超时 |
| `/contact help` | 显示帮助 |

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
| `session_timeout` | 会话超时时间（分钟），0 表示不超时 | `10` |
| `send_max` | 发送模式最大消息条数 | `20` |
| `send_timeout` | 发送模式超时时间（秒），0 表示不超时 | `300` |

使用 AstrBot 内置的 `sid` 命令可查询当前会话的 unified_msg_origin。

## 许可证

[MIT](LICENSE)
