# 启动 TeamSeatWatch

[返回项目首页](../README.md) · 简体中文 / [English](deployment.en.md)

这条路线适用于 **Linux x86_64 单机**。先准备 Docker Engine（含 Compose）、Python 3、OpenSSL，并确认当前用户可以运行 Docker。

## 1. 启动

```bash
git clone https://github.com/xft0202/Apophis-TeamSeatWatch.git
cd Apophis-TeamSeatWatch
python3 deploy/manage.py start
```

第一次会下载构建依赖，请等待构建完成。按提示设置至少 **14 个字符**的管理员密码，输入时不回显。出现 **“已就绪 / Ready”** 后，安装完成。

构建入口复用按镜像 digest 固定的、已部署验证的 ShardX 156.0.8078.48 浏览器，并在构建时再次校验 executable SHA256 和版本；最终镜像仅含未修改内核。无需从内容可变的 ZIP 下载地址暂存浏览器。每个账号在首次请求会话时建立独立档案，存于 control 的 `browser-profiles` 持久卷（容器内 `/var/lib/teamseatwatch/browser-profiles`），重启和重新创建容器复用此卷。空闲档案不启动浏览器。全局业务并发首次默认5，已保存的代理管理运行参数继续生效。

浏览器退出后，在账号档案锁内回收 HTTP、代码和 GPU/Dawn 可重建缓存；崩溃遗留缓存在下次打开档案时回收。固定指纹、设备身份、Cookie、网站持久存储和浏览器设置继续保留。执行期间可使用缓存，下一次启动会重新生成；缓存限制不代表整个档案大小的硬上限，长期网站数据仍需计入磁盘预算。回收失败会记录 `profile_cache_cleanup_failed`，不会将已完成登录改判为凭据错误。

启动工具会准备数据库、加密资料、证书和两个访问入口；再次运行会沿用已有数据与管理员。安装资料默认放在 `~/.local/share/apophis-teamseatwatch`，独立于源码。已有手工安装应先保留原备份；此入口创建独立安装，不自动接管旧容器或导入旧数据。

## 2. 打开工作台

把启动结果中的 `installation/tls/authority/ca.crt` 导入浏览器或系统的受信任根证书存储。只导入 `.crt` 证书。

| 入口 | 地址 | 首次操作 |
| --- | --- | --- |
| 管理工作台 | `https://localhost:18443/owner/` | 使用 `owner` 和刚设置的密码登录 |
| 用户兑换 | `https://localhost:18444/redeem/` | 输入卡密进行兑换或 401 找回 |

进入管理端后，先在“代理管理”选择直连或配置可用代理，再按[首页的使用流程](../README.md#workflow)准备账号、空间和批次。启动完成表示服务可用；真实账号接入结果会在操作时显示。

新安装会在权限为 `600` 的 `installation/control.env` 中生成 `TSW_CPA_WEBHOOK_SECRET`。如需接收 CPA 降智检测事件，在 CPA 插件中配置接收地址 `https://你的管理域名/internal/v1/cpa/degradation-events`，并填写同一密钥。接收端校验签名，以 CPA 当前账号邮箱匹配母号下新鲜、完整的 Team 成员证据，自动接管唯一的普通 Pro 成员后，会自动执行：隔离 CPA 凭证 → 移除该成员 → 备用号补位 → 获取工作空间 OAuth 凭证 → 注册回 CPA。无需逐单批准。只有 CPA 确认注册成功才标记完成。置信度不足、成员证据过期、角色受保护或没有可用备用号时不会继续移除成员。已有安装不会被更新流程自动写入密钥；需要启用时，请手动向原 `control.env` 添加一个至少 16 字符的随机密钥并重启 control 服务。

还需在 control 服务环境配置 `TSW_CPA_MANAGEMENT_URL`（CPA 管理 API 基础地址，例如 `http://127.0.0.1:8317`）和 `TSW_CPA_MANAGEMENT_KEY`（CPA 当前的管理密钥）。地址必须为 control 服务可访问的回环地址；容器内的 `127.0.0.1` 指向容器自身。未配置时轮换等待，不会踢成员。Apophis 导入的子号就是备用池，无需手工建立备用批次。系统会将材料完整且不在 CPA 当前账号或 Team active 成员中的账号纳入自动备用组，准备个人登录会话并实际探测；只有探测可用的账号才能补位。成员权限不足或证据过期时，后台刷新所选母号的专用成员验证记录，并重试近期未映射回调。管理端“凭证自动轮换”可查看每个阶段与失败原因。连续远端失败会阻断案例并触发熔断。

CPA 已有子号可导入 Apophis 的完整登录材料（账号、密码及所需 TOTP）托管。系统按身份匹配 CPA 当前凭证，匹配到 CPA 的账号不会进入备用池。每两分钟读取 CPA 已观察到的认证状态，明确 401 时创建独立的同账号 OAuth 续授权任务；它不触发踢人或补位，也不尝试 PAT。复用隔离的个人登录会话，按原有浏览器 PKCE 流程获取带 `refresh_token` 的 OAuth 凭证，更新 CPA 原文件名，并下载核对账号及实际令牌摘要。

新补位账号复用已经成功生成的 OAuth 版本交付 CPA。每次首次交付或续授权，从 AP 代理池的健康节点中均匀随机选择一个出口，写入 CPA 的 `proxy_url`；凭证和代理分配结果一起加密保存，上传重试不重新登录、不重新选代理。代理池无可用节点时等待或失败，不静默直连。CPA 回读必须核对账号、凭证和代理摘要，成功后才完成任务。

任务记录保存在 `tsw_cpa_reauthorizations`，失败退避，最多三次后阻断；人工禁用或轮换隔离的 CPA 文件不自动恢复。401 来源为 CPA 已观察到的上游失败，不会为了巡检主动消耗模型调用。VLESS、VMess、Hysteria2 需先由相应协议客户端转换为本机 HTTP/SOCKS 入口，再导入 AP 自带代理池；协议客户端须随系统启动，配置文件应限制读取权限。

<details>
<summary><strong>在服务器安装，从自己的电脑打开</strong></summary>

在电脑上转发两个访问端口（替换 SSH 主机）：

```bash
ssh -N -L 18443:127.0.0.1:18443 -L 18444:127.0.0.1:18444 user@your-server
```

将服务器上显示的 CA 证书复制到电脑并信任，再打开同样的两个 `localhost` 地址。默认所有服务仅监听主机本地地址。

为用户提供远程兑换时，在服务器上用现有域名代理服务，将兑换域名通过受信任 HTTPS 转发到 `https://localhost:18444`；上游校验使用本安装 CA，服务器名为 `localhost`。管理入口继续使用本机或 SSH 转发方式。网关、数据库与内部服务保持原监听配置。

</details>

<details>
<summary><strong>日常维护：查看状态、重启、更新与备份</strong></summary>

在源码目录执行：

```bash
python3 deploy/manage.py status
python3 deploy/manage.py logs
python3 deploy/manage.py stop
python3 deploy/manage.py start
```

忘记密码：`python3 deploy/manage.py reset-password`，旧登录会话会失效。

更新：先 `git pull --ff-only`，再运行 `python3 deploy/manage.py start --build`。工具会先构建、停下应用、备份，再迁移和启动；失败时保留资料，查看日志后继续同一安装。

备份：运行 `python3 deploy/manage.py backup`。这会暂停应用，在资料目录的 `backups/` 中保存数据库与配套加密资料、证书和配置。完成后运行 `start` 恢复服务。每次启动迁移前也会自动保存一份备份。

把完整备份复制到独立位置。恢复必须使用同一份备份中的 `database.dump` 与 `installation.tar.gz`；数据库与加密密钥必须配套，不能重新生成密钥代替。保留原资料目录与 Compose 项目标识，数据库持久卷在重启和更新时复用。

本机 CA 有效期 10 年，服务证书有效期 1 年；到期前用原 CA 续签叶证书，保持 keyring 不变，并重启服务。

</details>

<details>
<summary><strong>端口、自定义目录与启动异常</strong></summary>

首次安装可指定独立资料目录与连续六个端口的起点：

```bash
python3 deploy/manage.py start --data-dir /your/private/tsw-data --port-base 19440
```

此时管理端和兑换端分别为 `https://localhost:19443/owner/` 和 `https://localhost:19444/redeem/`。后续每条命令始终使用相同 `--data-dir`，端口会自动沿用。默认连续端口为 18440–18445。

| 遇到的问题 | 下一步 |
| --- | --- |
| 构建中断或依赖下载失败 | 确认网络可达后，再次运行同一个 `start` |
| 启动检查未通过 | 运行 `logs`，按实际报错检查端口、数据库或证书 |
| 浏览器提示证书错误 | 确认已在浏览器所在设备信任 CA，并使用 `localhost` 地址 |
| 登录或操作返回 403 | 使用启动输出的准确管理端地址，并重新登录 |
| 平台登录或探测失败 | 查看对应账号的结果；核对资料、权限与代理设置 |

使用交流：**QQ 1129084117**。可复现的问题提交 [GitHub Issues](https://github.com/xft0202/Apophis-TeamSeatWatch/issues)，附已脱敏日志。

</details>
