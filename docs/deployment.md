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

构建入口先把固定 SHA256 的官方 ShardX 152.0.7977.65 ZIP 缓存在源码目录 `.browser-artifacts/`，校验后解压到镜像；最终镜像仅含未修改内核。直接运行 `docker build` 前执行 `python3 tools/prepare-browser.py`；已有相同制品可用 `--source /path/to/ShardX-Linux.zip` 复用。每个账号在首次请求会话时建立独立档案，存于 control 的 `browser-profiles` 持久卷（容器内 `/var/lib/teamseatwatch/browser-profiles`），重启和重新创建容器复用此卷。空闲档案不启动浏览器。全局业务并发首次默认5，已保存的代理管理运行参数继续生效。

浏览器退出后，在账号档案锁内回收 HTTP、代码和 GPU/Dawn 可重建缓存；崩溃遗留缓存在下次打开档案时回收。固定指纹、设备身份、Cookie、网站持久存储和浏览器设置继续保留。执行期间可使用缓存，下一次启动会重新生成；缓存限制不代表整个档案大小的硬上限，长期网站数据仍需计入磁盘预算。回收失败会记录 `profile_cache_cleanup_failed`，不会将已完成登录改判为凭据错误。

启动工具会准备数据库、加密资料、证书和两个访问入口；再次运行会沿用已有数据与管理员。安装资料默认放在 `~/.local/share/apophis-teamseatwatch`，独立于源码。已有手工安装应先保留原备份；此入口创建独立安装，不自动接管旧容器或导入旧数据。

## 2. 打开工作台

把启动结果中的 `installation/tls/authority/ca.crt` 导入浏览器或系统的受信任根证书存储。只导入 `.crt` 证书。

| 入口 | 地址 | 首次操作 |
| --- | --- | --- |
| 管理工作台 | `https://localhost:18443/owner/` | 使用 `owner` 和刚设置的密码登录 |
| 用户兑换 | `https://localhost:18444/redeem/` | 输入卡密进行兑换或 401 找回 |

进入管理端后，先在“代理管理”选择直连或配置可用代理，再按[首页的使用流程](../README.md#workflow)准备账号、空间和批次。启动完成表示服务可用；真实账号接入结果会在操作时显示。

新安装会在权限为 `600` 的 `installation/control.env` 中生成 `TSW_CPA_WEBHOOK_SECRET`。如需接收 CPA 降智检测事件，在 CPA 插件中配置接收地址 `https://你的管理域名/internal/v1/cpa/degradation-events`，并填写同一密钥。接收端只保存、映射并展示待人工审核事件，不会自动踢出席位、邀请成员或创建轮转任务。已有安装不会被更新流程自动写入密钥；需要启用时，请手动向原 `control.env` 添加一个至少 16 字符的随机密钥并重启 control 服务。

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
