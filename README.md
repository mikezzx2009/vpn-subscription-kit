# VPN Subscription Kit

[![Tests](https://github.com/mikezzx2009/vpn-subscription-kit/actions/workflows/test.yml/badge.svg)](https://github.com/mikezzx2009/vpn-subscription-kit/actions/workflows/test.yml)

在一台新的 Linux 云服务器上部署 VLESS + REALITY + Vision，并生成 **FlClash 和 Shadowrocket 可直接导入的 HTTPS 订阅 URL**。无需购买域名；可选安装查看活动来源 IP、连接数和流量的监控面板。

## 支持范围

- Ubuntu 22.04 / 24.04，Debian 12 / 13；amd64 或 arm64，使用 systemd。
- 独立公网 IPv4，能够访问 GitHub、系统软件源及 Let's Encrypt。
- root 权限，或可使用 sudo；运行下方命令前需要已安装 `curl`。
- 入站 TCP `80`、`443`、`8443` 可用；开启监控还需 `8444`。

下方默认安装模式适用于干净的 VPS；已有网站必须使用[共存模式](#与已有网站共存)。IPv6-only、没有端口转发的 NAT 主机、没有 systemd 的共享容器及其他操作系统不在支持范围内。安装器会拒绝端口冲突或接管已有部署，不会修改 SSH 配置。

## 一条命令安装（独占服务器）

先在云平台安全组 / 防火墙中放行上面的端口，然后执行：

```bash
curl -q -fsSL 'https://raw.githubusercontent.com/mikezzx2009/vpn-subscription-kit/v1.1.0/install.sh' -o /tmp/vpnkit-install.sh && sudo bash /tmp/vpnkit-install.sh --accept-acme-tos
```

如果已经以 root 登录，可以省略 `sudo`。命令固定使用 `v1.1.0`，不会自动追踪开发分支。旧版 `v1.0.0` 存在系统版本变量覆盖下载地址的问题；若遇到 `curl: (3)`，请重新下载上述修正版脚本。

**`--accept-acme-tos` 表示你同意 [Let's Encrypt ACME 服务条款](https://letsencrypt.org/repository/)**，安装器会向其申请公网 IP 的 HTTPS 证书，并配置自动续期。若不同意，请勿使用该参数或运行这条安装命令。

要同时安装监控，在同一条命令末尾加上 `--with-monitor`：

```bash
curl -q -fsSL 'https://raw.githubusercontent.com/mikezzx2009/vpn-subscription-kit/v1.1.0/install.sh' -o /tmp/vpnkit-install.sh && sudo bash /tmp/vpnkit-install.sh --accept-acme-tos --with-monitor
```

也可显式指定公网 IP、节点名称和 REALITY 握手目标：

```bash
sudo bash /tmp/vpnkit-install.sh \
  --accept-acme-tos \
  --server-ip 203.0.113.10 \
  --name 'My-VPN' \
  --handshake-host dl.google.com \
  --with-monitor
```

`203.0.113.10` 是文档示例地址，必须替换为服务器实际公网 IPv4。默认握手目标为 `dl.google.com`，服务器必须能访问该目标。

## 与已有网站共存

**已有 Nginx、网站或其他业务时，使用 `--coexist`，不要停用网站或跳过端口检查。** 共存模式不占用网站的 80/443，不编辑或重启现有 Nginx，不安装/升级系统软件，不自动修改主机防火墙，不申请或修改网站证书。

需要已有 Python 3、Nginx、OpenSSL、curl、iproute2 和 systemd；缺少依赖时会在部署前退出，不会自动安装。订阅域名必须由已有、受系统信任的证书覆盖，且直接通过唯一 A 记录指向服务器公网 IPv4（无 CDN 代理及 AAAA）。如果网站使用 CDN 或 IPv6，请为订阅选择独立且受证书覆盖的 DNS 名称，不要直接改动网站的 DNS。

先下载脚本；以下域名和路径都是示例，必须换成自己已核对的实际值，再执行安装：

```bash
curl -q -fsSL 'https://raw.githubusercontent.com/mikezzx2009/vpn-subscription-kit/v1.1.0/install.sh' -o /tmp/vpnkit-install.sh
sudo bash /tmp/vpnkit-install.sh --coexist --with-monitor \
  --tls-host vpn.example.com \
  --tls-cert /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/vpn.example.com/privkey.pem
```

使用外部证书无需 `--accept-acme-tos`。若 Nginx 不在 PATH，可传 `--nginx-binary /绝对路径/nginx`；共存模式只读取现有二进制，不安装替代版本。

| 用途 | 默认 TCP 端口 | 可调整参数 |
| --- | --- | --- |
| VPN | 24443 | `--vpn-port` |
| HTTPS 订阅 | 28443 | `--subscription-port` |
| HTTPS 监控（可选） | 28444 | `--monitor-port` |
| 本机监控 API | 29090，仅绑定 127.0.0.1 | `--api-port` |

端口必须互不相同且处于 1024–65535；安装前会检查冲突。仅将 VPN、订阅和可选监控端口加入云安全组及主机防火墙，**不要开放本机 API 端口**。默认模式的 80/443/8443/8444 放行规则不适用于共存模式。

证书原文件及原续期方式由现有网站管理。VPN 只保存自己的私密副本，每小时检查外部证书，校验证书链、域名、有效期及密钥匹配后，只重载自己的订阅服务；无效更新会保留原副本。可运行 `sudo vpnkit sync-cert` 手动同步。不要发送或上传私钥文件。

共存服务使用独立 PID、配置和临时目录，VPN 核心 CPU 上限为单核的 25%、内存上限为 256 MiB；订阅服务 CPU 上限为单核的 10%、内存上限为 128 MiB。这些限制会限制 VPN 吞吐量，且**同机仍共享带宽、磁盘和内核，无法承诺性能完全不受影响**。对现有业务有严格零影响要求时应使用独立服务器。此模式不支持将已有独占安装自动迁移为共存安装。

## 导入客户端

安装完成后，终端会显示两条订阅 URL；之后也可运行：

```bash
sudo vpnkit urls
```

- **FlClash**：在配置 / Profile 中新增 URL 配置，粘贴 FlClash 订阅地址，下载并启用该配置。
- **Shadowrocket**：新增订阅，粘贴 Shadowrocket 订阅地址，更新订阅后选择新节点。

客户端需要支持 VLESS、REALITY 和 `xtls-rprx-vision`。具体按钮名称可能随客户端版本变化。把完整地址作为订阅 URL 导入；不要只填写服务器 IP。

两条订阅使用同一个节点账号。HTTPS URL 中的随机路径就是访问凭据，任何拿到完整链接的人都能获取节点配置；请只分享给你希望授权的人，不要发到公开 Issue。

安装信息保存在 `/root/vpnkit-access.txt`，只有 root 可读。

## 日常管理

```bash
sudo vpnkit urls       # 查看订阅地址及监控访问方式
sudo vpnkit status     # 查看服务状态
sudo vpnkit doctor     # 运行故障诊断
sudo vpnkit --help     # 查看命令帮助
```

重复运行安装器会保留现有 UUID、REALITY 密钥和订阅路径，不会自动生成一套新凭据。它不会接管其他工具安装的 VPN，也不会把重复安装当作升级到最新版本的命令。

### 云平台更换 IP 后

先在云平台完成公网 IP 更换，再执行：

```bash
sudo vpnkit update-ip --accept-acme-tos
```

若自动识别不正确，可显式指定新的公网 IPv4：

```bash
sudo vpnkit update-ip --accept-acme-tos --server-ip 203.0.113.10
```

该命令会更新本机配置、订阅内容和 HTTPS 证书。订阅 URL 的 IP 部分也会变化，**需要在两个客户端中替换旧订阅 URL，再更新订阅**；监控地址同样会变化。它不会向云平台申请换 IP，也不能修复网络运营商对 IP 的阻断。

### 可选监控

使用 `--with-monitor` 安装后，可查看中文概览和 [MetaCubeXD](https://github.com/MetaCubeX/metacubexd) 详细面板。访问地址和独立的随机登录密码由 `vpnkit urls` 显示，并保存在 `/root/vpnkit-access.txt`。监控默认账号为 `admin`，不会复用你的服务器密码。

请在首次安装时决定是否启用监控；此版本不支持给已经完成的无监控部署追加 `--with-monitor`。

面板以只读方式提供活动连接和流量信息。**“活跃来源 IP 数”不是人数**：同一 Wi-Fi 下多台设备可能共用一个 IP；一个人使用多个网络也可能出现多个 IP；客户端空闲时可能没有活动连接。这个版本不提供按真人计数或多人独立账号管理。

## 安装内容

下表中的系统软件安装和 Certbot 签发仅适用于独占模式。共存模式只下载 VPN 核心及可选监控页面，使用现有 Nginx 二进制和外部证书。

| 组件 | 用途 |
| --- | --- |
| [sing-box](https://github.com/SagerNet/sing-box) `1.14.0` | TCP 443 上提供 VLESS + REALITY + Vision |
| Nginx | 独立配置及服务，提供 HTTPS 订阅和可选监控 |
| Certbot `5.8.0` | 独立 Python 虚拟环境中申请、续期 IP 证书 |
| [MetaCubeXD](https://github.com/MetaCubeX/metacubexd) `1.273.1`（可选） | 活动连接详细面板 |

sing-box 使用官方发行文件并校验固定的 SHA-256。公开仓库仅保存安装代码，不托管你的订阅或节点凭据。

| 入站端口 | 用途 | 是否需要 |
| --- | --- | --- |
| TCP 80 | ACME HTTP 验证及证书续期 | 持续开放 |
| TCP 443 | VPN 节点 | 必需 |
| TCP 8443 | HTTPS 订阅 | 必需 |
| TCP 8444 | HTTPS 监控 | 使用 `--with-monitor` 时 |

检测到已启用的 UFW 或 firewalld 时，安装器添加所需规则；不会启用原本关闭的主机防火墙。**云平台安全组需要你自行放行**，修改本机防火墙不能代替这一步。SSH 原有端口和访问方式保持不变。

主要数据位置：

| 路径 | 内容 |
| --- | --- |
| `/etc/vpnkit/state.json` | 部署状态及节点凭据，仅 root 可读 |
| `/var/lib/vpnkit/subscriptions` | 客户端订阅文件 |
| `/var/lib/vpnkit/monitor` | 可选监控页面 |
| `/root/vpnkit-access.txt` | 访问地址和登录信息，仅 root 可读 |

备份时应加密保存这些包含凭据的文件。不要将它们提交到 GitHub。

## 故障排查与安全

遇到超时、订阅下载失败或换 IP 问题，先运行 `sudo vpnkit doctor`，再查看[故障排查](docs/troubleshooting.md)。提交反馈前请按[安全说明](SECURITY.md)隐藏订阅路径、UUID、密钥和密码。

本项目的安装和配置代码采用 [MIT License](LICENSE)；上游组件按各自许可证分发，详见 [第三方组件说明](THIRD_PARTY.md)。

## 验证与开发

本地运行 `python3 -m unittest discover -s tests -p 'test_*.py' -v`（证书测试需要支持 `-verify_hostname` 的 OpenSSL）。GitHub Actions 在临时 Ubuntu 22.04、24.04 和 24.04 ARM64 服务器中执行实际安装，检查 HTTPS 订阅、真实 VLESS REALITY 代理连接、监控权限、重复安装和换 IP。另在 Ubuntu 22.04/24.04 上先运行 80/443 网站，再测试共存安装、网站持续可访问、进程与配置保留及证书同步。

CI 用本地测试 CA 替代公网 ACME 签发，并严格验证 TLS；正式安装使用 Let's Encrypt。CI 不能代替目标服务器的公网端口和客户端网络可达性检查。破坏性集成脚本仅允许在明确标记的 GitHub 托管临时环境中运行。

维护者运行 `python3 scripts/package.py` 生成发行包和 SHA-256，并将校验值写入 `install.sh`。发布时必须将同一次构建的脚本、Git 标签和 `dist/` 发行附件一起发布；版本发布后不要移动标签或替换附件。
