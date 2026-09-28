# 第三方组件

VPN Subscription Kit 的安装及配置代码采用 [MIT License](LICENSE)。以下第三方项目拥有独立的版权和许可证；本项目的 MIT 许可证不会替代其许可证。

本仓库不内嵌这些组件的程序包或前端构建文件。安装器在运行时从上游官方发布渠道下载相应版本；Nginx 和其他系统依赖由操作系统软件源提供。

| 组件 | 固定版本 | 上游许可证 | 项目及源码 |
| --- | --- | --- | --- |
| sing-box | `1.14.0` | GPL-3.0-or-later | [项目](https://github.com/SagerNet/sing-box) · [版本源码与许可证](https://github.com/SagerNet/sing-box/tree/v1.14.0) |
| MetaCubeXD（可选） | `1.273.1` | MIT | [项目](https://github.com/MetaCubeX/metacubexd) · [版本源码与许可证](https://github.com/MetaCubeX/metacubexd/tree/v1.273.1) |
| Certbot | `5.8.0` | Apache-2.0 | [项目](https://github.com/certbot/certbot) · [版本源码与许可证](https://github.com/certbot/certbot/tree/v5.8.0) |

分发上游组件、修改后的版本或包含它们的镜像时，请遵守对应许可证对版权声明、许可证副本、源码及其他材料的要求。上游源代码和许可证以链接的具体发布版本为准。

Let's Encrypt 是证书签发服务，其 [ACME 服务条款](https://letsencrypt.org/repository/) 属于使用服务时的协议，与上述软件许可证不同。
