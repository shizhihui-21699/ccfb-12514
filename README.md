# MineWatch · 挖矿入侵发现平台（Django 演示项目）

面向云主机被植入挖矿程序场景的检测与事件复盘平台。汇总主机 **CPU 曲线、进程列表快照、
出站连接、云计费明细** 四类遥测，用规则识别挖矿迹象，并把同一批主机上的关联信号归并成
一次带完整证据链的入侵事件。

## 检测能力

| 规则 | 识别迹象 | 默认阈值 |
|---|---|---|
| `cpu_idle_traffic` 长时间满载且无业务流量 | CPU 持续 ≥90% 同时出向流量 <200kbps | 连续 ≥6 小时 |
| `disguised_process` 伪装系统服务的挖矿进程 | 仿冒 `systemd-/kworker` 等命名却位于 `/tmp`、`/dev/shm`；命中 xmrig/kdevtmpfsi 等已知家族；命令行含 stratum 参数或钱包地址 | 进程 CPU ≥30% |
| `pool_connection` 矿池地址/端口通信 | 命中矿池 IOC 清单，或连接 3333/4444/14444 等矿池常用 stratum 端口 | 48h 窗口 |
| `billing_spike` 计费异常飙升 | 日费用相对主机基线异常上涨 | ≥2.5 倍基线 |

阈值集中在 `detection/rules.py` 顶部，复盘后可直接调参。

## 事件关联逻辑

检测引擎（`detection/engine.py`）每轮执行：规则扫描 → 信号按指纹去重 →
并查集关联 → 事件/证据链重建 → 主机状态回写。满足任一关系即归并为同一事件：

1. 同一台主机上的信号；
2. 同一集群、时间窗口重叠（2 小时容差）的信号；
3. 命中同一个矿池 IOC 的信号。

只有中/低级别信号的主机不会自动开事件，保留为「疑似」待人工研判；
在办事件的信号全部消失时自动闭环并写入一条生命周期证据。

## 快速开始

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python manage.py migrate
python manage.py seed_pools     # 初始化矿池 IOC 清单（18 条，幂等）
python manage.py seed_demo --flush   # 生成演示数据并自动跑一轮检测
python manage.py runserver
```

打开 http://127.0.0.1:8000 。后台 `/admin/` 可用 `python manage.py createsuperuser` 建账号。

常用命令：

```bash
python manage.py run_detection --hours 48   # 重新执行检测（幂等）
python manage.py test detection             # 15 个规则/关联测试
```

## 演示数据剧本

10 台主机、48 小时小时级指标、每 4 小时一次进程/连接快照、20 天日计费：

- **事件一（web-cluster）**：`web-01`、`web-02` 被同一波入侵，分别伪装成
  `systemd-update`（`/tmp/.systemd/`）和 `kworker/30`（`/dev/shm/.k/`），
  持续 30 小时满载、连接同一个演示矿池 `203.0.113.10:18081`，日费涨约 3 倍 → 8 条证据。
- **事件二（cache-cluster）**：`redis-cache-01` 直接跑裸奔的 `xmrig`，
  连接 `203.0.113.40:14444` → 4 条证据。
- **疑似（不开事件）**：`test-runner-01` 的 `/var/tmp/.jvm/java-worker` 有可疑路径与外连，
  但 CPU 未越阈值、外连端口不在矿池表，只产生中等级别信号供研判。
- 其余 6 台为正常业务主机，作为基线对照。

## 矿池 IOC 清单说明

初始 18 条（`seed_pools` 命令）：

- **真实条目**：SupportXMR、MoneroOcean、minexmr、HashVault、Nanopool、2Miners、
  F2Pool、AntPool、BTC.com、Slush Pool、ViaBTC、Ethermine、NiceHash 等公开安全报告中
  长期出现的矿池域名，仅用于流量比对，平台不会主动发起任何连接；
- **合成条目（`is_synthetic=True`）**：使用 RFC 5737 文档保留地址
  `203.0.113.10` / `203.0.113.40`，专供演示数据命中，避免把真实主机 IP 写死成 IOC。
  生产环境应替换为团队情报源（如威胁情报平台 API）定期同步的指标。

演示命令行中的钱包地址为符合 Monero 地址格式的随机合成串，不对应任何真实钱包。

## 代码结构

```
detection/
├── models.py        # 主机/指标/进程/连接/计费/IOC/信号/事件/证据链 9 个模型
├── rules.py         # 四条检测规则与阈值
├── engine.py        # 调度、并查集关联、证据链生成、状态回写
├── views.py         # 总览/事件/主机/IOC 页面
├── admin.py         # 后台管理
├── tests.py         # 规则命中与事件关联测试
├── templatetags/    # 零依赖内联 SVG 折线图
└── management/commands/
    ├── seed_pools.py    # IOC 清单初始化
    ├── seed_demo.py     # 演示数据生成
    └── run_detection.py # 检测重跑
```

> 演示项目使用 SQLite 与内置 runserver，`SECRET_KEY/DEBUG` 均为开发配置，
> 生产部署需切换数据库/WSGI 服务并接入真实主机 Agent 上报通道。
