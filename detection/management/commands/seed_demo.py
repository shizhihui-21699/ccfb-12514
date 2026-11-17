"""生成演示环境：10 台主机、2 起挖矿入侵事件、1 台疑似主机。

数据全部由固定随机种子生成，可重复执行（--flush 清库重建）。
时间线以"当前时间"为锚点向前铺 48 小时指标与 20 天计费。
"""

import random
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from detection.engine import run_detection
from detection.models import (
    BillingRecord,
    CpuMetric,
    Host,
    NetworkConnection,
    Process as Proc,
    ProcessSnapshot,
)

RNG = random.Random(20261118)
BASE58 = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789"
WALLET = "48UmFq" + "".join(RNG.choice(BASE58) for _ in range(89))

# (name, cloud, role, cluster, internal_ip, external_ip, spec, baseline, 状态标签)
HOST_SPECS = [
    ("web-01", "阿里云/杭州", "前端 Web 服务器", "web-cluster", "10.20.10.11", "47.92.16.21", "ecs.c7.4xlarge", "48.00", "infected_a"),
    ("web-02", "阿里云/杭州", "前端 Web 服务器", "web-cluster", "10.20.10.12", "47.92.16.22", "ecs.c7.4xlarge", "48.00", "infected_a"),
    ("web-03", "阿里云/杭州", "前端 Web 服务器", "web-cluster", "10.20.10.13", "47.92.16.23", "ecs.c7.4xlarge", "48.00", "normal"),
    ("redis-cache-01", "阿里云/杭州", "Redis 缓存", "cache-cluster", "10.20.20.11", "8.31.4.91", "ecs.g7.2xlarge", "36.00", "infected_b"),
    ("mysql-01", "阿里云/杭州", "MySQL 主库", "data-cluster", "10.20.30.10", "", "ecs.r7.4xlarge", "72.00", "normal"),
    ("kafka-01", "阿里云/杭州", "Kafka 消息队列", "data-cluster", "10.20.30.20", "", "ecs.g7.4xlarge", "60.00", "normal"),
    ("api-01", "阿里云/上海", "订单 API", "api-cluster", "10.40.10.11", "101.132.40.8", "ecs.c7.2xlarge", "42.00", "normal"),
    ("api-02", "阿里云/上海", "订单 API", "api-cluster", "10.40.10.12", "101.132.40.9", "ecs.c7.2xlarge", "42.00", "normal"),
    ("bastion-01", "阿里云/上海", "运维跳板机", "", "10.40.0.10", "121.40.88.12", "ecs.t6.large", "18.00", "normal"),
    ("test-runner-01", "阿里云/上海", "CI 测试执行机", "", "10.40.50.30", "39.101.192.7", "ecs.g7.2xlarge", "30.00", "suspect"),
]

# 每类角色的常驻业务进程（合法路径，作为伪装对照）
BASELINE_PROCESSES = {
    "web": [("nginx", "/usr/sbin/nginx", 7), ("php-fpm", "/usr/sbin/php-fpm", 11),
            ("node", "/usr/bin/node", 14), ("sshd", "/usr/sbin/sshd", 1),
            ("systemd", "/usr/lib/systemd/systemd", 1), ("rsyslogd", "/usr/sbin/rsyslogd", 1)],
    "cache": [("redis-server", "/usr/local/bin/redis-server", 18), ("sshd", "/usr/sbin/sshd", 1),
              ("systemd", "/usr/lib/systemd/systemd", 1), ("node_exporter", "/usr/local/bin/node_exporter", 2)],
    "data": [("mysqld", "/usr/sbin/mysqld", 22), ("sshd", "/usr/sbin/sshd", 1),
             ("systemd", "/usr/lib/systemd/systemd", 1), ("tuned", "/usr/bin/tuned", 1)],
    "api": [("java", "/usr/lib/jvm/bin/java", 26), ("sshd", "/usr/sbin/sshd", 1),
            ("systemd", "/usr/lib/systemd/systemd", 1), ("envoy", "/usr/local/bin/envoy", 4)],
    "ops": [("sshd", "/usr/sbin/sshd", 2), ("systemd", "/usr/lib/systemd/systemd", 1),
            ("ansible-playbook", "/usr/bin/ansible-playbook", 6)],
    "test": [("python3", "/usr/bin/python3", 19), ("dockerd", "/usr/bin/dockerd", 5),
             ("containerd", "/usr/bin/containerd", 3), ("sshd", "/usr/sbin/sshd", 1)],
}
ROLE_KIND = {
    "前端 Web 服务器": "web", "Redis 缓存": "cache", "MySQL 主库": "data",
    "Kafka 消息队列": "data", "订单 API": "api", "运维跳板机": "ops", "CI 测试执行机": "test",
}

# 三台中招主机各自的挖矿程序伪装
MINER_PROFILE = {
    "infected_a_web-01": {
        "name": "systemd-update", "exe": "/tmp/.systemd/systemd-update",
        "cmdline": f"/tmp/.systemd/systemd-update -o 203.0.113.10:18081 -u {WALLET} --donate-level 1 --background",
        "cpu": 96,
    },
    "infected_a_web-02": {
        "name": "kworker/30", "exe": "/dev/shm/.k/kworker",
        "cmdline": f"/dev/shm/.k/kworker --pool stratum+tcp://203.0.113.10:18081 --wallet {WALLET}",
        "cpu": 95,
    },
    "infected_b": {
        "name": "xmrig", "exe": "/tmp/xmrig/xmrig",
        "cmdline": f"/tmp/xmrig/xmrig --url 203.0.113.40:14444 --user {WALLET} --coin monero --cpu-max-threads-hint 100",
        "cpu": 97,
    },
}

POOL_CONN = {
    "infected_a": ("203.0.113.10", 18081, "pool.supportxmr.com", "SupportXMR-CN(演示合成)"),
    "infected_b": ("203.0.113.40", 14444, "gulf.moneroocean.stream", "MoneroOcean-CN(演示合成)"),
}

# 感染开始时间（距锚点终点的小时数）
INFECT_AFTER = {"infected_a": 30, "infected_b": 20, "suspect": 8}


class Command(BaseCommand):
    help = "生成挖矿入侵演示数据并执行一轮检测"

    def add_arguments(self, parser):
        parser.add_argument("--flush", action="store_true", help="先清空检测库全部数据")

    def handle(self, *args, **options):
        if options["flush"]:
            from detection.models import EvidenceItem, Incident, Signal

            for model in (EvidenceItem, Signal, Incident, BillingRecord,
                          NetworkConnection, Proc, ProcessSnapshot,
                          CpuMetric, Host):
                model.objects.all().delete()
            self.stdout.write("已清空旧演示数据")

        if Host.objects.exists():
            self.stdout.write(self.style.WARNING("主机数据已存在，跳过生成（可加 --flush 重建）"))
            return

        now = timezone.now().replace(minute=0, second=0, microsecond=0)
        metric_hours = [now - timedelta(hours=47 - i) for i in range(48)]
        snapshot_hours = [metric_hours[i] for i in range(0, 48, 4)]

        hosts = {}
        for spec in HOST_SPECS:
            (name, cloud, role, cluster, ip_in, ip_out, inst, baseline, tag) = spec
            hosts[name] = (
                Host.objects.create(
                    name=name, cloud=cloud, role=role, cluster=cluster,
                    ip_internal=ip_in, ip_external=ip_out or None,
                    instance_type=inst, daily_cost_baseline=baseline,
                ),
                tag,
            )

        metric_batch, snapshot_batch, proc_batch, conn_batch, billing_batch = [], [], [], [], []

        for name, (host, tag) in hosts.items():
            kind = ROLE_KIND[host.role]
            is_infected_tag = tag in ("infected_a", "infected_b")
            infect_idx = 48 - INFECT_AFTER[tag] if is_infected_tag else None
            pool = POOL_CONN.get(tag)
            miner_key = tag if tag == "infected_b" else f"{tag}_{name}"
            miner = MINER_PROFILE.get(miner_key)

            # ---- 1. CPU / 流量时序 ----
            for idx, ts in enumerate(metric_hours):
                infected = infect_idx is not None and idx >= infect_idx
                if infected:
                    cpu = round(RNG.uniform(94, 99.5), 1)
                    load = round(cpu / 25 + RNG.uniform(0.5, 1.5), 2)
                    net_in = round(RNG.uniform(8, 60), 1)
                    net_out = round(RNG.uniform(15, 140), 1)
                elif tag == "suspect" and idx >= 48 - 8:
                    # 用确定性上限保证稳定低于 90% 阈值，不触发规则 1
                    cpu = round(min(88.0, RNG.uniform(80, 95)), 1)
                    load = round(cpu / 25, 2)
                    # 有明显出向流量，与"满载静默"的挖矿形态区分
                    net_in = round(RNG.uniform(400, 900), 1)
                    net_out = round(RNG.uniform(500, 1200), 1)
                else:
                    wave = 28 + 12 * abs((idx % 24) - 12) / 12
                    cpu = round(max(6, wave + RNG.uniform(-7, 7)), 1)
                    load = round(cpu / 25 + RNG.uniform(0, 0.6), 2)
                    net_in = round(RNG.uniform(900, 5200), 1)
                    net_out = round(RNG.uniform(800, 6100), 1)
                metric_batch.append(
                    CpuMetric(host=host, timestamp=ts, cpu_percent=cpu,
                              load_avg=load, net_in_kbps=net_in, net_out_kbps=net_out)
                )

            # ---- 2. 进程快照 ----
            for s_idx, ts in enumerate(snapshot_hours):
                hour_idx = metric_hours.index(ts)
                snap = ProcessSnapshot(host=host, timestamp=ts)
                snapshot_batch.append(snap)
                pid_base = RNG.randint(400, 900)
                for p_idx, (pname, exe, pcpu) in enumerate(BASELINE_PROCESSES[kind]):
                    proc_batch.append(Proc(
                        snapshot=snap, pid=pid_base + p_idx * 7, name=pname,
                        exe_path=exe, cmdline=f"{exe} --daemon" if pname != "sshd" else exe,
                        cpu_percent=round(max(0.2, pcpu + RNG.uniform(-2, 2)), 1),
                        mem_percent=round(RNG.uniform(0.3, 4), 1),
                    ))
                infected_now = infect_idx is not None and hour_idx >= infect_idx
                if infected_now and miner:
                    proc_batch.append(Proc(
                        snapshot=snap, pid=31337 + s_idx, name=miner["name"],
                        exe_path=miner["exe"], cmdline=miner["cmdline"],
                        cpu_percent=round(miner["cpu"] + RNG.uniform(-2, 2), 1),
                        mem_percent=round(RNG.uniform(1.5, 3.2), 1),
                    ))
                if tag == "suspect" and hour_idx >= 48 - 8:
                    proc_batch.append(Proc(
                        snapshot=snap, pid=28410, name="java-worker",
                        exe_path="/var/tmp/.jvm/java-worker",
                        cmdline="/var/tmp/.jvm/java-worker --mode background",
                        cpu_percent=round(RNG.uniform(34, 48), 1),
                        mem_percent=round(RNG.uniform(2, 5), 1),
                    ))

            # ---- 3. 出站连接 ----
            for s_idx, ts in enumerate(snapshot_hours):
                hour_idx = metric_hours.index(ts)
                # 良性连接
                benign = [
                    ("10.20.30.10", 3306, "", "mysql", "tcp"),
                    ("10.20.0.2", 123, "", "chronyd", "udp"),
                    ("100.100.30.12", 80, "mirrors.cloud.internal", "yum", "tcp"),
                ]
                for bip, bport, bhost, bproc, proto in benign[: 2 + s_idx % 2]:
                    conn_batch.append(NetworkConnection(
                        host=host, timestamp=ts, local_port=RNG.randint(30000, 60000),
                        remote_ip=bip, remote_port=bport, remote_hostname=bhost,
                        protocol=proto, process_name=bproc,
                        bytes_sent=RNG.randint(2_000, 800_000),
                        bytes_recv=RNG.randint(10_000, 4_000_000),
                    ))
                infected_now = infect_idx is not None and hour_idx >= infect_idx
                if infected_now and pool:
                    ip, port, hostname, _ = pool
                    elapsed = (hour_idx - infect_idx)
                    conn_batch.append(NetworkConnection(
                        host=host, timestamp=ts, local_port=RNG.randint(40000, 60000),
                        remote_ip=ip, remote_port=port, remote_hostname=hostname,
                        protocol="tcp", process_name=miner["name"],
                        bytes_sent=200_000 + elapsed * 90_000 + RNG.randint(0, 40_000),
                        bytes_recv=40_000 + elapsed * 12_000,
                    ))
                if tag == "suspect" and hour_idx >= 48 - 8:
                    # 可疑外连但端口不在矿池端口表 -> 只留弱信号给人工研判
                    conn_batch.append(NetworkConnection(
                        host=host, timestamp=ts, local_port=51220,
                        remote_ip="198.51.100.77", remote_port=8443,
                        remote_hostname="update.corp-ops.example", protocol="tcp",
                        process_name="java-worker",
                        bytes_sent=120_000 + RNG.randint(0, 30_000),
                        bytes_recv=8_000,
                    ))

            # ---- 4. 20 天计费 ----
            baseline = float(host.daily_cost_baseline)
            infected_days = 2 if tag in ("infected_a", "infected_b") else 0
            for d in range(19, -1, -1):
                day = (now - timedelta(days=d)).date()
                if infected_days and d < infected_days:
                    ratio = RNG.uniform(2.8, 3.4)
                    note = "云监控：CPU 持续高占用，费用异常"
                elif tag == "suspect" and d == 0:
                    ratio = RNG.uniform(1.3, 1.6)  # 不够 2.5 倍，不触发计费规则
                    note = ""
                else:
                    ratio = RNG.uniform(0.92, 1.08)
                    note = ""
                billing_batch.append(BillingRecord(
                    host=host, date=day, cost=round(baseline * ratio, 2), note=note,
                ))

        CpuMetric.objects.bulk_create(metric_batch)
        ProcessSnapshot.objects.bulk_create(snapshot_batch)
        Proc.objects.bulk_create(proc_batch)
        NetworkConnection.objects.bulk_create(conn_batch)
        BillingRecord.objects.bulk_create(billing_batch)

        self.stdout.write(self.style.SUCCESS(
            f"演示数据生成完成：{Host.objects.count()} 台主机 / "
            f"{CpuMetric.objects.count()} 条指标 / {Proc.objects.count()} 条进程 / "
            f"{NetworkConnection.objects.count()} 条连接 / {BillingRecord.objects.count()} 条计费"
        ))

        stats = run_detection()
        self.stdout.write(self.style.SUCCESS(
            "检测完成：扫描 {hosts_scanned} 台，活动信号 {active_signals} 条，"
            "事件 {incidents} 起（处置中 {open_incidents}）".format(**stats)
        ))
