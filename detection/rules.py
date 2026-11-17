"""挖矿行为检测规则库。

四条规则各自独立扫描，产出统一形态的信号字典，交由 engine 去重与关联：
  1. cpu_idle_traffic  长时间 CPU 满载但业务流量极低
  2. disguised_process 进程名伪装成系统服务 / 已知挖矿程序特征
  3. pool_connection   命中矿池 IOC、矿池端口或 stratum 协议特征
  4. billing_spike     日费用相对基线异常飙升
"""

import hashlib
import re
from datetime import datetime, time as datetime_time, timedelta

from django.db.models import Avg, Max
from django.utils import timezone

from .models import (
    BillingRecord,
    CpuMetric,
    MiningPool,
    NetworkConnection,
    Process,
    ProcessSnapshot,
)

# ---- 规则阈值（集中管理，便于复盘后调参） ----
CPU_HIGH_THRESHOLD = 90.0          # CPU 满载线
TRAFFIC_IDLE_KBPS = 200.0          # 业务流量"静默"线（出向）
MIN_FULL_LOAD_HOURS = 6            # 连续满载最少小时数
LOOKBACK_HOURS = 48                # 检测窗口
BILLING_SPIKE_RATIO = 2.5          # 费用相对基线飙升倍数
PROCESS_CPU_MIN = 30.0             # 可疑进程的最低 CPU 占用
SUSPICIOUS_PATH_RE = re.compile(r"/tmp/|/dev/shm/|/var/tmp/|\.\./|/run/shm/")
STRATUM_RE = re.compile(r"stratum\+tcp|stratum2|--url\s*\S+|--pool\s*\S+|--wallet", re.I)
WALLET_RE = re.compile(r"(4[0-9AB][0-9A-HJ-NP-Za-km-z]{93}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})")

# 公开报告中常见的挖矿程序名 / 木马家族
KNOWN_MINER_NAMES = {
    "xmrig", "cpuminer", "minerd", "kdevtmpfsi", "kinsing", "kthreaddi",
    "sysupdate", "networkstatus", "sysguard", "watchbog", "masscan",
    "dbused", "xmr-stak", "ethminer", "nbminer", "phoenixminer", "t-rex",
    "nanominer", "nicehashminer", "cryptominer",
}

# 系统服务/内核线程常见命名前缀，挖矿木马最爱仿冒
SYSTEM_NAME_PREFIXES = (
    "system", "kthread", "kworker", "ksoftirq", "kblockd", "rcu_",
    "watchdog", "journal", "systemd", "dbus", "sshd", "cron", "init",
    "udevd", "rsyslogd", "chronyd", "ntpd",
)

# 真实系统服务的标准路径前缀；伪装进程的 exe_path 往往不在这里
LEGIT_PATH_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/sbin/", "/bin/")

# 主流币种矿池常用 stratum 端口
MINING_PORTS = {
    3333, 3334, 3357, 4444, 4570, 5555, 5730, 7777, 8888, 9332,
    14444, 14433, 10001, 10101, 20535, 20536,
}

SEVERITY_RANK = {"low": 10, "medium": 20, "high": 40, "critical": 70}


def _fingerprint(parts):
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


def _signal(host, rule, severity, title, detail, evidence, fp_parts, first_seen, last_seen):
    return {
        "host": host,
        "rule": rule,
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": evidence,
        "fingerprint": _fingerprint(fp_parts),
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


# ---------- 规则 1：长时间满载 + 无业务流量 ----------
def detect_cpu_idle_traffic(host, since):
    metrics = list(
        CpuMetric.objects.filter(host=host, timestamp__gte=since).order_by("timestamp")
    )
    if not metrics:
        return []

    # 找出最长的连续"高 CPU + 低出向流量"区段
    best, current = [], []
    for m in metrics:
        if m.cpu_percent >= CPU_HIGH_THRESHOLD and m.net_out_kbps < TRAFFIC_IDLE_KBPS:
            current.append(m)
            if len(current) > len(best):
                best = list(current)
        else:
            current = []

    if len(best) < MIN_FULL_LOAD_HOURS:
        return []

    avg_cpu = sum(m.cpu_percent for m in best) / len(best)
    avg_out = sum(m.net_out_kbps for m in best) / len(best)
    avg_in = sum(m.net_in_kbps for m in best) / len(best)
    severity = "critical" if len(best) >= 24 else "high"
    evidence = {
        "hours": len(best),
        "avg_cpu_percent": round(avg_cpu, 1),
        "avg_net_out_kbps": round(avg_out, 1),
        "avg_net_in_kbps": round(avg_in, 1),
        "threshold_cpu": CPU_HIGH_THRESHOLD,
        "threshold_traffic_kbps": TRAFFIC_IDLE_KBPS,
        "window_start": best[0].timestamp.isoformat(),
        "window_end": best[-1].timestamp.isoformat(),
    }
    return [
        _signal(
            host,
            "cpu_idle_traffic",
            severity,
            f"连续 {len(best)} 小时 CPU 满载（均值 {avg_cpu:.0f}%）但业务流量近乎为零",
            (
                f"{best[0].timestamp:%Y-%m-%d %H:%M} 至 {best[-1].timestamp:%m-%d %H:%M}，"
                f"CPU 均值 {avg_cpu:.1f}%，出向流量均值仅 {avg_out:.0f}kbps，"
                "符合挖矿程序占满算力、不产生业务流量的典型特征。"
            ),
            evidence,
            ["cpu", host.id, best[0].timestamp.strftime("%Y%m%d%H")],
            best[0].timestamp,
            best[-1].timestamp,
        )
    ]


# ---------- 规则 2：伪装系统服务 / 挖矿进程 ----------
def detect_disguised_processes(host, since):
    snapshots = ProcessSnapshot.objects.filter(host=host, timestamp__gte=since)
    if not snapshots:
        return []
    latest = snapshots.order_by("-timestamp").first()
    processes = Process.objects.filter(snapshot=latest).select_related()

    signals = []
    for p in processes:
        name_l = p.name.lower()
        looks_like_system = name_l.startswith(SYSTEM_NAME_PREFIXES)
        legit_path = p.exe_path.startswith(LEGIT_PATH_PREFIXES)
        suspicious_path = bool(p.exe_path and SUSPICIOUS_PATH_RE.search(p.exe_path))
        cmdline_blob = f"{p.cmdline} {p.exe_path}"
        has_miner_args = bool(STRATUM_RE.search(cmdline_blob) or WALLET_RE.search(cmdline_blob))
        known_miner = name_l in KNOWN_MINER_NAMES

        reasons = []
        severity = None
        if known_miner or has_miner_args:
            severity = "critical"
            if known_miner:
                reasons.append(f"进程名命中已知挖矿程序/木马家族：{p.name}")
            if has_miner_args:
                reasons.append("命令行包含 stratum 矿池参数或钱包地址")
        elif looks_like_system and (suspicious_path or not legit_path):
            severity = "high"
            reasons.append(
                f"进程名仿冒系统服务「{p.name}」，但可执行文件位于非常规路径 {p.exe_path or '(空)'}"
            )
        elif suspicious_path and p.cpu_percent >= PROCESS_CPU_MIN:
            severity = "medium"
            reasons.append(f"进程运行在临时/共享内存目录且 CPU 占用 {p.cpu_percent:.0f}%")

        if not severity:
            continue

        evidence = {
            "pid": p.pid,
            "name": p.name,
            "exe_path": p.exe_path,
            "cmdline": p.cmdline[:500],
            "cpu_percent": round(p.cpu_percent, 1),
            "mem_percent": round(p.mem_percent, 1),
            "snapshot_at": latest.timestamp.isoformat(),
            "reasons": reasons,
        }
        signals.append(
            _signal(
                host,
                "disguised_process",
                severity,
                f"可疑挖矿进程：{p.name}（PID {p.pid}，CPU {p.cpu_percent:.0f}%）",
                "；".join(reasons),
                evidence,
                ["proc", host.id, name_l, p.pid],
                latest.timestamp,
                latest.timestamp,
            )
        )
    return signals


# ---------- 规则 3：矿池 IOC / 矿池端口通信 ----------
def detect_pool_connections(host, since):
    conns = list(
        NetworkConnection.objects.filter(host=host, timestamp__gte=since).order_by("timestamp")
    )
    if not conns:
        return []

    pools = list(MiningPool.objects.filter(enabled=True))
    pool_by_ip = {p.value: p for p in pools if p.ioc_type == "ip"}
    pool_by_domain = {p.value.lower(): p for p in pools if p.ioc_type == "domain"}

    # 按 (远端 IP, 端口) 聚合命中，保留首次/末次连接
    grouped = {}
    for c in conns:
        matched_pool = pool_by_ip.get(c.remote_ip)
        if not matched_pool and c.remote_hostname:
            matched_pool = pool_by_domain.get(c.remote_hostname.lower())
        is_mining_port = c.remote_port in MINING_PORTS
        if not matched_pool and not is_mining_port:
            continue

        key = (c.remote_ip, c.remote_port)
        item = grouped.setdefault(
            key,
            {
                "conn": c,
                "pool": matched_pool,
                "mining_port": is_mining_port,
                "first": c.timestamp,
                "last": c.timestamp,
                "count": 0,
                "sent": 0,
                "recv": 0,
            },
        )
        item["first"] = min(item["first"], c.timestamp)
        item["last"] = max(item["last"], c.timestamp)
        item["count"] += 1
        item["sent"] = max(item["sent"], c.bytes_sent)
        item["recv"] = max(item["recv"], c.bytes_recv)

    signals = []
    for (ip, port), item in grouped.items():
        c, pool = item["conn"], item["pool"]
        if pool:
            severity = "critical"
            title = f"出站连接命中矿池 IOC：{pool.name}（{ip}:{port}）"
            reason = f"连接目标与 IOC 清单「{pool.name}」({pool.coin}) 匹配"
        else:
            severity = "high"
            title = f"连接疑似矿池 stratum 端口 {ip}:{port}"
            reason = f"远端端口 {port} 为矿池常用 stratum 端口，无对应业务解释"

        evidence = {
            "remote_ip": ip,
            "remote_port": port,
            "remote_hostname": c.remote_hostname,
            "protocol": c.protocol,
            "process_name": c.process_name,
            "connection_count": item["count"],
            "bytes_sent": item["sent"],
            "bytes_recv": item["recv"],
            "matched_pool": pool.name if pool else None,
            "ioc_value": pool.value if pool else None,
            "first_seen": item["first"].isoformat(),
            "last_seen": item["last"].isoformat(),
        }
        signals.append(
            _signal(
                host,
                "pool_connection",
                severity,
                title,
                f"{reason}；发起进程 {c.process_name or '未知'}，窗口内观测到 {item['count']} 次连接。",
                evidence,
                ["conn", host.id, ip, port],
                item["first"],
                item["last"],
            )
        )
    return signals


# ---------- 规则 4：计费飙升 ----------
def detect_billing_spike(host, since):
    baseline = float(host.daily_cost_baseline or 0)
    if baseline <= 0:
        return []

    # 只看检测窗口覆盖到的账期
    start_date = since.date()
    records = BillingRecord.objects.filter(host=host, date__gte=start_date).order_by("date")
    worst = None
    for r in records:
        ratio = float(r.cost) / baseline
        if ratio >= BILLING_SPIKE_RATIO and (worst is None or ratio > worst[1]):
            worst = (r, ratio)
    if worst is None:
        return []

    record, ratio = worst
    severity = "critical" if ratio >= 5 else "high"
    evidence = {
        "date": record.date.isoformat(),
        "cost": float(record.cost),
        "baseline": baseline,
        "ratio": round(ratio, 2),
        "note": record.note,
    }
    return [
        _signal(
            host,
            "billing_spike",
            severity,
            f"日费用飙升至基线的 {ratio:.1f} 倍（{record.date:%m-%d}）",
            (
                f"{record.date:%Y-%m-%d} 费用 {record.cost:.2f} 元，"
                f"基线 {baseline:.2f} 元/日，涨幅 {ratio:.1f} 倍。{record.note}"
            ),
            evidence,
            ["bill", host.id, record.date.isoformat()],
            timezone.make_aware(datetime.combine(record.date, datetime_time.min)),
            timezone.now(),
        )
    ]


def run_all_rules(host, lookback_hours=LOOKBACK_HOURS):
    """对单台主机执行全部规则，返回原始信号列表。"""
    since = timezone.now() - timedelta(hours=lookback_hours)
    signals = []
    for fn in (
        detect_cpu_idle_traffic,
        detect_disguised_processes,
        detect_pool_connections,
        detect_billing_spike,
    ):
        signals.extend(fn(host, since))
    return signals
