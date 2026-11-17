"""检测调度与事件关联引擎。

流程：
  规则扫描 -> 信号 upsert 去重 -> 并查集关联 -> 生成/更新事件与证据链 -> 回写主机状态

关联关系（满足任一即归并到同一事件）：
  - 同一主机上的有效信号
  - 同集群、时间窗口重叠的信号
  - 命中同一个矿池 IOC 的信号
中等级别以下的信号只预警、不自动开事件（保留人工研判空间）。
"""

from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from .models import (
    EvidenceItem,
    Host,
    Incident,
    MiningPool,
    Signal,
)
from .rules import SEVERITY_RANK, run_all_rules

# 低于该分值的信号不自动开事件
INCIDENT_MIN_SEVERITY = "high"
# 同集群信号的关联时间重叠容差
OVERLAP_TOLERANCE = timedelta(hours=2)
RULE_STAGE = {
    "cpu_idle_traffic": EvidenceItem.Stage.CPU,
    "disguised_process": EvidenceItem.Stage.PROCESS,
    "pool_connection": EvidenceItem.Stage.NETWORK,
    "billing_spike": EvidenceItem.Stage.BILLING,
}


def _upsert_signals(raw_signals):
    """按指纹去重写入，返回数据库 Signal 对象列表。"""
    result = []
    for raw in raw_signals:
        obj, created = Signal.objects.update_or_create(
            host=raw["host"],
            rule=raw["rule"],
            fingerprint=raw["fingerprint"],
            defaults={
                "severity": raw["severity"],
                "title": raw["title"],
                "detail": raw["detail"],
                "evidence": raw["evidence"],
                "first_seen": raw["first_seen"],
                "last_seen": raw["last_seen"],
                "active": True,
            },
        )
        result.append(obj)
    return result


def _deactivate_stale_signals():
    """本轮没有重新命中的活动信号标记为失效（威胁可能已被清除）。"""
    Signal.objects.filter(active=True).update(active=False)


class _UnionFind:
    def __init__(self, items):
        self.parent = {id(x): id(x) for x in items}
        self._item = {id(x): x for x in items}

    def find(self, x):
        root = id(x)
        while self.parent[root] != root:
            self.parent[root] = self.parent[self.parent[root]]
            root = self.parent[root]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

    def groups(self):
        buckets = {}
        for x in self._item.values():
            buckets.setdefault(self.find(x), []).append(x)
        return list(buckets.values())


def _correlate(signals):
    """用并查集把有关联的信号归并为事件候选组。"""
    uf = _UnionFind(signals)

    for i, a in enumerate(signals):
        for b in signals[i + 1 :]:
            linked = False
            # 关系 1：同主机
            if a.host_id == b.host_id:
                linked = True
            # 关系 2：同集群且时间窗口重叠（含容差）
            elif (
                a.host.cluster
                and a.host.cluster == b.host.cluster
                and a.first_seen <= b.last_seen + OVERLAP_TOLERANCE
                and b.first_seen <= a.last_seen + OVERLAP_TOLERANCE
            ):
                linked = True
            # 关系 3：同一矿池 IOC
            if not linked:
                pa, pb = a.evidence.get("matched_pool"), b.evidence.get("matched_pool")
                if pa and pa == pb:
                    linked = True
            if linked:
                uf.union(a, b)
    return uf.groups()


def _severity_for_group(group):
    return max((s.severity for s in group), key=lambda x: SEVERITY_RANK[x])


def _score_for_group(group):
    """风险评分：严重度加权 + 信号数量 + 涉及主机数，封顶 100。"""
    score = sum(SEVERITY_RANK[s.severity] for s in group)
    hosts = {s.host_id for s in group}
    score += min(len(hosts), 3) * 10
    return min(score, 100)


def _build_title(group, hosts):
    host_names = "、".join(sorted(h.name for h in hosts))
    has_pool = any(s.rule == "pool_connection" for s in group)
    has_process = any(s.rule == "disguised_process" for s in group)
    if has_pool and has_process:
        kind = "挖矿木马入侵（进程+矿池通信双证据）"
    elif has_pool:
        kind = "疑似挖矿（矿池通信）"
    elif has_process:
        kind = "疑似挖矿（可疑进程）"
    else:
        kind = "算力异常占用"
    cluster = next((h.cluster for h in hosts if h.cluster), "")
    scope = f"{cluster} " if cluster else ""
    return f"{scope}{kind}：{host_names}"


def _build_summary(group, hosts, incident):
    rules = {s.get_rule_display() for s in group}
    lines = [
        f"涉及主机 {len(hosts)} 台：{'、'.join(h.name for h in hosts)}。",
        f"命中规则 {len(rules)} 类：{'、'.join(sorted(rules))}。",
        f"活动时间 {incident.started_at:%Y-%m-%d %H:%M} 至 {incident.last_seen:%m-%d %H:%m}。",
    ]
    pools = sorted(
        {s.evidence["matched_pool"] for s in group if s.evidence.get("matched_pool")}
    )
    if pools:
        lines.append(f"关联矿池：{'、'.join(pools)}。")
    return "".join(lines)


def _rebuild_evidence(incident, group):
    """根据组内信号重建时间线证据链（幂等）。"""
    EvidenceItem.objects.filter(incident=incident).delete()
    items = []
    for sig in group:
        ev = sig.evidence or {}
        stage = RULE_STAGE[sig.rule]
        if sig.rule == "cpu_idle_traffic":
            title = f"[{sig.host.name}] {sig.title}"
            detail = (
                f"持续 {ev.get('hours')} 小时，CPU 均值 {ev.get('avg_cpu_percent')}%，"
                f"出向流量均值 {ev.get('avg_net_out_kbps')}kbps"
            )
            ts = sig.first_seen
        elif sig.rule == "disguised_process":
            title = f"[{sig.host.name}] 进程取证：{ev.get('name')}（PID {ev.get('pid')}）"
            detail = "；".join(ev.get("reasons", []))
            ts = sig.last_seen
        elif sig.rule == "pool_connection":
            title = (
                f"[{sig.host.name}] 矿池连接：{ev.get('remote_ip')}:{ev.get('remote_port')}"
            )
            detail = (
                f"发起进程 {ev.get('process_name') or '未知'}，"
                f"窗口内 {ev.get('connection_count')} 次连接，"
                f"发送 {ev.get('bytes_sent', 0)} 字节 / 接收 {ev.get('bytes_recv', 0)} 字节"
            )
            ts = sig.first_seen
        else:
            title = f"[{sig.host.name}] 计费异常：{ev.get('cost')} 元（{ev.get('ratio')} 倍基线）"
            detail = sig.detail
            ts = sig.first_seen

        items.append(
            EvidenceItem(
                incident=incident,
                host=sig.host,
                stage=stage,
                timestamp=ts,
                title=title,
                detail=detail,
                data={
                    "rule": sig.rule,
                    "signal_id": sig.id,
                    "severity": sig.severity,
                    "evidence": ev,
                },
            )
        )
    EvidenceItem.objects.bulk_create(items)


def _sync_incident(group):
    hosts = {s.host for s in group}
    severity = _severity_for_group(group)
    # 弱信号组（最高仅中/低）只预警，不自动开事件，保留人工研判空间
    if SEVERITY_RANK[severity] < SEVERITY_RANK[INCIDENT_MIN_SEVERITY]:
        Signal.objects.filter(id__in=[s.id for s in group]).update(incident=None)
        return None

    started = min(s.first_seen for s in group)
    last = max(s.last_seen for s in group)

    existing = (
        Incident.objects.filter(signals__in=group, status__in=["open", "confirmed"])
        .order_by("id")
        .distinct()
        .first()
    )
    if existing:
        incident = existing
        incident.severity = severity
        incident.score = _score_for_group(group)
        incident.started_at = min(incident.started_at, started)
        incident.last_seen = max(incident.last_seen, last)
    else:
        incident = Incident.objects.create(
            title="待命名",
            severity=severity,
            score=_score_for_group(group),
            started_at=started,
            last_seen=last,
        )

    incident.title = _build_title(group, hosts)
    incident.summary = _build_summary(group, hosts, incident)
    incident.save()

    Signal.objects.filter(id__in=[s.id for s in group]).update(incident=incident)
    _rebuild_evidence(incident, group)
    return incident


def _refresh_host_status():
    for host in Host.objects.all():
        active = host.signals.filter(active=True)
        severities = set(active.values_list("severity", flat=True))
        if severities & {"critical", "high"} and active.filter(
            incident__status__in=["open", "confirmed"]
        ).exists():
            host.status = Host.Status.COMPROMISED
        elif severities:
            host.status = Host.Status.SUSPECT
        else:
            host.status = Host.Status.NORMAL
        host.save(update_fields=["status"])


def _close_orphan_incidents():
    """没有任何活动信号的在办事件自动闭环（信号消失通常意味着威胁已清除）。"""
    for incident in Incident.objects.filter(status__in=["open", "confirmed"]):
        if not incident.signals.filter(active=True).exists():
            incident.status = Incident.Status.RESOLVED
            incident.save(update_fields=["status", "updated_at"])
            EvidenceItem.objects.create(
                incident=incident,
                host=None,
                stage=EvidenceItem.Stage.LIFECYCLE,
                timestamp=timezone.now(),
                title="检测信号全部消失，事件自动闭环",
                detail="最近一轮检测未再命中任何规则，若已完成处置可归档；如为误报请手动标记。",
                data={"auto": True},
            )


@transaction.atomic
def run_detection(lookback_hours=48):
    """执行一轮完整检测，返回统计字典。"""
    _deactivate_stale_signals()

    all_signals = []
    for host in Host.objects.all():
        all_signals.extend(run_all_rules(host, lookback_hours))
    persisted = _upsert_signals(all_signals)

    incidents = []
    for group in _correlate(persisted):
        inc = _sync_incident(group)
        if inc:
            incidents.append(inc)

    _close_orphan_incidents()
    _refresh_host_status()

    return {
        "hosts_scanned": Host.objects.count(),
        "signals": len(persisted),
        "active_signals": Signal.objects.filter(active=True).count(),
        "incidents": Incident.objects.count(),
        "open_incidents": Incident.objects.filter(
            status__in=["open", "confirmed"]
        ).count(),
    }
