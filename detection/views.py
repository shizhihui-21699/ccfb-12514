from datetime import timedelta

from django.contrib import messages
from django.db.models import Avg, Count, Q, Sum
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .models import (
    BillingRecord,
    CpuMetric,
    EvidenceItem,
    Host,
    Incident,
    MiningPool,
    Signal,
)

HOURS_48 = timedelta(hours=48)
DAYS_7 = timedelta(days=7)


def dashboard(request):
    now = timezone.now()
    since = now - HOURS_48

    hosts = Host.objects.all()
    incidents = Incident.objects.prefetch_related("signals").order_by("-last_seen")
    active_signals = Signal.objects.filter(active=True).select_related("host")

    cost_rows = (
        BillingRecord.objects.filter(date__gte=(now - DAYS_7).date())
        .values("date")
        .annotate(total=Sum("cost"))
        .order_by("date")
    )
    cost_labels = [r["date"].strftime("%m-%d") for r in cost_rows]
    cost_values = [float(r["total"]) for r in cost_rows]

    cpu_rows = (
        CpuMetric.objects.filter(timestamp__gte=since)
        .values("timestamp")
        .annotate(avg=Avg("cpu_percent"))
        .order_by("timestamp")
    )
    cpu_labels = [r["timestamp"].strftime("%m-%d %H:%M") for r in cpu_rows]
    cpu_values = [round(r["avg"] or 0, 1) for r in cpu_rows]

    context = {
        "host_total": hosts.count(),
        "host_compromised": hosts.filter(status="compromised").count(),
        "host_suspect": hosts.filter(status="suspect").count(),
        "open_incident_count": incidents.filter(
            status__in=["open", "confirmed"]
        ).count(),
        "active_signal_count": active_signals.count(),
        "week_total_cost": round(sum(cost_values), 2),
        "incidents": incidents[:10],
        "risk_hosts": hosts.exclude(status="normal"),
        "cost_labels": cost_labels,
        "cost_series": [{"name": "每日总费用(元)", "values": cost_values}],
        "cpu_labels": cpu_labels,
        "cpu_series": [{"name": "平均 CPU(%)", "values": cpu_values}],
        "cpu_threshold": {"value": 90, "label": "满载线 90%"},
    }
    return render(request, "detection/dashboard.html", context)


def incident_list(request):
    incidents = (
        Incident.objects.annotate(host_count=Count("signals__host", distinct=True))
        .order_by("-last_seen")
    )
    return render(request, "detection/incident_list.html", {"incidents": incidents})


def incident_detail(request, pk):
    incident = get_object_or_404(Incident, pk=pk)
    signals = incident.signals.select_related("host").order_by("-last_seen")
    hosts = Host.objects.filter(signals__in=signals).distinct()
    evidence = incident.evidence_items.select_related("host").order_by("timestamp")

    # 证据链按阶段分组，便于页面分区呈现
    stages = []
    for code, label in EvidenceItem.Stage.choices:
        items = [e for e in evidence if e.stage == code]
        if items:
            stages.append({"code": code, "label": label, "items": items})

    if request.method == "POST":
        new_status = request.POST.get("status")
        if new_status in dict(Incident.Status.choices):
            incident.status = new_status
            incident.save(update_fields=["status", "updated_at"])
            messages.success(
                request, f"事件状态已更新为「{incident.get_status_display()}」"
            )
            return redirect("detection:incident_detail", pk=incident.pk)

    context = {
        "incident": incident,
        "signals": signals,
        "hosts": hosts,
        "stages": stages,
        "status_choices": Incident.Status.choices,
    }
    return render(request, "detection/incident_detail.html", context)


def host_list(request):
    hosts = Host.objects.annotate(
        signal_count=Count(
            "signals", filter=Q(signals__active=True), distinct=True
        )
    )
    return render(request, "detection/host_list.html", {"hosts": hosts})


def host_detail(request, pk):
    host = get_object_or_404(Host, pk=pk)
    since = timezone.now() - HOURS_48
    metrics = host.cpu_metrics.filter(timestamp__gte=since).order_by("timestamp")
    latest_snapshot = host.process_snapshots.order_by("-timestamp").first()
    processes = (
        latest_snapshot.processes.order_by("-cpu_percent") if latest_snapshot else []
    )
    connections = (
        host.connections.filter(timestamp__gte=since).order_by("-timestamp")[:30]
    )
    billing = list(host.billing_records.order_by("-date")[:20])
    signals = host.signals.filter(active=True).order_by("-last_seen")

    cpu_labels = [m.timestamp.strftime("%m-%d %H:%M") for m in metrics]
    cpu_values = [m.cpu_percent for m in metrics]
    out_values = [m.net_out_kbps for m in metrics]
    bill_labels = [b.date.strftime("%m-%d") for b in billing][::-1]
    bill_values = [float(b.cost) for b in billing][::-1]
    baseline = float(host.daily_cost_baseline or 0)
    for b in billing:
        b.ratio = round(float(b.cost) / baseline, 2) if baseline else 0

    context = {
        "host": host,
        "latest_snapshot": latest_snapshot,
        "processes": processes,
        "connections": connections,
        "signals": signals,
        "cpu_labels": cpu_labels,
        "cpu_series": [{"name": "CPU(%)", "values": cpu_values}],
        "cpu_threshold": {"value": 90, "label": "满载线 90%"},
        "out_series": [{"name": "出向流量(kbps)", "values": out_values}],
        "bill_labels": bill_labels,
        "bill_series": [{"name": "日费用(元)", "values": bill_values}],
        "bill_threshold": {"value": baseline * 2.5, "label": f"飙升线 {baseline * 2.5:.0f} 元"},
        "billing": billing,
        "baseline": baseline,
    }
    return render(request, "detection/host_detail.html", context)


def pool_list(request):
    pools = MiningPool.objects.all().order_by("coin", "name")
    return render(request, "detection/pool_list.html", {"pools": pools})
