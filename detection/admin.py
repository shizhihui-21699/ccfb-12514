from django.contrib import admin

from .models import (
    BillingRecord,
    CpuMetric,
    EvidenceItem,
    Host,
    Incident,
    MiningPool,
    NetworkConnection,
    Process,
    ProcessSnapshot,
    Signal,
)


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ("name", "cluster", "role", "cloud", "ip_internal",
                    "daily_cost_baseline", "status")
    list_filter = ("status", "cluster", "cloud")
    search_fields = ("name", "ip_internal", "role")


@admin.register(CpuMetric)
class CpuMetricAdmin(admin.ModelAdmin):
    list_display = ("host", "timestamp", "cpu_percent", "net_out_kbps")
    list_filter = ("host",)
    date_hierarchy = "timestamp"


@admin.register(ProcessSnapshot)
class ProcessSnapshotAdmin(admin.ModelAdmin):
    list_display = ("host", "timestamp")
    list_filter = ("host",)


@admin.register(Process)
class ProcessAdmin(admin.ModelAdmin):
    list_display = ("name", "pid", "cpu_percent", "mem_percent", "snapshot")
    search_fields = ("name", "exe_path", "cmdline")
    list_filter = ("snapshot__host",)


@admin.register(NetworkConnection)
class NetworkConnectionAdmin(admin.ModelAdmin):
    list_display = ("host", "timestamp", "remote_ip", "remote_port",
                    "remote_hostname", "process_name")
    list_filter = ("host",)
    search_fields = ("remote_ip", "remote_hostname")


@admin.register(BillingRecord)
class BillingRecordAdmin(admin.ModelAdmin):
    list_display = ("host", "date", "cost", "note")
    list_filter = ("host",)
    date_hierarchy = "date"


@admin.register(MiningPool)
class MiningPoolAdmin(admin.ModelAdmin):
    list_display = ("name", "coin", "ioc_type", "value", "port_hint",
                    "is_synthetic", "enabled")
    list_filter = ("coin", "ioc_type", "is_synthetic", "enabled")
    search_fields = ("name", "value")


class SignalInline(admin.TabularInline):
    model = Signal
    extra = 0
    fields = ("rule", "severity", "title", "active", "first_seen", "last_seen")
    readonly_fields = ("rule", "severity", "title", "first_seen", "last_seen")
    show_change_link = True


class EvidenceInline(admin.TabularInline):
    model = EvidenceItem
    extra = 0
    fields = ("stage", "timestamp", "host", "title")
    readonly_fields = ("stage", "timestamp", "host", "title")


@admin.register(Signal)
class SignalAdmin(admin.ModelAdmin):
    list_display = ("title", "host", "rule", "severity", "active",
                    "incident", "first_seen", "last_seen")
    list_filter = ("rule", "severity", "active")
    search_fields = ("title", "detail")
    readonly_fields = ("fingerprint",)


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "score", "status", "started_at", "last_seen")
    list_filter = ("status", "severity")
    search_fields = ("title", "summary")
    inlines = [SignalInline, EvidenceInline]


@admin.register(EvidenceItem)
class EvidenceItemAdmin(admin.ModelAdmin):
    list_display = ("incident", "stage", "host", "timestamp", "title")
    list_filter = ("stage",)
    search_fields = ("title", "detail")
