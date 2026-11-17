from django.db import models


class Host(models.Model):
    """纳管的云主机。"""

    class Status(models.TextChoices):
        NORMAL = "normal", "正常"
        SUSPECT = "suspect", "疑似"
        COMPROMISED = "compromised", "已确认中招"

    name = models.CharField("主机名", max_length=128, unique=True)
    cloud = models.CharField("云厂商/区域", max_length=64)
    role = models.CharField("业务角色", max_length=64)
    cluster = models.CharField("集群/分组", max_length=64, blank=True)
    ip_internal = models.GenericIPAddressField("内网 IP")
    ip_external = models.GenericIPAddressField("外网 IP", null=True, blank=True)
    instance_type = models.CharField("实例规格", max_length=64)
    daily_cost_baseline = models.DecimalField(
        "日费用基线(元)", max_digits=10, decimal_places=2, default=0
    )
    status = models.CharField(
        "状态", max_length=16, choices=Status.choices, default=Status.NORMAL
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "主机"
        verbose_name_plural = verbose_name
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.ip_internal})"


class CpuMetric(models.Model):
    """CPU / 网络流量时间序列点（演示环境按 1 小时粒度）。"""

    host = models.ForeignKey(
        Host, related_name="cpu_metrics", on_delete=models.CASCADE
    )
    timestamp = models.DateTimeField("时间")
    cpu_percent = models.FloatField("CPU 使用率(%)")
    load_avg = models.FloatField("负载(load1)", default=0)
    net_in_kbps = models.FloatField("入向流量(kbps)", default=0)
    net_out_kbps = models.FloatField("出向流量(kbps)", default=0)

    class Meta:
        verbose_name = "CPU 指标"
        verbose_name_plural = verbose_name
        unique_together = ("host", "timestamp")
        indexes = [models.Index(fields=["host", "timestamp"])]
        ordering = ["timestamp"]


class ProcessSnapshot(models.Model):
    """进程列表快照。"""

    host = models.ForeignKey(
        Host, related_name="process_snapshots", on_delete=models.CASCADE
    )
    timestamp = models.DateTimeField("快照时间")

    class Meta:
        verbose_name = "进程快照"
        verbose_name_plural = verbose_name
        indexes = [models.Index(fields=["host", "timestamp"])]
        ordering = ["-timestamp"]


class Process(models.Model):
    """快照中的单个进程。"""

    snapshot = models.ForeignKey(
        ProcessSnapshot, related_name="processes", on_delete=models.CASCADE
    )
    pid = models.IntegerField("PID")
    name = models.CharField("进程名", max_length=128)
    exe_path = models.CharField("可执行文件路径", max_length=512, blank=True)
    cmdline = models.TextField("完整命令行", blank=True)
    cpu_percent = models.FloatField("CPU 占用(%)", default=0)
    mem_percent = models.FloatField("内存占用(%)", default=0)

    class Meta:
        verbose_name = "进程"
        verbose_name_plural = verbose_name
        indexes = [models.Index(fields=["name"])]


class NetworkConnection(models.Model):
    """出站网络连接快照。"""

    host = models.ForeignKey(
        Host, related_name="connections", on_delete=models.CASCADE
    )
    timestamp = models.DateTimeField("时间")
    local_port = models.IntegerField("本地端口", default=0)
    remote_ip = models.GenericIPAddressField("远端 IP")
    remote_port = models.IntegerField("远端端口")
    remote_hostname = models.CharField("远端域名", max_length=255, blank=True)
    protocol = models.CharField("协议", max_length=8, default="tcp")
    process_name = models.CharField("发起进程", max_length=128, blank=True)
    bytes_sent = models.BigIntegerField("累计发送字节", default=0)
    bytes_recv = models.BigIntegerField("累计接收字节", default=0)

    class Meta:
        verbose_name = "出站连接"
        verbose_name_plural = verbose_name
        indexes = [
            models.Index(fields=["host", "timestamp"]),
            models.Index(fields=["remote_ip"]),
        ]
        ordering = ["-timestamp"]


class BillingRecord(models.Model):
    """云计费日明细。"""

    host = models.ForeignKey(
        Host, related_name="billing_records", on_delete=models.CASCADE
    )
    date = models.DateField("账期日期")
    cost = models.DecimalField("当日费用(元)", max_digits=10, decimal_places=2)
    note = models.CharField("备注", max_length=255, blank=True)

    class Meta:
        verbose_name = "计费记录"
        verbose_name_plural = verbose_name
        unique_together = ("host", "date")
        ordering = ["-date"]


class MiningPool(models.Model):
    """矿池/挖矿基础设施 IOC 清单。"""

    class IoCType(models.TextChoices):
        DOMAIN = "domain", "域名"
        IP = "ip", "IP 地址"

    name = models.CharField("矿池名称", max_length=128)
    ioc_type = models.CharField("指标类型", max_length=8, choices=IoCType.choices)
    value = models.CharField("IOC 值", max_length=255, unique=True)
    coin = models.CharField("币种", max_length=32, blank=True)
    port_hint = models.CharField("典型端口", max_length=64, blank=True)
    is_synthetic = models.BooleanField("演示用合成地址", default=False)
    enabled = models.BooleanField("启用", default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "矿池 IOC"
        verbose_name_plural = verbose_name
        ordering = ["coin", "name"]

    def __str__(self):
        return f"{self.name} {self.value}"


class Signal(models.Model):
    """检测规则命中后产生的信号（一个主机一条规则一条指纹）。"""

    class Severity(models.TextChoices):
        LOW = "low", "低"
        MEDIUM = "medium", "中"
        HIGH = "high", "高"
        CRITICAL = "critical", "严重"

    RULES = [
        ("cpu_idle_traffic", "长时间满载且无业务流量"),
        ("disguised_process", "伪装系统服务的挖矿进程"),
        ("pool_connection", "矿池地址/矿池端口通信"),
        ("billing_spike", "计费异常飙升"),
    ]

    host = models.ForeignKey(
        Host, related_name="signals", on_delete=models.CASCADE
    )
    rule = models.CharField("检测规则", max_length=32, choices=RULES)
    severity = models.CharField(
        "严重度", max_length=12, choices=Severity.choices
    )
    title = models.CharField("信号标题", max_length=255)
    detail = models.TextField("详细描述", blank=True)
    evidence = models.JSONField("结构化证据", default=dict)
    fingerprint = models.CharField("去重指纹", max_length=64)
    first_seen = models.DateTimeField("首次发现")
    last_seen = models.DateTimeField("最近发现")
    active = models.BooleanField("当前有效", default=True)
    incident = models.ForeignKey(
        "Incident",
        related_name="signals",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    class Meta:
        verbose_name = "检测信号"
        verbose_name_plural = verbose_name
        unique_together = ("host", "rule", "fingerprint")
        indexes = [models.Index(fields=["active"])]
        ordering = ["-last_seen"]


class Incident(models.Model):
    """同一批主机上关联信号归并出的入侵事件。"""

    class Status(models.TextChoices):
        OPEN = "open", "处置中"
        CONFIRMED = "confirmed", "已确认入侵"
        RESOLVED = "resolved", "已闭环"
        FALSE_POSITIVE = "false_positive", "误报"

    title = models.CharField("事件标题", max_length=255)
    status = models.CharField(
        "状态", max_length=16, choices=Status.choices, default=Status.OPEN
    )
    severity = models.CharField(
        "最高严重度", max_length=12, choices=Signal.Severity.choices
    )
    score = models.IntegerField("风险评分", default=0)
    started_at = models.DateTimeField("开始时间")
    last_seen = models.DateTimeField("最近活动")
    summary = models.TextField("事件摘要", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "入侵事件"
        verbose_name_plural = verbose_name
        ordering = ["-last_seen"]

    def __str__(self):
        return self.title


class EvidenceItem(models.Model):
    """事件证据链上的一个环节。"""

    class Stage(models.TextChoices):
        CPU = "cpu", "资源异常"
        PROCESS = "process", "进程证据"
        NETWORK = "network", "网络证据"
        BILLING = "billing", "计费证据"
        LIFECYCLE = "lifecycle", "处置记录"

    incident = models.ForeignKey(
        Incident, related_name="evidence_items", on_delete=models.CASCADE
    )
    host = models.ForeignKey(
        Host, related_name="evidence_items", on_delete=models.CASCADE, null=True
    )
    stage = models.CharField("证据阶段", max_length=12, choices=Stage.choices)
    timestamp = models.DateTimeField("证据时间")
    title = models.CharField("标题", max_length=255)
    detail = models.TextField("描述", blank=True)
    data = models.JSONField("证据数据", default=dict)

    class Meta:
        verbose_name = "证据链"
        verbose_name_plural = verbose_name
        ordering = ["timestamp", "id"]
