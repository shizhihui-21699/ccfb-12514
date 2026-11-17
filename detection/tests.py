from datetime import timedelta
from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from .engine import run_detection
from .models import (
    BillingRecord,
    CpuMetric,
    Host,
    Incident,
    MiningPool,
    NetworkConnection,
    Process,
    ProcessSnapshot,
    Signal,
)
from .rules import (
    detect_cpu_idle_traffic,
    detect_disguised_processes,
    detect_pool_connections,
    detect_billing_spike,
)


def make_host(name="h1", cluster="c1", baseline="10.00"):
    return Host.objects.create(
        name=name, cloud="test/zone", role="测试机", cluster=cluster,
        ip_internal="10.0.0.1", instance_type="test.small",
        daily_cost_baseline=Decimal(baseline),
    )


def cpu_series(host, hours, cpu, out=50):
    now = timezone.now().replace(minute=0, second=0, microsecond=0)
    CpuMetric.objects.bulk_create([
        CpuMetric(host=host, timestamp=now - timedelta(hours=hours - 1 - i),
                  cpu_percent=cpu, load_avg=2, net_in_kbps=10, net_out_kbps=out)
        for i in range(hours)
    ])


class RuleTests(TestCase):
    def setUp(self):
        self.host = make_host()
        self.now = timezone.now().replace(minute=0, second=0, microsecond=0)
        self.since = self.now - timedelta(hours=48)

    def test_cpu_rule_hits_on_sustained_full_load_silent_traffic(self):
        cpu_series(self.host, 12, cpu=97, out=40)
        signals = detect_cpu_idle_traffic(self.host, self.since)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["rule"], "cpu_idle_traffic")
        self.assertIn("hours", signals[0]["evidence"])

    def test_cpu_rule_ignores_busy_traffic(self):
        cpu_series(self.host, 12, cpu=97, out=5000)
        self.assertEqual(detect_cpu_idle_traffic(self.host, self.since), [])

    def test_cpu_rule_requires_duration(self):
        cpu_series(self.host, 3, cpu=99, out=10)
        self.assertEqual(detect_cpu_idle_traffic(self.host, self.since), [])

    def test_disguised_system_process_in_tmp(self):
        snap = ProcessSnapshot.objects.create(host=self.host, timestamp=self.now)
        Process.objects.create(snapshot=snap, pid=1, name="systemd-update",
                               exe_path="/tmp/.x/systemd-update",
                               cmdline="./systemd-update", cpu_percent=80)
        signals = detect_disguised_processes(self.host, self.since)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["severity"], "high")

    def test_known_miner_with_stratum_cmdline_is_critical(self):
        snap = ProcessSnapshot.objects.create(host=self.host, timestamp=self.now)
        Process.objects.create(
            snapshot=snap, pid=2, name="xmrig", exe_path="/tmp/xmrig/xmrig",
            cmdline="xmrig --url 203.0.113.10:18081 --user 48UmFq" + "A" * 89,
            cpu_percent=95,
        )
        signals = detect_disguised_processes(self.host, self.since)
        self.assertEqual(signals[0]["severity"], "critical")

    def test_legit_systemd_not_flagged(self):
        snap = ProcessSnapshot.objects.create(host=self.host, timestamp=self.now)
        Process.objects.create(snapshot=snap, pid=1, name="systemd",
                               exe_path="/usr/lib/systemd/systemd",
                               cmdline="/usr/lib/systemd/systemd", cpu_percent=1)
        self.assertEqual(detect_disguised_processes(self.host, self.since), [])

    def test_pool_ioc_match(self):
        MiningPool.objects.create(name="P", ioc_type="ip", value="203.0.113.10",
                                  coin="XMR", is_synthetic=True)
        NetworkConnection.objects.create(
            host=self.host, timestamp=self.now, remote_ip="203.0.113.10",
            remote_port=18081, process_name="xmrig",
        )
        signals = detect_pool_connections(self.host, self.since)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["severity"], "critical")
        self.assertEqual(signals[0]["evidence"]["matched_pool"], "P")

    def test_mining_port_without_ioc_is_high(self):
        NetworkConnection.objects.create(
            host=self.host, timestamp=self.now, remote_ip="198.51.100.9",
            remote_port=3333, process_name="kworker/30",
        )
        signals = detect_pool_connections(self.host, self.since)
        self.assertEqual(signals[0]["severity"], "high")

    def test_benign_port_ignored(self):
        NetworkConnection.objects.create(
            host=self.host, timestamp=self.now, remote_ip="10.0.0.9",
            remote_port=3306, process_name="nginx",
        )
        self.assertEqual(detect_pool_connections(self.host, self.since), [])

    def test_billing_spike(self):
        today = self.now.date()
        BillingRecord.objects.create(host=self.host, date=today,
                                     cost=Decimal("32.00"))
        signals = detect_billing_spike(self.host, self.since)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["evidence"]["ratio"], 3.2)

    def test_billing_normal_ignored(self):
        BillingRecord.objects.create(host=self.host, date=self.now.date(),
                                     cost=Decimal("10.50"))
        self.assertEqual(detect_billing_spike(self.host, self.since), [])


class CorrelationTests(TestCase):
    def _compromise(self, host, pool_ip="203.0.113.10", pool_name="P"):
        now = timezone.now().replace(minute=0, second=0, microsecond=0)
        cpu_series(host, 10, cpu=96, out=30)
        snap = ProcessSnapshot.objects.create(host=host, timestamp=now)
        Process.objects.create(
            snapshot=snap, pid=9, name="systemd-update",
            exe_path="/tmp/.s/systemd-update", cpu_percent=90,
            cmdline=f"--url {pool_ip}:18081",
        )
        MiningPool.objects.get_or_create(
            value=pool_ip,
            defaults={"name": pool_name, "ioc_type": "ip", "coin": "XMR",
                      "is_synthetic": True},
        )
        NetworkConnection.objects.create(
            host=host, timestamp=now, remote_ip=pool_ip,
            remote_port=18081, process_name="systemd-update",
        )
        BillingRecord.objects.create(host=host, date=now.date(),
                                     cost=host.daily_cost_baseline * 3)

    def test_cluster_hosts_merge_into_one_incident(self):
        h1 = make_host("web-01", cluster="web-cluster")
        h2 = make_host("web-02", cluster="web-cluster")
        self._compromise(h1)
        self._compromise(h2)

        stats = run_detection()
        self.assertEqual(stats["open_incidents"], 1)
        incident = Incident.objects.get()
        self.assertEqual(incident.signals.values("host").distinct().count(), 2)
        self.assertEqual(incident.evidence_items.count(), 8)  # 4 规则 × 2 主机
        h1.refresh_from_db()
        self.assertEqual(h1.status, Host.Status.COMPROMISED)

    def test_separate_clusters_form_separate_incidents(self):
        h1 = make_host("web-01", cluster="web-cluster")
        h2 = make_host("redis-01", cluster="cache-cluster")
        self._compromise(h1, "203.0.113.10", "P1")
        self._compromise(h2, "203.0.113.40", "P2")
        run_detection()
        self.assertEqual(Incident.objects.count(), 2)

    def test_rerun_detection_is_idempotent(self):
        h1 = make_host("web-01", cluster="web-cluster")
        self._compromise(h1)
        run_detection()
        run_detection()
        self.assertEqual(Incident.objects.count(), 1)
        self.assertEqual(Signal.objects.filter(active=True).count(), 4)

    def test_medium_only_signals_do_not_open_incident(self):
        host = make_host("lone-01", cluster="")
        snap = ProcessSnapshot.objects.create(
            host=host, timestamp=timezone.now()
        )
        # 可疑路径 + 中等 CPU，只产生 medium
        Process.objects.create(
            snapshot=snap, pid=5, name="java-worker",
            exe_path="/var/tmp/.j/java-worker", cpu_percent=40,
            cmdline="java-worker --mode background",
        )
        run_detection()
        self.assertEqual(Incident.objects.count(), 0)
        self.assertTrue(Signal.objects.filter(active=True).exists())
        host.refresh_from_db()
        self.assertEqual(host.status, Host.Status.SUSPECT)
