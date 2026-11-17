from django.core.management.base import BaseCommand

from detection.engine import run_detection


class Command(BaseCommand):
    help = "对全部主机重新执行一轮挖矿行为检测与事件关联"

    def add_arguments(self, parser):
        parser.add_argument("--hours", type=int, default=48, help="检测回溯窗口（小时）")

    def handle(self, *args, **options):
        stats = run_detection(lookback_hours=options["hours"])
        self.stdout.write(
            self.style.SUCCESS(
                "检测完成：扫描 {hosts_scanned} 台主机，信号 {signals} 条（活动 {active_signals}），"
                "事件 {incidents} 起（处置中 {open_incidents}）".format(**stats)
            )
        )
