from django.core.management.base import BaseCommand

from detection.models import MiningPool

# 初始矿池 IOC 清单。
# 真实条目取自公开安全报告中长期被提及的主流矿池域名（仅用于流量比对，平台不会主动连接）；
# synthetic=True 的条目使用 RFC 5737 文档保留地址 203.0.113.0/24，
# 专供演示数据命中，避免把任何真实主机 IP 写死成 IOC。
INITIAL_POOLS = [
    # --- XMR（门罗币）：主机挖矿木马最常对接 ---
    ("SupportXMR", "domain", "pool.supportxmr.com", "XMR", "3333,4444,5555,7777", False),
    ("MoneroOcean", "domain", "gulf.moneroocean.stream", "XMR", "10101,10001", False),
    ("minexmr-archive", "domain", "pool.minexmr.com", "XMR", "4444,5555", False),
    ("xmrpool.eu", "domain", "xmrpool.eu", "XMR", "3333,443", False),
    ("2Miners-XMR", "domain", "xmr.2miners.com", "XMR", "10101", False),
    ("HashVault", "domain", "pool.hashvault.pro", "XMR", "3333,4444,14444", False),
    ("Nanopool-XMR", "domain", "xmr-eu1.nanopool.org", "XMR", "14444", False),
    ("SupportXMR-CN(演示合成)", "ip", "203.0.113.10", "XMR", "18081", True),
    ("MoneroOcean-CN(演示合成)", "ip", "203.0.113.40", "XMR", "14444", True),
    # --- BTC / 通用矿池 ---
    ("F2Pool", "domain", "tcp.f2pool.com", "BTC", "3333,8888", False),
    ("AntPool", "domain", "stratum.antpool.com", "BTC", "3333,443,1800", False),
    ("BTC.com Pool", "domain", "stratum.btc.com", "BTC", "3333,443", False),
    ("Slush Pool", "domain", "stratum.slushpool.com", "BTC", "3333", False),
    ("ViaBTC", "domain", "stratum-dallas.viabtc.com", "BTC", "3333,25", False),
    # --- ETHW / ETC / RVN 等显卡矿币种 ---
    ("Ethermine-ETC", "domain", "etc.ethermine.org", "ETC", "4444,5555", False),
    ("2Miners-ETHW", "domain", "ethw.2miners.com", "ETHW", "2020", False),
    ("NiceHash", "domain", "stratum+tcp://randomxmonero.auto.nicehash.com", "XMR", "9200", False),
    ("NanoPool-ETH(归档)", "domain", "eth-eu1.nanopool.org", "ETH", "14444", False),
]


class Command(BaseCommand):
    help = "初始化矿池 IOC 清单（幂等，按 value 去重）"

    def handle(self, *args, **options):
        created, skipped = 0, 0
        for name, ioc_type, value, coin, ports, synthetic in INITIAL_POOLS:
            _, was_created = MiningPool.objects.get_or_create(
                value=value,
                defaults={
                    "name": name,
                    "ioc_type": ioc_type,
                    "coin": coin,
                    "port_hint": ports,
                    "is_synthetic": synthetic,
                },
            )
            if was_created:
                created += 1
            else:
                skipped += 1
        self.stdout.write(
            self.style.SUCCESS(
                f"矿池 IOC 初始化完成：新增 {created} 条，已存在跳过 {skipped} 条，"
                f"当前共 {MiningPool.objects.count()} 条"
            )
        )
