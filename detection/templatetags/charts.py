"""轻量级内联 SVG 折线图标签，零前端依赖。"""

from django import template

register = template.Library()

_PALETTE = ["#4da3ff", "#ff7b5a", "#43d39e", "#ffd166", "#b18cff"]


@register.inclusion_tag("detection/_line_chart.html")
def line_chart(labels, series, *, height=240, y_max=None, threshold=None,
               y_unit="", x_ticks=6):
    """
    labels:  x 轴标签列表
    series:  [{"name": ..., "values": [...]}, ...]
    threshold: 可选阈值线，形如 {"value": 90, "label": "满载线 90%"}
    """
    width, pad_l, pad_r, pad_t, pad_b = 760, 48, 16, 16, 34
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    n = len(labels)

    all_values = [v for s in series for v in s["values"]]
    if threshold is not None:
        all_values.append(threshold["value"])
    data_max = max(all_values, default=1)
    top = y_max if y_max is not None else max(1, data_max * 1.15)

    def x(i):
        if n <= 1:
            return pad_l
        return pad_l + plot_w * i / (n - 1)

    def y(v):
        return pad_t + plot_h * (1 - v / top)

    drawn_series = []
    for idx, s in enumerate(series):
        color = s.get("color") or _PALETTE[idx % len(_PALETTE)]
        points = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(s["values"]))
        drawn_series.append({"name": s["name"], "color": color, "points": points})

    # y 轴 4 条网格线
    grid = [
        {"y": y(top * i / 4), "label": f"{top * i / 4:.0f}{y_unit}"}
        for i in range(5)
    ]
    threshold_line = None
    if threshold is not None:
        threshold_line = {
            "y": y(threshold["value"]),
            "label": threshold.get("label", str(threshold["value"])),
        }

    # x 轴等距抽样标签
    x_labels = []
    if n:
        step = max(1, n // x_ticks)
        for i in range(0, n, step):
            x_labels.append({"x": x(i), "label": labels[i]})
        if labels[-1] not in [xl["label"] for xl in x_labels]:
            x_labels.append({"x": x(n - 1), "label": labels[-1]})

    return {
        "width": width,
        "height": height,
        "pad_l": pad_l,
        "pad_t": pad_t,
        "plot_w": plot_w,
        "plot_h": plot_h,
        "series": drawn_series,
        "grid": grid,
        "threshold_line": threshold_line,
        "x_labels": x_labels,
    }
