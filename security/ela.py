from PIL import Image, ImageChops, ImageEnhance
import numpy as np
import io


def compute_ela(image_bytes: bytes, quality=90) -> bytes:
    """Returns PNG bytes of an ELA heatmap. Higher brightness = region more
    likely to have been edited. This is a HEURISTIC signal, never the
    verification verdict — the verdict always comes from crypto_engine.verify_chain."""
    original = Image.open(io.BytesIO(image_bytes)).convert("RGB")

    buf = io.BytesIO()
    original.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    resaved = Image.open(buf)

    diff = ImageChops.difference(original, resaved)
    extrema = diff.getextrema()
    max_diff = max([ex[1] for ex in extrema]) or 1
    scale = 255.0 / max_diff
    diff = ImageEnhance.Brightness(diff).enhance(scale)

    out = io.BytesIO()
    diff.save(out, "PNG")
    return out.getvalue()
