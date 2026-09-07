"""
VeriTrace Editorial Verifier Engine (FC-03-B: Legitimate Edit & Content Forgery Discrimination)
Distinguishes authorized newsroom transformations (cropping, format recompression, declared masking)
from malicious content modifications (>= 15% content forgery).
"""
import io
import math
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from PIL import Image, ImageChops, ImageFile
from scipy.signal import fftconvolve
from scipy.ndimage import binary_closing, generate_binary_structure, label, find_objects

ImageFile.LOAD_TRUNCATED_IMAGES = True


def _create_diff_heatmap(norm_array: np.ndarray) -> bytes:
    """
    Renders an anomalous difference map into a thermal/color-coded PNG image.
    Cool/Dark Blue = identical; Cyan = compression noise; Bright Red = Content Forgery.
    """
    clipped = np.clip(norm_array, 0.0, 1.0)
    # Red channel highlights significant deviations
    r = np.clip(2.0 * clipped - 0.2, 0.0, 1.0)
    g = np.clip(1.8 * (1.0 - np.abs(clipped - 0.5)), 0.0, 1.0)
    b = np.clip(1.5 * (1.0 - clipped) - 0.2, 0.0, 1.0)

    rgb = np.stack([r, g, b], axis=-1)
    rgb_uint8 = (rgb * 255).astype(np.uint8)

    img = Image.fromarray(rgb_uint8, mode="RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def detect_subwindow_crop(genesis_img: Image.Image, candidate_img: Image.Image) -> Dict[str, Any]:
    """
    Locates where a cropped candidate image originated inside the Genesis original asset.
    Uses multi-resolution normalized cross-correlation for high speed and robustness against JPEG artifacts.
    """
    gw, gh = genesis_img.size
    cw, ch = candidate_img.size

    # If candidate is identical or larger, default to (0, 0, gw, gh)
    if cw >= gw and ch >= gh:
        return {
            "found": True,
            "x": 0, "y": 0,
            "width": gw, "height": gh,
            "confidence": 1.0,
            "method": "identity"
        }

    # Downsample for fast coarse alignment
    scale = min(0.25, 200.0 / max(gw, gh))
    scale = max(scale, 0.05)

    gen_small = genesis_img.convert("L").resize((max(8, int(gw * scale)), max(8, int(gh * scale))), Image.Resampling.BILINEAR)
    cand_small = candidate_img.convert("L").resize((max(4, int(cw * scale)), max(4, int(ch * scale))), Image.Resampling.BILINEAR)

    g_arr = np.array(gen_small, dtype=np.float32)
    c_arr = np.array(cand_small, dtype=np.float32)

    c_zm = c_arr - np.mean(c_arr)
    c_rot = np.rot90(c_zm, 2)

    corr = fftconvolve(g_arr, c_rot, mode="valid")
    if corr.size == 0:
        return {
            "found": False,
            "x": 0, "y": 0,
            "width": min(gw, cw), "height": min(gh, ch),
            "confidence": 0.0,
            "method": "fallback"
        }

    y_peak, x_peak = np.unravel_index(np.argmax(corr), corr.shape)
    est_x = int(round(x_peak / scale))
    est_y = int(round(y_peak / scale))

    # Clamp coordinates inside genesis bounds
    est_x = max(0, min(est_x, gw - cw))
    est_y = max(0, min(est_y, gh - ch))

    # Local refinement in a +-8 pixel neighborhood at 1x resolution
    search_x0 = max(0, est_x - 8)
    search_x1 = min(gw - cw, est_x + 8)
    search_y0 = max(0, est_y - 8)
    search_y1 = min(gh - ch, est_y + 8)

    best_x, best_y = est_x, est_y
    min_diff = float("inf")

    c_full = np.array(candidate_img.convert("L"), dtype=np.float32)
    step = 2 if (search_x1 - search_x0 > 4 or search_y1 - search_y0 > 4) else 1

    for cy in range(search_y0, search_y1 + 1, step):
        for cx in range(search_x0, search_x1 + 1, step):
            crop_patch = genesis_img.convert("L").crop((cx, cy, cx + cw, cy + ch))
            g_patch = np.array(crop_patch, dtype=np.float32)
            d = float(np.mean(np.abs(g_patch - c_full)))
            if d < min_diff:
                min_diff = d
                best_x, best_y = cx, cy

    confidence = max(0.0, min(1.0, 1.0 - (min_diff / 80.0)))

    return {
        "found": confidence > 0.40,
        "x": best_x,
        "y": best_y,
        "width": cw,
        "height": ch,
        "confidence": round(confidence, 4),
        "method": "multi_scale_correlation"
    }


def evaluate_editorial_transformation(
    genesis_bytes: bytes,
    candidate_bytes: bytes,
    manifest: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates whether a candidate asset is an authorized editorial transformation (crop/recompression/declared redaction)
    or contains unauthorized malicious modifications exceeding the 15% content forgery threshold.

    Parameters:
        genesis_bytes   : Raw bytes of the certified Genesis original asset
        candidate_bytes : Raw bytes of the candidate file being verified
        manifest        : Optional declared editorial recipe dictionary:
                          {
                             "crop": {"x": int, "y": int, "width": int, "height": int},
                             "redacted_boxes": [{"x": int, "y": int, "width": int, "height": int}],
                             "target_quality": int
                          }
    Returns:
        Dictionary with forensic metrics:
        - is_legitimate_transform (bool)
        - is_content_forgery (bool: True if >= 15% forgery threshold)
        - forgery_ratio (float: 0.0 to 1.0)
        - forgery_percent (float: 0.0% to 100.0%)
        - forged_regions (List of bounding boxes)
        - aligned_crop (Dict with x, y, width, height)
        - ssim_score (float)
        - summary (str)
        - diff_heatmap_png (bytes)
    """
    gen_img = Image.open(io.BytesIO(genesis_bytes)).convert("RGB")
    cand_img = Image.open(io.BytesIO(candidate_bytes)).convert("RGB")
    cw, ch = cand_img.size
    total_pixels = cw * ch

    declared_crop = None
    declared_redactions = []
    if manifest and isinstance(manifest, dict):
        if "crop" in manifest and isinstance(manifest["crop"], dict):
            declared_crop = manifest["crop"]
        if "redacted_boxes" in manifest and isinstance(manifest["redacted_boxes"], list):
            declared_redactions = list(manifest["redacted_boxes"])
        if "operations" in manifest and isinstance(manifest["operations"], list):
            for op in manifest["operations"]:
                if isinstance(op, dict):
                    op_type = str(op.get("type", "")).upper()
                    params = op.get("parameters", {})
                    if op_type == "CROP" and isinstance(params, dict):
                        declared_crop = params
                    elif op_type in ("REDACTION_BOX", "REDACT", "MASK") and isinstance(params, dict):
                        declared_redactions.append(params)

    # 1. Align candidate against Genesis
    if declared_crop and all(k in declared_crop for k in ("x", "y", "width", "height")):
        crop_x = int(declared_crop["x"])
        crop_y = int(declared_crop["y"])
        crop_w = int(declared_crop["width"])
        crop_h = int(declared_crop["height"])
        gen_crop = gen_img.crop((crop_x, crop_y, crop_x + crop_w, crop_y + crop_h))
        if gen_crop.size != cand_img.size:
            gen_crop = gen_crop.resize(cand_img.size, Image.Resampling.BILINEAR)
        alignment_info = {"x": crop_x, "y": crop_y, "width": crop_w, "height": crop_h, "confidence": 1.0, "method": "declared_manifest"}
    else:
        alignment_info = detect_subwindow_crop(gen_img, cand_img)
        crop_x, crop_y = alignment_info["x"], alignment_info["y"]
        crop_w, crop_h = alignment_info["width"], alignment_info["height"]
        gen_crop = gen_img.crop((crop_x, crop_y, crop_x + crop_w, crop_y + crop_h))
        if gen_crop.size != cand_img.size:
            gen_crop = gen_crop.resize(cand_img.size, Image.Resampling.BILINEAR)

    cand_arr = np.array(cand_img, dtype=np.float32)
    gen_arr = np.array(gen_crop, dtype=np.float32)

    # 2. Compute absolute RGB delta
    diff_rgb = np.abs(cand_arr - gen_arr)
    diff_max = np.max(diff_rgb, axis=2) # Peak color channel delta

    # 3. Suppress declared redaction boxes (authorized blackouts/blur)
    mask_redactions = np.zeros((ch, cw), dtype=bool)
    for box in declared_redactions:
        if isinstance(box, dict) and all(k in box for k in ("x", "y", "width", "height")):
            bx, by = int(box["x"]), int(box["y"])
            bw, bh = int(box["width"]), int(box["height"])
            bx0 = max(0, min(bx, cw))
            by0 = max(0, min(by, ch))
            bx1 = max(0, min(bx + bw, cw))
            by1 = max(0, min(by + bh, ch))
            mask_redactions[by0:by1, bx0:bx1] = True

    # 4. Filter compression noise
    # Typical JPEG recompression error across photographic edges is <= 32
    # Anomalous content modifications exhibit sharp deviations > 35
    anom_pixels = (diff_max > 35.0) & (~mask_redactions)

    # 5. Morphological clustering: group adjacent altered pixels, filter isolated noise
    struct = generate_binary_structure(2, 2)
    clustered_anom = binary_closing(anom_pixels, structure=struct, iterations=3)

    # Extract bounding boxes of distinct forged clusters
    labeled_clusters, num_clusters = label(clustered_anom, structure=struct)
    slices = find_objects(labeled_clusters)

    forged_regions = []
    significant_forged_pixels = 0

    for slc in slices:
        y_slice, x_slice = slc
        patch = clustered_anom[y_slice, x_slice]
        patch_pixels = int(np.sum(patch))
        # Ignore tiny speckles (< 64 pixels)
        if patch_pixels >= 64:
            significant_forged_pixels += patch_pixels
            forged_regions.append({
                "x": int(x_slice.start),
                "y": int(y_slice.start),
                "width": int(x_slice.stop - x_slice.start),
                "height": int(y_slice.stop - y_slice.start),
                "altered_pixels": patch_pixels
            })

    # Sort largest forged clusters first
    forged_regions.sort(key=lambda r: r["altered_pixels"], reverse=True)

    # Calculate Surface Area Ratio
    forgery_ratio = significant_forged_pixels / max(1, total_pixels)
    forgery_percent = round(forgery_ratio * 100.0, 2)

    # SSIM approximation
    mean_diff = float(np.mean(diff_max))
    ssim_approx = max(0.0, min(1.0, 1.0 - (mean_diff / 128.0)))

    # Decision Thresholds
    # FC-03-B: 15% content forgery boundary
    is_content_forgery = (forgery_ratio >= 0.15)
    is_legitimate = (forgery_ratio < 0.05) and (alignment_info.get("confidence", 1.0) >= 0.50)

    if is_content_forgery:
        summary = f"CRITICAL CONTENT FORGERY: {forgery_percent}% altered surface area exceeds the 15% editorial tolerance threshold."
    elif is_legitimate:
        summary = f"Authorized editorial transformation verified: {forgery_percent}% alteration within benign crop/compression tolerance."
    else:
        summary = f"Uncertain modification: {forgery_percent}% alteration detected without declared transformation manifest."

    # Generate visual heatmap
    norm_diff = np.clip(diff_max / 100.0, 0.0, 1.0)
    # Highlight clustered anomalous regions in bright red
    norm_diff[clustered_anom] = 1.0
    diff_png = _create_diff_heatmap(norm_diff)

    return {
        "is_legitimate_transform": is_legitimate,
        "is_content_forgery": is_content_forgery,
        "forgery_ratio": round(forgery_ratio, 4),
        "forgery_percent": forgery_percent,
        "forgery_threshold_percent": 15.0,
        "forged_regions": forged_regions,
        "aligned_crop": alignment_info,
        "ssim_approx": round(ssim_approx, 4),
        "declared_redactions_applied": len(declared_redactions),
        "summary": summary,
        "diff_heatmap_png": diff_png
    }
