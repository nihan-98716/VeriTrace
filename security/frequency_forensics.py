"""
VeriTrace Spatial & Frequency Domain Image Forensics Engine
Provides 2D Fast Fourier Transform (2D-FFT) and 8x8 Block Discrete Cosine Transform (Block-DCT)
for detecting generative AI lattice artifacts and localized image splicing.
"""
import io
import math
from typing import Dict, Any, Tuple, Optional, List
import numpy as np
from PIL import Image, ImageOps
import scipy.fft as sfft


def _create_heatmap_image(norm_array: np.ndarray) -> bytes:
    """
    Takes 2D float array normalized between 0.0 and 1.0, applies high-contrast
    forensic thermal colormap (Dark Blue -> Cyan -> Yellow -> Bright Red/White),
    and returns PNG bytes.
    """
    clipped = np.clip(norm_array, 0.0, 1.0)
    
    # 3-channel RGB mapping
    r = np.clip(1.5 * clipped - 0.2, 0.0, 1.0)
    g = np.clip(2.0 * (1.0 - np.abs(clipped - 0.5)), 0.0, 1.0)
    b = np.clip(1.5 * (1.0 - clipped) - 0.2, 0.0, 1.0)
    
    rgb = np.stack([r, g, b], axis=-1)
    rgb_uint8 = (rgb * 255).astype(np.uint8)
    
    img = Image.fromarray(rgb_uint8, mode="RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def compute_2d_fft_spectrum(image_bytes: bytes) -> Dict[str, Any]:
    """
    Computes 2D-FFT power spectrum and checks for periodic generative AI (Diffusion/GAN) lattice spikes
    using radial frequency residual analysis and reflection symmetry.
    """
    from scipy.ndimage import maximum_filter

    img = Image.open(io.BytesIO(image_bytes)).convert("L")
    arr = np.array(img, dtype=np.float32)
    h, w = arr.shape
    cy, cx = h // 2, w // 2
    
    # 2D Fast Fourier Transform
    f = np.fft.fft2(arr)
    fshift = np.fft.fftshift(f)
    
    # Log magnitude spectrum
    magnitude = np.abs(fshift)
    log_spectrum = np.log1p(magnitude)
    
    # Normalize spectrum for display
    s_min, s_max = log_spectrum.min(), log_spectrum.max()
    norm_spectrum = (log_spectrum - s_min) / (s_max - s_min + 1e-8)
    
    # Coordinate grids for radial frequency analysis
    y, x = np.ogrid[:h, :w]
    r = np.sqrt((x - cx)**2 + (y - cy)**2)
    
    min_dim = min(h, w)
    r_min = min_dim * 0.08
    r_max = min_dim * 0.45
    band_mask = (r >= r_min) & (r <= r_max)

    # Compute radial average profile
    r_int = np.clip(r.astype(int), 0, int(r_max) + 1)
    r_bins = int(r_max) + 2
    r_sums = np.bincount(r_int[band_mask], weights=log_spectrum[band_mask], minlength=r_bins)
    r_counts = np.bincount(r_int[band_mask], minlength=r_bins)
    r_counts[r_counts == 0] = 1
    r_profile = r_sums / r_counts

    # Subtract expected smooth 1/f falloff curve
    expected_radial = r_profile[r_int]
    residual = log_spectrum - expected_radial

    band_residual = residual[band_mask]
    res_std = float(np.std(band_residual))
    res_mean = float(np.mean(band_residual))

    # Local maxima in 5x5 window (filters out continuous noise tails)
    local_max = (log_spectrum == maximum_filter(log_spectrum, size=5))
    peak_mask = band_mask & local_max

    prominent_spikes = int(np.sum((residual > (res_mean + 4.5 * res_std)) & peak_mask))
    severe_spikes = int(np.sum((residual > (res_mean + 6.0 * res_std)) & peak_mask))

    # Reflection symmetry: check if spikes have conjugate harmonic counter-peaks
    spike_y, spike_x = np.where((residual > (res_mean + 4.5 * res_std)) & peak_mask)
    symmetric_count = 0
    for sy, sx in zip(spike_y, spike_x):
        opp_y, opp_x = 2 * cy - sy, 2 * cx - sx
        if 0 <= opp_y < h and 0 <= opp_x < w:
            if residual[opp_y, opp_x] > (res_mean + 3.5 * res_std):
                symmetric_count += 1

    metric = (prominent_spikes * 0.5) + (symmetric_count * 1.5) + (severe_spikes * 2.0)
    ai_confidence = min(0.98, max(0.02, metric / 25.0))
    is_ai_suspect = ai_confidence > 0.50

    png_bytes = _create_heatmap_image(norm_spectrum)
    
    return {
        "fft_png_bytes": png_bytes,
        "peak_count": prominent_spikes,
        "ai_synthesis_probability": round(ai_confidence, 2),
        "is_ai_suspect": is_ai_suspect,
        "summary": f"Periodic high-frequency lattice harmonics detected (generative AI grid artifacts, {prominent_spikes} prominent peaks)" if is_ai_suspect else "Natural continuous frequency spectrum (no AI grid artifacts)"
    }


def compute_block_dct_splicing(image_bytes: bytes, original_bytes: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Analyzes 8x8 block DCT coefficients to detect compression inconsistencies,
    edge feathering, and foreign spliced additions.
    If original_bytes are supplied, performs exact differential block-DCT localization.
    """
    img = Image.open(io.BytesIO(image_bytes)).convert("L")
    arr = np.array(img, dtype=np.float32)
    h, w = arr.shape
    
    # Align to 8x8 grid
    h_aligned = (h // 8) * 8
    w_aligned = (w // 8) * 8
    arr = arr[:h_aligned, :w_aligned]
    
    blocks_h = h_aligned // 8
    blocks_w = w_aligned // 8
    
    # If original bytes are present, compute differential block map
    if original_bytes:
        try:
            orig_img = Image.open(io.BytesIO(original_bytes)).convert("L")
            if orig_img.size != img.size:
                orig_img = orig_img.resize(img.size, Image.Resampling.BILINEAR)
            orig_arr = np.array(orig_img, dtype=np.float32)[:h_aligned, :w_aligned]
            diff = np.abs(arr - orig_arr)
            
            # Aggregate by 8x8 blocks
            block_diffs = diff.reshape(blocks_h, 8, blocks_w, 8).mean(axis=(1, 3))
            max_d = float(block_diffs.max())
            
            if max_d > 0.05:
                norm_map = np.clip(block_diffs / max_d, 0.0, 1.0)
                upscaled = np.repeat(np.repeat(norm_map, 8, axis=0), 8, axis=1)
                png_bytes = _create_heatmap_image(upscaled)
                
                y_indices, x_indices = np.where(block_diffs > max(0.5, 0.08 * max_d))
                spliced_coords = []
                if len(y_indices) > 0:
                    y_min, y_max = int(y_indices.min() * 8), int((y_indices.max() + 1) * 8)
                    x_min, x_max = int(x_indices.min() * 8), int((x_indices.max() + 1) * 8)
                    spliced_coords.append({"x": x_min, "y": y_min, "width": x_max - x_min, "height": y_max - y_min})
                    
                return {
                    "splicing_detected": len(spliced_coords) > 0,
                    "spliced_regions": spliced_coords,
                    "anomaly_score": round(max_d, 2),
                    "dct_png_bytes": png_bytes,
                    "summary": f"Spliced/modified region localized at (x:{spliced_coords[0]['x']}, y:{spliced_coords[0]['y']}, w:{spliced_coords[0]['width']}, h:{spliced_coords[0]['height']})" if spliced_coords else f"Minor pixel variance (max diff {max_d:.1f}) against original"
                }
            else:
                # Completely identical image
                norm_map = np.zeros_like(block_diffs)
                upscaled = np.repeat(np.repeat(norm_map, 8, axis=0), 8, axis=1)
                png_bytes = _create_heatmap_image(upscaled)
                return {
                    "splicing_detected": False,
                    "spliced_regions": [],
                    "anomaly_score": 0.0,
                    "dct_png_bytes": png_bytes,
                    "summary": "Identical image — no spatial or block modifications detected against original"
                }
        except Exception:
            pass
            
    # Blind Block-DCT Analysis (when no original is available)
    # Reshape into 8x8 blocks: (blocks_h, 8, blocks_w, 8)
    blocks = arr.reshape(blocks_h, 8, blocks_w, 8).swapaxes(1, 2) # (blocks_h, blocks_w, 8, 8)
    
    # Compute 2D DCT for each block
    dct_blocks = sfft.dctn(blocks, axes=(-2, -1), norm="ortho")
    
    # Calculate high-frequency AC energy per block (exclude DC at [0,0])
    ac_energy = np.sum(np.abs(dct_blocks[:, :, 1:, 1:]), axis=(-2, -1))
    
    # Compute z-score of block energy
    mean_e = np.mean(ac_energy)
    std_e = np.std(ac_energy) + 1e-8
    z_scores = (ac_energy - mean_e) / std_e
    
    # Anomalous blocks with high statistical deviation (> 2.8 sigma)
    anomaly_map = np.clip(np.abs(z_scores) / 4.0, 0.0, 1.0)
    upscaled = np.repeat(np.repeat(anomaly_map, 8, axis=0), 8, axis=1)
    png_bytes = _create_heatmap_image(upscaled)
    
    spliced_coords = []
    y_indices, x_indices = np.where(z_scores > 2.8)
    splicing_detected = len(y_indices) > 6
    
    if splicing_detected:
        y_min, y_max = int(y_indices.min() * 8), int((y_indices.max() + 1) * 8)
        x_min, x_max = int(x_indices.min() * 8), int((x_indices.max() + 1) * 8)
        spliced_coords.append({"x": x_min, "y": y_min, "width": x_max - x_min, "height": y_max - y_min})
        
    return {
        "splicing_detected": splicing_detected,
        "spliced_regions": spliced_coords,
        "anomaly_score": round(float(np.max(z_scores)), 2),
        "dct_png_bytes": png_bytes,
        "summary": f"Potential foreign spliced region detected at (x:{spliced_coords[0]['x']}, y:{spliced_coords[0]['y']})" if splicing_detected else "Consistent block-DCT compression statistics across entire canvas"
    }
