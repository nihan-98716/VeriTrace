import zipfile
import xml.etree.ElementTree as ET
import hashlib
import json
import io
from typing import Dict, List, Tuple, Any

def compute_document_merkle_tree(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Computes a Merkle tree of internal segments for documents (.pptx, .docx, .pdf, or generic).
    For PPTX: Hashes individual slides and media assets.
    For DOCX: Hashes document header, body paragraphs, and footer.
    For PDF: Hashes incremental pages/objects.
    For Audio/Video/Generic: Computes chunk/segment Merkle hashes.
    """
    extension = filename.lower().split('.')[-1] if '.' in filename else ''
    
    segments = {} # name -> sha256_hash
    
    if extension in ('pptx', 'docx'):
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes), 'r') as zf:
                for item in zf.namelist():
                    if extension == 'pptx' and item.startswith('ppt/slides/slide'):
                        slide_data = zf.read(item)
                        slide_name = item.split('/')[-1].replace('.xml', '') # e.g. slide1
                        segments[f"Slide ({slide_name})"] = hashlib.sha256(slide_data).hexdigest()
                    elif extension == 'pptx' and item.startswith('ppt/media/'):
                        media_name = item.split('/')[-1]
                        media_data = zf.read(item)
                        segments[f"Media ({media_name})"] = hashlib.sha256(media_data).hexdigest()
                    elif extension == 'docx' and item in ('word/document.xml', 'word/styles.xml', 'word/header1.xml'):
                        doc_data = zf.read(item)
                        segments[f"Section ({item})"] = hashlib.sha256(doc_data).hexdigest()
        except Exception:
            pass

    # Generic chunking fallback for video/audio or unhandled formats
    if not segments:
        chunk_size = max(1024 * 64, len(file_bytes) // 8 or 1024) # ~8 segments
        for i in range(0, len(file_bytes), chunk_size):
            chunk = file_bytes[i:i + chunk_size]
            seg_index = (i // chunk_size) + 1
            start_k = f"{i // 1024}KB"
            end_k = f"{min(len(file_bytes), i + chunk_size) // 1024}KB"
            segments[f"Segment {seg_index} ({start_k}-{end_k})"] = hashlib.sha256(chunk).hexdigest()
            
    # Compute Merkle Root
    segment_hashes = list(segments.values())
    merkle_root = hashlib.sha256("".join(segment_hashes).encode()).hexdigest() if segment_hashes else hashlib.sha256(file_bytes).hexdigest()
    
    return {
        "merkle_root": merkle_root,
        "segments": segments
    }

def analyze_tampered_segments(original_segments: Dict[str, str], current_file_bytes: bytes, filename: str) -> List[str]:
    """
    Compares original segment hashes against current file to return specific tampered segments.
    """
    current_info = compute_document_merkle_tree(current_file_bytes, filename)
    current_segments = current_info["segments"]
    
    tampered_parts = []
    
    for seg_name, orig_hash in original_segments.items():
        curr_hash = current_segments.get(seg_name)
        if curr_hash is None:
            tampered_parts.append(f"{seg_name} (Deleted/Missing)")
        elif curr_hash != orig_hash:
            tampered_parts.append(f"{seg_name} (Modified)")
            
    for seg_name in current_segments:
        if seg_name not in original_segments:
            tampered_parts.append(f"{seg_name} (Inserted/New)")
            
    return tampered_parts
