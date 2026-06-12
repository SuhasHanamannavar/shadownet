"""
Convert animated WebP to MP4 using Pillow + FFmpeg.
"""
import os
import subprocess
import tempfile
import shutil
from PIL import Image

WEBP_PATH = r"C:\Users\smgal\.gemini\antigravity\brain\59f963eb-d42b-4257-8630-e2166064ee03\full_attack_stream_1777943065172.webp"
MP4_OUT   = r"C:\Users\smgal\Documents\shadownet\live_attack_demo.mp4"
FFMPEG    = r"C:\Users\smgal\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-8.1.1-full_build\bin\ffmpeg.exe"

tmpdir = tempfile.mkdtemp()
try:
    img = Image.open(WEBP_PATH)
    frame_idx = 0
    durations = []
    try:
        while True:
            frame = img.convert("RGB")
            frame.save(os.path.join(tmpdir, f"frame_{frame_idx:06d}.png"))
            dur = img.info.get("duration", 100)   # ms
            durations.append(dur)
            frame_idx += 1
            img.seek(img.tell() + 1)
    except EOFError:
        pass

    print(f"Extracted {frame_idx} frames")

    if frame_idx == 0:
        print("No frames found!")
        raise SystemExit(1)

    avg_ms  = sum(durations) / len(durations)
    fps     = round(1000 / avg_ms, 2)
    print(f"Average frame duration: {avg_ms:.1f}ms  →  {fps} fps")

    cmd = [
        FFMPEG, "-y",
        "-framerate", str(fps),
        "-i", os.path.join(tmpdir, "frame_%06d.png"),
        "-c:v", "libx264",
        "-pix_fmt", "yuv420p",
        "-preset", "fast",
        "-crf", "20",
        "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2",
        MP4_OUT
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        size_mb = os.path.getsize(MP4_OUT) / 1e6
        print(f"SUCCESS! MP4 saved to: {MP4_OUT}  ({size_mb:.1f} MB)")
    else:
        print("FFmpeg error:\n", result.stderr[-2000:])
finally:
    shutil.rmtree(tmpdir, ignore_errors=True)
