"""
Screen record the live attack demo using mss + imageio → MP4
"""
import subprocess, time, os, shutil, tempfile

FFMPEG = r"C:\Users\smgal\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-8.1.1-full_build\bin\ffmpeg.exe"
OUTPUT = r"C:\Users\smgal\Documents\harvestX\live_attack_demo.mp4"
FRAMES_DIR = tempfile.mkdtemp()
DURATION = 55   # seconds to record
FPS = 5

print(f"Installing mss if needed...")
subprocess.run(["pip", "install", "mss", "Pillow", "-q"], capture_output=True)

import mss
from PIL import Image

print(f"Recording {DURATION}s at {FPS}fps → {FRAMES_DIR}")
print("Recording starts NOW...")

sct = mss.mss()
monitor = sct.monitors[1]  # primary monitor

frame_count = 0
start = time.time()

while time.time() - start < DURATION:
    t0 = time.time()
    screenshot = sct.grab(monitor)
    img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
    # Resize to 1280x720 for manageable file size
    img = img.resize((1280, 720), Image.LANCZOS)
    img.save(os.path.join(FRAMES_DIR, f"frame_{frame_count:06d}.png"))
    frame_count += 1
    elapsed = time.time() - t0
    sleep_time = max(0, (1/FPS) - elapsed)
    time.sleep(sleep_time)

print(f"Captured {frame_count} frames. Encoding to MP4...")

cmd = [
    FFMPEG, "-y",
    "-framerate", str(FPS),
    "-i", os.path.join(FRAMES_DIR, "frame_%06d.png"),
    "-c:v", "libx264",
    "-pix_fmt", "yuv420p",
    "-preset", "fast",
    "-crf", "23",
    OUTPUT
]
result = subprocess.run(cmd, capture_output=True, text=True)
shutil.rmtree(FRAMES_DIR, ignore_errors=True)

if result.returncode == 0:
    size = os.path.getsize(OUTPUT) / 1e6
    print(f"\n✅ SUCCESS! Video saved: {OUTPUT}  ({size:.1f} MB)")
else:
    print("FFmpeg error:\n", result.stderr[-1000:])
