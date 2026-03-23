from PIL import Image, ImageDraw
import os

os.makedirs("extension/icons", exist_ok=True)

def make_icon(size, filename):
    img  = Image.new("RGBA", (size, size), (0,0,0,0))
    draw = ImageDraw.Draw(img)
    m    = size // 10
    draw.ellipse([m, m, size-m, size-m],
                 fill=(20,30,60,255))
    cx = size // 2
    s  = size * 0.35
    pts = [
        (cx,   size*0.15),
        (cx+s, size*0.25),
        (cx+s, size*0.55),
        (cx,   size*0.85),
        (cx-s, size*0.55),
        (cx-s, size*0.25),
    ]
    draw.polygon(pts, fill=(0,212,255,255))
    r = size * 0.08
    draw.ellipse(
        [cx-r, size*0.45-r, cx+r, size*0.45+r],
        fill=(10,15,30,255)
    )
    img.save(filename)
    print(f"✅ Created {filename}")

make_icon(16,  "extension/icons/icon16.png")
make_icon(48,  "extension/icons/icon48.png")
make_icon(128, "extension/icons/icon128.png")
print("🎉 All icons created!")