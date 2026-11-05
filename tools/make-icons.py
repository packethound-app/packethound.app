"""
Builds PacketHound's icons from the logo. Re-run after changing the logo:

    python tools/make-icons.py

Input:   src/PacketHound/Assets/logo.png  (full logo, transparent background)
Outputs: src/PacketHound/Assets/PacketHound.ico         app, windows, shortcuts, tray (protection on)
         src/PacketHound/Assets/PacketHound-paused.ico  tray while paused (greyed out)
         installer/wizard-small-<size>.bmp              installer wizard corner image, per DPI
         website/assets/img/                            favicon, app icons, logo, social preview image

The icon is the hound's head from the logo in a round badge (white, with the logo's orange as a
ring), because the full illustration and lettering are unreadable at 16-32 px.
Needs Pillow (pip install pillow).
"""
import io
import struct
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "src" / "PacketHound" / "Assets"
INSTALLER = ROOT / "installer"
WEB_IMG = ROOT / "website" / "assets" / "img"

ORANGE = (254, 120, 1, 255)  # "Hound" in the wordmark
WHITE = (255, 255, 255, 255)
HEAD_BOX = (128, 40, 266, 176)  # the hound's head, in logo.png's 384x256 pixel coordinates
ICON_SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
WIZARD_SIZES = [55, 69, 83, 110, 138]  # 100%, 125%, 150%, 200%, 250% DPI
N = 1024  # working resolution


def badge(logo: Image.Image) -> Image.Image:
    ring = int(N * 0.065)
    img = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse((0, 0, N - 1, N - 1), fill=ORANGE)
    draw.ellipse((ring, ring, N - 1 - ring, N - 1 - ring), fill=WHITE)

    head = logo.crop(HEAD_BOX)
    width = int(N * 0.98)
    head = head.resize((width, int(width * head.height / head.width)), Image.LANCZOS)
    layer = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    layer.paste(head, ((N - head.width) // 2, (N - head.height) // 2), head)

    inside = Image.new("L", (N, N), 0)
    ImageDraw.Draw(inside).ellipse((ring, ring, N - 1 - ring, N - 1 - ring), fill=255)
    img.paste(layer, (0, 0), Image.composite(layer.split()[3], Image.new("L", (N, N), 0), inside))
    return img


def greyed(img: Image.Image) -> Image.Image:
    grey = img.convert("LA").convert("RGBA")
    grey.putalpha(img.split()[3])
    return grey


def scaled(img: Image.Image, size: int) -> Image.Image:
    small = img.resize((size, size), Image.LANCZOS)
    if size <= 32:  # small sizes go soft; sharpen the colour, keep the edges' alpha as is
        alpha = small.split()[3]
        small = small.filter(ImageFilter.UnsharpMask(radius=0.6, percent=60, threshold=1))
        small.putalpha(alpha)
    return small


def dib(img: Image.Image, for_icon: bool) -> bytes:
    """32-bit BGRA bitmap, bottom-up. Icons add an AND mask and a doubled height."""
    w, h = img.size
    pixels = img.tobytes("raw", "BGRA")
    rows = b"".join(pixels[y * w * 4:(y + 1) * w * 4] for y in reversed(range(h)))
    header = struct.pack("<IiiHHIIiiII", 40, w, h * 2 if for_icon else h, 1, 32, 0, len(rows), 2835, 2835, 0, 0)
    if not for_icon:
        return header + rows
    mask_row = ((w + 31) // 32) * 4
    return header + rows + bytes(mask_row * h)


def write_ico(img: Image.Image, path: Path) -> None:
    # Small sizes as classic bitmaps (most compatible); 256 as PNG (what Windows expects there).
    frames = []
    for size in ICON_SIZES:
        frame = scaled(img, size)
        if size >= 256:
            buf = io.BytesIO()
            frame.save(buf, "PNG")
            frames.append((size, buf.getvalue()))
        else:
            frames.append((size, dib(frame, for_icon=True)))

    out = struct.pack("<HHH", 0, 1, len(frames))
    offset = 6 + 16 * len(frames)
    for size, data in frames:
        dim = 0 if size >= 256 else size
        out += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    path.write_bytes(out + b"".join(data for _, data in frames))


def write_bmp(img: Image.Image, path: Path) -> None:
    data = dib(img, for_icon=False)
    path.write_bytes(struct.pack("<2sIHHI", b"BM", 14 + len(data), 0, 0, 14 + 40) + data)


def main() -> None:
    logo = Image.open(ASSETS / "logo.png").convert("RGBA")
    icon = badge(logo)
    write_ico(icon, ASSETS / "PacketHound.ico")
    write_ico(greyed(icon), ASSETS / "PacketHound-paused.ico")
    for size in WIZARD_SIZES:
        write_bmp(icon.resize((size, size), Image.LANCZOS), INSTALLER / f"wizard-small-{size}.bmp")
    write_website(logo, icon)
    print("Icons written to", ASSETS, INSTALLER, "and", WEB_IMG)


def write_website(logo: Image.Image, icon: Image.Image) -> None:
    WEB_IMG.mkdir(parents=True, exist_ok=True)
    logo.save(WEB_IMG / "logo.png", optimize=True)
    for size in (32, 180, 192, 512):  # favicon, Apple touch icon, Android/PWA icons
        scaled(icon, size).save(WEB_IMG / f"icon-{size}.png", optimize=True)
    icon.resize((48, 48), Image.LANCZOS).save(WEB_IMG.parent.parent / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])

    # Social preview (link previews in chat apps and social sites): logo centred on white, 1200x630.
    card = Image.new("RGBA", (1200, 630), WHITE)
    big = logo.resize((logo.width * 2, logo.height * 2), Image.LANCZOS)
    card.paste(big, ((1200 - big.width) // 2, (630 - big.height) // 2), big)
    card.convert("RGB").save(WEB_IMG / "social-preview.png", optimize=True)


if __name__ == "__main__":
    main()
