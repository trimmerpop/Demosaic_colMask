"""Demosaic Tool (colMask) 아이콘 생성기.

아이콘 디자인 컨셉
    - 라운드 사각형 배지(인디고 → 스카이 그라데이션) 안에 다크 스크린
    - 스크린 내부는 대각선을 기준으로 좌상단(매끄러운 원본 화면)과
      우하단(블록으로 뭉개진 모자이크)으로 나뉨
      => "모자이크가 벗겨져 원본이 드러나는(demosaic)" 모티프
    - 16px 같은 작은 크기에서도 보이도록 대비가 큰 색만 사용

사용법
    python make_icon.py                 # demosaic colMask.ico / .png 생성
    python make_icon.py --preview       # 각 크기 미리보기 이미지도 생성 (icon_preview.png)
    python make_icon.py --out-dir path  # 출력 디렉터리 지정
"""

import argparse
import io
import os
import struct

from PIL import Image, ImageChops, ImageDraw, ImageFilter

ICON_NAME = "demosaic colMask.ico"
PNG_NAME = "demosaic colMask.png"
# .ico 에 담을 크기들 (Windows 탐색기/작업표시줄/고DPI 대응)
ICO_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]

# 렌더링 시 슈퍼샘플링 배율 (크게 그린 뒤 축소 → 안티앨리어싱)
SUPERSAMPLE = 4
# 모자이크 블록 수 (작은 크기에서는 블록을 줄여 뭉개짐 방지)
BLOCKS_LARGE = 5
BLOCKS_SMALL = 3
SMALL_SIZE_THRESHOLD = 32

# 색상 팔레트
BADGE_TOP = (67, 56, 202)       # indigo-700
BADGE_BOTTOM = (14, 165, 233)   # sky-500
SCREEN_BG = (2, 6, 23)          # slate-950
SMOOTH_START = (125, 211, 252)  # sky-300
SMOOTH_END = (129, 140, 248)    # indigo-400
WIPE_EDGE = (240, 249, 255)     # sky-50


def lerp(a, b, t):
    return a + (b - a) * t


def lerp_rgb(c1, c2, t):
    return tuple(int(round(lerp(c1[i], c2[i], t))) for i in range(3))


def base_gradient(w, h, c1, c2):
    """좌상단 c1 → 우하단 c2 대각선 그라데이션 이미지(RGB)."""
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            t = (x / max(w - 1, 1) + y / max(h - 1, 1)) / 2.0
            px[x, y] = lerp_rgb(c1, c2, t)
    return img


def rounded_mask(size, box, radius, ss):
    """슈퍼샘플된 캔버스 크기(size)에 맞는 라운드 사각형 마스크(L)."""
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle(box, radius=radius, fill=255)
    return mask

def render_icon(size):
    """지정한 크기의 아이콘을 RGBA 이미지로 렌더링합니다."""
    ss = SUPERSAMPLE
    W = size * ss
    blocks = BLOCKS_LARGE if size >= SMALL_SIZE_THRESHOLD else BLOCKS_SMALL

    icon = Image.new("RGBA", (W, W), (0, 0, 0, 0))

    # 1) 배지 (라운드 사각형 + 대각선 그라데이션)
    badge_box = [0.02 * W, 0.02 * W, 0.98 * W, 0.98 * W]
    badge_mask = rounded_mask(W, badge_box, 0.24 * W, ss)
    badge = base_gradient(W, W, BADGE_TOP, BADGE_BOTTOM).convert("RGBA")
    icon.paste(badge, (0, 0), badge_mask)

    # 1-1) 좌상단 광택(글로시) 효과
    gloss = Image.new("L", (W, W), 0)
    ImageDraw.Draw(gloss).ellipse([-0.35 * W, -0.55 * W, 1.0 * W, 0.42 * W], fill=64)
    gloss = gloss.filter(ImageFilter.GaussianBlur(0.05 * W))
    gloss = ImageChops.multiply(gloss, badge_mask)
    icon.paste(Image.new("RGBA", (W, W), (255, 255, 255, 255)), (0, 0), gloss)

    # 2) 스크린(다크 패널)과 내부 콘텐츠
    inset = 0.165 * W
    screen_box = [inset, inset, W - inset, W - inset]
    screen_radius = 0.09 * W
    screen_w = int(round(W - inset * 2))
    screen_mask = rounded_mask(W, screen_box, screen_radius, ss).crop(
        (int(inset), int(inset), int(inset) + screen_w, int(inset) + screen_w)
    )

    # 2-1) 우하단 영역: 모자이크(픽셀 블록). 블록 사이에 간격을 두어 '뭉개진 픽셀'로 보이게 한다.
    screen = Image.new("RGBA", (screen_w, screen_w), SCREEN_BG + (255,))
    screen_draw = ImageDraw.Draw(screen)
    block = screen_w / blocks
    gap = block * (0.16 if size >= SMALL_SIZE_THRESHOLD else 0.10)
    for by in range(blocks):
        for bx in range(blocks):
            t = ((bx + 0.5) / blocks + (by + 0.5) / blocks) / 2.0
            screen_draw.rounded_rectangle(
                [
                    bx * block + gap / 2,
                    by * block + gap / 2,
                    (bx + 1) * block - gap / 2,
                    (by + 1) * block - gap / 2,
                ],
                radius=gap * 0.35,
                fill=lerp_rgb(SMOOTH_START, SMOOTH_END, t) + (255,),
            )

    # 2-2) 좌상단 영역: 모자이크가 벗겨져 드러난 매끄러운 원본 화면
    grad = base_gradient(96, 96, SMOOTH_START, SMOOTH_END)
    smooth = grad.resize((screen_w, screen_w), Image.BICUBIC).convert("RGBA")
    smooth_mask = Image.new("L", (screen_w, screen_w), 0)
    ImageDraw.Draw(smooth_mask).polygon(
        [(0, 0), (screen_w, 0), (0, screen_w)], fill=255
    )
    smooth_mask = smooth_mask.filter(
        ImageFilter.GaussianBlur(max(1.0, 0.012 * screen_w))
    )
    screen = Image.alpha_composite(
        screen,
        Image.composite(
            smooth, Image.new("RGBA", (screen_w, screen_w), (0, 0, 0, 0)), smooth_mask
        ),
    )

    # 2-3) 벗겨지는 경계: 밝은 대각선 + 글로우
    edge = Image.new("RGBA", (screen_w, screen_w), (0, 0, 0, 0))
    ImageDraw.Draw(edge).line(
        [(0, screen_w), (screen_w, 0)],
        fill=WIPE_EDGE + (255,),
        width=max(1, int(0.013 * W)),
    )
    screen = Image.alpha_composite(screen, edge.filter(ImageFilter.GaussianBlur(0.02 * W)))
    screen = Image.alpha_composite(screen, edge)

    icon.paste(screen, (int(inset), int(inset)), screen_mask)

    # 3) 스크린 테두리 (작은 크기에서도 경계가 보이도록)
    ImageDraw.Draw(icon).rounded_rectangle(
        screen_box,
        radius=screen_radius,
        outline=(255, 255, 255, 90),
        width=max(1, int(0.012 * W)),
    )

    # 4) 최종 축소 (안티앨리어싱)
    return icon.resize((size, size), Image.LANCZOS)


def _bmp_entry(img):
    """ICO 에 들어갈 32bpp DIB(BMP) 데이터를 만듭니다. (알파 채널 포함)"""
    img = img.convert("RGBA")
    w, h = img.size
    header = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, w * h * 4, 0, 0, 0, 0)
    pixels = img.transpose(Image.FLIP_TOP_BOTTOM).tobytes("raw", "BGRA")
    # AND 마스크 (32bpp 에서는 사용되지 않지만 형식상 필요, 4바이트 정렬)
    row_bytes = ((w + 31) // 32) * 4
    and_mask = b"\x00" * (row_bytes * h)
    return header + pixels + and_mask


def _png_entry(img):
    """ICO 에 들어갈 PNG 데이터를 만듭니다."""
    buffer = io.BytesIO()
    img.convert("RGBA").save(buffer, format="PNG")
    return buffer.getvalue()


def save_ico(path, images):
    """Windows 호환성이 좋은 ICO 를 직접 작성합니다.

    128px 이하는 BMP(DIB) 항목, 256px 은 PNG 항목으로 넣는다.
    (Windows 는 PNG 항목을 256x256 에 대해서만 공식 지원)
    """
    entries = []
    for size in ICO_SIZES:
        img = images[size]
        data = _png_entry(img) if size[0] >= 256 else _bmp_entry(img)
        entries.append((size, data))

    header = struct.pack("<HHH", 0, 1, len(entries))
    offset = len(header) + 16 * len(entries)
    directory = b""
    payload = b""
    for (width, height), data in entries:
        directory += struct.pack(
            "<BBBBHHII",
            width if width < 256 else 0,
            height if height < 256 else 0,
            0,  # bColorCount
            0,  # bReserved
            1,  # wPlanes
            32,  # wBitCount
            len(data),
            offset,
        )
        payload += data
        offset += len(data)

    with open(path, "wb") as fp:
        fp.write(header + directory + payload)


def make_preview(image256, path):
    """큰 아이콘 + 실제 사용 크기들을 어두운/밝은 배경 위에 나열한 미리보기 시트."""
    sizes = [64, 48, 32, 24, 16]
    pad = 16
    cell_w = 256 + pad * 2
    cell_h = 256 + pad + 80
    sheet = Image.new("RGB", (cell_w * 2 + pad * 3, cell_h * 2 + pad * 3), (28, 28, 32))

    backgrounds = [
        (pad, pad, (28, 28, 32)),
        (cell_w + pad * 2, pad, (238, 238, 238)),
        (pad, cell_h + pad * 2, (64, 64, 72)),
        (cell_w + pad * 2, cell_h + pad * 2, (255, 255, 255)),
    ]
    for ox, oy, bg in backgrounds:
        ImageDraw.Draw(sheet).rectangle(
            [ox, oy, ox + cell_w - pad * 2, oy + cell_h - pad * 2], fill=bg
        )
        sheet.paste(image256, (ox + pad // 2, oy + pad // 2), image256)
        small_x = ox + pad // 2
        small_y = oy + 256 + pad
        for size in sizes:
            small = image256.resize((size, size), Image.LANCZOS)
            sheet.paste(small, (small_x, small_y + (64 - size) // 2), small)
            small_x += size + 8

    sheet.save(path)
    return path


def main():
    parser = argparse.ArgumentParser(description="Demosaic Tool 아이콘 생성기")
    parser.add_argument(
        "--out-dir",
        default=os.path.dirname(os.path.abspath(__file__)),
        help="출력 디렉터리 (기본: 이 스크립트가 있는 디렉터리)",
    )
    parser.add_argument(
        "--preview", action="store_true", help="크기별 미리보기 이미지를 함께 생성"
    )
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # 크기별 네이티브 렌더링 (작은 크기가 뭉개지지 않도록)
    images = {size: render_icon(size[0]) for size in ICO_SIZES}

    ico_path = os.path.join(args.out_dir, ICON_NAME)
    save_ico(ico_path, images)
    print(f"[OK] ico     : {ico_path} ({os.path.getsize(ico_path):,} bytes)")

    png_path = os.path.join(args.out_dir, PNG_NAME)
    images[(256, 256)].save(png_path)
    print(f"[OK] png     : {png_path} ({os.path.getsize(png_path):,} bytes)")

    if args.preview:
        preview_path = make_preview(
            images[(256, 256)], os.path.join(args.out_dir, "icon_preview.png")
        )
        print(f"[OK] preview : {preview_path}")


if __name__ == "__main__":
    main()
