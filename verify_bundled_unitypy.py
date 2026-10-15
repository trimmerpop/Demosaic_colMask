"""빌드된 실행 파일에 실제로 번들된 UnityPy 버전을 확인합니다.

PyInstaller 로 만든 onefile exe 내부의 PYZ 아카이브에서 `UnityPy` 패키지 코드를
꺼내 `__version__` 상수를 읽고, 기대 버전(기본: 현재 환경에 설치된 버전)과
비교합니다. 빌드 전 `pip install --upgrade unitypy` 가 실제로 exe 에 반영됐는지
검증하는 용도입니다.

사용법
    python verify_bundled_unitypy.py                    # dist 의 최신 exe 자동 선택
    python verify_bundled_unitypy.py "dist\\이름.exe"    # 대상 지정
    python verify_bundled_unitypy.py --expect 1.25.4    # 기대 버전 직접 지정
    python verify_bundled_unitypy.py "build\\demosaic colMask\\PYZ-00.pyz"  # PYZ 직접 검사

종료 코드
    0 = 기대 버전과 일치
    1 = 불일치
    2 = 검사 자체를 수행할 수 없음 (대상/PyInstaller/UnityPy 를 찾지 못함)
"""

import argparse
import marshal
import os
import re
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT_PATH = os.path.join(HERE, "demosaic colMask.py")
DIST_DIR = os.path.join(HERE, "dist")


def _typcd(entry):
    """CArchive toc 항목에서 타입 코드를 꺼냅니다 ('z' = PYZ)."""
    try:
        return entry[-1]
    except (TypeError, IndexError):
        return None


def read_app_version():
    """demosaic colMask.py 의 APP_VERSION 값을 읽습니다 (spec 과 동일한 규칙)."""
    try:
        with open(SCRIPT_PATH, encoding="utf-8") as fp:
            matched = re.search(r"^APP_VERSION\s*=\s*(.+)$", fp.read(), re.M)
    except OSError:
        return None
    return matched.group(1).strip().strip("'\"") if matched else None


def default_exe_path():
    """APP_VERSION 에 해당하는 exe 를 우선 사용하고, 없으면 최신 exe 를 씁니다."""
    app_version = read_app_version()
    if app_version:
        candidate = os.path.join(DIST_DIR, f"demosaic colMask v{app_version}.exe")
        if os.path.isfile(candidate):
            return candidate
    if not os.path.isdir(DIST_DIR):
        return None
    exes = [
        os.path.join(DIST_DIR, name)
        for name in os.listdir(DIST_DIR)
        if name.lower().endswith(".exe")
    ]
    if not exes:
        return None
    return max(exes, key=os.path.getmtime)


def iter_version_constants(code):
    """코드 객체에서 `__version__` 에 대입된 문자열 상수를 재귀적으로 수집합니다."""
    if "__version__" in code.co_names:
        for const in code.co_consts:
            if isinstance(const, str):
                yield const
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from iter_version_constants(const)


def _as_code(blob):
    """PyInstaller 버전에 따라 extract() 결과가 code 객체이거나 marshalled 바이트입니다."""
    return blob if isinstance(blob, types.CodeType) else marshal.loads(blob)


def unitypy_versions_from_pyz(pyz):
    """PYZ 아카이브에서 UnityPy 패키지의 __version__ 후보를 읽습니다."""
    module_names = list(pyz.toc)
    targets = [n for n in module_names if n == "UnityPy" or n.startswith("UnityPy.")]
    if not targets:
        return []
    # 패키지 __init__("UnityPy")을 먼저 보고, 없으면 하위 모듈을 확인합니다.
    ordered = ([n for n in targets if n == "UnityPy"] or []) + [n for n in targets if n != "UnityPy"]
    for name in ordered:
        try:
            versions = list(iter_version_constants(_as_code(pyz.extract(name))))
        except Exception:
            continue
        if versions:
            return list(dict.fromkeys(versions))
    return []


def _load_readers():
    from PyInstaller.archive import readers

    return readers


def unitypy_versions_from_exe(exe_path):
    """exe 내부의 PYZ 아카이브(들)에서 UnityPy 버전을 읽습니다."""
    readers = _load_readers()
    archive = readers.CArchiveReader(exe_path)
    pyz_names = [name for name, entry in archive.toc.items() if _typcd(entry) == "z"]
    if not pyz_names:
        raise RuntimeError("exe 안에서 PYZ 아카이브를 찾지 못했습니다.")
    versions = []
    for pyz_name in pyz_names:
        versions.extend(unitypy_versions_from_pyz(archive.open_embedded_archive(pyz_name)))
    return list(dict.fromkeys(versions))


def unitypy_versions_from_pyz_file(pyz_path):
    """PYZ 아카이브 파일(-00.pyz)을 직접 검사합니다."""
    readers = _load_readers()
    return unitypy_versions_from_pyz(readers.ZlibArchiveReader(pyz_path))


def installed_unitypy_version():
    """현재 파이썬 환경에 설치된 UnityPy 버전을 반환합니다."""
    try:
        import UnityPy
    except ImportError:
        return None
    return getattr(UnityPy, "__version__", None)


def main(argv=None):
    parser = argparse.ArgumentParser(description="빌드된 exe 에 번들된 UnityPy 버전 확인")
    parser.add_argument("target", nargs="?", help="대상 exe 또는 .pyz 경로 (기본: dist 의 최신 exe)")
    parser.add_argument("--expect", help="기대 버전 (기본: 현재 환경에 설치된 UnityPy 버전)")
    args = parser.parse_args(argv)

    try:
        _load_readers()
    except ImportError:
        print("[X] PyInstaller 가 설치되어 있지 않아 exe 내부를 읽을 수 없습니다.")
        print("    python -m pip install -r requirements-build.txt 후 다시 실행하세요.")
        return 2

    target = args.target or default_exe_path()
    if not target or not os.path.exists(target):
        print("[X] 검사할 exe 를 찾지 못했습니다. 먼저 빌드하세요 (dist 폴더를 확인하세요).")
        return 2
    print(f"[i] 대상      : {os.path.relpath(target, HERE)}")

    try:
        if target.lower().endswith(".pyz"):
            found = unitypy_versions_from_pyz_file(target)
        else:
            found = unitypy_versions_from_exe(target)
    except Exception as exc:
        print(f"[X] 내부 아카이브를 읽는 중 오류: {exc}")
        return 2

    if not found:
        print("[X] 번들된 UnityPy 버전을 찾지 못했습니다 (UnityPy 가 포함되지 않았을 수 있습니다).")
        return 2

    bundled = found[0]
    expected = args.expect or installed_unitypy_version()
    print(f"[i] 번들된 버전: UnityPy {', '.join(found)}")
    print(f"[i] 기대 버전  : {expected if expected else '(확인 불가)'}")
    if len(found) > 1:
        print("[!] 버전 문자열이 여러 개 발견되었습니다. 번들 상태를 확인하세요.")

    if not expected:
        print("[!] 기대 버전을 알 수 없어 일치 여부를 검사하지 못했습니다.")
        return 2
    if bundled != expected:
        print(f"[X] 불일치: exe 는 UnityPy {bundled} 를 포함하지만 현재 환경은 {expected} 입니다.")
        print("    빌드 후 환경이 바뀌었거나, 다른 환경에서 만들어진 exe 입니다.")
        return 1
    print(f"[OK] 번들된 UnityPy {bundled} 가 기대 버전과 일치합니다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
