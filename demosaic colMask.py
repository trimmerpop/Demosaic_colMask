import os
import shutil
import sys
import UnityPy
import tkinter as tk
import zipfile
import tempfile
import subprocess
import threading
from tkinterdnd2 import DND_FILES, TkinterDnD
from queue import Queue, Empty
import re
from packaging import version
from tkinter import ttk, filedialog, messagebox

# Mosaic 인식 키워드
KEYWORDS = ["mos", "moz", "masi", "maz", "pixel", "censor", "ピクセル", "モザイク"]
# 스캔 대상 에셋 파일 확장자
ASSET_EXTENSIONS = (".assets", ".bundle", ".unity3d", ".sharedAssets", ".resS", ".dat")

class DemosaicGUI:
    def __init__(self, master):
        self.master = master

        # 데이터 변수들을 UI 위젯 생성보다 먼저 초기화합니다.
        self.all_shaders = [] # (shader_name, path_id, file_path) 튜플 리스트
        self.replacement_map = {} # {target_item_id: source_values}
        self.apk_session_temp_dir = None # APK 모드에서 사용할 최상위 임시 디렉토리
        self.apk_map = {} # {original_apk_path: temp_dir_for_apk}
        self.path_var = tk.StringVar()
        self.filter_var = tk.StringVar()
        self.backup_var = tk.BooleanVar(value=True)

        master.title("Demosaic Tool (colMask)")
        master.geometry("800x600")

        # 상단 프레임 (경로 입력 및 스캔 버튼)
        top_frame = ttk.Frame(master, padding="10")
        top_frame.pack(fill=tk.X)

        ttk.Label(top_frame, text="Path:").pack(side=tk.LEFT, padx=(0, 5))
        self.path_entry = ttk.Entry(top_frame, textvariable=self.path_var)
        self.path_var.trace_add("write", self.on_path_change)
        self.placeholder = "Drag & Drop or Double click to select a folder or file"
        self.placeholder_color = 'grey'
        self.default_fg_color = self.path_entry.cget('foreground')

        self.path_entry.bind("<FocusIn>", self.on_entry_focus_in)
        self.path_entry.bind("<FocusOut>", self.on_entry_focus_out)

        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.path_entry.bind("<Double-1>", self.select_path)
        # 드래그 앤 드롭 설정
        self.master.drop_target_register(DND_FILES)
        self.master.dnd_bind('<<Drop>>', self.on_drop)

        self.scan_all_button = ttk.Button(top_frame, text="Scan All", command=self.scan_all_for_gui)
        self.scan_all_button.pack(side=tk.LEFT, padx=(5, 0))

        #self.scan_button = ttk.Button(top_frame, text="Scan Shaders", command=self.scan_shaders_for_gui, state="disabled")
        #self.scan_button.pack(side=tk.LEFT, padx=(5, 0))

        self.backup_check = ttk.Checkbutton(top_frame, text="Backup File", variable=self.backup_var)
        self.backup_check.pack(side=tk.LEFT, padx=(5, 0))

        self.start_button = ttk.Button(top_frame, text="Start Demosaic", command=self.start_processing)
        self.start_button.pack(side=tk.LEFT, padx=(5, 0))

        self.buttons = [self.scan_all_button, self.start_button]
        # if self.scan_button is used, add it here too.
        # self.buttons.append(self.scan_button)

        # 중앙 프레임 (셰이더 목록)
        main_frame = ttk.Frame(master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # PanedWindow를 사용하여 드래그 가능한 구분선 생성
        paned_window = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)

        # 사용 가능한 셰이더 목록
        available_frame = ttk.LabelFrame(main_frame, text="Available Shaders", padding="5")
        available_frame.grid_rowconfigure(1, weight=1)
        available_frame.grid_columnconfigure(0, weight=1)
        paned_window.add(available_frame, weight=1)

        self.filter_var.trace_add("write", lambda *args: self.update_available_list())
        self.filter_entry = ttk.Entry(available_frame, textvariable=self.filter_var)
        self.filter_entry.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 5))

        self.filter_placeholder = "filter"
        self.filter_entry.bind("<FocusIn>", self.on_filter_entry_focus_in)
        self.filter_entry.bind("<FocusOut>", self.on_filter_entry_focus_out)

        self.available_tree = self.create_shader_treeview(available_frame)
        self.available_tree.grid(row=1, column=0, sticky="nsew")
        self.available_tree.bind("<Double-1>", self.move_to_selected)
        self.available_tree.bind("<Button-3>", self.show_context_menu)

        available_v_scrollbar = ttk.Scrollbar(available_frame, orient="vertical", command=self.available_tree.yview)
        available_v_scrollbar.grid(row=1, column=1, sticky="ns")
        available_h_scrollbar = ttk.Scrollbar(available_frame, orient="horizontal", command=self.available_tree.xview)
        available_h_scrollbar.grid(row=2, column=0, sticky="ew")
        self.available_tree.configure(yscrollcommand=available_v_scrollbar.set, xscrollcommand=available_h_scrollbar.set)

        # 선택된 셰이더 목록
        selected_frame = ttk.LabelFrame(main_frame, text="Selected Shaders", padding="5")
        selected_frame.grid_rowconfigure(0, weight=1)
        selected_frame.grid_columnconfigure(0, weight=1) # Treeview가 프레임을 채우도록 설정
        paned_window.add(selected_frame, weight=1)

        self.selected_tree = self.create_shader_treeview(selected_frame)
        # 'status' 열 추가
        self.selected_tree.configure(columns=("name", "path_id", "file", "status", "fullpath"), displaycolumns=("name", "status", "path_id", "file"))
        self.selected_tree.heading("status", text="Status", command=lambda: self.sort_treeview(self.selected_tree, "status", False))
        # 컬럼 재정의 후, 기존 컬럼들의 제목을 다시 설정합니다.
        self.selected_tree.heading("name", text="Shader Name", command=lambda: self.sort_treeview(self.selected_tree, "name", False))
        self.selected_tree.heading("path_id", text="PathID", command=lambda: self.sort_treeview(self.selected_tree, "path_id", False))
        self.selected_tree.heading("file", text="File Path", command=lambda: self.sort_treeview(self.selected_tree, "file", False))

        self.selected_tree.column("name", stretch=tk.NO) # name 컬럼이 독립적으로 너비를 갖도록 설정
        self.selected_tree.column("status", width=150, stretch=tk.NO)
        # 모든 컬럼의 stretch 속성을 NO로 설정하여 자동 크기 조절 방지
        self.selected_tree.column("path_id", stretch=tk.NO)
        self.selected_tree.column("file", stretch=tk.NO)

        self.selected_tree.grid(row=0, column=0, sticky="nsew")
        self.selected_tree.bind("<Double-1>", self.move_to_available)
        self.selected_tree.bind("<Button-3>", self.show_context_menu)

        selected_v_scrollbar = ttk.Scrollbar(selected_frame, orient="vertical", command=self.selected_tree.yview)
        selected_v_scrollbar.grid(row=0, column=1, sticky="ns")
        selected_h_scrollbar = ttk.Scrollbar(selected_frame, orient="horizontal", command=self.selected_tree.xview)
        selected_h_scrollbar.grid(row=1, column=0, sticky="ew")
        self.selected_tree.configure(yscrollcommand=selected_v_scrollbar.set, xscrollcommand=selected_h_scrollbar.set)

        # 하단 프레임 (로그)
        log_frame = ttk.LabelFrame(master, text="Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, side=tk.BOTTOM, padx=10, pady=(0, 10))
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, state='disabled', wrap=tk.WORD, height=3)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text.config(yscrollcommand=scrollbar.set)

        # 프로그레스 바
        self.progress_bar = ttk.Progressbar(log_frame, orient='horizontal', mode='determinate')
        self.progress_bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        self.progress_bar.grid_remove() # 초기에는 숨김

        # stdout 리디렉션
        self.log_queue = Queue()
        sys.stdout = self.QueueTextRedirector(self.log_queue)
        self.master.after(100, self.process_log_queue)

        self.on_entry_focus_out(None) # 초기 플레이스홀더 설정
        self.on_filter_entry_focus_out(None) # 필터 플레이스홀더 초기 설정

        # 태그 설정
        self.available_tree.tag_configure('suggest_source', background='pale green')
        self.selected_tree.tag_configure('suggest_target', background='#FFDDC1') # Light Orange
        self.selected_tree.tag_configure('replaced', background='pale green')

        # 컨텍스트 메뉴
        self.context_menu = tk.Menu(master, tearoff=0)
        self.context_menu.add_command(label="Replace with...", command=self.open_replace_window)
        self.context_menu.add_command(label="Copy Info", command=lambda: self.copy_shader_info(self.selected_tree))

        self.available_context_menu = tk.Menu(master, tearoff=0)
        self.available_context_menu.add_command(label="Copy Info", command=lambda: self.copy_shader_info(self.available_tree))

        # 프로그램 종료 시 임시 폴더 정리
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def process_log_queue(self):
        """
        GUI 스레드에서 안전하게 로그 메시지를 처리하고 표시합니다.
        다른 스레드에서 생성된 로그를 주기적으로 확인하여 Text 위젯에 추가합니다.
        """
        try:
            message = self.log_queue.get_nowait()
            self.log_text.config(state='normal')
            self.log_text.insert(tk.END, message)
            self.log_text.see(tk.END)
            self.log_text.config(state='disabled')
        except Empty:
            pass
        finally:
            self.master.after(100, self.process_log_queue)

    class QueueTextRedirector:
        def __init__(self, queue):
            self.queue = queue

        def write(self, s):
            self.queue.put(s)

        def flush(self):
            pass

    def on_closing(self):
        """
        프로그램 종료 시 임시 폴더를 정리합니다.
        """
        if self.apk_session_temp_dir and os.path.exists(self.apk_session_temp_dir):
            try:
                shutil.rmtree(self.apk_session_temp_dir)
                print(f"Cleaned up session temporary directory on exit: {self.apk_session_temp_dir}")
            except Exception as e:
                print(f"Error cleaning up temporary directory on exit: {e}")
        self.master.destroy()

    def _find_uber_apk_signer_jar(self):
        """
        스크립트 디렉토리에서 uber-apk-signer jar 파일을 찾습니다.
        1. 'uber-apk-signer.jar'가 있으면 우선적으로 반환합니다.
        2. 없다면 'uber-apk-signer-*.jar' 패턴의 파일 중 가장 버전이 높은 파일을 찾습니다.
        3. 적절한 파일을 찾지 못하면 None을 반환합니다.
        """
        if getattr(sys, 'frozen', False):
            script_dir = os.path.dirname(sys.executable)
        else:
            script_dir = os.path.dirname(os.path.abspath(__file__))

        # 1. 'uber-apk-signer.jar' 우선 확인
        default_jar_path = os.path.join(script_dir, "uber-apk-signer.jar")
        if os.path.exists(default_jar_path):
            return default_jar_path

        # 2. 버전이 포함된 jar 파일 검색
        signer_jars = []
        for filename in os.listdir(script_dir):
            if filename.startswith("uber-apk-signer-") and filename.endswith(".jar"):
                signer_jars.append(filename)

        if not signer_jars:
            return None

        # 가장 최신 버전의 jar 파일 찾기
        latest_jar = max(signer_jars, key=lambda f: version.parse(re.search(r'uber-apk-signer-(.*?)\.jar', f).group(1)))
        return os.path.join(script_dir, latest_jar)

    def on_entry_focus_in(self, event):
        if self.path_var.get() == self.placeholder:
            self.path_entry.delete(0, "end")
            self.path_entry.config(foreground=self.default_fg_color)

    def on_entry_focus_out(self, event):
        if not self.path_var.get():
            self.path_entry.insert(0, self.placeholder)
            self.path_entry.config(foreground=self.placeholder_color)

    def on_filter_entry_focus_in(self, event):
        if self.filter_var.get() == self.filter_placeholder:
            self.filter_entry.delete(0, "end")
            self.filter_entry.config(foreground=self.default_fg_color)

    def on_filter_entry_focus_out(self, event):
        if not self.filter_var.get():
            self.filter_entry.insert(0, self.filter_placeholder)
            self.filter_entry.config(foreground=self.placeholder_color)

    def on_drop(self, event):
        # event.data는 공백으로 구분된 경로 목록일 수 있으며, 각 경로는 중괄호로 묶일 수 있습니다.
        # 예: '{C:/path with space/file1.txt}' '{C:/path with space/file2.txt}' 또는 'C:/path/file.txt'
        # 첫 번째 경로만 사용합니다.
        path = event.data.strip()
        if path.startswith('{') and '}' in path:
            path = path[1:path.find('}')]
        
        is_valid = False
        if os.path.isdir(path):
            is_valid = True
        elif os.path.isfile(path):
            try:
                if path.lower().endswith('.apk'):
                    with zipfile.ZipFile(path, 'r') as zf:
                        # 파일 목록을 한번 읽어보는 것으로 유효한 zip 파일인지 간단히 확인
                        zf.infolist()
                    is_valid = True
                else:
                    # UnityPy로 열어서 유효한 에셋 파일인지 확인
                    UnityPy.load(path)
                    is_valid = True
            except zipfile.BadZipFile:
                messagebox.showwarning("Invalid File", f"The dropped file is not a valid APK file:\n{os.path.basename(path)}")
            except Exception as e:
                messagebox.showwarning("Unsupported File", f"The dropped file is not a supported Unity asset file or is corrupted:\n{os.path.basename(path)}\n\nError: {e}")

        if not is_valid:
            return

        self.path_entry.config(foreground=self.default_fg_color)
        self.path_var.set(path)
        self.master.after(10, lambda: (self.path_entry.selection_range(0, tk.END), self.path_entry.icursor(tk.END)))

    def create_shader_treeview(self, parent):
        # 'fullpath' 열을 추가하되, displaycolumns를 통해 숨김
        tree = ttk.Treeview(parent, columns=("name", "path_id", "file", "fullpath"), show="headings", selectmode="extended")
        tree.configure(displaycolumns=("name", "path_id", "file"))

        tree.heading("name", text="Shader Name", command=lambda: self.sort_treeview(tree, "name", False))
        tree.heading("path_id", text="PathID", command=lambda: self.sort_treeview(tree, "path_id", False))
        tree.heading("file", text="File Path", command=lambda: self.sort_treeview(tree, "file", False))

        tree.column("name", width=200, stretch=tk.NO)
        tree.column("path_id", width=80, anchor="e", stretch=tk.NO)
        tree.column("file", width=250, stretch=tk.NO)

        return tree

    def sort_treeview(self, tree, col, reverse):
        # 정렬 전에 모든 헤더에서 정렬 표시 제거
        if not hasattr(tree, '_heading_texts'):
            tree._heading_texts = {c: tree.heading(c, 'text') for c in tree.cget('columns') if c != 'fullpath'}

        for c in tree._heading_texts:
            tree.heading(c, text=tree._heading_texts[c])

        # 현재 정렬 상태를 위젯에 저장
        tree.sort_info = {'col': col, 'reverse': reverse}
        
        data = [(tree.set(item, col), item) for item in tree.get_children('')]
        # 각 컬럼 타입에 맞는 정렬 함수 설정
        if col == "status":
            sort_key_func = lambda x: str(x).lstrip('-> ')
        elif col == "path_id":
            sort_key_func = int
        else:
            sort_key_func = str.lower
        # reverse=True는 내림차순, False는 오름차순
        data.sort(key=lambda t: sort_key_func(str(t[0])), reverse=reverse)
        for index, (val, item) in enumerate(data):
            tree.move(item, '', index)
        
        # 현재 정렬된 컬럼에만 표시 추가 (▲: 오름차순, ▼: 내림차순)
        new_heading_text = f"{tree._heading_texts[col]} {'▼' if reverse else '▲'}"
        tree.heading(col, text=new_heading_text)
        tree.heading(col, command=lambda: self.sort_treeview(tree, col, not reverse))

    def select_path(self, event=None):
        initial_dir = os.path.dirname(self.path_var.get()) if self.path_var.get() and os.path.exists(os.path.dirname(self.path_var.get())) else "/"
        # askopenfilename은 폴더 선택을 지원하지 않으므로 askdirectory로 변경합니다.
        path = filedialog.askdirectory(
            initialdir=initial_dir,
            title="Select a folder"
        )
        
        if path:
            self.path_entry.config(foreground=self.default_fg_color)
            self.path_var.set(path)
            # after를 사용하여 UI 업데이트 후 선택이 적용되도록 함
            self.master.after(10, lambda: (self.path_entry.selection_range(0, tk.END), self.path_entry.icursor(tk.END)))

    def on_path_change(self, *args):
        if self.path_var.get() == self.placeholder:
            return
        
        path = self.path_var.get()
        if path and os.path.exists(path):
            self.scan_shaders_for_gui(scan_all=False) # 폴더 선택 시 자동 스캔 (기본 확장자만)
        #else:
        #    self.clear_all()
        #    self.scan_button.config(state="disabled")

    def toggle_buttons(self, enabled):
        for button in self.buttons:
            button.config(state=tk.NORMAL if enabled else tk.DISABLED)

    def scan_all_for_gui(self):
        self.scan_shaders_for_gui(scan_all=True)

    def scan_shaders_for_gui(self, scan_all=False):
        def _scan_task(scan_paths):
            # 이전 세션의 임시 파일 정리 (스캔 시작 시)
            if self.apk_session_temp_dir and os.path.exists(self.apk_session_temp_dir):
                # Windows에서 파일 핸들 잠금 문제로 rmtree가 실패하는 경우를 대비하여 onerror 핸들러 추가
                def remove_readonly(func, path, excinfo):
                    # 오류가 발생해도 무시하고 계속 진행
                    pass
                shutil.rmtree(self.apk_session_temp_dir, onerror=remove_readonly)

            self.apk_session_temp_dir = None
            self.apk_map = {}
            is_apk_mode = False

            self.all_shaders = []
            self.master.after(0, self.clear_treeview, self.available_tree)
            self.master.after(0, self.replacement_map.clear)
            self.master.after(0, self.clear_treeview, self.selected_tree)
            
            self.master.after(0, self.toggle_buttons, False)
            self.master.after(0, self.progress_bar.grid)

            # 2. 모드 결정 및 APK 처리
            target_path = self.path_var.get()
            
            asset_files = []
            apk_files = []
            if os.path.isdir(target_path):
                all_files_in_dir = [os.path.join(r, f) for r, _, fs in os.walk(target_path) for f in fs]
                asset_files = [f for f in all_files_in_dir if f.lower().endswith(ASSET_EXTENSIONS)]
                apk_files = [f for f in all_files_in_dir if f.lower().endswith(".apk")]
            elif os.path.isfile(target_path):
                if target_path.lower().endswith(ASSET_EXTENSIONS):
                    asset_files.append(target_path)
                elif target_path.lower().endswith(".apk"):
                    apk_files.append(target_path)

            scan_targets = []
            # 일반 에셋 파일이 없고, APK 파일만 있을 때 APK 모드로 진입
            if not asset_files and apk_files:
                # 여러 APK가 발견되어도 첫 번째 파일만 처리
                apk_to_process = apk_files[0]
                if len(apk_files) > 1:
                    print(f"Multiple APKs found. Processing the first one: {apk_to_process}")

                # self.master.after(0, self.path_var.set, apk_to_process) # 이 줄이 무한 루프를 유발하므로 주석 처리 또는 삭제합니다.
                self.master.after(0, self.backup_var.set, False)
                is_apk_mode = True
                print("APK mode detected. Only .apk files found.")
                
                java_ok = shutil.which("java") is not None
                jar_path = self._find_uber_apk_signer_jar()

                if not java_ok or not jar_path:
                    error_msg = "APK Repacking Environment Check Failed:\n\n"
                    if not java_ok: error_msg += "• Java is not installed or not in your system's PATH.\n"
                    if not jar_path:
                        script_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
                        error_msg += f"• uber-apk-signer.jar not found in the script directory:\n  {script_dir}\n"
                    error_msg += "\nAPK repacking will not be possible."
                    self.master.after(0, messagebox.showwarning, "Environment Warning", error_msg)

                self.apk_session_temp_dir = tempfile.mkdtemp(prefix="demosaic_session_")
                try:
                    apk_name = os.path.splitext(os.path.basename(apk_to_process))[0]
                    temp_sub_dir = os.path.join(self.apk_session_temp_dir, apk_name)
                    os.makedirs(temp_sub_dir, exist_ok=True)
                    print(f"Extracting {os.path.basename(apk_to_process)} to {temp_sub_dir}...")
                    with zipfile.ZipFile(apk_to_process, 'r') as zip_ref:
                        zip_ref.extractall(temp_sub_dir)
                    self.apk_map[apk_to_process] = temp_sub_dir
                    for root, _, files in os.walk(temp_sub_dir):
                        for file in files:
                            if file.lower().endswith(ASSET_EXTENSIONS):
                                scan_targets.append(os.path.join(root, file))
                except Exception as e:
                    print(f"[Error] Failed to extract {os.path.basename(apk_to_process)}: {e}")
            else:
                print("Normal mode detected.")
                self.master.after(0, self.backup_var.set, True)
                if scan_all:
                    if os.path.isdir(target_path):
                        scan_targets = [f for f in all_files_in_dir if not f.endswith(".bak")]
                    else: # 파일 하나만 Scan All 하는 경우는 해당 파일만 스캔
                        scan_targets = asset_files
                else:
                    scan_targets = asset_files

            # 3. 실제 파일 스캔
            total_files = len(scan_targets)
            self.master.after(0, self.progress_bar.config, {'maximum': total_files, 'value': 0})
            print(f"Scanning {total_files} files for shaders...")
            found_shaders = []
            for i, file_path in enumerate(scan_targets):
                try:
                    with open(file_path, "rb") as f:
                        env = UnityPy.load(f)
                        for obj in env.objects:
                            if obj.type.name == "Shader":
                                tree = obj.read_typetree()
                                shader_name = tree.get('m_Name', '').strip()
                                if not shader_name:
                                    try:
                                        shader_name = tree["m_ParsedForm"]["m_Name"]
                                    except (KeyError, TypeError):
                                        shader_name = "Unknown Shader"
                                
                                found_shaders.append((shader_name, obj.path_id, file_path))
                except Exception as e:
                    pass
                
                self.master.after(0, self.progress_bar.config, {'value': i + 1})
                self.master.after(0, self.progress_bar.update)
            
            self.all_shaders = found_shaders
            self.master.after(0, self.update_available_list)
            self.master.after(0, self.auto_select_mosaic_shaders)
            self.master.after(0, self.reset_and_reapply_suggestions)
            self.master.after(0, self.progress_bar.config, {'value': 0})
            self.master.after(0, self.progress_bar.grid_remove)
            self.master.after(0, self.toggle_buttons, True)
            print("Scan complete.")

        target_path = self.path_var.get()
        if not target_path or not os.path.exists(target_path):
            messagebox.showerror("Error", "Please select a valid folder first.")
            return

        self.filter_var.set("") # 필터 초기화

        #self.scan_button.config(state="disabled") # 스캔 중 버튼 비활성화
        threading.Thread(target=_scan_task, args=(target_path,), daemon=True).start()

    def clear_treeview(self, tree):
        for item in tree.get_children():
            tree.delete(item)

    def update_available_list(self):
        self.clear_treeview(self.available_tree)
        filter_text = self.filter_var.get().lower()
        
        selected_path_ids = {self.selected_tree.item(item)['values'][1] for item in self.selected_tree.get_children()}

        for shader_name, path_id, file_path in self.all_shaders:
            if path_id in selected_path_ids:
                continue
            
            # 필터는 셰이더 이름과 파일 경로 모두에 적용
            if filter_text in shader_name.lower() or filter_text in file_path.lower():
                self.available_tree.insert("", tk.END, values=(shader_name, path_id, os.path.basename(file_path), file_path))
        
        # 필터링 후, 기존 정렬 상태가 있다면 다시 적용
        if hasattr(self.available_tree, 'sort_info'):
            sort_info = self.available_tree.sort_info
            self.sort_treeview(self.available_tree, sort_info['col'], sort_info['reverse'])

    def move_item(self, src_tree, dest_tree):
        selected_items = src_tree.selection()
        if not selected_items:
            return
        
        for item_id in selected_items:
            item_values = list(src_tree.item(item_id)['values'])
            
            # 대상 트리가 selected_tree인 경우, status 컬럼을 위한 빈 값을 추가합니다.
            if dest_tree == self.selected_tree and len(item_values) == 4:
                item_values.insert(3, "-> colMask edit 0") # status 컬럼 위치에 기본값 삽입

            # 항목을 일단 맨 끝에 추가합니다.
            new_item_id = dest_tree.insert("", tk.END, values=tuple(item_values), iid=item_id)
            src_tree.delete(item_id)
            if item_id in self.replacement_map and dest_tree == self.available_tree:
                del self.replacement_map[item_id]
        
        # 항목 추가가 모두 끝난 후, 대상 트리의 정렬 상태에 따라 다시 정렬합니다.
        if hasattr(dest_tree, 'sort_info'):
            sort_info = dest_tree.sort_info
            # 현재 저장된 정렬 상태(컬럼, 방향)를 그대로 사용하여 다시 정렬합니다.
            self.sort_treeview(dest_tree, sort_info['col'], sort_info['reverse'])
        
        if src_tree == self.selected_tree:
            self.update_available_list()
            self.reset_and_reapply_suggestions()
        elif dest_tree == self.selected_tree:
            self.find_and_highlight_suggestion(new_item_id)

    def move_to_selected(self, event=None):
        self.move_item(self.available_tree, self.selected_tree)

    def move_to_available(self, event=None):
        self.move_item(self.selected_tree, self.available_tree)

    def auto_select_mosaic_shaders(self):
        items_to_move = []
        for item_id in self.available_tree.get_children():
            shader_name = self.available_tree.item(item_id)['values'][0]
            if any(keyword in shader_name.lower() for keyword in KEYWORDS):
                items_to_move.append(item_id)

        if items_to_move:
            self.available_tree.selection_set(items_to_move)
            self.move_to_selected()

    def is_subsequence(self, s1, s2):
        """s1이 s2의 서브시퀀스인지 확인합니다."""
        it = iter(s2)
        return all(c in it for c in s1)

    def find_and_highlight_suggestion(self, target_item_id):
        """지정된 대상 아이템에 대한 교체 후보를 찾아 하이라이트합니다."""
        if not self.selected_tree.exists(target_item_id):
            return

        target_values = self.selected_tree.item(target_item_id, 'values')
        target_name = target_values[0]

        best_match_id = None
        max_len = -1

        # available_tree에서 target_name의 서브시퀀스가 되는 가장 긴 이름을 찾습니다.
        for source_item_id in self.available_tree.get_children():
            source_name = self.available_tree.item(source_item_id, 'values')[0]
            
            # 이름이 완전히 같으면 건너뜀
            if target_name == source_name:
                continue

            # source_name이 target_name의 서브시퀀스이고, 현재까지 찾은 것보다 긴 경우
            if self.is_subsequence(source_name, target_name):
                if len(source_name) > max_len:
                    max_len = len(source_name)
                    best_match_id = source_item_id
        
        # 가장 긴 서브시퀀스를 찾았고, 길이 차이가 너무 크지 않은 경우에만 하이라이트
        # (예: 길이 차이가 원본 길이의 50%를 넘지 않도록)
        if best_match_id:
            len_diff = len(target_name) - max_len
            if len_diff <= len(target_name) * 0.5:
                self.selected_tree.item(target_item_id, tags=('suggest_target',))
                self.available_tree.item(best_match_id, tags=('suggest_source',))

    def reset_and_reapply_suggestions(self):
        """모든 제안 하이라이트를 초기화하고 다시 적용합니다."""
        for item_id in self.available_tree.get_children():
            self.available_tree.item(item_id, tags=())
        
        for item_id in self.selected_tree.get_children():
            if 'replaced' not in self.selected_tree.item(item_id, 'tags'):
                self.selected_tree.item(item_id, tags=())
                self.find_and_highlight_suggestion(item_id)

    def show_context_menu(self, event):
        """선택된 아이템에 대한 컨텍스트 메뉴를 표시합니다."""
        tree = event.widget
        selection = tree.selection()
        if selection:
            item_id = tree.identify_row(event.y)
            if item_id in selection:
                if tree == self.selected_tree:
                    self.context_menu.post(event.x_root, event.y_root)
                elif tree == self.available_tree:
                    self.available_context_menu.post(event.x_root, event.y_root)

    def copy_shader_info(self, tree):
        """선택된 셰이더의 정보를 클립보드에 복사합니다."""
        selection = tree.selection()
        if not selection:
            return
        
        info_to_copy = []
        for item_id in selection:
            values = tree.item(item_id, 'values')
            if tree == self.selected_tree:
                name, path_id, _, _, fullpath = values
            else: # available_tree
                name, path_id, _, fullpath = values
            
            info_to_copy.append(f"Name: {name}\nPathID: {path_id}\nFile: {fullpath}")
        
        self.master.clipboard_clear()
        self.master.clipboard_append("\n".join(info_to_copy))
        print(f"{len(info_to_copy)} item(s) info copied to clipboard.")

    def find_suggestion_for_target(self, target_item_id):
        """주어진 대상 아이템 ID에 대한 최적의 제안 소스를 찾아서 ID를 반환합니다."""
        if not self.selected_tree.exists(target_item_id):
            return None

        target_values = self.selected_tree.item(target_item_id, 'values')
        target_name = target_values[0]

        best_match_id = None
        max_len = -1

        for source_item_id in self.available_tree.get_children():
            source_name = self.available_tree.item(source_item_id, 'values')[0]
            if target_name == source_name:
                continue
            if self.is_subsequence(source_name, target_name):
                if len(source_name) > max_len:
                    max_len = len(source_name)
                    best_match_id = source_item_id
        
        if best_match_id:
            len_diff = len(target_name) - max_len
            if len_diff <= len(target_name) * 0.5:
                return best_match_id
        return None

    def open_replace_window(self):
        """셰이더 교체를 위한 새 창을 엽니다."""
        target_item_id = self.selected_tree.selection()[0]
        target_values = self.selected_tree.item(target_item_id, 'values')
        target_name, target_pid, _, _, target_fpath = target_values
        
        win = tk.Toplevel(self.master)
        win.title("Select Source Shader")
        win.geometry("600x400")
        win.transient(self.master)
        win.grab_set()

        # 현재 타겟에 대한 제안 아이템을 찾습니다.
        suggested_item_id = self.find_suggestion_for_target(target_item_id)

        def update_list():
            tree.delete(*tree.get_children())
            filter_text = filter_var.get().lower()
            for item_id in self.available_tree.get_children():
                values = self.available_tree.item(item_id, 'values')
                tags = self.available_tree.item(item_id, 'tags')
                if filter_text in values[0].lower() or filter_text in values[3].lower():
                    tree.insert("", "end", iid=item_id, values=values, tags=tags)
            
            # 제안된 항목이 있으면 해당 위치로 스크롤
            if suggested_item_id and tree.exists(suggested_item_id):
                tree.see(suggested_item_id)
                tree.selection_set(suggested_item_id)


        def on_ok():
            source_selection = tree.selection()
            if not source_selection:
                messagebox.showwarning("Warning", "Please select a source shader.", parent=win)
                return
            
            source_item_id = source_selection[0]
            source_values = self.available_tree.item(source_item_id, 'values')

            self.replacement_map[target_item_id] = source_values

            self.selected_tree.item(target_item_id, tags=('replaced',))
            self.selected_tree.set(target_item_id, 'status', f"-> {source_values[0]}")

            self.reset_and_reapply_suggestions()
            win.destroy()

        # --- 창 레이아웃 구성 ---
        # 상단 프레임 (정보 + 버튼)
        top_section_frame = ttk.Frame(win)
        top_section_frame.pack(fill=tk.X, padx=5, pady=5)

        # 교체 대상 정보 (왼쪽)
        target_info_frame = ttk.LabelFrame(top_section_frame, text="Target Shader (to be replaced)", padding=5)
        target_info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        info_text = (f"Name: {target_name}\n"
                     f"PathID: {target_pid}\n"
                     f"File: {os.path.basename(target_fpath)}")
        ttk.Label(target_info_frame, text=info_text, justify=tk.LEFT).pack(anchor='w')

        # OK/Cancel 버튼 (오른쪽)
        btn_frame = ttk.Frame(top_section_frame)
        btn_frame.pack(side=tk.RIGHT, anchor='center', padx=(10, 0))
        ttk.Button(btn_frame, text="OK", command=on_ok).pack(pady=2, fill=tk.X)
        ttk.Button(btn_frame, text="Cancel", command=win.destroy).pack(pady=2, fill=tk.X)

        # 필터 엔트리
        filter_var = tk.StringVar()
        filter_var.trace_add("write", lambda *args: update_list())
        ttk.Entry(win, textvariable=filter_var).pack(fill=tk.X, padx=5, pady=(0, 5))

        # --- Treeview와 스크롤바를 담을 프레임 ---
        tree_frame = ttk.Frame(win)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        tree = self.create_shader_treeview(tree_frame)
        tree.grid(row=0, column=0, sticky="nsew")

        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        # 태그 및 목록 업데이트
        tree.tag_configure('suggest_source', background=self.available_tree.tag_configure('suggest_source', 'background'))
        update_list() # 초기 목록 채우기

        # 창이 닫힐 때까지 기다립니다.
        self.master.wait_window(win)

    def start_processing(self):
        def _processing_task():
            selected_items = self.selected_tree.get_children()
            if not selected_items:
                messagebox.showinfo("Info", "No shaders selected for processing.")
                return
            
            self.master.after(0, self.toggle_buttons, False)

            selected_shaders_info = []
            replacement_tasks = []

            for item_id in selected_items:
                values = self.selected_tree.item(item_id)['values']
                tags = self.selected_tree.item(item_id, 'tags')

                if 'replaced' in tags and item_id in self.replacement_map:
                    target_path_id = values[1]
                    target_file_path = values[4]
                    source_values = self.replacement_map[item_id]
                    source_path_id = source_values[1]
                    source_file_path = source_values[3]
                    replacement_tasks.append({
                        'target_file': target_file_path,
                        'target_pid': target_path_id,
                        'source_file': source_file_path,
                        'source_pid': source_path_id
                    })
                else:
                    path_id = values[1]
                    full_path = values[4]
                    if full_path:
                        selected_shaders_info.append({'path_id': path_id, 'file_path': full_path})

            if replacement_tasks:
                print("\nStarting shader replacement process...")
                for task in replacement_tasks:
                    self.execute_replacement(task)

            shaders_to_process = {}
            for info in selected_shaders_info:
                file_path = info['file_path']
                if file_path not in shaders_to_process:
                    shaders_to_process[file_path] = []
                shaders_to_process[file_path].append(info['path_id'])
            
            if shaders_to_process:
                print("\nStarting demosaic (colMask) process...")
                for file_path, path_ids in shaders_to_process.items():
                    self.process_asset_file(file_path, set(path_ids))

            # APK 모드에서 수정된 파일들을 원본 APK별로 그룹화
            modified_files_by_apk = {}
            if self.apk_map:
                for original_apk_path, temp_dir in self.apk_map.items():
                    modified_files_by_apk[original_apk_path] = []

                for modified_file_path in shaders_to_process.keys():
                    for original_apk_path, temp_dir in self.apk_map.items():
                        if modified_file_path.startswith(temp_dir):
                            modified_files_by_apk[original_apk_path].append(modified_file_path)
                            break
                
                # replacement_tasks에 있는 파일들도 추가
                # (이 부분은 현재 로직에서는 shaders_to_process에 이미 포함되므로 생략 가능하나, 안정성을 위해 추가)

            # APK 모드인 경우, 리패키징 수행
            if self.apk_map:
                print("\nStarting APK repacking process...")
                for original_apk_path, temp_dir in self.apk_map.items():
                    print(f"Repacking for {os.path.basename(original_apk_path)}...")
                    base, ext = os.path.splitext(original_apk_path)
                    output_apk_path = f"{base}_mod{ext}"

                    if not output_apk_path:
                        print("Repacking cancelled by user.")
                        continue

                    try:
                        # 1. 수정된 파일 목록을 {arcname: full_path} 형태의 딕셔너리로 변환
                        modified_files_map = {
                            os.path.relpath(f, temp_dir): f
                            for f in modified_files_by_apk.get(original_apk_path, [])
                        }

                        # 2. 새로운 임시 APK를 만들면서 수정된 파일만 교체
                        unsigned_apk_path = os.path.join(self.apk_session_temp_dir, f"temp_{os.path.basename(original_apk_path)}")
                        print(f"Rebuilding APK with {len(modified_files_map)} modified files...")
                        
                        with zipfile.ZipFile(original_apk_path, 'r') as zin:
                            with zipfile.ZipFile(unsigned_apk_path, 'w') as zout:
                                for item in zin.infolist():
                                    # 수정된 파일 목록에 현재 파일이 있다면, 수정된 파일의 내용으로 교체
                                    if item.filename in modified_files_map:
                                        modified_file_path = modified_files_map[item.filename]
                                        # .so 파일은 압축하지 않음
                                        compress_type = zipfile.ZIP_STORED if item.filename.lower().endswith('.so') else zipfile.ZIP_DEFLATED
                                        zout.write(modified_file_path, item.filename, compress_type=compress_type)
                                        print(f"  -> Updated: {item.filename}")
                                    else:
                                        # 수정되지 않은 파일은 원본 그대로 복사
                                        buffer = zin.read(item.filename)
                                        zout.writestr(item, buffer)
                        print(f"Rebuilt unsigned APK: {unsigned_apk_path}")

                        # 2. Sign the APK
                        print("Signing APK with debug key...")
                        jar_path = self._find_uber_apk_signer_jar()
                        if not jar_path:
                            script_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
                            raise Exception(f"uber-apk-signer.jar not found in the script directory:\n{script_dir}")

                        apk_dir = os.path.dirname(unsigned_apk_path)
                        result = subprocess.run(
                            # cwd를 apk_dir로 설정하고, unsigned.apk의 전체 경로를 전달
                            # zipalign을 다시 활성화하기 위해 --skip-zip-align 제거
                            ["java", "-Dfile.encoding=UTF-8", "-jar", jar_path, "-a", unsigned_apk_path, "--out", apk_dir],
                            capture_output=True, text=True, check=False, encoding='utf-8', errors='ignore', cwd=apk_dir
                        )

                        if result.returncode != 0:
                            error_message = result.stderr or result.stdout
                            raise Exception(f"uber-apk-signer failed with exit code {result.returncode}:\n---\n{error_message.strip()}\n---")

                        # uber-apk-signer는 입력 파일명을 기준으로 결과물을 생성
                        base_name = os.path.splitext(os.path.basename(unsigned_apk_path))[0]
                        
                        signed_apk_aligned = os.path.join(apk_dir, f"{base_name}-aligned-debugSigned.apk")

                        # uber-apk-signer가 생성한 서명된 파일을 최종 목적지로 이동합니다.
                        shutil.move(signed_apk_aligned, output_apk_path)
                        print(f"[✔] Signed APK saved to: {output_apk_path}")

                        # 서명에 사용된 임시 unsigned.apk 파일은 삭제합니다.
                        os.remove(unsigned_apk_path) # 서명에 사용된 원본은 삭제

                    except Exception as e:
                        messagebox.showerror("APK Repack Error", f"Failed to repack or sign APK for {os.path.basename(original_apk_path)}: {e}")
                        print(f"[✘] Failed to repack or sign APK: {e}")

            self.master.after(0, self.toggle_buttons, True)
            messagebox.showinfo("Complete", "Processing finished. Check the console for details.")

            print("Complete.")
        
        threading.Thread(target=_processing_task, daemon=True).start()

    def execute_replacement(self, task):
        """셰이더 내용을 다른 셰이더의 내용으로 교체합니다."""
        target_file, target_pid = task['target_file'], task['target_pid']
        source_file, source_pid = task['source_file'], task['source_pid']

        print(f"[+] Replacing shader in {os.path.basename(target_file)} (pathId:{target_pid})")
        print(f"    Source: {os.path.basename(source_file)} (pathId:{source_pid})")

        try:
            source_tree = None
            with open(source_file, "rb") as f:
                env = UnityPy.load(f)
                for obj in env.objects:
                    if obj.path_id == int(source_pid):
                        source_tree = obj.read_typetree()
                        break
            if not source_tree:
                print(f"    -> [Error] Source shader (pathId:{source_pid}) not found in {source_file}")
                return

            modified = False
            env_target = UnityPy.load(target_file)
            for obj in env_target.objects:
                if obj.path_id == int(target_pid):
                    target_tree = obj.read_typetree()
                    original_name = target_tree.get('m_Name') or target_tree.get("m_ParsedForm", {}).get("m_Name", "Unknown")
                    
                    source_tree['m_Name'] = original_name
                    if "m_ParsedForm" in source_tree and "m_Name" in source_tree["m_ParsedForm"]:
                        source_tree["m_ParsedForm"]['m_Name'] = original_name

                    obj.save_typetree(source_tree)
                    modified = True
                    print(f"   -> Replaced content of '{original_name}'")
                    break
            
            if modified:
                self.save_modified_file(target_file, env_target.file.save(packer='original'))
        except Exception as e:
            print(f"    -> [Error] Failed to execute replacement: {e}")

    def process_asset_file(self, path, selected_path_ids):
        try:
            with open(path, "rb") as f:
                env = UnityPy.load(f)
                modified = False

                for obj in env.objects:
                    if obj.path_id not in selected_path_ids or obj.type.name != "Shader":
                        continue

                    try:
                        tree = obj.read_typetree()
                        shader_name = tree.get('m_Name', '').strip()
                        if not shader_name:
                            try:
                                shader_name = tree["m_ParsedForm"]["m_Name"]
                            except (KeyError, TypeError):
                                pass # 이름이 없어도 처리는 계속
                        print(f"[+] Processing: {shader_name} in {os.path.basename(path)} (pathId:{obj.path_id})")

                        parsed_form = tree.get("m_ParsedForm")
                        if parsed_form and "m_SubShaders" in parsed_form:
                            subshaders = parsed_form["m_SubShaders"]
                            for subshader in subshaders:
                                for shader_pass in subshader.get("m_Passes", []):
                                    state = shader_pass.get("m_State", {})
                                    for _, value in state.items():
                                        if hasattr(value, 'get'):
                                            col = value.get("colMask")
                                            if hasattr(col, 'get') and col.get("val", 0) > 0:
                                                col["val"] = 0
                                                modified = True
                            if modified:
                                print(f"   -> modified")
                                obj.save_typetree(tree)
                        else:
                            print(f"    -> Skipping: m_ParsedForm or m_SubShaders not found.")
                    except Exception as e:
                        print(f"    -> Error processing shader: {e}")

                # with 블록이 끝나면 파일 핸들이 닫히므로, 닫힌 후에 저장 작업을 수행합니다.
                if modified:
                    self.save_modified_file(path, env.file.save(packer='original'))
        except Exception as e:
            print(f"[✘] Failed to process or save {path}: {e}\n")

    def save_modified_file(self, path, file_bytes):
        """파일을 백업하고 저장하는 공통 로직"""
        if self.backup_var.get():
            backup_path = path + ".bak"
            if not os.path.exists(backup_path):
                print(f"   -> Backing up original file to {os.path.basename(backup_path)}")
                shutil.copy2(path, backup_path)
            else:
                print(f"   -> Backup file {os.path.basename(backup_path)} already exists. Skipping backup.")

        with open(path, "wb") as f:
            f.write(file_bytes)
        print(f"[✔] Saved → {path}\n")


if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = DemosaicGUI(root)
    root.mainloop()
