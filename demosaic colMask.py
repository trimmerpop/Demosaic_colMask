import os
import shutil
import sys
import UnityPy
import tkinter as tk
import threading
from tkinterdnd2 import DND_FILES, TkinterDnD
from queue import Queue, Empty
from tkinter import ttk, filedialog, messagebox

# Mosaic 인식 키워드
KEYWORDS = ["mos", "moz", "maz", "pixel", "censor", "ピクセル", "モザイク"]

class DemosaicGUI:
    def __init__(self, master):
        self.master = master
        master.title("Demosaic Tool (colMask)")
        master.geometry("800x600")

        # 상단 프레임 (경로 입력 및 스캔 버튼)
        top_frame = ttk.Frame(master, padding="10")
        top_frame.pack(fill=tk.X)

        ttk.Label(top_frame, text="Path:").pack(side=tk.LEFT, padx=(0, 5))
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(top_frame, textvariable=self.path_var)
        self.path_var.trace_add("write", self.on_path_change)

        self.placeholder = "Drag & Drop or Double click to select a folder"
        self.placeholder_color = 'grey'
        self.default_fg_color = self.path_entry.cget('foreground')

        self.path_entry.bind("<FocusIn>", self.on_entry_focus_in)
        self.path_entry.bind("<FocusOut>", self.on_entry_focus_out)

        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.path_entry.bind("<Double-1>", self.select_folder)
        # 드래그 앤 드롭 설정
        self.path_entry.drop_target_register(DND_FILES)
        self.path_entry.dnd_bind('<<Drop>>', self.on_drop)

        self.scan_all_button = ttk.Button(top_frame, text="Scan All", command=self.scan_all_for_gui)
        self.scan_all_button.pack(side=tk.LEFT, padx=(5, 0))

        #self.scan_button = ttk.Button(top_frame, text="Scan Shaders", command=self.scan_shaders_for_gui, state="disabled")
        #self.scan_button.pack(side=tk.LEFT, padx=(5, 0))

        self.backup_var = tk.BooleanVar(value=True)
        backup_check = ttk.Checkbutton(top_frame, text="Backup File", variable=self.backup_var)
        backup_check.pack(side=tk.LEFT, padx=(5, 0))

        self.start_button = ttk.Button(top_frame, text="Start Demosaic", command=self.start_processing)
        self.start_button.pack(side=tk.LEFT, padx=(5, 0))

        self.buttons = [self.scan_all_button, self.start_button]
        # if self.scan_button is used, add it here too.
        # self.buttons.append(self.scan_button)

        # 중앙 프레임 (셰이더 목록)
        main_frame = ttk.Frame(master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        main_frame.grid_rowconfigure(1, weight=1)

        # 사용 가능한 셰이더 목록
        available_frame = ttk.LabelFrame(main_frame, text="Available Shaders", padding="5")
        available_frame.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 5))
        available_frame.grid_rowconfigure(1, weight=1)
        available_frame.grid_columnconfigure(0, weight=1)

        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *args: self.update_available_list())
        filter_entry = ttk.Entry(available_frame, textvariable=self.filter_var)
        filter_entry.grid(row=0, column=0, sticky="ew", pady=(0, 5))

        self.available_tree = self.create_shader_treeview(available_frame)
        self.available_tree.grid(row=1, column=0, sticky="nsew")
        self.available_tree.bind("<Double-1>", self.move_to_selected)

        # 선택된 셰이더 목록
        selected_frame = ttk.LabelFrame(main_frame, text="Selected Shaders", padding="5")
        selected_frame.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=(5, 0))
        selected_frame.grid_rowconfigure(0, weight=1)
        selected_frame.grid_columnconfigure(0, weight=1)
        
        self.selected_tree = self.create_shader_treeview(selected_frame)
        self.selected_tree.grid(row=0, column=0, sticky="nsew")
        self.selected_tree.bind("<Double-1>", self.move_to_available)

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

        self.all_shaders = [] # (shader_name, path_id, file_path)

    def process_log_queue(self):
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

    def on_entry_focus_in(self, event):
        if self.path_var.get() == self.placeholder:
            self.path_entry.delete(0, "end")
            self.path_entry.config(foreground=self.default_fg_color)

    def on_entry_focus_out(self, event):
        if not self.path_var.get():
            self.path_entry.insert(0, self.placeholder)
            self.path_entry.config(foreground=self.placeholder_color)

    def on_drop(self, event):
        # event.data는 중괄호로 묶인 경로 문자열일 수 있음 (예: '{D:/path/to/folder}')
        path = event.data.strip('{}')

        # 여러 파일이 드롭된 경우, 첫 번째 항목을 사용
        if ' ' in path and not os.path.isdir(path):
            path = path.split(' ')[0]

        # 드롭된 것이 폴더인지 확인
        if os.path.isdir(path):
            self.path_entry.config(foreground=self.default_fg_color)
            self.path_var.set(path)
        else:
            messagebox.showwarning("Warning", "Please drop a folder, not a file.")


    def create_shader_treeview(self, parent):
        # 'fullpath' 열을 추가하되, displaycolumns를 통해 숨김
        tree = ttk.Treeview(parent, columns=("name", "path_id", "file", "fullpath"), show="headings")
        tree.configure(displaycolumns=("name", "path_id", "file"))

        tree.heading("name", text="Shader Name", command=lambda: self.sort_treeview(tree, "name", False))
        tree.heading("path_id", text="PathID", command=lambda: self.sort_treeview(tree, "path_id", False))
        tree.heading("file", text="File Path", command=lambda: self.sort_treeview(tree, "file", False))

        tree.column("name", width=200)
        tree.column("path_id", width=80, anchor="e")
        tree.column("file", width=250)
        return tree

    def sort_treeview(self, tree, col, reverse):
        data = [(tree.set(item, col), item) for item in tree.get_children('')]
        # PathID는 숫자 기준으로 정렬
        key = int if col == "path_id" else str.lower
        data.sort(key=lambda t: key(t[0]), reverse=reverse)
        for index, (val, item) in enumerate(data):
            tree.move(item, '', index)
        tree.heading(col, command=lambda: self.sort_treeview(tree, col, not reverse))

    def select_folder(self, event=None):
        folder_selected = filedialog.askdirectory(initialdir=self.path_var.get())
        if folder_selected:
            self.path_entry.config(foreground=self.default_fg_color)
            self.path_var.set(folder_selected)

    def on_path_change(self, *args):
        if self.path_var.get() == self.placeholder:
            #self.scan_button.config(state="disabled")
            return
        
        path = self.path_var.get()
        if path and os.path.isdir(path):
            #self.scan_button.config(state="normal")
            self.scan_shaders_for_gui(scan_all=False) # 폴더 선택 시 자동 스캔 (기본 확장자만)
        #else:
        #    self.scan_button.config(state="disabled")

    def toggle_buttons(self, enabled):
        for button in self.buttons:
            button.config(state=tk.NORMAL if enabled else tk.DISABLED)

    def scan_all_for_gui(self):
        self.scan_shaders_for_gui(scan_all=True)

    def scan_shaders_for_gui(self, scan_all=False):
        def _scan_task(target_path, scan_all_files):
            self.all_shaders = []
            self.master.after(0, self.clear_treeview, self.available_tree)
            self.master.after(0, self.clear_treeview, self.selected_tree)
            
            self.master.after(0, self.toggle_buttons, False)
            self.master.after(0, self.progress_bar.grid) # 스캔 시작 시 프로그레스 바 표시

            print(f"Scanning for shaders in: {target_path}")

            # 1. 스캔할 파일 목록 및 총 개수 계산
            files_to_scan = []
            for root, _, files in os.walk(target_path):
                for file in files:
                    if (scan_all_files and not file.endswith(".bak")) or file.endswith((".assets", ".bundle", ".unity3d", ".sharedAssets", ".resS", ".dat")):
                        files_to_scan.append(os.path.join(root, file))
            
            total_files = len(files_to_scan)
            self.master.after(0, self.progress_bar.config, {'maximum': total_files, 'value': 0})

            def update_progress(value):
                self.progress_bar.config(value=value)
                self.progress_bar.update()

            # 2. 실제 스캔 및 프로그레스 바 업데이트
            found_shaders = []
            for i, file_path in enumerate(files_to_scan):
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
                    print(f"Error processing {file_path}: {e}")
                
                # 프로그레스 바 업데이트
                self.master.after(0, update_progress, i + 1)
            
            self.all_shaders = found_shaders
            self.master.after(0, self.update_available_list)
            self.master.after(0, self.auto_select_mosaic_shaders)
            self.master.after(0, self.progress_bar.config, {'value': 0}) # 완료 후 초기화
            self.master.after(0, self.progress_bar.grid_remove) # 스캔 완료 시 프로그레스 바 숨김
            self.master.after(0, self.toggle_buttons, True)
            print("Scan complete.")

        target_path = self.path_var.get()
        if not target_path or target_path == self.placeholder or not os.path.isdir(target_path):
            # 이 부분은 주로 수동 입력 시 경로가 유효하지 않을 때를 대비합니다.
            messagebox.showerror("Error", "Invalid or empty path specified.")
            return

        self.filter_var.set("") # 필터 초기화

        #self.scan_button.config(state="disabled") # 스캔 중 버튼 비활성화
        threading.Thread(target=_scan_task, args=(target_path, scan_all), daemon=True).start()

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

    def move_item(self, src_tree, dest_tree):
        selected_items = src_tree.selection()
        if not selected_items:
            return
        
        for item_id in selected_items:
            item_values = src_tree.item(item_id)['values']
            dest_tree.insert("", tk.END, values=item_values)
            src_tree.delete(item_id)
        
        if src_tree == self.selected_tree:
            self.update_available_list()

    def move_to_selected(self, event=None):
        self.move_item(self.available_tree, self.selected_tree)

    def move_to_available(self, event=None):
        self.move_item(self.selected_tree, self.available_tree)
        self.update_available_list()

    def auto_select_mosaic_shaders(self):
        items_to_move = []
        for item_id in self.available_tree.get_children():
            shader_name = self.available_tree.item(item_id)['values'][0]
            if any(keyword in shader_name.lower() for keyword in KEYWORDS):
                items_to_move.append(item_id)

        if items_to_move:
            self.available_tree.selection_set(items_to_move)
            self.move_to_selected()

    def start_processing(self):
        def _processing_task():
            selected_items = self.selected_tree.get_children()
            if not selected_items:
                messagebox.showinfo("Info", "No shaders selected for processing.")
                return

            # Treeview에서 선택된 항목들의 path_id와 file_path를 가져옵니다.
            self.master.after(0, self.toggle_buttons, False)

            selected_shaders_info = []
            for item_id in selected_items:
                values = self.selected_tree.item(item_id)['values']
                path_id = values[1]
                # 숨겨진 'fullpath' 열에서 전체 경로를 직접 가져옴
                full_path = values[3]
                if full_path:
                    selected_shaders_info.append({'path_id': path_id, 'file_path': full_path})

            # Group shaders by file path
            shaders_to_process = {}
            for info in selected_shaders_info:
                file_path = info['file_path']
                if file_path not in shaders_to_process:
                    shaders_to_process[file_path] = []
                shaders_to_process[file_path].append(info['path_id'])

            print("\nStarting demosaic process...")
            for file_path, path_ids in shaders_to_process.items():
                self.process_asset_file(file_path, set(path_ids))
            
            self.master.after(0, self.toggle_buttons, True)
            messagebox.showinfo("Complete", "Processing finished. Check the console for details.")
            print("Complete.")
        
        threading.Thread(target=_processing_task, daemon=True).start()

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
                    file_bytes = env.file.save(packer='original')

            if modified:
                if self.backup_var.get():
                    backup_path = path + ".bak"
                    if not os.path.exists(backup_path):
                        print(f"   -> Backing up original file to {os.path.basename(backup_path)}")
                        shutil.copy2(path, backup_path)
                    else:
                        print(f"   -> Backup file {os.path.basename(backup_path)} already exists. Skipping backup.")

                with open(path, "wb") as f:
                    f.write(file_bytes)

                # chunk_size = 65536 # 64KB
                # bytes_written = 0
                # with open(path, "wb") as f:
                #     for i in range(0, len(file_bytes), chunk_size):
                #         chunk = file_bytes[i:i + chunk_size]
                #         f.write(chunk)
                #         bytes_written += len(chunk)

                print(f"[✔] Saved → {path}\n")
        except Exception as e:
            print(f"[✘] Failed to process or save {path}: {e}\n")


if __name__ == "__main__":
    root = TkinterDnD.Tk() # tk.Tk() 대신 TkinterDnD.Tk() 사용
    app = DemosaicGUI(root)
    root.mainloop()
