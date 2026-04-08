from __future__ import annotations

import os
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .services import (
    analyze_cleanup,
    empty_recycle_bin,
    invalidate_scan_cache,
    move_to_recycle_bin,
    run_temp_cleanup,
    scan_directory,
    search_files,
)


def format_bytes(value: int) -> str:
    size = max(float(value or 0), 0.0)
    if size < 1024:
        return f"{int(size)} B"

    units = ["KB", "MB", "GB", "TB"]
    index = 0
    size /= 1024

    while size >= 1024 and index < len(units) - 1:
        size /= 1024
        index += 1

    precision = 1 if size >= 10 else 2
    return f"{size:.{precision}f} {units[index]}"


def format_count(value: int) -> str:
    return f"{int(value or 0):,}"


def risk_tag(risk: str) -> str:
    if risk == "低风险":
        return "低风险"
    if risk == "中风险":
        return "中风险"
    if risk == "高风险":
        return "高风险"
    return "普通"


class CClearApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("CClear")
        self.geometry("1500x940")
        self.minsize(1280, 800)
        self.configure(bg="#0f172a")

        self.root_var = tk.StringVar(value=os.environ.get("SystemDrive", "C:") + "\\")
        self.status_var = tk.StringVar(value="就绪")
        self.progress_var = tk.StringVar(value=self.root_var.get())
        self.search_query_var = tk.StringVar()
        self.search_min_size_var = tk.StringVar(value="100")
        self.prefer_index_var = tk.BooleanVar(value=True)
        self.scan_summary_var = tk.StringVar(value="尚未扫描")
        self.search_summary_var = tk.StringVar(value="尚未搜索")
        self.cleanup_summary_var = tk.StringVar(value="尚未分析清理机会")

        self.event_queue: queue.Queue = queue.Queue()
        self.busy = False
        self.scan_result: dict | None = None
        self.search_result: dict | None = None
        self.cleanup_analysis: dict | None = None

        self.action_buttons: list[ttk.Button] = []
        self.metrics: dict[str, tk.StringVar] = {}
        self.log_list: tk.Listbox | None = None
        self.scan_files_tree: ttk.Treeview | None = None
        self.scan_directories_tree: ttk.Treeview | None = None
        self.extension_tree: ttk.Treeview | None = None
        self.search_tree: ttk.Treeview | None = None
        self.cleanup_tree: ttk.Treeview | None = None
        self.download_tree: ttk.Treeview | None = None

        self._configure_style()
        self._build_layout()
        self.after(160, self._drain_events)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#0f172a")
        style.configure("Card.TFrame", background="#111827")
        style.configure("Header.TLabel", background="#0f172a", foreground="#f8fafc", font=("Microsoft YaHei UI", 22, "bold"))
        style.configure("SubHeader.TLabel", background="#0f172a", foreground="#94a3b8", font=("Microsoft YaHei UI", 10))
        style.configure("Section.TLabel", background="#111827", foreground="#f8fafc", font=("Microsoft YaHei UI", 12, "bold"))
        style.configure("Value.TLabel", background="#111827", foreground="#e2e8f0", font=("Microsoft YaHei UI", 11))
        style.configure("TButton", padding=(10, 8))
        style.configure("Treeview", background="#0b1220", fieldbackground="#0b1220", foreground="#e2e8f0", rowheight=28)
        style.configure("Treeview.Heading", background="#1e293b", foreground="#e2e8f0", font=("Microsoft YaHei UI", 10, "bold"))
        style.map("Treeview", background=[("selected", "#1d4ed8")])
        style.configure("TNotebook", background="#0f172a")
        style.configure("TNotebook.Tab", padding=(12, 8), background="#1e293b", foreground="#e2e8f0")
        style.map("TNotebook.Tab", background=[("selected", "#2563eb")], foreground=[("selected", "#ffffff")])

    def _build_layout(self) -> None:
        outer = ttk.Frame(self, padding=18)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 12))

        ttk.Label(header, text="CClear", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header, text="Windows 桌面磁盘管理工具原型：扫描、搜索、清理一体化", style="SubHeader.TLabel").pack(
            anchor="w", pady=(2, 0)
        )

        top_bar = ttk.Frame(outer, style="Card.TFrame", padding=16)
        top_bar.pack(fill="x", pady=(0, 12))

        ttk.Label(top_bar, text="扫描路径", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        entry = ttk.Entry(top_bar, textvariable=self.root_var, width=80)
        entry.grid(row=1, column=0, sticky="ew", padx=(0, 10), pady=(8, 0))
        top_bar.columnconfigure(0, weight=1)

        browse_button = ttk.Button(top_bar, text="选择目录", command=self.choose_root)
        browse_button.grid(row=1, column=1, padx=(0, 10), pady=(8, 0))
        scan_button = ttk.Button(top_bar, text="开始扫描", command=self.start_scan)
        scan_button.grid(row=1, column=2, pady=(8, 0))
        refresh_button = ttk.Button(top_bar, text="强制重扫", command=lambda: self.start_scan(force_refresh=True))
        refresh_button.grid(row=1, column=3, padx=(10, 0), pady=(8, 0))
        self.action_buttons.extend([browse_button, scan_button, refresh_button])

        status_row = ttk.Frame(top_bar, style="Card.TFrame")
        status_row.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(12, 0))
        ttk.Label(status_row, text="当前状态", style="SubHeader.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(status_row, textvariable=self.status_var, style="Value.TLabel").grid(row=1, column=0, sticky="w")
        ttk.Label(status_row, text="进度路径", style="SubHeader.TLabel").grid(row=0, column=1, sticky="w", padx=(40, 0))
        ttk.Label(status_row, textvariable=self.progress_var, style="Value.TLabel").grid(row=1, column=1, sticky="w", padx=(40, 0))

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)

        scan_tab = ttk.Frame(notebook, padding=14, style="Card.TFrame")
        search_tab = ttk.Frame(notebook, padding=14, style="Card.TFrame")
        cleanup_tab = ttk.Frame(notebook, padding=14, style="Card.TFrame")
        notebook.add(scan_tab, text="扫描概览")
        notebook.add(search_tab, text="搜索")
        notebook.add(cleanup_tab, text="清理")

        self._build_scan_tab(scan_tab)
        self._build_search_tab(search_tab)
        self._build_cleanup_tab(cleanup_tab)

    def _build_scan_tab(self, parent: ttk.Frame) -> None:
        summary_frame = ttk.Frame(parent, style="Card.TFrame")
        summary_frame.pack(fill="x", pady=(0, 12))

        for label, key in (
            ("总占用", "total_size"),
            ("文件数", "total_files"),
            ("目录数", "total_directories"),
            ("跳过项", "skipped_entries"),
            ("扫描耗时", "duration_seconds"),
            ("扫描根路径", "root"),
        ):
            variable = tk.StringVar(value="-")
            self.metrics[key] = variable
            card = ttk.Frame(summary_frame, style="Card.TFrame", padding=12)
            card.pack(side="left", fill="x", expand=True, padx=(0, 8))
            ttk.Label(card, text=label, style="SubHeader.TLabel").pack(anchor="w")
            ttk.Label(card, textvariable=variable, style="Section.TLabel").pack(anchor="w", pady=(8, 0))

        ttk.Label(parent, textvariable=self.scan_summary_var, style="SubHeader.TLabel").pack(anchor="w", pady=(0, 8))

        upper = ttk.PanedWindow(parent, orient="horizontal")
        upper.pack(fill="both", expand=True)

        left_frame = ttk.Frame(upper, style="Card.TFrame")
        right_frame = ttk.Frame(upper, style="Card.TFrame")
        upper.add(left_frame, weight=1)
        upper.add(right_frame, weight=1)

        ttk.Label(left_frame, text="最大文件", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
        self.scan_files_tree = self._create_tree(
            left_frame,
            ("name", "size", "risk", "modified", "path"),
            ("名称", "大小", "风险", "修改时间", "路径"),
            (180, 100, 80, 140, 520),
        )

        ttk.Label(right_frame, text="最大目录", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
        self.scan_directories_tree = self._create_tree(
            right_frame,
            ("name", "size", "files", "risk", "path"),
            ("名称", "大小", "文件数", "风险", "路径"),
            (180, 100, 90, 80, 520),
        )

        lower = ttk.Frame(parent, style="Card.TFrame")
        lower.pack(fill="both", expand=True, pady=(12, 0))
        ttk.Label(lower, text="扩展名分布", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
        self.extension_tree = self._create_tree(
            lower,
            ("extension", "size", "count"),
            ("扩展名", "占用大小", "文件数"),
            (180, 140, 120),
        )

    def _build_search_tab(self, parent: ttk.Frame) -> None:
        control = ttk.Frame(parent, style="Card.TFrame")
        control.pack(fill="x", pady=(0, 12))

        ttk.Label(control, text="关键词", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Entry(control, textvariable=self.search_query_var, width=32).grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Label(control, text="最小大小(MB)", style="Section.TLabel").grid(row=0, column=1, sticky="w", padx=(16, 0))
        ttk.Entry(control, textvariable=self.search_min_size_var, width=12).grid(row=1, column=1, sticky="w", padx=(16, 0), pady=(8, 0))
        ttk.Checkbutton(control, text="优先使用索引缓存", variable=self.prefer_index_var).grid(
            row=1, column=2, sticky="w", padx=(16, 0), pady=(8, 0)
        )

        search_button = ttk.Button(control, text="开始搜索", command=self.start_search)
        search_button.grid(row=1, column=3, padx=(16, 0), pady=(8, 0))
        locate_button = ttk.Button(control, text="打开所在位置", command=lambda: self.locate_selected(self.search_tree))
        locate_button.grid(row=1, column=4, padx=(8, 0), pady=(8, 0))
        trash_button = ttk.Button(control, text="移入回收站", command=lambda: self.trash_selected(self.search_tree))
        trash_button.grid(row=1, column=5, padx=(8, 0), pady=(8, 0))
        self.action_buttons.extend([search_button, locate_button, trash_button])

        ttk.Label(parent, textvariable=self.search_summary_var, style="SubHeader.TLabel").pack(anchor="w", pady=(0, 8))
        self.search_tree = self._create_tree(
            parent,
            ("name", "size", "risk", "modified", "path"),
            ("名称", "大小", "风险", "修改时间", "路径"),
            (180, 100, 80, 140, 700),
        )

    def _build_cleanup_tab(self, parent: ttk.Frame) -> None:
        control = ttk.Frame(parent, style="Card.TFrame")
        control.pack(fill="x", pady=(0, 12))

        analyze_button = ttk.Button(control, text="分析清理机会", command=self.start_cleanup_analysis)
        analyze_button.pack(side="left")
        cleanup_button = ttk.Button(control, text="清理临时文件", command=self.start_temp_cleanup)
        cleanup_button.pack(side="left", padx=(8, 0))
        empty_button = ttk.Button(control, text="清空回收站", command=self.start_empty_recycle_bin)
        empty_button.pack(side="left", padx=(8, 0))
        locate_download_button = ttk.Button(control, text="打开建议项位置", command=lambda: self.locate_selected(self.download_tree))
        locate_download_button.pack(side="left", padx=(8, 0))
        trash_download_button = ttk.Button(control, text="建议项移入回收站", command=lambda: self.trash_selected(self.download_tree))
        trash_download_button.pack(side="left", padx=(8, 0))
        self.action_buttons.extend(
            [analyze_button, cleanup_button, empty_button, locate_download_button, trash_download_button]
        )

        ttk.Label(parent, textvariable=self.cleanup_summary_var, style="SubHeader.TLabel").pack(anchor="w", pady=(0, 8))

        top = ttk.PanedWindow(parent, orient="horizontal")
        top.pack(fill="both", expand=True)

        left_frame = ttk.Frame(top, style="Card.TFrame")
        right_frame = ttk.Frame(top, style="Card.TFrame")
        top.add(left_frame, weight=1)
        top.add(right_frame, weight=1)

        ttk.Label(left_frame, text="临时文件候选概览", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
        self.cleanup_tree = self._create_tree(
            left_frame,
            ("name", "size", "count", "risk", "path"),
            ("分组", "大小", "候选数", "风险", "路径"),
            (160, 100, 90, 80, 520),
        )

        ttk.Label(right_frame, text="下载目录大文件建议", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
        self.download_tree = self._create_tree(
            right_frame,
            ("name", "size", "risk", "modified", "path"),
            ("名称", "大小", "风险", "修改时间", "路径"),
            (180, 100, 80, 140, 520),
        )

        log_frame = ttk.Frame(parent, style="Card.TFrame")
        log_frame.pack(fill="both", expand=True, pady=(12, 0))
        ttk.Label(log_frame, text="执行日志", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
        self.log_list = tk.Listbox(log_frame, bg="#0b1220", fg="#e2e8f0", borderwidth=0, highlightthickness=0)
        self.log_list.pack(fill="both", expand=True)

    def _create_tree(
        self,
        parent: ttk.Frame,
        columns: tuple[str, ...],
        headings: tuple[str, ...],
        widths: tuple[int, ...],
    ) -> ttk.Treeview:
        wrapper = ttk.Frame(parent, style="Card.TFrame")
        wrapper.pack(fill="both", expand=True)

        tree = ttk.Treeview(wrapper, columns=columns, show="headings")
        scrollbar = ttk.Scrollbar(wrapper, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for column, heading, width in zip(columns, headings, widths):
            tree.heading(column, text=heading)
            tree.column(column, width=width, anchor="w")

        return tree

    def choose_root(self) -> None:
        selected = filedialog.askdirectory(initialdir=self.root_var.get() or os.environ.get("SystemDrive", "C:\\"))
        if selected:
            self.root_var.set(selected)
            self.set_status("已选择扫描路径", selected)

    def set_status(self, text: str, progress_path: str | None = None) -> None:
        self.status_var.set(text)
        if progress_path is not None:
            self.progress_var.set(progress_path)

    def set_busy(self, busy: bool) -> None:
        self.busy = busy
        state = "disabled" if busy else "normal"
        for button in self.action_buttons:
            button.configure(state=state)

    def append_log(self, message: str) -> None:
        if self.log_list is None:
            return
        self.log_list.insert("end", message)
        self.log_list.yview_moveto(1)

    def _start_background_task(self, status: str, job, on_success) -> None:
        if self.busy:
            return

        self.set_busy(True)
        self.set_status(status, self.root_var.get())

        def progress_callback(payload: dict) -> None:
            self.event_queue.put(("progress", payload))

        def runner() -> None:
            try:
                result = job(progress_callback)
                self.event_queue.put(("done", on_success, result))
            except Exception as error:
                self.event_queue.put(("error", str(error)))

        threading.Thread(target=runner, daemon=True).start()

    def _drain_events(self) -> None:
        while True:
            try:
                event = self.event_queue.get_nowait()
            except queue.Empty:
                break

            kind = event[0]
            if kind == "progress":
                payload = event[1]
                phase = payload.get("phase")
                label = "正在搜索文件" if phase == "search" else "正在扫描目录"
                self.set_status(label, payload.get("current_path") or payload.get("root") or self.root_var.get())
            elif kind == "done":
                on_success, result = event[1], event[2]
                self.set_busy(False)
                on_success(result)
            elif kind == "error":
                self.set_busy(False)
                message = event[1]
                self.set_status("发生错误", message)
                messagebox.showerror("CClear", message)
                self.append_log(f"失败：{message}")

        self.after(160, self._drain_events)

    def start_scan(self, force_refresh: bool = False) -> None:
        root = self.root_var.get().strip()
        if not root:
            messagebox.showwarning("CClear", "请先选择扫描路径。")
            return

        self._start_background_task(
            "正在扫描目录",
            lambda progress: scan_directory(root, progress, force_refresh=force_refresh),
            self.on_scan_done,
        )

    def on_scan_done(self, result: dict) -> None:
        self.scan_result = result
        self.metrics["total_size"].set(format_bytes(result["total_size"]))
        self.metrics["total_files"].set(format_count(result["total_files"]))
        self.metrics["total_directories"].set(format_count(result["total_directories"]))
        self.metrics["skipped_entries"].set(format_count(result["skipped_entries"]))
        self.metrics["duration_seconds"].set(f'{result["duration_seconds"]:.2f} 秒')
        self.metrics["root"].set(result["root"])
        source_label = "缓存快照" if result.get("result_source") == "cache" else "实时扫描"
        snapshot_created_at = result.get("snapshot_created_at") or "-"
        self.scan_summary_var.set(
            f'扫描完成：来源 {source_label}，共发现 {format_count(result["total_files"])} 个文件，最大占用 {format_bytes(result["total_size"])}，索引时间 {snapshot_created_at}。'
        )
        self.set_status("扫描完成", result["root"])
        self.append_log(self.scan_summary_var.get())
        self._fill_tree(
            self.scan_files_tree,
            [
                (item["name"], format_bytes(item["size"]), risk_tag(item["risk"]), item["modified_at"], item["path"])
                for item in result["largest_files"]
            ],
        )
        self._fill_tree(
            self.scan_directories_tree,
            [
                (
                    item["name"],
                    format_bytes(item["size"]),
                    format_count(item["file_count"]),
                    risk_tag(item["risk"]),
                    item["path"],
                )
                for item in result["largest_directories"]
            ],
        )
        self._fill_tree(
            self.extension_tree,
            [(item["extension"], format_bytes(item["size"]), format_count(item["count"])) for item in result["extension_stats"]],
        )

    def start_search(self) -> None:
        root = self.root_var.get().strip()
        query = self.search_query_var.get().strip()
        if not root:
            messagebox.showwarning("CClear", "请先选择扫描路径。")
            return
        if not query:
            messagebox.showwarning("CClear", "请输入搜索关键词。")
            return

        try:
            min_size_bytes = int(float(self.search_min_size_var.get() or "0") * 1024 * 1024)
        except ValueError:
            messagebox.showwarning("CClear", "最小大小必须是数字。")
            return
        if min_size_bytes < 0:
            messagebox.showwarning("CClear", "最小大小不能为负数。")
            return

        self._start_background_task(
            "正在搜索文件",
            lambda progress: search_files(
                root,
                query,
                min_size_bytes=min_size_bytes,
                progress_callback=progress,
                prefer_index=self.prefer_index_var.get(),
            ),
            self.on_search_done,
        )

    def on_search_done(self, result: dict) -> None:
        self.search_result = result
        source_label = "索引缓存" if result.get("result_source") == "index_cache" else "实时遍历"
        self.search_summary_var.set(
            f'搜索完成：来源 {source_label}，检查 {format_count(result["searched_files"])} 个文件，命中 {format_count(len(result["results"]))} 个结果。'
        )
        self.set_status("搜索完成", self.root_var.get())
        self.append_log(self.search_summary_var.get())
        self._fill_tree(
            self.search_tree,
            [
                (item["name"], format_bytes(item["size"]), risk_tag(item["risk"]), item["modified_at"], item["path"])
                for item in result["results"]
            ],
        )

    def start_cleanup_analysis(self) -> None:
        self._start_background_task("正在分析清理机会", lambda _progress: analyze_cleanup(), self.on_cleanup_analysis_done)

    def on_cleanup_analysis_done(self, result: dict) -> None:
        self.cleanup_analysis = result
        self.cleanup_summary_var.set(
            f'分析完成：预计可回收 {format_bytes(result["estimated_recoverable_bytes"])}，下载目录建议 {result["downloads"]["count"]} 项。'
        )
        self.set_status("清理分析完成", result["user_temp"]["path"])
        self.append_log(self.cleanup_summary_var.get())
        self._fill_tree(
            self.cleanup_tree,
            [
                (
                    result["user_temp"]["label"],
                    format_bytes(result["user_temp"]["size"]),
                    format_count(result["user_temp"]["count"]),
                    "低风险",
                    result["user_temp"]["path"],
                ),
                (
                    result["windows_temp"]["label"],
                    format_bytes(result["windows_temp"]["size"]),
                    format_count(result["windows_temp"]["count"]),
                    "中风险",
                    result["windows_temp"]["path"],
                ),
            ],
        )
        self._fill_tree(
            self.download_tree,
            [
                (item["name"], format_bytes(item["size"]), risk_tag(item["risk"]), item["modified_at"], item["path"])
                for item in result["downloads"]["targets"]
            ],
        )

    def start_temp_cleanup(self) -> None:
        if self.cleanup_analysis is None:
            messagebox.showinfo("CClear", "请先分析清理机会。")
            return

        confirmed = messagebox.askyesno("CClear", "将把临时文件移动到回收站，是否继续？")
        if not confirmed:
            return

        self._start_background_task(
            "正在清理临时文件",
            lambda _progress: run_temp_cleanup(self.cleanup_analysis),
            self.on_temp_cleanup_done,
        )

    def on_temp_cleanup_done(self, result: dict) -> None:
        invalidate_scan_cache(self.root_var.get())
        self.set_status("临时文件清理完成", f'成功 {result["success_count"]} 项')
        self.append_log(
            f'临时文件清理完成：成功 {result["success_count"]} 项，失败 {result["failure_count"]} 项，预计释放 {format_bytes(result["reclaimed_bytes"])}。'
        )
        self.start_cleanup_analysis()

    def start_empty_recycle_bin(self) -> None:
        confirmed = messagebox.askyesno("CClear", "该操作会清空系统回收站，是否继续？")
        if not confirmed:
            return

        self._start_background_task("正在清空回收站", lambda _progress: empty_recycle_bin(), self.on_empty_recycle_bin_done)

    def on_empty_recycle_bin_done(self, _result: dict) -> None:
        invalidate_scan_cache(self.root_var.get())
        self.set_status("回收站已清空", self.root_var.get())
        self.append_log("回收站已清空。")

    def _selected_path(self, tree: ttk.Treeview | None) -> str | None:
        if tree is None:
            return None
        selection = tree.selection()
        if not selection:
            return None
        values = tree.item(selection[0], "values")
        if not values:
            return None
        return str(values[-1])

    def locate_selected(self, tree: ttk.Treeview | None) -> None:
        target_path = self._selected_path(tree)
        if not target_path:
            messagebox.showinfo("CClear", "请先选择一项。")
            return

        if os.path.isdir(target_path):
            os.startfile(target_path)
        else:
            subprocess.run(["explorer", f"/select,{target_path}"], check=False)
        self.append_log(f"已定位：{target_path}")

    def trash_selected(self, tree: ttk.Treeview | None) -> None:
        target_path = self._selected_path(tree)
        if not target_path:
            messagebox.showinfo("CClear", "请先选择一项。")
            return

        confirmed = messagebox.askyesno("CClear", f"确认将以下内容移入回收站？\n{target_path}")
        if not confirmed:
            return

        self._start_background_task(
            "正在移动到回收站",
            lambda _progress: move_to_recycle_bin(target_path),
            lambda _result: self.on_trash_done(target_path),
        )

    def on_trash_done(self, target_path: str) -> None:
        invalidate_scan_cache(self.root_var.get())
        self.set_status("已移入回收站", target_path)
        self.append_log(f"已移入回收站：{target_path}")
        if self.search_result:
            self.search_result["results"] = [item for item in self.search_result["results"] if item["path"] != target_path]
            self.on_search_done(self.search_result)

    def _fill_tree(self, tree: ttk.Treeview | None, rows: list[tuple]) -> None:
        if tree is None:
            return
        for item_id in tree.get_children():
            tree.delete(item_id)
        for row in rows:
            tree.insert("", "end", values=row)


def run() -> None:
    app = CClearApp()
    app.mainloop()
