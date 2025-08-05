#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Поиск пар email:пароль по списку email."""

from __future__ import annotations

import argparse
import os
import threading
import tkinter as tk
from concurrent.futures import ProcessPoolExecutor, as_completed
from tkinter import filedialog, messagebox
from tkinter.ttk import Progressbar


# ------------------------------ core logic ------------------------------

def load_input_emails(path: str) -> dict[str, list[str]]:
    """Загружает исходный список email и группирует по логину."""

    orig_map: dict[str, list[str]] = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            email = line.strip()
            if "@" not in email:
                continue
            local = email.lower().split("@", 1)[0]
            orig_map.setdefault(local, []).append(email)
    return orig_map


def find_txt_files(root_dir: str):
    """Ищет все .txt файлы в каталоге."""

    for dirpath, _, files in os.walk(root_dir):
        for fname in files:
            if fname.lower().endswith(".txt"):
                yield os.path.join(dirpath, fname)


def process_file(args):
    """Обрабатывает один файл в отдельном процессе."""

    fname, keys_set, full_match, partial_match = args
    matches: list[tuple[str, str]] = []
    logs: list[str] = []
    base = os.path.basename(fname)
    try:
        with open(fname, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                text = line.rstrip("\n")
                logs.append(f"{base}: processing '{text}'")
                if ":" not in text or "@" not in text:
                    continue
                email_part, pwd = text.split(":", 1)
                local = email_part.lower().split("@", 1)[0]
                found = []
                if full_match and local in keys_set:
                    found = [(local, pwd.strip())]
                elif partial_match:
                    for key in keys_set:
                        if key in local:
                            found.append((key, pwd.strip()))
                if found:
                    logs.append(f"{base}: found {len(found)} match(es)")
                    matches.extend(found)
    except Exception as e:  # pragma: no cover - защита от ошибок чтения
        logs.append(f"Error reading {base}: {e}")
    return fname, matches, logs


def process_all(
    email_file: str,
    search_dir: str,
    output_file: str,
    full: bool,
    part: bool,
    files: list[str] | None = None,
    progress_cb=None,
    log_cb=None,
) -> int:
    """Обрабатывает все файлы и возвращает количество найденных записей."""

    orig_map = load_input_emails(email_file)
    keys_set = set(orig_map.keys())
    if files is None:
        files = list(find_txt_files(search_dir))
    if not files:
        if log_cb:
            log_cb("No .txt files found.")
        return 0

    seen = set()
    total = 0
    with open(output_file, "w", encoding="utf-8", buffering=1) as fout, \
            ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = {
            executor.submit(process_file, (path, keys_set, full, part)): path
            for path in files
        }
        completed = 0
        for future in as_completed(futures):
            fname, matches, logs = future.result()
            base = os.path.basename(fname)
            if log_cb:
                for msg in logs:
                    log_cb(msg)
                log_cb(f"{base}: {len(matches)} total match(es)")
            for key, pwd in matches:
                for orig in orig_map.get(key, []):
                    entry = f"{orig}:{pwd}"
                    if entry not in seen:
                        seen.add(entry)
                        fout.write(entry + "\n")
                        if log_cb:
                            log_cb(f"Wrote: {entry}")
                        total += 1
            completed += 1
            if progress_cb:
                progress_cb(completed, len(files))
    if log_cb:
        log_cb(f"Done. {total} entries found and written.")
    return total


# ------------------------------ GUI mode ------------------------------


def on_start():  # pragma: no cover - используется только в GUI
    email_file = entry_email.get().strip()
    search_dir = entry_dir.get().strip()
    output_file = entry_out.get().strip()
    full = var_full.get()
    part = var_part.get()

    if full and part:
        messagebox.showerror(
            "Error", "Select either exact or partial match, not both."
        )
        return
    if not (full or part):
        messagebox.showerror("Error", "Select a search mode.")
        return
    if not os.path.isfile(email_file):
        messagebox.showerror("Error", "Invalid email list file.")
        return
    if not os.path.isdir(search_dir):
        messagebox.showerror("Error", "Invalid search directory.")
        return
    if not output_file:
        messagebox.showerror("Error", "Specify an output file.")
        return

    files = list(find_txt_files(search_dir))
    if not files:
        messagebox.showinfo("Info", "No .txt files found.")
        return

    progress.config(maximum=len(files), value=0)
    button_start.config(state="disabled")
    log_text.config(state="normal")
    log_text.delete("1.0", "end")
    log_text.config(state="disabled")
    log_message(
        f"Starting on {len(files)} files using {os.cpu_count()} cores."
    )

    def progress_cb(done, total):
        root.after(0, progress.config, {"value": done})

    def log_cb(msg):
        root.after(0, log_message, msg)

    def task():
        total = process_all(
            email_file,
            search_dir,
            output_file,
            full,
            part,
            files=files,
            progress_cb=progress_cb,
            log_cb=log_cb,
        )
        root.after(0, finish, total)

    threading.Thread(target=task, daemon=True).start()


def log_message(msg: str):  # pragma: no cover - GUI
    log_text.config(state="normal")
    log_text.insert("end", msg + "\n")
    log_text.see("end")
    log_text.config(state="disabled")


def finish(total: int):  # pragma: no cover - GUI
    button_start.config(state="normal")
    log_message(f"Done. {total} entries found and written.")
    messagebox.showinfo("Done", f"Processed complete, {total} entries.")


def start_gui():  # pragma: no cover - GUI
    global root, entry_email, entry_dir, entry_out
    global var_full, var_part, progress, button_start, log_text

    root = tk.Tk()
    root.title("Password Parser")

    tk.Label(root, text="Email list:").grid(
        row=0, column=0, padx=5, pady=5, sticky="e"
    )
    entry_email = tk.Entry(root, width=40)
    entry_email.grid(row=0, column=1, padx=5, pady=5)
    tk.Button(
        root,
        text="Browse",
        command=lambda: entry_email.delete(0, "end")
        or entry_email.insert(
            0,
            filedialog.askopenfilename(
                filetypes=[("Text files", "*.txt")],
                title="Select email file",
            ),
        ),
    ).grid(row=0, column=2, padx=5)

    tk.Label(root, text="Search folder:").grid(
        row=1, column=0, padx=5, pady=5, sticky="e"
    )
    entry_dir = tk.Entry(root, width=40)
    entry_dir.grid(row=1, column=1, padx=5, pady=5)
    tk.Button(
        root,
        text="Browse",
        command=lambda: entry_dir.delete(0, "end")
        or entry_dir.insert(
            0, filedialog.askdirectory(title="Select folder")
        ),
    ).grid(row=1, column=2, padx=5)

    tk.Label(root, text="Output file:").grid(
        row=2, column=0, padx=5, pady=5, sticky="e"
    )
    entry_out = tk.Entry(root, width=40)
    entry_out.grid(row=2, column=1, padx=5, pady=5)
    tk.Button(
        root,
        text="Browse",
        command=lambda: entry_out.delete(0, "end")
        or entry_out.insert(
            0,
            filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")],
                title="Output file",
            ),
        ),
    ).grid(row=2, column=2, padx=5)

    var_full = tk.BooleanVar()
    var_part = tk.BooleanVar()
    tk.Checkbutton(root, text="Exact match", variable=var_full).grid(
        row=3, column=1, sticky="w"
    )
    tk.Checkbutton(root, text="Partial match", variable=var_part).grid(
        row=4, column=1, sticky="w"
    )

    progress = Progressbar(root, orient="horizontal", length=300, mode="determinate")
    progress.grid(row=5, column=0, columnspan=3, pady=10)

    button_start = tk.Button(root, text="Start", command=on_start)
    button_start.grid(row=6, column=1, pady=10)

    log_text = tk.Text(root, width=60, height=10, state="disabled")
    log_text.grid(row=7, column=0, columnspan=3, padx=5, pady=5)

    root.mainloop()


# ------------------------------ CLI mode ------------------------------


def main_cli(args: argparse.Namespace):
    """Запуск без GUI для удобства тестирования."""

    def progress_cb(done, total):
        print(f"\rProcessed {done}/{total} files", end="", flush=True)

    def log_cb(msg):
        print(msg)

    total = process_all(
        args.email_list,
        args.search_dir,
        args.output,
        args.full,
        args.partial,
        progress_cb=progress_cb,
        log_cb=log_cb,
    )
    print(f"\nDone. {total} entries found and written.")


# ----------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Search credentials by email list"
    )
    parser.add_argument("--email-list", help="Path to email list file")
    parser.add_argument("--search-dir", help="Directory with credential files")
    parser.add_argument("--output", help="File to write matches")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--full", action="store_true", help="Exact login match")
    mode.add_argument(
        "--partial", action="store_true", help="Partial login match"
    )
    parser.add_argument("--gui", action="store_true", help="Force GUI mode")
    args = parser.parse_args()

    if args.gui or not (args.email_list and args.search_dir and args.output):
        start_gui()
    else:
        if not args.full and not args.partial:
            parser.error("Specify --full or --partial")
        main_cli(args)

