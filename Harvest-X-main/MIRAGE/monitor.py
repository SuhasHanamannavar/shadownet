import json
import time
import threading
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Callable

logger = logging.getLogger("CowrieMonitor")

class CowrieLogHandler(FileSystemEventHandler):
    def __init__(self, log_file_path: str, callback: Callable):
        self.log_file_path = log_file_path
        self.callback = callback
        self.last_position = 0
        
    def on_modified(self, event):
        if event.src_path.replace("\\", "/").endswith(self.log_file_path.replace("\\", "/")):
            self.process_new_lines()
            
    def process_new_lines(self):
        try:
            with open(self.log_file_path, 'r') as f:
                f.seek(self.last_position)
                lines = f.readlines()
                self.last_position = f.tell()
                
                for line in lines:
                    if line.strip():
                        try:
                            event = json.loads(line)
                            self.callback(event)
                        except json.JSONDecodeError:
                            logger.error(f"Failed to parse JSON: {line}")
        except FileNotFoundError:
            pass

class CowrieMonitor:
    def __init__(self, log_dir: str, log_file_name: str, callback: Callable):
        self.log_dir = log_dir
        self.log_file_name = log_file_name
        self.log_file_path = f"{log_dir}/{log_file_name}"
        self.callback = callback
        self.observer = Observer()
        
    def start(self):
        # Initial read of existing logs
        handler = CowrieLogHandler(self.log_file_path, self.callback)
        handler.process_new_lines()
        
        self.observer.schedule(handler, path=self.log_dir, recursive=False)
        self.observer.start()
        logger.info(f"Started monitoring {self.log_file_path}")
        
    def stop(self):
        self.observer.stop()
        self.observer.join()
        logger.info("Stopped monitoring")
