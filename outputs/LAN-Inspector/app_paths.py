"""Writable state lives next to the EXE, resources remain in the bundle."""
from pathlib import Path
import sys


def app_dir():
    return Path(sys.executable).resolve().parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parent


def launch_args(*arguments):
    return list(arguments) if getattr(sys,'frozen',False) else [str(Path(__file__).resolve().parent/'lan_inspector.py')]+list(arguments)
