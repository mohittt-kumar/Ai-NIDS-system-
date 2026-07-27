import sys
import os

# Add root folder to python path so we can import run.py and app package
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from run import app
