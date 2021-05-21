#!/usr/bin/env python3

from rich.console import Console
from rich.logging import RichHandler
# from rich.table import Table
# from rich import box
# from rich.panel import Panel
from rich.theme import Theme
import logging
# import sys


# Rich console and theme init.
themefile = './utils/theme.ini'
mytheme = Theme().read(themefile)
console = Console(theme=mytheme)

# logger - Rich
logging.basicConfig(
	# filename='',
	level='INFO',
	format='%(message)s',
	datefmt='[%X]',
	handlers=[RichHandler(console=console, rich_tracebacks=True, omit_repeated_times=False)]
	)
logging = logging.getLogger('rich')