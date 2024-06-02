import sys

from PyQt5.QtWidgets import QApplication

import SSniffer_gui

if __name__ == '__main__':
    app = QApplication(sys.argv)
    sniff_window = SSniffer_gui.SniffWindow()
    sniff_window.show()
    sys.exit(app.exec_())
