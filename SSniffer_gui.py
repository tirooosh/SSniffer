from collections import defaultdict
import logging
import sys
import threading
from functools import partial

import pyshark
from PyQt5.QtCore import Qt, QRect, pyqtSlot, QObject, pyqtSignal
from PyQt5.QtGui import QPixmap, QPalette, QBrush
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QScrollArea, QApplication, QPushButton, QFileDialog, \
    QMessageBox

import SSniffer_functions
from Loading_screen import LoadingScreen, CustomTitleBar, BaseWindow  # Ensure this module is correctly implemented


class SniffWindow(BaseWindow):
    def __init__(self):
        super().__init__("SSniffer", "pictures\\ssniffer_screen.png")
        self.initUI()
        self.packet_details = {}
        self.stop_event = threading.Event()
        self.capture_thread = None

    def initUI(self):
        self.windows = {}
        self.options_button = QPushButton("options", self)

        self.options_button.setStyleSheet("""
                                        QPushButton {
                                            font-size: 25px; /* Larger font size */
                                            color: #EED487; /* Text color */
                                            background-color: rgba(0, 0, 0, 0); /* Transparent background */
                                            border: 0px solid white; /* White border for visibility */
                                        }
                                        QPushButton:hover {
                                            background-color: rgba(255, 255, 255, 0.1); /* Slightly visible on hover */
                                        }
                                    """)
        self.options_button.clicked.connect(self.open_option_window)
        self.options_button.move(75, 90)
        # Set background image for the entire window
        self.setAutoFillBackground(True)
        palette = QPalette()
        pixmap = QPixmap(self.image_path)
        palette.setBrush(QPalette.Window, QBrush(pixmap))
        self.setPalette(palette)

        # Adding custom title bar
        self.titleBar = CustomTitleBar()
        self.titleBar.setGeometry(QRect(0, 0, self.width(), 50))

        # Scrollable area setup
        self.scroll = QScrollArea(self)
        self.scroll.setGeometry(QRect(80, 141, 1120, 485))  # Set the position and size of the scroll area

        self.widget = QWidget()
        self.vbox = QVBoxLayout(self.widget)  # Layout for scrollable content
        self.vbox.setSpacing(0)  # No space between widgets
        self.vbox.setContentsMargins(0, 0, 0, 0)  # No margins around the layout

        self.widget.setStyleSheet("background-color: #2E3B5B;")

        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.widget)

        # Scrollbar styling
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.scroll.setStyleSheet("QScrollBar:vertical {background: #2E3B5B;}")

        self.setWindowFlags(Qt.FramelessWindowHint)

        # Initialize the network selection screen
        self.network_selection_screen()

        self.thread_manager = ThreadManager()
        self.thread_manager.finished.connect(self.on_thread_finished)

        self.option_window = None

    def add_label(self, text, location, size):
        label = QLabel(text, self.widget)  # Ensure parent is self.widget
        label.setStyleSheet("color: white; background-color: #2E3B5B; font-size: 25px;")
        self.vbox.addWidget(label)  # Add label to the QVBoxLayout
        return label

    def network_selection_screen(self):
        # Remove previous widgets from the layout
        for i in reversed(range(self.vbox.count())):
            self.vbox.itemAt(i).widget().deleteLater()

        # Get list of available networks
        interfaces = SSniffer_functions.list_network_interfaces()
        self.network_buttons = []

        for idx, interface in enumerate(interfaces):
            button = self.setup_buttons(interface,
                                        partial(self.on_network_selected, interface), self.vbox)
            self.network_buttons.append(button)

    @pyqtSlot()
    def on_network_selected(self, interface):
        # Perform the network selection logic here
        print(f"Selected Network Interface: {interface}")
        self.start_packet_capture(interface)

    def start_packet_capture(self, interface):
        self.packet_details = {}
        self.stop_event.clear()
        self.as_is = []
        self.capture_thread = threading.Thread(target=SSniffer_functions.capture_packets,
                                               args=(interface, self.packet_details, self.stop_event, self.as_is))
        self.capture_thread.start()

        self.second_menu()

    def second_menu(self):
        self.update_ui()

        # Suggestion 2: Add logging for key actions to improve traceability and debugging.
        logging.info("Summary button clicked")

        try:
            summary_button = self.setup_buttons("Show all the packet transactions ", self.show_summary, self.vbox,
                                                size=(1100, 50))
        except Exception as e:
            print(f"Error setting up summary button: {str(e)}")

        try:
            readable_button = self.setup_buttons("Show all the packet transactions that have readable payloads",
                                                 self.show_only_readable, self.vbox, size=(1100, 50))
        except Exception as e:
            print(f"Error setting up readable button: {str(e)}")

        try:
            stop_button = self.setup_buttons("Stop Capturing packets without closing the program",
                                             self.stop_packet_capture, self.vbox, size=(1100, 50))
        except Exception as e:
            print(f"Error setting up stop button: {str(e)}")

    @pyqtSlot()
    def show_only_readable(self):

        # Clear current widgets from the layout
        self.update_ui()
        # Create and set up the refresh button
        refresh_button = self.setup_buttons("Refresh", self.show_only_readable, self.vbox, size=(100, 50))
        self.vbox.addWidget(refresh_button)  # Add the button to the layout
        # Add label for the readable packets screen
        headline = self.add_label(f"", (50, 50), (600, 40))
        packet_list = []
        # Display only the readable packets
        if self.packet_details:
            readable_count = 0
            for key, packets in self.packet_details.items():
                if readable_count == 1:
                    headline.setText("Readable Packets:")
                if packets['readable']:
                    packet_list.append((key, packets))
                    button = self.setup_buttons(
                        f"{key}: \n{len(packets['readable'])} readable packets",
                        partial(self.show_packet_details, key, packets), self.vbox, size=(1110, 30))
                    readable_count += 1

            if readable_count == 0:
                self.add_label("No readable packets found.", (50, 150), (600, 40))
            self.add_label(f"there are {readable_count} groups of readable Packets", (50, 50), (600, 40))
            sort_button = self.setup_buttons("sort by ip", partial(self.show_packet_groups_of_packet_groups,
                                                                   SSniffer_functions.sort_by_ip(packet_list)),
                                             self.vbox, size=(1100, 40))
        else:
            self.add_label("No packets captured.", (50, 100), (600, 40))

    def show_packet_groups_of_packet_groups(self, packets_lists):
        self.update_ui()

        def get_ip(packet_group):
            key, _ = packet_group
            parts = key.split(" ")
            src_ip = parts[0]
            dst_ip = parts[3]
            return src_ip, dst_ip

        if packets_lists:
            for packet_group in packets_lists:
                src_ip, _ = get_ip(packet_group[0])
                try:
                    key, _ = packet_group[0]
                    resolved_ip = key.split(" ")[1]
                except Exception as e:
                    resolved_ip = "Unknown"
                    print(f"Error resolving IP {src_ip}: {e}")

                self.setup_buttons(
                    f"there are {len(packet_group)} packet groups that involves:\n {src_ip} which is {resolved_ip}",
                    partial(self.show_packets_in_order, packet_group),
                    self.vbox, size=(1100, 60))
        else:
            self.add_label("No packets to display.", (50, 100), (600, 40))

    def show_packets_in_order(self, packet_list):
        self.update_ui()
        print(packet_list)
        if packet_list:
            for key, packets in packet_list:
                self.setup_buttons(
                    f"{key}: \n{len(packets['readable'])} readable packets, {len(packets['encrypted'])} potentially encrypted packets",
                    partial(self.show_packet_details, key, packets),
                    self.vbox, size=(1100, 60))
        else:
            self.add_label("No packets to display.", (50, 100), (600, 40))

    @pyqtSlot()
    def stop_packet_capture(self):
        self.stop_event.set()
        if self.capture_thread:
            self.capture_thread.join()
        print("Packet capture stopped.")

    def show_summary(self):
        # Show the summary
        self.update_ui()

        packet_list = []

        # Create and set up the refresh button
        refresh_button = self.setup_buttons("Refresh", self.show_summary, self.vbox, size=(100, 50))
        sort_button = self.setup_buttons("Sort by ip", partial(self.show_packet_groups_of_packet_groups,
                                                               SSniffer_functions.sort_by_ip(packet_list)),
                                         self.vbox,
                                         size=(123, 50))

        if self.packet_details:
            self.add_label(
                f"Summary of the network traffic there are {len(self.packet_details)} packet groups captured:",
                (50, 50), (600, 40))
            sorted_details = sorted(self.packet_details.items(),
                                    key=lambda item: len(item[1]['readable']) + len(item[1]['encrypted']), reverse=True)
            for idx, (key, packets) in enumerate(sorted_details):
                packet_list.append((key, packets))
                summary_text = f"{key}: \n{len(packets['readable'])} readable,{len(packets['encrypted'])} potentially encrypted packets"
                button = self.setup_buttons(summary_text, partial(self.show_packet_details, key, packets), self.vbox,
                                            size=(1100, 80))
            sort_button.pressed.connect(partial(self.show_packet_groups_of_packet_groups,
                                                SSniffer_functions.sort_by_ip(packet_list)))

        else:
            self.add_label("No packets captured yet please refresh.", (50, 100), (1100, 40))

    def show_packet_details(self, key, packets):
        self.update_ui()  # Clear and prepare UI for new data
        self.add_label(f"Details for {key}:", (50, 50), (600, 40))

        self.list_packets(packets['readable'], "Readable Packets", 100)
        self.list_packets(packets['encrypted'], "Encrypted Packets", 150 + len(packets['readable']) * 50)

        back_button = self.setup_buttons("Back to Summary", self.show_summary, self.vbox)

    def list_packets(self, packet_list, title, start_y):
        self.add_label(f"{title} ({len(packet_list)}):", (50, start_y), (600, 40))
        for idx, packet in enumerate(packet_list):
            button = self.setup_buttons(f"Packet {idx + 1}", partial(self.show_individual_packet, packet), self.vbox,
                                        size=(150, 30))

    def show_individual_packet(self, packet):
        self.update_ui()  # Clear and prepare UI for new data
        self.display_packet_details(packet)
        self.setup_buttons("Back to Packet Group", self.show_summary, self.vbox, size=(1100, 50))

    def start_loading_bar(self, duration_ms):
        self.loading_screen = LoadingScreen(duration_ms)
        self.loading_screen.show()

    def display_packet_details(self, packet):
        self.start_loading_bar(0)

        # Starting the thread to process packet details
        def thread_function():
            try:
                packet_details = SSniffer_functions.show_packet_content(packet)  # Assume this is your function
                self.thread_manager.finished.emit(packet_details)  # Emit signal with the results
            except Exception as e:
                self.thread_manager.finished.emit(f"Error displaying packet details: {str(e)}")

        thread = threading.Thread(target=thread_function)
        thread.start()

    def on_thread_finished(self, packet_details):
        # Close the loading screen and update the UI
        self.loading_screen.close()
        self.add_label(packet_details, (50, 100), (600, 40))

    def update_ui(self):
        """Clear all widgets from the QVBoxLayout and prepare for new content."""
        while self.vbox.count():
            widget = self.vbox.itemAt(0).widget()
            if widget is not None:
                self.vbox.removeWidget(widget)
                widget.deleteLater()

    def open_option_window(self):
        self.option_window = OptionWindow(self)
        self.option_window.move(200, 100)
        self.option_window.show()

    def load_packet_details(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_path, _ = QFileDialog.getOpenFileName(
            None, "Load Packet Details", "", "PCAP Files (*.pcap);;All Files (*)", options=options)
        packet_details = SSniffer_functions.load_packet_details(file_path)
        self.display_loaded_packet_details(packet_details)
    
    def display_loaded_packet_details(self, packet_details):
        self.update_ui()

        packet_list = []

        # Create and set up the refresh button
        refresh_button = self.setup_buttons("Refresh", self.show_summary, self.vbox, size=(100, 50))
        sort_button = self.setup_buttons("Sort by ip", partial(self.show_packet_groups_of_packet_groups,
                                                               SSniffer_functions.sort_by_ip(packet_list)),
                                         self.vbox,
                                         size=(123, 50))

        if packet_details:
            self.add_label(
                f"Summary of the network traffic there are {len(packet_details)} packet groups captured:",
                (50, 50), (600, 40))
            sorted_details = sorted(packet_details.items(),
                                    key=lambda item: len(item[1]['readable']) + len(item[1]['encrypted']), reverse=True)
            for idx, (key, packets) in enumerate(sorted_details):
                packet_list.append((key, packets))
                summary_text = f"{key}: \n{len(packets['readable'])} readable,{len(packets['encrypted'])} potentially encrypted packets"
                button = self.setup_buttons(summary_text, partial(self.show_packet_details, key, packets), self.vbox,
                                            size=(1100, 80))
            sort_button.pressed.connect(partial(self.show_packet_groups_of_packet_groups,
                                                SSniffer_functions.sort_by_ip(packet_list)))

        else:
            self.add_label("No packets captured yet please refresh.", (50, 100), (1100, 40))

    def save_packet_details(self, packet_list=None):
        if packet_list is None:
            packet_list = self.as_is
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_path, _ = QFileDialog.getSaveFileName(
            None, "Save Packet Details", "", "PCAP Files (*.pcap);;All Files (*)", options=options)

        if file_path:
            # Ensure the file has a .pcap extension
            if not file_path.lower().endswith('.pcap'):
                file_path += '.pcap'
        
        SSniffer_functions.save_packets_to_pcap(file_path, packet_list)

class ThreadManager(QObject):
    finished = pyqtSignal(str, name='finished')  # Signal to notify when the thread is done


class OptionWindow(BaseWindow):
    def __init__(self, SniffWindow):
        super().__init__("Options", "pictures\\options.png")
        self.initUI(SniffWindow)

    def initUI(self, SniffWindow):
        WINDOW_LENGTH = 350
        WINDOW_Hight = int((WINDOW_LENGTH * 800) / 1280) + 50
        button_hight = int((WINDOW_Hight - 100) / 6)
        self.setFixedSize(WINDOW_LENGTH, WINDOW_Hight)
        self.setup_buttons("", SniffWindow.show_summary, self.main_layout, size=(WINDOW_LENGTH, button_hight))
        self.setup_buttons("", SniffWindow.show_only_readable, self.main_layout, size=(WINDOW_LENGTH, button_hight))
        self.setup_buttons("", SniffWindow.network_selection_screen, self.main_layout,
                           size=(WINDOW_LENGTH, button_hight))
        self.setup_buttons("", SniffWindow.save_packet_details, self.main_layout, size=(WINDOW_LENGTH, button_hight))
        self.setup_buttons("", SniffWindow.load_packet_details, self.main_layout,
                           size=(WINDOW_LENGTH, button_hight + 40))

        # close button
        self.button = QPushButton("X", self)
        self.button.setStyleSheet(
            """color: #EED487 ;background-color: #2E3B5B; font-size: 14px;font-weight: 500;border: 0px solid white;}QPushButton:hover {
                            background-color: rgba(255, 255, 255, 0.1); /* Slightly visible on hover */}""")
        self.button.setFixedSize(20, 20)
        self.button.move(WINDOW_LENGTH - 30, 10)
        self.button.clicked.connect(exit)




if __name__ == '__main__':
    app = QApplication(sys.argv)
    sniff_window = SniffWindow()
    # window = OptionWindow(sniff_window)
    # window.show()

    sys.exit(app.exec_())
