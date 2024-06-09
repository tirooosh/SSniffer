from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap, QPainter, QColor, QPainterPath, QTransform
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QHBoxLayout, QMessageBox, QApplication
import sys


class BaseWindow(QWidget):
    def __init__(self, title, image_path):
        super().__init__()
        self.setWindowTitle(title)
        self.setFixedSize(1280, 800)

        # Set window transparency and remove the frame
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setWindowFlags(Qt.FramelessWindowHint)

        self.image_path = image_path

        # Set the background color
        self.setAutoFillBackground(True)
        palette = self.palette()
        palette.setColor(self.backgroundRole(), QColor('#2E3B5B'))
        self.setPalette(palette)

        # Create a vertical layout for the whole window
        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)
        self.main_layout.setContentsMargins(0, 0, 0, 0)

        # Create the custom title bar and add it to the layout
        self.titleBar = CustomTitleBar()
        self.main_layout.addWidget(self.titleBar)  # Add the title bar to the layout

        self.moving = False
        self.offset = None

        self.setWindowFlags(Qt.FramelessWindowHint)

        self.windows = {}

        # close button
        self.button = QPushButton("X", self)
        self.button.setStyleSheet(
            "color: rgba(255, 255, 255, 255);background-color: #2E3B5B; font-size: 18px;font-weight: 500;")
        self.button.setFixedSize(30, 30)
        self.button.move(1240, 12)
        self.button.clicked.connect(self.close_button)

    def navigate_to(self, window_class, *args, **kwargs):
        if window_class not in self.windows or not self.windows[window_class].isVisible():
            self.windows[window_class] = window_class(*args, **kwargs)
            self.windows[window_class].show()
        else:
            self.windows[window_class].activateWindow()  # Bring the window to the front if it's already open


    def close_button(self):
        answer = QMessageBox.question(self, 'Notice',
                                      "Are you sure?",
                                      QMessageBox.Yes | QMessageBox.No,
                                      QMessageBox.No)
        if answer == QMessageBox.Yes:
            self.close()
            exit()

    def setup_buttons(self, text, slot, layout, **kwargs):
        button = QPushButton(text, self)
        button.setStyleSheet("""
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

        # Set optional properties if provided

        if 'size' in kwargs:
            button.setFixedSize(*kwargs['size'])

        button.clicked.connect(slot)
        layout.addWidget(button)
        return button

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)  # Enable antialiasing for smooth corners

        path = QPainterPath()
        path.addRoundedRect(0, 0, self.width(), self.height(), 20, 20)  # Using explicit dimensions for clarity
        painter.setClipPath(path)

        painter.fillPath(path, self.palette().window())  # Fill the path with window background color

        pixmap = QPixmap(self.image_path)
        painter.drawPixmap(self.rect(), pixmap)

    def closeEvent(self, event):
        # Perform any cleanup or save state if necessary
        event.accept()


class CustomTitleBar(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QHBoxLayout()
        self.offset = None
        self.moving = None
        self.initUI()

    def initUI(self):
        self.setLayout(self.layout)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.addStretch(-1)

    def onClose(self):
        self.window().close()

    def mousePressEvent(self, event):
        x, y = event.x(), event.y()
        if y < 20:
            if event.button() == Qt.LeftButton:
                self.parent().moving = True
                self.parent().offset = event.pos()

    def mouseMoveEvent(self, event):
        x, y = event.x(), event.y()
        if y < 20:
            if self.parent().moving:
                self.parent().move(event.globalPos() - self.parent().offset)


class LoadingScreen(BaseWindow):
    def __init__(self, duration=10000):
        super().__init__("Loading Screen", "pictures\\loadingscreen.png")
        self.num_legs = 0  # Number of legs displayed (each pair counts as two)
        self.leg_spacing = 100  # Horizontal space between legs
        self.x_pos = 400  # Starting x position for the first leg
        self.x_increment = 45  # Increment for x position of the second leg in each pair
        self.max_legs = 10  # Maximum number of legs
        self.adding_second_leg = False  # Track if adding second leg in pair

        # Calculate appropriate pixmap dimensions
        self.pixmap = QPixmap(self.width(), self.height())
        self.pixmap.fill(Qt.transparent)  # Initialize pixmap as transparent

        self.setup_ui()
        self.button.close()
        self.start_loading(duration)

    def setup_ui(self):
        self.setWindowTitle('Loading Screen')
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.add_legs)
        self.timer.start(500)  # Start with 500 milliseconds for the first leg

    def start_loading(self, duration):
        if duration != 0:
            # Timer for closing the loading screen after a duration
            self.close_timer = QTimer(self)
            self.close_timer.timeout.connect(self.close)
            self.close_timer.start(duration)  # Close after specified duration

    def add_legs(self):
        if self.num_legs < self.max_legs:
            base_x_position = self.x_pos + (self.num_legs // 2) * self.leg_spacing
            y_position = 635 if not self.adding_second_leg else 652
            x_position = base_x_position if not self.adding_second_leg else base_x_position + self.x_increment
            scale = 0.06

            self.draw_leg(x_position, y_position, scale)
            self.num_legs += 1
            self.update()  # Redraw window

            if not self.adding_second_leg:
                self.adding_second_leg = True
                self.timer.start(500)  # Same delay for the second leg
            else:
                self.adding_second_leg = False
                self.timer.start(1000)  # Twice the delay before the next set
        else:
            self.reset_animation()

    def reset_animation(self):
        self.pixmap.fill(Qt.transparent)  # Clear the pixmap
        self.num_legs = 0  # Reset the leg counter
        self.adding_second_leg = False  # Reset leg pair state
        self.timer.start(500)  # Restart the timer

    def draw_leg(self, x, y, scale):
        leg_pixmap = QPixmap("pictures\\paw.png")
        if leg_pixmap.isNull():
            print("Failed to load leg image")
            return
        # Scale down the pixmap
        transform = QTransform().scale(scale, scale)
        scaled_pixmap = leg_pixmap.transformed(transform, Qt.SmoothTransformation)
        painter = QPainter(self.pixmap)
        painter.drawPixmap(x, y, scaled_pixmap)
        painter.end()

    def paintEvent(self, event):
        super().paintEvent(event)  # Ensure background is painted
        painter = QPainter(self)
        painter.drawPixmap(0, 0, self.pixmap)  # Draw the legs pixmap

    def mousePressEvent(self, event):
        pass


if __name__ == '__main__':
    app = QApplication(sys.argv)

    # Allow the user to input the duration
    duration = 20000  # Set a default duration (e.g., 20 seconds)
    input_duration = input("Enter the duration for the loading screen in milliseconds (default is 20000): ")
    try:
        duration = int(input_duration)
    except ValueError:
        print(f"Invalid input, using default duration of {duration} milliseconds.")

    loading_screen = LoadingScreen(duration)
    loading_screen.show()

    sys.exit(app.exec_())
