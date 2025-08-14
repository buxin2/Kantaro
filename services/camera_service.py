# =====================================
# services/camera_service.py - Camera processing logic
# =====================================

import os
import time
import math
import cv2
import cvzone
import numpy as np
from ultralytics import YOLO

class CameraService:
    def __init__(self):
        # Lazy-load the YOLO model to avoid heavy startup and torch load issues
        self.model = None
        self.classNames = [
            "person", "bicycle", "car", "motorbike", "aeroplane", "bus", "train",
            "truck", "boat", "traffic light", "fire hydrant", "stop sign", "parking meter",
            "bench", "bird", "cat", "dog", "horse", "sheep", "cow", "elephant", "bear",
            "zebra", "giraffe", "backpack", "umbrella", "handbag", "tie", "suitcase",
            "frisbee", "skis", "snowboard", "sports ball", "kite", "baseball bat",
            "baseball glove", "skateboard", "surfboard", "tennis racket", "bottle",
            "wine glass", "cup", "fork", "knife", "spoon", "bowl", "banana", "apple",
            "sandwich", "orange", "broccoli", "carrot", "hot dog", "pizza", "donut",
            "cake", "chair", "sofa", "pottedplant", "bed", "diningtable", "toilet",
            "tvmonitor", "laptop", "mouse", "remote", "keyboard", "cell phone",
            "microwave", "oven", "toaster", "sink", "refrigerator", "book", "clock",
            "vase", "scissors", "teddy bear", "hair drier", "toothbrush"
        ]
    
    def get_camera_capture(self, camera):
        """Initialize camera capture based on camera type"""
        if camera.camera_type == 'ip':
            return cv2.VideoCapture(camera.camera_url)
        else:
            # Device cameras are not available on Render. This will fail there.
            return cv2.VideoCapture(0)

    def _make_text_frame(self, message_lines, width=960, height=540):
        """Create a JPEG frame with centered text messages for error/info display."""
        img = np.zeros((height, width, 3), dtype=np.uint8)
        img[:] = (30, 30, 30)
        y = 60
        for line in message_lines:
            (tw, th), _ = cv2.getTextSize(line, cv2.FONT_HERSHEY_SIMPLEX, 0.8, 2)
            x = (width - tw) // 2
            cv2.putText(img, line, (x, y), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (200, 200, 200), 2, cv2.LINE_AA)
            y += th + 24
        _, buffer = cv2.imencode('.jpg', img)
        return (b'--frame\r\n'
                b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')

    def annotate_frame(self, frame):
        """Return a JPEG bytes image with YOLO detections drawn.
        Falls back to raw frame with a notice if model is unavailable."""
        try:
            self._ensure_model()
            results = self.model(frame, stream=True)
        except Exception:
            cv2.putText(frame, 'Detection unavailable', (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1,
                        (0, 0, 255), 2, cv2.LINE_AA)
            _, buf = cv2.imencode('.jpg', frame)
            return buf.tobytes()

        for r in results:
            for box in r.boxes:
                x1, y1, x2, y2 = map(int, box.xyxy[0])
                w, h = x2 - x1, y2 - y1
                conf = float(box.conf[0]) if box.conf is not None else 0.0
                cls = int(box.cls[0]) if box.cls is not None else -1
                detected_class = self.classNames[cls] if 0 <= cls < len(self.classNames) else 'object'

                cvzone.cornerRect(frame, (x1, y1, w, h))
                cvzone.putTextRect(
                    frame,
                    f"{detected_class} {conf:.2f}",
                    (max(0, x1), max(35, y1)),
                    scale=1,
                    thickness=1
                )

        _, buf = cv2.imencode('.jpg', frame)
        return buf.tobytes()
    
    def _ensure_model(self):
        if self.model is None:
            # Load a small YOLO model on first use (CPU)
            self.model = YOLO("yolov8n.pt")

    def process_frame(self, frame):
        """Process frame with YOLO detection"""
        jpeg_bytes = self.annotate_frame(frame)
        return (b'--frame\r\n'
                b'Content-Type: image/jpeg\r\n\r\n' + jpeg_bytes + b'\r\n')
    
    def generate_frames(self, camera):
        """Generate video frames for streaming"""
        cap = self.get_camera_capture(camera)
        
        try:
            # Validate capture
            if not cap or not cap.isOpened():
                # Provide a visible message instead of hanging
                if camera.camera_type == 'device':
                    msg = [
                        'No device camera available on the server.',
                        'Set camera type to IP and provide a reachable RTSP/HTTP URL.',
                        'Example: rtsp://user:pass@host:554/stream or http://host:port/video'
                    ]
                else:
                    msg = [
                        'Failed to open IP camera URL.',
                        f'URL: {camera.camera_url or "(empty)"}',
                        'Ensure the URL is reachable from the server.'
                    ]
                yield self._make_text_frame(msg)
                return

            while True:
                success, frame = cap.read()
                if not success:
                    # Attempt a brief retry
                    time.sleep(0.2)
                    success, frame = cap.read()
                    if not success:
                        yield self._make_text_frame(['Stream ended or not readable.'])
                        break
                
                yield self.process_frame(frame)

                # throttle to ~15 FPS to reduce CPU usage
                time.sleep(1 / 15.0)
        finally:
            cap.release()
