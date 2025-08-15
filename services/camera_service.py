# =====================================
# services/camera_service.py - Camera processing logic
# =====================================

import os
import time
import math
import logging
import cv2
import cvzone
import numpy as np

class CameraService:
    def __init__(self):
        # Lazy-load the YOLO model to avoid heavy startup and torch load issues
        self.model = None
        self.logger = logging.getLogger(__name__)
        try:
            self.conf_threshold = float(os.environ.get('DETECTION_CONF', '0.35'))
        except Exception:
            self.conf_threshold = 0.35
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

    def detect_and_annotate(self, frame):
        """Run detection and return (jpeg_bytes, detected: bool).
        If detection disabled/unavailable, returns (jpeg_bytes, False)."""
        self._ensure_model()
        detected_any = False
        if self.model is None:
            # Detection disabled
            cv2.putText(frame, 'Detection disabled', (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1,
                        (0, 0, 255), 2, cv2.LINE_AA)
            _, buf = cv2.imencode('.jpg', frame)
            return buf.tobytes(), False
        # Downscale to speed up inference on small instances
        h, w = frame.shape[:2]
        scale = 640.0 / max(w, h) if max(w, h) > 640 else 1.0
        small = cv2.resize(frame, (int(w * scale), int(h * scale))) if scale != 1.0 else frame
        try:
            results = self.model(small, stream=True)
        except Exception:
            cv2.putText(frame, 'Detection unavailable', (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1,
                        (0, 0, 255), 2, cv2.LINE_AA)
            _, buf = cv2.imencode('.jpg', frame)
            return buf.tobytes(), False

        for r in results:
            if hasattr(r, 'boxes') and r.boxes is not None:
                for box in r.boxes:
                    x1, y1, x2, y2 = map(int, box.xyxy[0])
                    bw, bh = x2 - x1, y2 - y1
                    conf = float(box.conf[0]) if box.conf is not None else 0.0
                    cls = int(box.cls[0]) if box.cls is not None else -1
                    detected_class = self.classNames[cls] if 0 <= cls < len(self.classNames) else 'object'
                    if conf < self.conf_threshold:
                        continue
                    detected_any = True
                    # Map boxes back to original frame size
                    inv = 1.0 / scale
                    X1, Y1 = int(x1 * inv), int(y1 * inv)
                    BW, BH = int(bw * inv), int(bh * inv)
                    cvzone.cornerRect(frame, (X1, Y1, BW, BH))
                    cvzone.putTextRect(
                        frame,
                        f"{detected_class} {conf:.2f}",
                        (max(0, X1), max(35, Y1)),
                        scale=1,
                        thickness=1
                    )

        _, buf = cv2.imencode('.jpg', frame)
        return buf.tobytes(), detected_any

    def annotate_frame(self, frame):
        """Backward-compatible: return only JPEG bytes with overlays."""
        jpeg_bytes, _ = self.detect_and_annotate(frame)
        return jpeg_bytes
    
    def _ensure_model(self):
        if self.model is not None:
            return
        # Allow disabling detection via env var to reduce memory usage
        enable_detection = os.environ.get('ENABLE_DETECTION', '1').lower() in ('1', 'true', 'yes')
        if not enable_detection:
            self.model = None
            return
        try:
            # Import here so torch is only loaded if enabled
            from ultralytics import YOLO as _YOLO  # type: ignore
            self.model = _YOLO("yolov8n.pt")
            self.logger.info("YOLO model loaded for detection")
        except Exception as e:
            self.logger.error("Failed to load YOLO model: %s", e)
            self.model = None

    def process_frame(self, frame, enable_detection: bool = False):
        """Encode frame as MJPEG chunk. If enable_detection, overlay detections first."""
        if enable_detection:
            jpeg_bytes = self.annotate_frame(frame)
        else:
            _, buffer = cv2.imencode('.jpg', frame)
            jpeg_bytes = buffer.tobytes()
        return (b'--frame\r\n'
                b'Content-Type: image/jpeg\r\n\r\n' + jpeg_bytes + b'\r\n')
    
    def generate_frames(self, camera, enable_detection: bool = False):
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
                
                yield self.process_frame(frame, enable_detection=enable_detection)

                # throttle to ~15 FPS to reduce CPU usage
                time.sleep(1 / 15.0)
        finally:
            cap.release()
