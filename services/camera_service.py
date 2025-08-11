# =====================================
# services/camera_service.py - Camera processing logic
# =====================================

import cv2
import cvzone
from ultralytics import YOLO
import math

class CameraService:
    def __init__(self):
        self.model = YOLO("yolov8n.pt")
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
            return cv2.VideoCapture(0)
    
    def process_frame(self, frame):
        """Process frame with YOLO detection"""
        results = self.model(frame, stream=True)
        
        for r in results:
            for box in r.boxes:
                x1, y1, x2, y2 = map(int, box.xyxy[0])
                w, h = x2 - x1, y2 - y1
                conf = math.ceil(box.conf[0] * 100) / 100
                cls = int(box.cls[0])
                detected_class = self.classNames[cls]
                
                # Draw bounding box and label
                cvzone.cornerRect(frame, (x1, y1, w, h))
                cvzone.putTextRect(frame, f'{detected_class} {conf}',
                                   (max(0, x1), max(35, y1)),
                                   scale=1, thickness=1)
        
        # Encode frame to JPEG
        _, buffer = cv2.imencode('.jpg', frame)
        return (b'--frame\r\n'
                b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
    
    def generate_frames(self, camera):
        """Generate video frames for streaming"""
        cap = self.get_camera_capture(camera)
        
        try:
            while True:
                success, frame = cap.read()
                if not success:
                    break
                
                yield self.process_frame(frame)
        finally:
            cap.release()
