from flask import Flask, Response, render_template, request, redirect, url_for
import cv2
from ultralytics import YOLO

app = Flask(__name__)

model = YOLO("yolov8n.pt")  # Auto-download if not present
ip_camera_url = None  # Will be set by user

def generate_frames():
    global ip_camera_url
    if not ip_camera_url:
        return  # No URL set yet

    cap = cv2.VideoCapture(ip_camera_url)
    while True:
        success, frame = cap.read()
        if not success:
            break

        # Run YOLO detection
        results = model(frame, stream=True)
        for r in results:
            for box in r.boxes:
                x1, y1, x2, y2 = map(int, box.xyxy[0])
                cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)

        _, buffer = cv2.imencode('.jpg', frame)
        frame_bytes = buffer.tobytes()

        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

@app.route('/video')
def video():
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/', methods=['GET', 'POST'])
def index():
    global ip_camera_url
    if request.method == 'POST':
        ip_camera_url = request.form.get('camera_url')
        return redirect(url_for('stream'))
    return render_template('index.html')

@app.route('/stream')
def stream():
    if not ip_camera_url:
        return redirect(url_for('index'))
    return render_template('stream.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
