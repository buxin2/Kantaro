# Kantaro Smart Animal Detection 🐐

Flask web app that streams an IP camera feed and runs YOLOv8 object detection.

## Deploy to Render
1. Push this repo to GitHub.
2. Create a new Web Service on Render.
3. Set `IP_CAMERA_URL` in the environment variables.
4. Deploy and view your live stream.

## Local Run
```bash
pip install -r requirements.txt
export IP_CAMERA_URL="http://YOUR_CAMERA_STREAM_URL"
python app.py
